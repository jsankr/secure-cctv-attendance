"""Sentinel Attend cryptography: authenticated streaming encryption and the super-admin vault.

Two protection levels:

1. MEDIA KEY (symmetric, AES-256-GCM): blurred ("privacy") recordings, event snapshots, blurred
   attendance images, face templates. The server holds this key so authorised users can view
   privacy-safe material.

2. SEALED (X25519 + HKDF-SHA256 + AES-256-GCM, ECIES-style): raw unblurred recordings and raw
   attendance face crops. Sealed to the super-admin vault PUBLIC key, so recorders can write them
   but nothing on the server can read them back. Opening needs the vault PRIVATE key, which is
   stored only wrapped under:
     - a key derived with Argon2id (256 MiB, t=3, p=4) from the super-admin vault passphrase, and
     - a high-entropy offline recovery code (shown once at vault set-up).
   The API additionally demands the super admin's TOTP code before it will attempt an unlock.

File format (both levels): header || chunk*. Every chunk is AES-256-GCM with a nonce built from a
random prefix, a chunk counter and a last-chunk flag (the STREAM construction), and the header is
bound to every chunk as associated data — so chunks cannot be reordered, dropped, truncated,
or moved between files without detection.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterable, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"SVMS1"
MODE_KEY, MODE_SEALED = b"K", b"S"
CHUNK = 1 << 20  # 1 MiB plaintext per chunk
ARGON = {"iterations": 3, "lanes": 4, "memory_cost": 262144}  # 256 MiB


class CryptoError(Exception):
    pass


# --------------------------------------------------------------- primitives
def _hkdf(material: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(material)


def _wrap(kek: bytes, dek: bytes, aad: bytes) -> bytes:
    n = os.urandom(12)
    return n + AESGCM(kek).encrypt(n, dek, aad)


def _unwrap(kek: bytes, blob: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(kek).decrypt(blob[:12], blob[12:], aad)
    except InvalidTag as e:
        raise CryptoError("key unwrap failed (wrong key or tampered header)") from e


def key_id(key: bytes) -> bytes:
    return hashlib.sha256(b"svms-key-id" + key).digest()[:8]


def pub_bytes(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint(pub_raw: bytes) -> str:
    h = hashlib.sha256(pub_raw).hexdigest()[:24].upper()
    return "-".join(h[i:i + 4] for i in range(0, 24, 4))


# ------------------------------------------------------------ stream format
def _header_key(media_key: bytes, dek: bytes) -> bytes:
    kid = key_id(media_key)
    base = MAGIC + MODE_KEY + kid
    return base + _wrap(media_key, dek, base)


def _header_sealed(recipient_pub: bytes, dek: bytes) -> bytes:
    eph = X25519PrivateKey.generate()
    eph_pub = pub_bytes(eph.public_key())
    shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient_pub))
    kek = _hkdf(shared, eph_pub + recipient_pub, b"svms-seal-v1")
    base = MAGIC + MODE_SEALED + key_id(recipient_pub) + eph_pub
    return base + _wrap(kek, dek, base)


class Encryptor:
    """Incremental encryptor: feed bytes with write(), finish with close(). Output goes to `out`."""

    def __init__(self, out: BinaryIO, *, media_key: bytes | None = None, recipient_pub: bytes | None = None):
        if (media_key is None) == (recipient_pub is None):
            raise ValueError("exactly one of media_key / recipient_pub")
        self.dek = AESGCM.generate_key(bit_length=256)
        hdr = _header_key(media_key, self.dek) if media_key else _header_sealed(recipient_pub, self.dek)
        self.prefix = os.urandom(7)
        self.header = hdr + self.prefix + struct.pack(">I", CHUNK)
        self.out, self.buf, self.counter, self.closed = out, bytearray(), 0, False
        self.aead = AESGCM(self.dek)
        out.write(struct.pack(">I", len(self.header)) + self.header)

    def _emit(self, data: bytes, last: bool):
        if self.counter >= 0xFFFFFFFF:
            raise CryptoError("stream too long")
        nonce = self.prefix + struct.pack(">I", self.counter) + (b"\x01" if last else b"\x00")
        ct = self.aead.encrypt(nonce, bytes(data), self.header)
        self.out.write(struct.pack(">I", len(ct)) + ct)
        self.counter += 1

    def write(self, data: bytes):
        self.buf += data
        while len(self.buf) > CHUNK:  # keep >=1 byte back so the last chunk is flagged correctly
            self._emit(self.buf[:CHUNK], False)
            del self.buf[:CHUNK]

    def close(self):
        if not self.closed:
            self._emit(self.buf, True)
            self.buf.clear()
            self.closed = True


def _read_exact(f: BinaryIO, n: int) -> bytes:
    b = f.read(n)
    if len(b) != n:
        raise CryptoError("truncated ciphertext")
    return b


def read_header(f: BinaryIO) -> tuple[bytes, bytes]:
    """Returns (header, mode)."""
    (hl,) = struct.unpack(">I", _read_exact(f, 4))
    if hl > 4096:
        raise CryptoError("bad header")
    hdr = _read_exact(f, hl)
    if hdr[:5] != MAGIC:
        raise CryptoError("not a Sentinel Attend encrypted file")
    return hdr, hdr[5:6]


def _dek_from_header(hdr: bytes, *, media_key: bytes | None, private_key: X25519PrivateKey | None) -> bytes:
    mode = hdr[5:6]
    if mode == MODE_KEY:
        if media_key is None:
            raise CryptoError("media key required")
        if hdr[6:14] != key_id(media_key):
            raise CryptoError("encrypted with a different media key")
        base, wrapped = hdr[:14], hdr[14:14 + 60]
        return _unwrap(media_key, wrapped, base)
    if mode == MODE_SEALED:
        if private_key is None:
            raise CryptoError("sealed: vault private key required")
        recip = pub_bytes(private_key.public_key())
        if hdr[6:14] != key_id(recip):
            raise CryptoError("sealed to a different vault key")
        eph_pub = hdr[14:46]
        base, wrapped = hdr[:46], hdr[46:46 + 60]
        kek = _hkdf(private_key.exchange(X25519PublicKey.from_public_bytes(eph_pub)), eph_pub + recip, b"svms-seal-v1")
        return _unwrap(kek, wrapped, base)
    raise CryptoError("unknown mode")


def decrypt_iter(f: BinaryIO, *, media_key: bytes | None = None,
                 private_key: X25519PrivateKey | None = None) -> Iterator[bytes]:
    hdr, _ = read_header(f)
    dek = _dek_from_header(hdr, media_key=media_key, private_key=private_key)
    prefix = hdr[-11:-4]
    aead, counter = AESGCM(dek), 0
    while True:
        lb = f.read(4)
        if not lb:
            raise CryptoError("truncated: final chunk missing")
        (n,) = struct.unpack(">I", lb)
        ct = _read_exact(f, n)
        for last in (False, True):
            nonce = prefix + struct.pack(">I", counter) + (b"\x01" if last else b"\x00")
            try:
                pt = aead.decrypt(nonce, ct, hdr)
                break
            except InvalidTag:
                pt = None
        if pt is None:
            raise CryptoError("authentication failed (tampered, reordered or wrong key)")
        counter += 1
        yield pt
        if last:
            if f.read(1):
                raise CryptoError("trailing data after final chunk")
            return


def encrypt_bytes(data: bytes, **kw) -> bytes:
    out = io.BytesIO()
    e = Encryptor(out, **kw)
    e.write(data)
    e.close()
    return out.getvalue()


def decrypt_bytes(blob: bytes, **kw) -> bytes:
    return b"".join(decrypt_iter(io.BytesIO(blob), **kw))


def decrypt_file(path: str, **kw) -> bytes:
    with open(path, "rb") as f:
        return b"".join(decrypt_iter(f, **kw))


def is_sealed(path: str) -> bool:
    with open(path, "rb") as f:
        return read_header(f)[1] == MODE_SEALED


# -------------------------------------------------------------------- vault
def _argon(passphrase: str, salt: bytes, params: dict) -> bytes:
    return Argon2id(salt=salt, length=32, **params).derive(passphrase.encode("utf-8"))


def _recovery_kek(code: str) -> bytes:
    raw = base64.b32decode(code.replace("-", "").replace(" ", "").upper())
    return _hkdf(raw, b"svms-recovery-salt", b"svms-recovery-v1")


@dataclass
class VaultRecord:
    """Everything persisted about the vault. Contains no usable secret on its own."""
    public_key: bytes
    salt: bytes
    params: dict
    wrapped_by_passphrase: bytes
    wrapped_by_recovery: bytes

    def to_json(self) -> str:
        b = lambda x: base64.b64encode(x).decode()  # noqa: E731
        return json.dumps({"v": 1, "public_key": b(self.public_key), "salt": b(self.salt), "params": self.params,
                           "wp": b(self.wrapped_by_passphrase), "wr": b(self.wrapped_by_recovery)})

    @classmethod
    def from_json(cls, s: str) -> "VaultRecord":
        d = json.loads(s)
        u = base64.b64decode
        return cls(u(d["public_key"]), u(d["salt"]), d["params"], u(d["wp"]), u(d["wr"]))

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.public_key)


def check_passphrase_strength(p: str) -> str | None:
    if len(p) < 16:
        return "Vault passphrase must be at least 16 characters (a 4-5 word phrase works well)"
    if len(set(p)) < 8:
        return "Vault passphrase is too repetitive"
    return None


def create_vault(passphrase: str) -> tuple[VaultRecord, str]:
    """Returns (record, recovery_code). The recovery code is shown once and never stored."""
    err = check_passphrase_strength(passphrase)
    if err:
        raise CryptoError(err)
    priv = X25519PrivateKey.generate()
    raw_priv = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption())
    pub = pub_bytes(priv.public_key())
    salt = os.urandom(16)
    recovery_raw = os.urandom(20)  # 160-bit
    code = base64.b32encode(recovery_raw).decode()
    code = "-".join(code[i:i + 4] for i in range(0, len(code), 4))
    aad = b"svms-vault-v1" + pub
    rec = VaultRecord(pub, salt, dict(ARGON), _wrap(_argon(passphrase, salt, ARGON), raw_priv, aad),
                      _wrap(_recovery_kek(code), raw_priv, aad))
    return rec, code


def unlock_vault(rec: VaultRecord, *, passphrase: str | None = None, recovery_code: str | None = None) -> X25519PrivateKey:
    aad = b"svms-vault-v1" + rec.public_key
    try:
        if passphrase is not None:
            raw = _unwrap(_argon(passphrase, rec.salt, rec.params), rec.wrapped_by_passphrase, aad)
        elif recovery_code is not None:
            raw = _unwrap(_recovery_kek(recovery_code), rec.wrapped_by_recovery, aad)
        else:
            raise CryptoError("passphrase or recovery code required")
    except (CryptoError, ValueError) as e:
        raise CryptoError("Incorrect vault passphrase or recovery code") from e
    priv = X25519PrivateKey.from_private_bytes(raw)
    if pub_bytes(priv.public_key()) != rec.public_key:
        raise CryptoError("vault integrity check failed")
    return priv


def rewrap_vault(rec: VaultRecord, priv: X25519PrivateKey, new_passphrase: str) -> VaultRecord:
    err = check_passphrase_strength(new_passphrase)
    if err:
        raise CryptoError(err)
    raw = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    salt = os.urandom(16)
    aad = b"svms-vault-v1" + rec.public_key
    return VaultRecord(rec.public_key, salt, dict(ARGON), _wrap(_argon(new_passphrase, salt, ARGON), raw, aad),
                       rec.wrapped_by_recovery)


def iter_files(paths: Iterable[str], **kw) -> Iterator[bytes]:
    for p in paths:
        with open(p, "rb") as f:
            yield from decrypt_iter(f, **kw)
