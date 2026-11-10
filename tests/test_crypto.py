"""CR: encrypted storage and the super-admin vault."""
import io
import os
import struct

import pytest

import vmscrypto as C

PASS = "a long vault passphrase for tests"


@pytest.fixture(scope="module")
def vault():
    rec, code = C.create_vault(PASS)
    return rec, code, C.unlock_vault(rec, passphrase=PASS)


def _chunks(blob):
    hl = struct.unpack(">I", blob[:4])[0]
    head, pos, out = blob[:4 + hl], 4 + hl, []
    while pos < len(blob):
        n = struct.unpack(">I", blob[pos:pos + 4])[0]
        out.append(blob[pos:pos + 4 + n])
        pos += 4 + n
    return head, out


def test_CR_01_media_roundtrip_chunk_boundaries():
    """AES-256-GCM media encryption round-trips at every chunk-boundary size."""
    k = os.urandom(32)
    for n in (0, 1, C.CHUNK - 1, C.CHUNK, C.CHUNK + 1, 3 * C.CHUNK + 7):
        d = os.urandom(n)
        assert C.decrypt_bytes(C.encrypt_bytes(d, media_key=k), media_key=k) == d


def test_CR_02_sealed_roundtrip(vault):
    """Raw footage sealed to the vault public key opens only with the unlocked private key."""
    rec, _, priv = vault
    d = os.urandom(2 * C.CHUNK + 99)
    assert C.decrypt_bytes(C.encrypt_bytes(d, recipient_pub=rec.public_key), private_key=priv) == d


def test_CR_03_recovery_code(vault):
    """The offline recovery code unlocks the vault (case/space/dash insensitive)."""
    rec, code, _ = vault
    assert C.unlock_vault(rec, recovery_code=code.lower().replace("-", " ")).public_key()


def test_CR_04_wrong_passphrase(vault):
    """Wrong passphrase is rejected."""
    with pytest.raises(C.CryptoError):
        C.unlock_vault(vault[0], passphrase="not the passphrase at all")


def test_CR_05_sealed_needs_vault_key(vault):
    """A sealed file cannot be opened with the server's media key."""
    blob = C.encrypt_bytes(b"x" * 100, recipient_pub=vault[0].public_key)
    with pytest.raises(C.CryptoError):
        C.decrypt_bytes(blob, media_key=os.urandom(32))


def test_CR_06_other_vault_rejected(vault):
    """A different vault's key cannot open the file."""
    blob = C.encrypt_bytes(b"x" * 100, recipient_pub=vault[0].public_key)
    other, _ = C.create_vault("another vault passphrase here")
    with pytest.raises(C.CryptoError):
        C.decrypt_bytes(blob, private_key=C.unlock_vault(other, passphrase="another vault passphrase here"))


@pytest.mark.parametrize("where", ["chunk", "header", "length"])
def test_CR_07_tamper_detected(vault, where):
    """Bit flips in a chunk, the header or a length prefix are detected."""
    blob = bytearray(C.encrypt_bytes(os.urandom(C.CHUNK * 2), recipient_pub=vault[0].public_key))
    pos = {"chunk": 300, "header": 30, "length": 4 + struct.unpack(">I", blob[:4])[0] + 2}[where]
    blob[pos] ^= 1
    with pytest.raises(C.CryptoError):
        C.decrypt_bytes(bytes(blob), private_key=vault[2])


def test_CR_08_truncation_detected(vault):
    """Removing the final chunk (truncation attack) is detected."""
    head, ch = _chunks(C.encrypt_bytes(os.urandom(C.CHUNK * 2 + 5), recipient_pub=vault[0].public_key))
    with pytest.raises(C.CryptoError):
        C.decrypt_bytes(head + b"".join(ch[:-1]), private_key=vault[2])


def test_CR_09_reorder_detected(vault):
    """Swapping chunks is detected."""
    head, ch = _chunks(C.encrypt_bytes(os.urandom(C.CHUNK * 2 + 5), recipient_pub=vault[0].public_key))
    with pytest.raises(C.CryptoError):
        C.decrypt_bytes(head + ch[1] + ch[0] + ch[2], private_key=vault[2])


def test_CR_10_splice_detected(vault):
    """Chunks spliced from another file under the same key are detected."""
    a = C.encrypt_bytes(os.urandom(C.CHUNK * 2 + 5), recipient_pub=vault[0].public_key)
    b = C.encrypt_bytes(os.urandom(C.CHUNK * 2 + 5), recipient_pub=vault[0].public_key)
    head_a, _ = _chunks(a)
    _, ch_b = _chunks(b)
    with pytest.raises(C.CryptoError):
        C.decrypt_bytes(head_a + b"".join(ch_b), private_key=vault[2])


def test_CR_11_trailing_data_detected():
    """Data appended after the final chunk is rejected."""
    k = os.urandom(32)
    with pytest.raises(C.CryptoError):
        C.decrypt_bytes(C.encrypt_bytes(b"abc", media_key=k) + b"\x00", media_key=k)


def test_CR_12_malformed_header():
    """Garbage, empty input and oversize header lengths are rejected cleanly."""
    for blob in (b"", b"\x00\x00", b"\x00\x00\x10\x00" + b"x" * 10, b"\xff\xff\xff\xff", os.urandom(64)):
        with pytest.raises(C.CryptoError):
            C.decrypt_bytes(blob, media_key=os.urandom(32))


def test_CR_13_weak_passphrases_refused():
    """Short or repetitive vault passphrases are refused."""
    for p in ("short", "aaaaaaaaaaaaaaaaaaaa", "abababababababababab"):
        with pytest.raises(C.CryptoError):
            C.create_vault(p)


def test_CR_14_passphrase_rotation(vault):
    """Changing the passphrase keeps old footage readable and retires the old passphrase."""
    rec, _, priv = vault
    blob = C.encrypt_bytes(b"footage", recipient_pub=rec.public_key)
    new = C.rewrap_vault(rec, priv, "a brand new vault passphrase")
    assert C.decrypt_bytes(blob, private_key=C.unlock_vault(new, passphrase="a brand new vault passphrase")) == b"footage"
    with pytest.raises(C.CryptoError):
        C.unlock_vault(new, passphrase=PASS)


def test_CR_15_vault_record_tamper(vault):
    """Swapping the stored public key in the vault record is detected at unlock."""
    rec = C.VaultRecord.from_json(vault[0].to_json())
    rec.public_key = C.create_vault("third vault passphrase ok")[0].public_key
    with pytest.raises(C.CryptoError):
        C.unlock_vault(rec, passphrase=PASS)


def test_CR_16_nonce_uniqueness():
    """Every encryption uses a fresh data key and nonce prefix (no ciphertext repeats)."""
    k = os.urandom(32)
    assert len({C.encrypt_bytes(b"same plaintext", media_key=k) for _ in range(50)}) == 50


def test_CR_17_streaming_encryptor():
    """Incremental writes in odd sizes decrypt to the same stream."""
    k, data, out = os.urandom(32), os.urandom(3 * C.CHUNK + 12345), io.BytesIO()
    e = C.Encryptor(out, media_key=k)
    for i in range(0, len(data), 77777):
        e.write(data[i:i + 77777])
    e.close()
    assert C.decrypt_bytes(out.getvalue(), media_key=k) == data
