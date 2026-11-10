"""Security helpers with no framework dependencies (unit-testable on their own).

* TOTP (RFC 6238, HMAC-SHA1, 6 digits, 30 s) with STRICT replay protection: a code is accepted only if
  its time step is later than the last accepted step for that user, so no code (or older code) can
  ever be used twice. Replaces pyotp verification, whose valid_window let an older code be reused.
* csv_safe: neutralises spreadsheet formula injection (CWE-1236) in exported CSV cells.
* MAX_BODY: request-size cap applied before multipart parsing.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
from typing import Callable
from urllib.parse import parse_qs, quote

STEP, DIGITS = 30, 6
MAX_BODY = 64 * 1024 * 1024  # 64 MiB: kiosk uploads are ~3 MB, recordings are never uploaded


def random_base32(nbytes: int = 20) -> str:
    return base64.b32encode(os.urandom(nbytes)).decode().rstrip("=")


def _key(secret_b32: str) -> bytes:
    s = secret_b32.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def hotp(secret_b32: str, counter: int, digits: int = DIGITS) -> str:
    mac = hmac.new(_key(secret_b32), struct.pack(">Q", counter), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_at(secret_b32: str, t: float) -> str:
    return hotp(secret_b32, int(t // STEP))


def provisioning_uri(secret_b32: str, account: str, issuer: str) -> str:
    return (f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret_b32}"
            f"&issuer={quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={STEP}")


def totp_verify(secret_b32: str, code: str, last_marker: str, now: float | None = None) -> tuple[bool, str]:
    """Returns (ok, new_marker). Accepts the current step +/- 1 (clock drift) but only if the matched
    step is strictly greater than the last accepted step. The marker stores that step."""
    code = (code or "").strip()
    # isascii(): Unicode digits (e.g. full-width "１２３") satisfy isdigit() but crash compare_digest
    if len(code) != DIGITS or not (code.isascii() and code.isdigit()):
        return False, last_marker
    now = time.time() if now is None else now
    cur = int(now // STEP)
    try:
        last_step = int(last_marker.split(":")[-1]) if last_marker else -1
    except ValueError:
        last_step = -1
    for step in (cur - 1, cur, cur + 1):
        if hmac.compare_digest(hotp(secret_b32, step), code):
            if step <= last_step:
                return False, last_marker  # replay of this or an older code
            return True, str(step)
    return False, last_marker


_FORMULA = ("=", "+", "-", "@", "\t", "\r", "\n")


def csv_safe(v) -> str:
    """Prefix values that a spreadsheet would treat as a formula with an apostrophe."""
    s = "" if v is None else str(v)
    return "'" + s if s.startswith(_FORMULA) else s


def mediamtx_decision(body: dict, internal_token: str, claims_for: Callable[[str], dict | None]) -> bool:
    """MediaMTX external-auth decision. Internal services (publish, API, raw paths) use the internal
    identity. Browsers may only READ a face-blurred path (cam<N>_priv) with a short-lived stream token
    scoped to exactly that path. MediaMTX 1.9 passes 'Authorization: Bearer <t>' as query 'jwt=<t>'."""
    user, pw = body.get("user") or "", body.get("password") or ""
    action, path = body.get("action") or "", body.get("path") or ""
    if user == "internal" and pw and hmac.compare_digest(pw.encode(), internal_token.encode()):
        return True
    if action != "read" or not path.endswith("_priv"):
        return False
    tok = body.get("token") or (parse_qs(body.get("query") or "").get("jwt") or [""])[0]
    c = claims_for(tok) if tok else None
    return bool(c) and c.get("path") == path and c.get("act") == "read"


class ImageRejected(ValueError):
    pass


def decode_image(data: bytes, max_side: int = 4096, max_pixels: int = 12_000_000):
    """Decode an untrusted image safely. Dimensions are read from the header (no pixel decode) and
    oversized images are refused BEFORE OpenCV allocates memory: a 500 KB JPEG can declare
    16000x16000 px (~770 MB decoded) - a decompression bomb."""
    import io

    import cv2
    import numpy as np
    from PIL import Image, UnidentifiedImageError
    try:
        with Image.open(io.BytesIO(data)) as im:
            w, h = im.size
            fmt = im.format
    except Image.DecompressionBombError:
        raise ImageRejected("Image too large (decompression bomb)")
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError):
        raise ImageRejected("Not a valid image")
    if fmt not in ("JPEG", "PNG", "WEBP", "BMP"):
        raise ImageRejected(f"Unsupported image format {fmt}")
    if w > max_side or h > max_side or w * h > max_pixels:
        raise ImageRejected(f"Image too large ({w}x{h}); max {max_side}px per side")
    img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise ImageRejected("Not a valid image")
    return img


# ------------------------------------------------------------------ registration
# First-run setup and invitations replace any built-in account: the repository ships no usernames,
# passwords or keys. Tokens are random, single-use, short-lived and stored only as SHA-256 hashes.
_COMMON = {"password", "passw0rd", "letmein", "welcome", "qwerty", "admin", "administrator", "changeme", "sentinel",
           "iloveyou", "monkey", "dragon", "123456", "12345678", "123456789", "1234567890", "football", "baseball",
           "abc123", "trustno1", "superadmin", "college", "student", "attendance", "cctv", "camera"}


def password_problem(pw: str, username: str = "") -> str | None:
    """Account-password policy (NIST SP 800-63B style: length over composition, block obvious choices).
    Returns a human-readable reason, or None if acceptable."""
    if not isinstance(pw, str) or len(pw) < 12:
        return "Password must be at least 12 characters"
    if len(pw) > 256:
        return "Password is too long (max 256)"
    low = pw.lower()
    stripped = low.strip("0123456789!@#$%^&*._- ")
    if username and username.lower() in low:
        return "Password must not contain the username"
    if stripped in _COMMON or low in _COMMON or any(low.startswith(c) and len(low) - len(c) <= 4 for c in _COMMON):
        return "Password is too common"
    if len(set(pw)) < 6:
        return "Password is too repetitive"
    classes = sum(any(f(c) for c in pw) for f in (str.islower, str.isupper, str.isdigit, lambda c: not c.isalnum()))
    if len(pw) < 16 and classes < 3:
        return "Use 16+ characters, or mix at least three of: lower case, upper case, digits, symbols"
    return None


def new_setup_code() -> str:
    """80-bit one-time setup code, grouped for reading off a terminal: ABCD-EFGH-JKLM-NPQR."""
    raw = base64.b32encode(os.urandom(10)).decode()
    return "-".join(raw[i:i + 4] for i in range(0, 16, 4))


def normalise_code(code: str) -> str:
    return "".join(ch for ch in str(code).upper() if ch.isascii() and ch.isalnum())


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
