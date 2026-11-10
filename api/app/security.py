"""Authentication primitives: Argon2id passwords, Fernet-at-rest, JWT sessions, CSRF, RBAC."""
import base64
import secrets
import sys
import time
from collections import defaultdict, deque
from pathlib import Path

import jwt
from cryptography.exceptions import InvalidKey
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from . import models
from .config import settings
from .db import get_db
from .hardening import totp_verify

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shared"))  # laptop mode / repo layout
import vmscrypto  # noqa: E402

# Argon2id password hashing via `cryptography` (PHC strings, same format and defaults as argon2-cffi:
# m=64 MiB, t=3, p=4), so hashes written by earlier versions keep verifying. No C extension needed.
_PW_PARAMS = {"iterations": 3, "lanes": 4, "memory_cost": 65536}
if not hasattr(Argon2id, "verify_phc_encoded"):
    raise RuntimeError("cryptography >= 47 is required (Argon2id PHC password hashing); upgrade the package")


def _phc_hash(p: str) -> str:
    return Argon2id(salt=secrets.token_bytes(16), length=32, **_PW_PARAMS).derive_phc_encoded(p.encode())


_fernet = Fernet(settings.fernet_key.encode())
_DUMMY_HASH = _phc_hash(secrets.token_hex(16))
ALG = "HS256"
COOKIE = "vms_session"
ROLES = {"kiosk": 0, "viewer": 1, "operator": 2, "admin": 3, "superadmin": 4}
MEDIA_KEY = base64.b64decode(settings.media_key) if settings.media_key else b""
if MEDIA_KEY and len(MEDIA_KEY) != 32:
    raise RuntimeError("VMS_MEDIA_KEY must be 32 bytes, base64-encoded")


def media_encrypt(data: bytes) -> bytes:
    if not MEDIA_KEY:
        raise RuntimeError("VMS_MEDIA_KEY is not configured")
    return vmscrypto.encrypt_bytes(data, media_key=MEDIA_KEY)


def media_decrypt(blob: bytes) -> bytes:
    return vmscrypto.decrypt_bytes(blob, media_key=MEDIA_KEY)


def verify_totp(u: models.User, code: str, enrolling: bool = False) -> bool:
    """TOTP with strict replay protection (each time step usable once). Caller commits the session.
    `enrolling` is only for the enrolment step, where the secret exists but MFA is not yet switched on;
    everywhere else an account without enabled MFA can never pass."""
    if not u.totp_secret or (not u.totp_enabled and not enrolling):
        return False
    ok, marker = totp_verify(dec(u.totp_secret), code, u.last_totp)
    if ok:
        u.last_totp = marker
    return ok


def enc(s: str) -> str:
    return _fernet.encrypt(s.encode()).decode() if s else ""


def dec(s: str) -> str:
    return _fernet.decrypt(s.encode()).decode() if s else ""


def hash_pw(p: str) -> str:
    return _phc_hash(p)


def verify_pw(h: str | None, p: str) -> bool:
    """Constant work whether or not the user exists (dummy hash), so timing does not reveal usernames."""
    try:
        Argon2id.verify_phc_encoded(p.encode(), h or _DUMMY_HASH)
        return h is not None
    except (InvalidKey, ValueError, TypeError):
        return False


def make_token(claims: dict, seconds: int) -> str:
    t = int(time.time())
    return jwt.encode({**claims, "iat": t, "exp": t + seconds}, settings.secret_key, algorithm=ALG)


def read_token(tok: str, typ: str) -> dict | None:
    if not tok:
        return None
    try:
        c = jwt.decode(tok, settings.secret_key, algorithms=[ALG])
    except jwt.PyJWTError:
        return None
    return c if c.get("typ") == typ else None


def client_ip(request: Request) -> str:
    # Only Caddy / cloudflared can reach the API, so forwarded headers are trusted.
    return (request.headers.get("cf-connecting-ip")
            or request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else ""))


_hits: dict[str, deque] = defaultdict(deque)


def rate_limit(key: str, limit: int = 10, window: int = 300):
    q, t = _hits[key], time.time()
    while q and q[0] < t - window:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(429, "Too many attempts, try later")
    q.append(t)


def fail_count(key: str, window: int) -> int:
    q, t = _hits[key], time.time()
    while q and q[0] < t - window:
        q.popleft()
    return len(q)


def record_failure(key: str):
    _hits[key].append(time.time())


def current_user(request: Request, db: Session = Depends(get_db)) -> models.User:
    c = read_token(request.cookies.get(COOKIE, ""), "session")
    if not c:
        raise HTTPException(401, "Not authenticated")
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        if not secrets.compare_digest(request.headers.get("x-csrf-token", ""), c.get("csrf", "")):
            raise HTTPException(403, "CSRF check failed")
    u = db.get(models.User, int(c["sub"]))
    if not u or u.disabled or c.get("pwv") != u.pw_version:
        raise HTTPException(401, "Session revoked")
    request.state.claims = c
    return u


def require(role: str):
    def dep(u: models.User = Depends(current_user)) -> models.User:
        if ROLES.get(u.role, -1) < ROLES[role]:
            raise HTTPException(403, "Insufficient role")
        return u
    return dep


def require_kiosk(u: models.User = Depends(current_user)) -> models.User:
    if u.role not in ("kiosk", "operator", "admin", "superadmin"):
        raise HTTPException(403, "Kiosk access required")
    return u


def internal_only(request: Request):
    if not secrets.compare_digest(request.headers.get("x-internal-token", ""), settings.internal_token):
        raise HTTPException(401)


def audit(db: Session, user: str, action: str, target: str = "", request: Request | None = None, **detail):
    db.add(models.AuditLog(username=user, action=action, target=str(target),
                           ip=client_ip(request) if request else "", detail=detail))
    db.commit()
