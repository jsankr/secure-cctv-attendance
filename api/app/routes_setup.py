"""First-run setup and invitation-based registration.

No account, password or key ships with the code. On first start (no users) the API generates a one-time
setup code, writes it to a 0600 file in the data folder and shows it only on the local terminal
(launcher) or via `cat` inside the container. Whoever registers first must present it, so nobody who can
merely reach the web page can claim the super admin account (classic "first visitor becomes admin" race).

Every other account is created by invitation: a super admin invites admins/super admins, an admin
invites operators/viewers/kiosks. The invitee chooses their own username + password and must enrol MFA
before any session exists. Password resets use the same single-use links, so no administrator ever
knows another person's password.
"""
from __future__ import annotations

import datetime
import logging
import os
import secrets
import threading
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import models
from .config import settings
from .db import get_db
from .hardening import new_setup_code, normalise_code, password_problem, provisioning_uri, random_base32, token_hash
from .models import now
from .security import audit, client_ip, enc, hash_pw, make_token, rate_limit, require

log = logging.getLogger("vms.setup")
router = APIRouter(prefix="/api", tags=["setup"])

ISSUER = "Sentinel Attend"
USERNAME_RX = r"^[A-Za-z0-9._-]{3,64}$"
PHONE_RX = r"^(\+[1-9][0-9]{7,14})?$"
ROLE_RX = "^(kiosk|viewer|operator|admin|superadmin)$"
PRIVILEGED = ("admin", "superadmin")

# ------------------------------------------------------------------ setup code
_lock = threading.Lock()
_setup = {"hash": "", "fails": 0}
MAX_SETUP_FAILS = 10  # then the code is replaced (needs the terminal again)


def setup_code_path() -> Path:
    if settings.setup_code_file:
        return Path(settings.setup_code_file)
    return Path(settings.store_dir).resolve().parent / "setup-code.txt"


def _write_code(code: str):
    p = setup_code_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(code + "\n")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def needs_setup(db: Session) -> bool:
    return not db.scalar(select(func.count()).select_from(models.User))


def init_setup(db: Session):
    """Called at startup: arm a fresh one-time code if nobody has registered yet, else remove any leftover."""
    with _lock:
        if needs_setup(db):
            code = new_setup_code()
            _setup.update(hash=token_hash(normalise_code(code)), fails=0)
            _write_code(code)
            log.warning("FIRST-RUN SETUP: no accounts exist. One-time setup code written to %s "
                        "(open the console and choose 'Set up'; the code is needed once).", setup_code_path())
        else:
            _setup.update(hash="", fails=0)
            setup_code_path().unlink(missing_ok=True)


def _consume_setup(code: str) -> bool:
    with _lock:
        if not _setup["hash"]:
            return False
        ok = secrets.compare_digest(token_hash(normalise_code(code)), _setup["hash"])
        if ok:
            _setup.update(hash="", fails=0)
            setup_code_path().unlink(missing_ok=True)
            return True
        _setup["fails"] += 1
        if _setup["fails"] >= MAX_SETUP_FAILS:  # brute force: rotate; the attacker cannot read the new file
            code2 = new_setup_code()
            _setup.update(hash=token_hash(normalise_code(code2)), fails=0)
            _write_code(code2)
            log.warning("setup code rotated after %d failed attempts; read the new one from %s",
                        MAX_SETUP_FAILS, setup_code_path())
        return False


# ------------------------------------------------------------------ shared helpers
def _qr(uri: str) -> str:
    from .routes_auth import _qr as qr  # same QR renderer as login enrolment
    return qr(uri)


def mfa_enrolment(db: Session, u: models.User) -> dict:
    secret = random_base32()
    u.totp_secret, u.totp_enabled, u.last_totp = enc(secret), False, ""
    db.commit()
    return {"mfa_setup_required": True, "secret": secret, "username": u.username,
            "qr": _qr(provisioning_uri(secret, u.username, ISSUER)),
            "setup_token": make_token({"typ": "mfa_setup", "sub": str(u.id)}, 600)}


def _check_password(pw: str, username: str):
    why = password_problem(pw, username)
    if why:
        raise HTTPException(422, why)


def _username_free(db: Session, name: str):
    if db.scalar(select(models.User).where(func.lower(models.User.username) == name.lower())):
        raise HTTPException(409, "That username is taken")


# ------------------------------------------------------------------ first-run setup
class SetupIn(BaseModel):
    setup_code: str = Field(min_length=8, max_length=40)
    username: str = Field(pattern=USERNAME_RX)
    password: str = Field(max_length=256)
    email: str = Field(default="", max_length=255)
    phone: str = Field(default="", max_length=20, pattern=PHONE_RX)


@router.get("/setup/status")
def setup_status(db: Session = Depends(get_db)):
    """Public: only says whether first-run setup is still open (no other information)."""
    return {"needs_setup": needs_setup(db)}


@router.post("/setup/register")
def setup_register(body: SetupIn, request: Request, db: Session = Depends(get_db)):
    rate_limit("setup:" + client_ip(request), limit=5, window=900)
    if not needs_setup(db):
        raise HTTPException(409, "Setup is already complete; ask a super admin for an invitation")
    _check_password(body.password, body.username)
    if not _consume_setup(body.setup_code):
        audit(db, body.username, "setup_code_rejected", request=request)
        raise HTTPException(401, "Setup code is not valid")
    with _lock:
        if not needs_setup(db):  # lost a race with a concurrent valid registration
            raise HTTPException(409, "Setup is already complete")
        u = models.User(username=body.username, role="superadmin", pw_hash=hash_pw(body.password),
                        email=body.email.strip(), phone=body.phone.strip())
        db.add(u)
        db.commit()
    audit(db, u.username, "setup_superadmin_registered", u.username, request)
    log.warning("first super admin '%s' registered; setup closed", u.username)
    return mfa_enrolment(db, u)


# ------------------------------------------------------------------ invitations
class InviteIn(BaseModel):
    role: str = Field(pattern=ROLE_RX)
    email: str = Field(default="", max_length=255)
    phone: str = Field(default="", max_length=20, pattern=PHONE_RX)
    note: str = Field(default="", max_length=255)
    hours: int = Field(default=0, ge=0, le=168)


def guard_role(actor: models.User, role: str):
    """Admins can invite operators, viewers and kiosks; only a super admin can create admins/super admins."""
    if role in PRIVILEGED and actor.role != "superadmin":
        raise HTTPException(403, "Only a super admin can invite admins or super admins")


def new_link(db: Session, actor: models.User, *, kind: str, role: str, user_id: int | None = None,
             email: str = "", phone: str = "", note: str = "", hours: int = 0) -> dict:
    token = secrets.token_urlsafe(32)  # 256-bit
    exp = now() + datetime.timedelta(hours=hours or settings.invite_hours)
    inv = models.Invite(token_hash=token_hash(token), kind=kind, role=role, user_id=user_id, email=email.strip(),
                        phone=phone.strip(), note=note.strip(), created_by=actor.username, expires_at=exp)
    db.add(inv)
    db.commit()
    return {"id": inv.id, "token": token, "path": f"/#/register?code={token}", "expires_at": models.iso(exp),
            "role": role, "kind": kind}


def invite_out(i: models.Invite) -> dict:
    state = ("used" if i.used_at else "revoked" if i.revoked else "expired" if i.expires_at <= now() else "pending")
    return {"id": i.id, "kind": i.kind, "role": i.role, "email": i.email, "phone": i.phone, "note": i.note,
            "created_by": i.created_by, "created_at": models.iso(i.created_at), "expires_at": models.iso(i.expires_at),
            "used_by": i.used_by, "used_at": models.iso(i.used_at), "state": state}


@router.post("/users/invites")
def create_invite(body: InviteIn, request: Request, db: Session = Depends(get_db), a=Depends(require("admin"))):
    guard_role(a, body.role)
    out = new_link(db, a, kind="invite", role=body.role, email=body.email, phone=body.phone, note=body.note, hours=body.hours)
    audit(db, a.username, "invite_created", body.role, request, invite=out["id"], email=body.email)
    if body.role in PRIVILEGED:
        from .notify import security_alert
        security_alert(db, "privileged_invite", a.username,
                       f"{a.username} issued a {body.role} invitation (#{out['id']}{', ' + body.email if body.email else ''})")
    return out


@router.get("/users/invites")
def list_invites(db: Session = Depends(get_db), a=Depends(require("admin"))):
    q = select(models.Invite).order_by(models.Invite.id.desc()).limit(200)
    rows = db.scalars(q).all()
    if a.role != "superadmin":  # admins do not see privileged invitations
        rows = [i for i in rows if i.role not in PRIVILEGED]
    return [invite_out(i) for i in rows]


@router.delete("/users/invites/{iid}")
def revoke_invite(iid: int, request: Request, db: Session = Depends(get_db), a=Depends(require("admin"))):
    i = db.get(models.Invite, iid)
    if not i:
        raise HTTPException(404)
    guard_role(a, i.role)
    i.revoked = True
    db.commit()
    audit(db, a.username, "invite_revoked", str(iid), request)
    return {"ok": True}


# ------------------------------------------------------------------ redeem (public, token-gated)
class TokenIn(BaseModel):
    code: str = Field(min_length=20, max_length=100)


class RegisterIn(TokenIn):
    username: str = Field(default="", max_length=64)
    password: str = Field(max_length=256)
    email: str = Field(default="", max_length=255)
    phone: str = Field(default="", max_length=20, pattern=PHONE_RX)


def _live_invite(db: Session, code: str) -> models.Invite:
    i = db.scalar(select(models.Invite).where(models.Invite.token_hash == token_hash(code.strip())))
    if not i or i.used_at or i.revoked or i.expires_at <= now():
        raise HTTPException(404, "This link is invalid, used or expired; ask for a new one")
    return i


@router.post("/register/check")
def register_check(body: TokenIn, request: Request, db: Session = Depends(get_db)):
    rate_limit("register:" + client_ip(request), limit=20, window=900)
    i = _live_invite(db, body.code)
    user = db.get(models.User, i.user_id) if i.user_id else None
    return {"kind": i.kind, "role": i.role, "email": i.email, "expires_at": models.iso(i.expires_at),
            "username": user.username if user else ""}


@router.post("/register")
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    rate_limit("register:" + client_ip(request), limit=20, window=900)
    i = _live_invite(db, body.code)
    from .notify import security_alert
    if i.kind == "reset":
        u = db.get(models.User, i.user_id)
        if not u or u.disabled:
            raise HTTPException(404, "This link is invalid, used or expired; ask for a new one")
        _check_password(body.password, u.username)
        u.pw_hash, u.failed, u.locked_until = hash_pw(body.password), 0, None
        u.pw_version += 1
        i.used_at, i.used_by = now(), u.username
        db.commit()
        audit(db, u.username, "password_reset_completed", u.username, request)
        if u.role in PRIVILEGED:
            security_alert(db, "privileged_password_reset", u.username, f"Password reset completed for {u.role} '{u.username}'",
                           severity="medium")
        return mfa_enrolment(db, u) if not u.totp_enabled else {"ok": True, "message": "Password set. Sign in."}
    import re
    if not re.match(USERNAME_RX, body.username):
        raise HTTPException(422, "Username: 3-64 letters, digits, dot, dash or underscore")
    _check_password(body.password, body.username)
    _username_free(db, body.username)
    u = models.User(username=body.username, role=i.role, pw_hash=hash_pw(body.password),
                    email=(body.email or i.email).strip(), phone=(body.phone or i.phone).strip())
    db.add(u)
    i.used_at, i.used_by = now(), body.username
    db.commit()
    audit(db, u.username, "invite_redeemed", u.username, request, invite=i.id, role=i.role, invited_by=i.created_by)
    if i.role in PRIVILEGED:
        security_alert(db, "privileged_user_registered", u.username,
                       f"'{u.username}' registered as {i.role} (invited by {i.created_by})", severity="medium")
    return mfa_enrolment(db, u)
