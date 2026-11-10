import base64
import datetime
import io
import secrets
import time

import qrcode
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models
from .config import settings
from .db import get_db
from .hardening import password_problem, provisioning_uri, random_base32
from .models import now
from .security import (COOKIE, audit, client_ip, current_user, enc, hash_pw, make_token,
                       rate_limit, read_token, require, verify_pw, verify_totp)

router = APIRouter(prefix="/api/auth", tags=["auth"])
users_router = APIRouter(prefix="/api/users", tags=["users"])

MAX_FAILS, LOCK_MIN = 5, 15


class LoginIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)
    totp: str = Field(default="", max_length=8)


class EnrollIn(BaseModel):
    setup_token: str
    totp: str = Field(max_length=8)


class PwIn(BaseModel):
    old_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


def user_out(u: models.User) -> dict:
    return {"id": u.id, "username": u.username, "role": u.role, "mfa": u.totp_enabled,
            "disabled": u.disabled, "locked": bool(u.locked_until and u.locked_until > now()),
            "created_at": models.iso(u.created_at)}


def _qr(uri: str) -> str:
    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def _totp_ok(u: models.User, code: str) -> bool:
    return verify_totp(u, code)


def _fail(db: Session, u: models.User | None, request: Request, reason: str):
    if u:
        u.failed += 1
        if u.failed >= MAX_FAILS:
            u.locked_until = now() + datetime.timedelta(minutes=LOCK_MIN)
            u.failed = 0
        db.commit()
    audit(db, u.username if u else "?", "login_failed", request=request, reason=reason)
    raise HTTPException(401, "Invalid credentials")


def issue_session(response: Response, u: models.User, csrf: str | None = None, auth_time: int | None = None) -> dict:
    csrf = csrf or secrets.token_urlsafe(24)
    tok = make_token({"typ": "session", "sub": str(u.id), "role": u.role, "csrf": csrf,
                      "pwv": u.pw_version, "auth_time": auth_time or int(time.time())},
                     settings.session_minutes * 60)
    response.set_cookie(COOKIE, tok, httponly=True, secure=settings.cookie_secure, samesite="strict",
                        max_age=settings.session_minutes * 60, path="/")
    return {"user": user_out(u), "csrf": csrf}


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    rate_limit("login:" + client_ip(request))
    u = db.scalar(select(models.User).where(models.User.username == body.username))
    if not verify_pw(u.pw_hash if u else None, body.password) or not u or u.disabled:
        _fail(db, u, request, "password")
    if u.locked_until and u.locked_until > now():
        raise HTTPException(423, "Account temporarily locked")
    if not u.totp_enabled:  # first login: force MFA enrolment before any session exists
        secret = random_base32()
        u.totp_secret, u.last_totp = enc(secret), ""
        db.commit()
        uri = provisioning_uri(secret, u.username, "Sentinel Attend")
        return {"mfa_setup_required": True, "secret": secret, "qr": _qr(uri),
                "setup_token": make_token({"typ": "mfa_setup", "sub": str(u.id)}, 600)}
    if not _totp_ok(u, body.totp):
        _fail(db, u, request, "totp")
    u.failed = 0
    db.commit()
    audit(db, u.username, "login", request=request)
    return issue_session(response, u)


@router.post("/mfa/enroll")
def enroll(body: EnrollIn, request: Request, response: Response, db: Session = Depends(get_db)):
    rate_limit("enroll:" + client_ip(request))
    c = read_token(body.setup_token, "mfa_setup")
    u = db.get(models.User, int(c["sub"])) if c else None
    if not u or u.totp_enabled or not verify_totp(u, body.totp, enrolling=True):
        raise HTTPException(401, "Invalid code")
    u.totp_enabled = True
    db.commit()
    audit(db, u.username, "mfa_enrolled", request=request)
    return issue_session(response, u)


@router.get("/me")
def me(request: Request, u: models.User = Depends(current_user)):
    return {"user": user_out(u), "csrf": request.state.claims["csrf"]}


@router.post("/refresh")
def refresh(request: Request, response: Response, u: models.User = Depends(current_user)):
    c = request.state.claims
    if time.time() - c.get("auth_time", 0) > settings.session_max_hours * 3600:
        raise HTTPException(401, "Session expired")
    return issue_session(response, u, c["csrf"], c["auth_time"])


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db),
           u: models.User = Depends(current_user)):
    response.delete_cookie(COOKIE, path="/")
    u.pw_version += 1  # D-13: server-side revocation, a copied cookie stops working (signs out all devices)
    db.commit()
    audit(db, u.username, "logout", request=request)
    return {"ok": True}


@router.post("/password")
def change_password(body: PwIn, request: Request, response: Response, db: Session = Depends(get_db),
                    u: models.User = Depends(current_user)):
    if not verify_pw(u.pw_hash, body.old_password):
        raise HTTPException(400, "Current password incorrect")
    why = password_problem(body.new_password, u.username)
    if why:
        raise HTTPException(422, why)
    u.pw_hash = hash_pw(body.new_password)
    u.pw_version += 1  # revokes every other session
    db.commit()
    audit(db, u.username, "password_changed", request=request)
    return issue_session(response, u)


# ---------------------------------------------------------------- user admin
ROLE_RX = "^(kiosk|viewer|operator|admin|superadmin)$"


class UserPatch(BaseModel):
    role: str | None = Field(default=None, pattern=ROLE_RX)
    disabled: bool | None = None
    unlock: bool = False
    reset_mfa: bool = False
    reset_password: bool = False
    phone: str | None = Field(default=None, max_length=20, pattern=r"^(\+[1-9][0-9]{7,14})?$")
    email: str | None = Field(default=None, max_length=255)


def _guard_superadmin(actor: models.User, target_role: str | None, new_role: str | None = None):
    """Only a super admin may create, change or remove admin and super admin accounts (otherwise an admin
    could reset a super admin's password + MFA and take over the approval workflow, or mint more admins)."""
    if "superadmin" in (target_role, new_role) and actor.role != "superadmin":
        raise HTTPException(403, "Only a super admin can manage super admin accounts")
    if "admin" in (target_role, new_role) and actor.role != "superadmin":
        raise HTTPException(403, "Only a super admin can manage admin accounts")


def _superadmins(db: Session) -> int:
    return len(db.scalars(select(models.User).where(models.User.role == "superadmin",
                                                    models.User.disabled.is_(False))).all())


def user_out_admin(u: models.User) -> dict:
    return {**user_out(u), "phone": u.phone, "email": u.email}


@users_router.get("")
def list_users(db: Session = Depends(get_db), _=Depends(require("admin"))):
    return [user_out_admin(u) for u in db.scalars(select(models.User).order_by(models.User.id))]


# Accounts are created only through invitations (routes_setup.py): no temporary passwords exist.


@users_router.patch("/{uid}")
def patch_user(uid: int, body: UserPatch, request: Request, db: Session = Depends(get_db),
               a=Depends(require("admin"))):
    u = db.get(models.User, uid)
    if not u:
        raise HTTPException(404)
    own_contacts = u.id == a.id and not (body.model_dump(exclude_defaults=True).keys() - {"phone", "email"})
    if not own_contacts:  # anyone may update their own alert contacts
        _guard_superadmin(a, u.role, body.role)
    out = {}
    if u.id == a.id and (body.disabled or (body.role and body.role != u.role)):
        raise HTTPException(400, "Cannot change your own role or disable yourself")
    losing_super = u.role == "superadmin" and ((body.role and body.role != "superadmin") or body.disabled)
    if losing_super and _superadmins(db) <= 1:
        raise HTTPException(400, "This is the last super admin; promote another user first")
    if body.role:
        u.role = body.role
        u.pw_version += 1
    if body.disabled is not None:
        u.disabled = body.disabled
        u.pw_version += 1
    if body.unlock:
        u.locked_until, u.failed = None, 0
    if body.reset_mfa:
        u.totp_enabled, u.totp_secret = False, ""
        u.pw_version += 1
    if body.reset_password:  # single-use link: the user chooses the new password, nobody else learns it
        from .routes_setup import new_link
        link = new_link(db, a, kind="reset", role=u.role, user_id=u.id, hours=24)
        out["reset_link"] = {k: link[k] for k in ("path", "expires_at")}
        u.pw_hash = hash_pw(secrets.token_urlsafe(32))  # old password stops working immediately
        u.pw_version += 1
    if body.phone is not None:
        u.phone = body.phone
    if body.email is not None:
        u.email = body.email
    db.commit()
    audit(db, a.username, "user_updated", u.username, request, **body.model_dump(exclude_defaults=True))
    if body.role in ("admin", "superadmin") or body.reset_mfa or body.reset_password:
        from .notify import security_alert
        security_alert(db, "privileged_change", a.username, f"{a.username} changed account '{u.username}'",
                       detail=body.model_dump(exclude_defaults=True))
    return {"user": user_out_admin(u), **out}


@users_router.delete("/{uid}")
def delete_user(uid: int, request: Request, db: Session = Depends(get_db), a=Depends(require("admin"))):
    u = db.get(models.User, uid)
    if not u or u.id == a.id:
        raise HTTPException(400, "Cannot delete")
    _guard_superadmin(a, u.role)
    if u.role == "superadmin" and _superadmins(db) <= 1:
        raise HTTPException(400, "This is the last super admin")
    db.delete(u)
    db.commit()
    audit(db, a.username, "user_deleted", u.username, request)
    return {"ok": True}
