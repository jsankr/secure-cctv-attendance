"""Privacy controls: vault, approval-gated unblurring, encrypted playback, super-admin-only export,
and the security notification feed. Every export or unblur ATTEMPT (allowed, denied or failed)
raises a security alert to all admins and super admins."""
import base64
import datetime as dt
import logging
import threading
from collections import OrderedDict

import cv2
import numpy as np
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import facesvc, models
from .config import settings
from .db import SessionLocal, get_db
from .notify import security_alert
from .security import ROLES, audit, current_user, fail_count, record_failure, require, verify_totp, vmscrypto

import faceengine as F  # noqa: E402
import mediatools as M  # noqa: E402

if settings.ffmpeg:
    M.FFMPEG = settings.ffmpeg

log = logging.getLogger("privacy")
router = APIRouter(prefix="/api", tags=["privacy"])
_LOCAL = None


def local_tz():
    global _LOCAL
    if _LOCAL is None:
        from zoneinfo import ZoneInfo
        _LOCAL = ZoneInfo(settings.tz)
    return _LOCAL


def fmt_local(d: dt.datetime) -> str:
    return d.replace(tzinfo=dt.timezone.utc).astimezone(local_tz()).strftime("%Y-%m-%d %H:%M:%S")


# -------------------------------------------------------------------- vault
def get_vault(db: Session) -> vmscrypto.VaultRecord | None:
    s = db.get(models.Setting, "vault")
    return vmscrypto.VaultRecord.from_json(s.value) if s and s.value else None


def vault_meta(db: Session) -> dict:
    s = db.get(models.Setting, "vault_meta")
    import json
    return json.loads(s.value) if s and s.value else {}


class VaultSetupIn(BaseModel):
    passphrase: str = Field(min_length=16, max_length=512)
    totp: str = Field(max_length=8)


class VaultRotateIn(BaseModel):
    totp: str = Field(max_length=8)
    current_passphrase: str = Field(default="", max_length=512)
    recovery_code: str = Field(default="", max_length=128)
    new_passphrase: str = Field(min_length=16, max_length=512)


def step_up(db: Session, u: models.User, code: str, request: Request, action: str):
    """Fresh TOTP for sensitive actions; failures alert the security team."""
    key = f"stepup:{u.id}"
    if fail_count(key, 900) >= 5:  # only FAILED attempts count (D-14)
        raise HTTPException(429, "Too many failed authenticator codes; try again in 15 minutes")
    if not verify_totp(u, code):
        record_failure(key)
        db.commit()
        audit(db, u.username, f"{action}_mfa_failed", request=request)
        security_alert(db, f"{action}_mfa_failed", u.username, f"Failed MFA check by {u.username} for {action.replace('_', ' ')}")
        raise HTTPException(401, "Invalid authenticator code")
    db.commit()


@router.get("/vault")
def vault_status(db: Session = Depends(get_db), _=Depends(require("admin"))):
    v = get_vault(db)
    return {"configured": bool(v), "fingerprint": v.fingerprint if v else None, **vault_meta(db)}


@router.post("/vault/setup")
def vault_setup(body: VaultSetupIn, request: Request, db: Session = Depends(get_db), u=Depends(require("superadmin"))):
    if get_vault(db):
        raise HTTPException(409, "Vault already configured")
    step_up(db, u, body.totp, request, "vault_setup")
    err = vmscrypto.check_passphrase_strength(body.passphrase)
    if err:
        raise HTTPException(422, err)
    rec, code = vmscrypto.create_vault(body.passphrase)
    import json
    db.merge(models.Setting(key="vault", value=rec.to_json()))
    db.merge(models.Setting(key="vault_meta", value=json.dumps({"created_by": u.username, "created_at": models.iso(models.now())})))
    db.commit()
    audit(db, u.username, "vault_created", rec.fingerprint, request)
    security_alert(db, "vault_created", u.username, f"Encryption vault created by {u.username} (key {rec.fingerprint})", severity="medium")
    return {"fingerprint": rec.fingerprint, "recovery_code": code}


@router.post("/vault/passphrase")
def vault_rotate(body: VaultRotateIn, request: Request, db: Session = Depends(get_db), u=Depends(require("superadmin"))):
    v = get_vault(db)
    if not v:
        raise HTTPException(404, "Vault not configured")
    step_up(db, u, body.totp, request, "vault_passphrase_change")
    try:
        priv = vmscrypto.unlock_vault(v, passphrase=body.current_passphrase or None,
                                      recovery_code=None if body.current_passphrase else body.recovery_code)
        new = vmscrypto.rewrap_vault(v, priv, body.new_passphrase)
    except vmscrypto.CryptoError as e:
        security_alert(db, "vault_unlock_failed", u.username, f"Vault unlock failed for {u.username} (passphrase change)")
        raise HTTPException(401, str(e))
    db.merge(models.Setting(key="vault", value=new.to_json()))
    db.commit()
    security_alert(db, "vault_passphrase_changed", u.username, f"Vault passphrase changed by {u.username}", severity="medium")
    return {"ok": True}


# --------------------------------------------------------------- recordings
_cache: "OrderedDict[int, bytes]" = OrderedDict()
_cache_lock = threading.Lock()


def _segment_bytes(seg: models.Segment) -> bytes:
    with _cache_lock:
        if seg.id in _cache:
            _cache.move_to_end(seg.id)
            return _cache[seg.id]
    data = facesvc.read_media(seg.path)
    with _cache_lock:
        _cache[seg.id] = data
        while len(_cache) > 4:
            _cache.popitem(last=False)
    return data


def media_response(request: Request, data: bytes, mime: str = "video/mp4", filename: str | None = None) -> Response:
    headers = {"Accept-Ranges": "bytes", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
    if filename:
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    rng = request.headers.get("range", "")
    if rng.startswith("bytes=") and not filename:
        a, _, b = rng[6:].partition("-")
        start = int(a) if a else max(0, len(data) - int(b))
        end = min(len(data) - 1, int(b)) if (a and b) else len(data) - 1
        if start >= len(data):
            return Response(status_code=416, headers={"Content-Range": f"bytes */{len(data)}"})
        headers["Content-Range"] = f"bytes {start}-{end}/{len(data)}"
        return Response(data[start:end + 1], status_code=206, media_type=mime, headers=headers)
    return Response(data, media_type=mime, headers=headers)


@router.get("/recordings")
def list_recordings(camera_id: int, day: str = Query(pattern=r"^\d{4}-\d{2}-\d{2}$"),
                    db: Session = Depends(get_db), _=Depends(require("viewer"))):
    start = dt.datetime.fromisoformat(day).replace(tzinfo=local_tz()).astimezone(dt.timezone.utc).replace(tzinfo=None)
    end = start + dt.timedelta(days=1)
    q = select(models.Segment).where(models.Segment.camera_id == camera_id, models.Segment.kind == "priv",
                                     models.Segment.end > start, models.Segment.start < end).order_by(models.Segment.start)
    return [{"id": s.id, "start": models.iso(s.start), "end": models.iso(s.end), "size": s.size} for s in db.scalars(q)]


@router.get("/recordings/{sid}/media")
def recording_media(sid: int, request: Request, db: Session = Depends(get_db), _=Depends(require("viewer"))):
    s = db.get(models.Segment, sid)
    if not s or s.kind != "priv":
        raise HTTPException(404)
    try:
        return media_response(request, _segment_bytes(s))
    except FileNotFoundError:
        raise HTTPException(404, "Recording file no longer exists (retention)")


class ExportIn(BaseModel):
    totp: str = Field(default="", max_length=8)
    reason: str = Field(default="", max_length=300)


def _deny_export(db, u, request, what: str):
    audit(db, u.username, "export_denied", what, request)
    security_alert(db, "export_denied", u.username, f"{u.username} ({u.role}) tried to export {what}; blocked (super admin only)")
    raise HTTPException(403, "Export is restricted to super admins. Security has been notified.")


@router.post("/recordings/{sid}/export")
def export_recording(sid: int, body: ExportIn, request: Request, db: Session = Depends(get_db),
                     u: models.User = Depends(current_user)):
    s = db.get(models.Segment, sid)
    what = f"recording #{sid}" + (f" (camera {s.camera_id}, {fmt_local(s.start)})" if s else "")
    if u.role != "superadmin":
        _deny_export(db, u, request, what)
    if not s or s.kind != "priv":
        raise HTTPException(404)
    if len(body.reason.strip()) < 5:
        raise HTTPException(422, "A reason / case reference is required for export")
    step_up(db, u, body.totp, request, "export")
    stamp = fmt_local(models.now())
    lines = [f"EXPORTED BY {u.username} | {stamp} {settings.tz}", f"Camera {s.camera_id} | {fmt_local(s.start)} | Ref: {body.reason[:60]}"]
    out = M.transcode(_segment_bytes(s), lambda f, i: M.watermark(f, lines))
    audit(db, u.username, "export", what, request, reason=body.reason)
    security_alert(db, "export", u.username, f"{u.username} exported {what}. Reason: {body.reason[:120]}")
    return media_response(request, out, filename=f"camera{s.camera_id}_{s.start:%Y%m%d_%H%M%S}_blurred.mp4")


@router.post("/audit/client-snapshot")
def client_snapshot(body: dict, request: Request, db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    """The live-wall snapshot button is super-admin only; any attempt is reported."""
    cam = str(body.get("camera_id", ""))[:12]
    if u.role != "superadmin":
        _deny_export(db, u, request, f"a live snapshot of camera {cam}")
    audit(db, u.username, "snapshot_export", cam, request)
    security_alert(db, "snapshot_export", u.username, f"{u.username} saved a (blurred) live snapshot of camera {cam}", severity="medium")
    return {"ok": True}


# ------------------------------------------------------------------ unblur
class UnblurIn(BaseModel):
    attendance_id: int
    reason: str = Field(min_length=10, max_length=500)


class ApproveIn(BaseModel):
    totp: str = Field(max_length=8)
    passphrase: str = Field(default="", max_length=512)
    recovery_code: str = Field(default="", max_length=128)


class DenyIn(BaseModel):
    note: str = Field(default="", max_length=300)


def req_out(r: models.UnblurRequest, db: Session) -> dict:
    p = db.get(models.Person, r.person_id)
    expired = r.status == "ready" and r.expires_at and r.expires_at < models.now()
    return {"id": r.id, "created_at": models.iso(r.created_at), "requester": r.requester,
            "person": {"id": p.id, "code": p.code, "name": p.name} if p else None, "attendance_id": r.attendance_id,
            "camera_id": r.camera_id, "window_start": models.iso(r.window_start), "window_end": models.iso(r.window_end),
            "reason": r.reason, "status": "expired" if expired else r.status, "decided_by": r.decided_by,
            "decided_at": models.iso(r.decided_at), "expires_at": models.iso(r.expires_at),
            "has_video": bool(r.result_video), "has_image": bool(r.result_image), "detail": r.detail, "views": r.views}


@router.post("/unblur")
def request_unblur(body: UnblurIn, request: Request, db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    rec = db.get(models.AttendanceRecord, body.attendance_id)
    if ROLES.get(u.role, -1) < ROLES["operator"]:
        audit(db, u.username, "unblur_request_denied", body.attendance_id, request)
        security_alert(db, "unblur_denied", u.username, f"{u.username} ({u.role}) attempted to request unblurring; blocked")
        raise HTTPException(403, "Not permitted. Security has been notified.")
    if not rec:
        raise HTTPException(404, "Attendance record not found")
    p = db.get(models.Person, rec.person_id)
    r = models.UnblurRequest(requester=u.username, person_id=rec.person_id, attendance_id=rec.id, camera_id=rec.camera_id,
                             window_start=rec.first_seen - dt.timedelta(seconds=20),
                             window_end=rec.last_seen + dt.timedelta(seconds=20), reason=body.reason.strip())
    db.add(r)
    db.commit()
    audit(db, u.username, "unblur_requested", r.id, request, person=p.code if p else None)
    security_alert(db, "unblur_requested", u.username,
                   f"{u.username} requested unblurring of {p.name if p else '?'} ({p.code if p else '?'}), request #{r.id}. "
                   f"Reason: {r.reason[:120]}. Awaiting super admin approval.", severity="medium")
    return req_out(r, db)


@router.get("/unblur")
def list_unblur(db: Session = Depends(get_db), u=Depends(require("operator"))):
    q = select(models.UnblurRequest).order_by(models.UnblurRequest.id.desc()).limit(200)
    if ROLES[u.role] < ROLES["admin"]:
        q = q.where(models.UnblurRequest.requester == u.username)
    return [req_out(r, db) for r in db.scalars(q)]


@router.post("/unblur/{rid}/approve")
def approve_unblur(rid: int, body: ApproveIn, request: Request, db: Session = Depends(get_db),
                   u: models.User = Depends(current_user)):
    r = db.get(models.UnblurRequest, rid)
    if u.role != "superadmin":
        security_alert(db, "unblur_denied", u.username, f"{u.username} ({u.role}) tried to approve unblur request #{rid}; blocked")
        raise HTTPException(403, "Only a super admin can approve. Security has been notified.")
    if not r or r.status != "pending":
        raise HTTPException(409, "Request is not pending")
    v = get_vault(db)
    if not v:
        raise HTTPException(409, "Vault is not set up, so no unblurred material exists")
    step_up(db, u, body.totp, request, "unblur_approval")
    try:
        priv = vmscrypto.unlock_vault(v, passphrase=body.passphrase or None,
                                      recovery_code=None if body.passphrase else (body.recovery_code or None))
    except vmscrypto.CryptoError:
        audit(db, u.username, "vault_unlock_failed", rid, request)
        security_alert(db, "vault_unlock_failed", u.username, f"Vault unlock FAILED by {u.username} for unblur request #{rid}")
        raise HTTPException(401, "Incorrect vault passphrase")
    r.status, r.decided_by, r.decided_at = "rendering", u.username, models.now()
    db.commit()
    audit(db, u.username, "unblur_approved", rid, request)
    self_note = " (self-approved)" if r.requester == u.username else ""
    security_alert(db, "unblur_approved", u.username, f"{u.username} approved unblur request #{rid} from {r.requester}{self_note}")
    threading.Thread(target=_render, args=(rid, priv), daemon=True, name=f"unblur-{rid}").start()
    return req_out(r, db)


@router.post("/unblur/{rid}/deny")
def deny_unblur(rid: int, body: DenyIn, request: Request, db: Session = Depends(get_db), u=Depends(require("superadmin"))):
    r = db.get(models.UnblurRequest, rid)
    if not r or r.status != "pending":
        raise HTTPException(409, "Request is not pending")
    r.status, r.decided_by, r.decided_at, r.detail = "denied", u.username, models.now(), body.note[:300]
    db.commit()
    audit(db, u.username, "unblur_denied", rid, request)
    security_alert(db, "unblur_denied", u.username, f"{u.username} denied unblur request #{rid} from {r.requester}", severity="low")
    return req_out(r, db)


def _viewable(r: models.UnblurRequest | None, u: models.User):
    if not r or r.status != "ready" or not r.expires_at or r.expires_at < models.now():
        raise HTTPException(410, "Unblurred result is not available (expired or not approved)")
    if u.role != "superadmin" and u.username != r.requester:
        raise HTTPException(403, "Only the requester or a super admin may view this")


@router.get("/unblur/{rid}/video")
def unblur_video(rid: int, request: Request, db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    r = db.get(models.UnblurRequest, rid)
    _viewable(r, u)
    if not r.result_video:
        raise HTTPException(404, "No footage for this request")
    if not request.headers.get("range", "").startswith("bytes=") or request.headers["range"].startswith("bytes=0-"):
        r.views += 1
        db.commit()
        audit(db, u.username, "unblurred_viewed", rid, request)
        security_alert(db, "unblurred_viewed", u.username, f"{u.username} is viewing unblurred footage (request #{rid})", severity="medium")
    return media_response(request, facesvc.read_media(r.result_video))


@router.get("/unblur/{rid}/image")
def unblur_image(rid: int, request: Request, db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    r = db.get(models.UnblurRequest, rid)
    _viewable(r, u)
    if not r.result_image:
        raise HTTPException(404, "No face image for this request")
    audit(db, u.username, "unblurred_image_viewed", rid, request)
    return Response(facesvc.read_media(r.result_image), media_type="image/jpeg", headers={"Cache-Control": "no-store"})


@router.post("/unblur/{rid}/export")
def unblur_export(rid: int, body: ExportIn, request: Request, db: Session = Depends(get_db),
                  u: models.User = Depends(current_user)):
    r = db.get(models.UnblurRequest, rid)
    if u.role != "superadmin":
        _deny_export(db, u, request, f"UNBLURRED footage (request #{rid})")
    _viewable(r, u)
    if len(body.reason.strip()) < 5:
        raise HTTPException(422, "A reason / case reference is required for export")
    step_up(db, u, body.totp, request, "export")
    audit(db, u.username, "export_unblurred", rid, request, reason=body.reason)
    security_alert(db, "export_unblurred", u.username, f"{u.username} EXPORTED unblurred footage (request #{rid}). Reason: {body.reason[:120]}")
    return media_response(request, facesvc.read_media(r.result_video), filename=f"unblurred_request{rid}.mp4")


def _render(rid: int, priv):
    """Decrypt sealed raw footage, keep ONLY the requested person unblurred, watermark, re-encrypt."""
    db = SessionLocal()
    try:
        r = db.get(models.UnblurRequest, rid)
        p = db.get(models.Person, r.person_id)
        rec = db.get(models.AttendanceRecord, r.attendance_id) if r.attendance_id else None
        temps = facesvc.get_templates(p) if p else []
        stamp = fmt_local(models.now())
        lines = [f"UNBLURRED #{rid} | {p.code if p else '?'} | approved by {r.decided_by}",
                 f"Requested by {r.requester} | {stamp} {settings.tz} | CONFIDENTIAL"]
        notes = []
        if rec and rec.evidence_raw:
            try:
                img = cv2.imdecode(np.frombuffer(vmscrypto.decrypt_bytes(facesvc.read_file(rec.evidence_raw), private_key=priv), np.uint8), 1)
                ok, jpg = cv2.imencode(".jpg", M.watermark(img, lines[:1]), [cv2.IMWRITE_JPEG_QUALITY, 90])
                r.result_image = facesvc.store_media(jpg.tobytes(), "unblur")
            except Exception as e:
                notes.append(f"face image unavailable ({e})")
        if r.camera_id and r.window_start and temps:
            segs = db.scalars(select(models.Segment).where(
                models.Segment.camera_id == r.camera_id, models.Segment.kind == "raw",
                models.Segment.end > r.window_start, models.Segment.start < r.window_end).order_by(models.Segment.start)).all()
            if segs:
                eng = F.FaceEngine(settings.face_det_model, settings.face_rec_model)  # private instance (thread-safety)
                sel = F.SelectiveUnblur(eng, temps, settings.attendance_match_threshold - 0.04)

                def frame_fn(frame, i):
                    return M.watermark(sel(frame, i), lines)

                parts = []
                for s in segs:
                    data = vmscrypto.decrypt_bytes(facesvc.read_file(s.path), private_key=priv)
                    off = max(0.0, (r.window_start - s.start).total_seconds())
                    dur = (min(s.end, r.window_end) - max(s.start, r.window_start)).total_seconds()
                    if dur > 0.5:
                        parts.append((data, off, dur))
                if parts:
                    video = M.transcode_many(parts, frame_fn)
                    r.result_video = facesvc.store_media(video, "unblur")
                    if not sel.frames_kept:
                        notes.append("the person was not identified in this footage, so all faces remain blurred")
            else:
                notes.append("no raw footage was recorded for that time (vault not set up yet, or retention)")
        elif r.camera_id is None:
            notes.append("kiosk check-in: face image only, no camera footage")
        r.status = "ready" if (r.result_video or r.result_image) else "failed"
        r.expires_at = models.now() + dt.timedelta(minutes=settings.unblur_ttl_minutes)
        r.detail = "; ".join(notes)[:500]
        db.commit()
        from .realtime import hub
        hub.publish({"type": "unblur", "id": rid, "status": r.status}, min_role="operator")
    except Exception as e:
        log.exception("unblur render failed")
        r = db.get(models.UnblurRequest, rid)
        if r:
            r.status, r.detail = "failed", f"Rendering failed: {e}"[:500]
            db.commit()
    finally:
        db.close()
        del priv  # drop our reference to the vault key (CPython cannot guarantee memory wiping)


def purge_unblur(db: Session):
    for r in db.scalars(select(models.UnblurRequest).where(models.UnblurRequest.status == "ready",
                                                            models.UnblurRequest.expires_at < models.now())):
        facesvc.remove_file(r.result_video)
        facesvc.remove_file(r.result_image)
        r.result_video = r.result_image = ""
        r.status = "expired"
    for r in db.scalars(select(models.UnblurRequest).where(models.UnblurRequest.status == "rendering",
                                                            models.UnblurRequest.decided_at < models.now() - dt.timedelta(hours=1))):
        r.status, r.detail = "failed", "Rendering interrupted (server restart)"
    db.commit()


# ------------------------------------------------------------ notifications
@router.get("/notifications")
def notifications(db: Session = Depends(get_db), u=Depends(require("admin")), limit: int = Query(100, le=500)):
    rows = db.scalars(select(models.Notification).order_by(models.Notification.id.desc()).limit(limit)).all()
    out = [{"id": n.id, "ts": models.iso(n.ts), "kind": n.kind, "severity": n.severity, "actor": n.actor,
            "message": n.message, "read": u.username in (n.read_by or [])} for n in rows]
    return {"items": out, "unread": sum(1 for n in out if not n["read"])}


@router.post("/notifications/read")
def notifications_read(db: Session = Depends(get_db), u=Depends(require("admin"))):
    for n in db.scalars(select(models.Notification).order_by(models.Notification.id.desc()).limit(500)):
        if u.username not in (n.read_by or []):
            n.read_by = [*(n.read_by or []), u.username]
    db.commit()
    return {"ok": True}


def vault_pubkey_b64(db: Session) -> str | None:
    v = get_vault(db)
    return base64.b64encode(v.public_key).decode() if v else None

