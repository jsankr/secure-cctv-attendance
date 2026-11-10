"""Endpoints reachable only on the internal Docker network (Caddy never proxies /internal)."""
import datetime as dt
import json
import logging
import os
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import engine, models, onvif_ctl
from .config import settings
from .db import get_db
from .realtime import hub
from .routes_events import ev_out
from .hardening import mediamtx_decision
from .security import internal_only, media_encrypt, read_token

log = logging.getLogger("internal")
router = APIRouter(prefix="/internal", include_in_schema=False)


@router.post("/mediamtx-auth")
async def mediamtx_auth(request: Request):
    """MediaMTX external auth hook; decision logic in hardening.mediamtx_decision (unit/e2e tested)."""
    b = await request.json()
    if not mediamtx_decision(b, settings.internal_token, lambda t: read_token(t, "stream")):
        raise HTTPException(401)
    return {"ok": True}


@router.get("/cameras", dependencies=[Depends(internal_only)])
def worker_cameras(db: Session = Depends(get_db)):
    return [{"id": c.id, "name": c.name, "ai_enabled": c.ai_enabled, "auto_ir": c.auto_ir, "ir_mode": c.ir_mode,
             "lowlight_threshold": c.lowlight_threshold, "day_start": c.day_start, "day_end": c.day_end,
             "loiter_seconds": c.loiter_seconds, "record": c.record, "attendance": c.attendance}
            for c in db.scalars(select(models.Camera).where(models.Camera.enabled.is_(True)))]


@router.post("/events", dependencies=[Depends(internal_only)])
def ingest(data: str = Form(...), image: UploadFile | None = File(None), db: Session = Depends(get_db)):
    d = json.loads(data)
    cam = db.get(models.Camera, int(d["camera_id"]))
    if not cam:
        raise HTTPException(404)
    meta = d.get("meta") or {}
    hits = engine.match_watchlists(db, meta)
    kind, severity = d.get("kind", "object"), d.get("severity", "info")
    if hits:
        meta["watchlist"] = hits
        if any(h["list"] == "deny" for h in hits):
            kind, severity = "watchlist", "critical"
    snap = ""
    if image is not None:  # comes from the blurred stream; encrypted at rest with the media key
        day = models.now().strftime("%Y-%m-%d")
        os.makedirs(os.path.join(settings.snapshot_dir, day), exist_ok=True)
        snap = f"{day}/{uuid.uuid4().hex}.svms"
        with open(os.path.join(settings.snapshot_dir, snap), "wb") as f:
            f.write(media_encrypt(image.file.read(8_000_000)))
    ev = models.Event(camera_id=cam.id, kind=kind, label=str(d.get("label", ""))[:64],
                      confidence=float(d.get("confidence", 0)), severity=severity, bbox=d.get("bbox"),
                      snapshot=snap, meta=meta)
    db.add(ev)
    db.commit()
    ev.rules = engine.evaluate(db, ev, cam)
    db.commit()
    hub.publish({"type": "event", "event": ev_out(ev), "camera": cam.name})
    return {"id": ev.id, "rules": ev.rules}


@router.post("/lowlight", dependencies=[Depends(internal_only)])
def lowlight(body: dict, db: Session = Depends(get_db)):
    """Worker reports a sustained light-level change; switch IR-cut if the camera is on software auto."""
    cam = db.get(models.Camera, int(body["camera_id"]))
    if not cam or not cam.auto_ir:
        return {"ok": False}
    mode = "night" if body.get("dark") else "day"
    err = ""
    try:
        onvif_ctl.set_ir(cam, mode)
        cam.ir_mode = mode
    except HTTPException as e:
        err = e.detail
    ev = models.Event(camera_id=cam.id, kind="lowlight", label=f"ir_{mode}", severity="info",
                      meta={"luma": body.get("luma"), "error": err})
    db.add(ev)
    db.commit()
    hub.publish({"type": "event", "event": ev_out(ev), "camera": cam.name})
    return {"ok": not err, "mode": mode}


def purge_old(db: Session):
    """Retention: drop events + snapshots older than event_retention_days, expired watchlist entries."""
    cut = models.now() - dt.timedelta(days=settings.event_retention_days)
    n = 0
    for e in db.scalars(select(models.Event).where(models.Event.ts < cut).limit(20000)):
        if e.snapshot:
            try:
                os.remove(os.path.join(settings.snapshot_dir, e.snapshot))
            except OSError:
                pass
        db.delete(e)
        n += 1
    for w in db.scalars(select(models.Watchlist).where(models.Watchlist.expires_at < models.now())):
        db.delete(w)
    db.commit()
    if n:
        log.info("retention purged %d events", n)


# ------------------------------------------------------------ privacy pipeline
@router.get("/vault/pubkey", dependencies=[Depends(internal_only)])
def vault_pubkey(db: Session = Depends(get_db)):
    from .routes_privacy import vault_pubkey_b64
    return {"public_key": vault_pubkey_b64(db)}


@router.post("/segments", dependencies=[Depends(internal_only)])
def add_segment(body: dict, db: Session = Depends(get_db)):
    if body.get("kind") not in ("priv", "raw") or ".." in body.get("path", ""):
        raise HTTPException(422)
    p = lambda s: dt.datetime.fromisoformat(s).astimezone(dt.timezone.utc).replace(tzinfo=None)  # noqa: E731
    db.add(models.Segment(camera_id=int(body["camera_id"]), kind=body["kind"], start=p(body["start"]), end=p(body["end"]),
                          path=body["path"], size=int(body.get("size", 0))))
    db.commit()
    return {"ok": True}


@router.post("/attendance", dependencies=[Depends(internal_only)])
def cctv_attendance(data: str = Form(...), blurred: UploadFile | None = File(None), sealed: UploadFile | None = File(None),
                    db: Session = Depends(get_db)):
    from .routes_attendance import ingest_cctv
    return ingest_cctv(db, json.loads(data), blurred.file.read(4_000_000) if blurred else None,
                       sealed.file.read(4_000_000) if sealed else None)


def purge_store(db: Session):
    """Drop index rows for encrypted segments past retention (the recorder deletes the files)."""
    cut = models.now() - dt.timedelta(hours=settings.recording_retention_hours)
    db.execute(delete(models.Segment).where(models.Segment.end < cut))
    db.commit()


def purge_plaintext_snapshots():
    """Snapshots written before privacy mode were plaintext and could contain faces: remove them."""
    root = settings.snapshot_dir
    n = 0
    if not os.path.isdir(root):
        return
    for d, _, files in os.walk(root):
        for f in files:
            if not f.endswith(".svms"):
                try:
                    os.remove(os.path.join(d, f))
                    n += 1
                except OSError:
                    pass
    if n:
        log.warning("removed %d legacy plaintext snapshots (privacy mode)", n)


@router.get("/config", dependencies=[Depends(internal_only)])
def worker_config(db: Session = Depends(get_db)):
    from .facesvc import as_config
    return {"antispoof": as_config(db)}
