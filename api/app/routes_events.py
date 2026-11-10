import datetime as dt
import os

import httpx
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import models
from .config import settings
from .db import get_db
from .engine import cosine, norm_plate
from .security import audit, media_decrypt, require

router = APIRouter(prefix="/api", tags=["events"])


def ev_out(e: models.Event) -> dict:
    meta = {k: v for k, v in (e.meta or {}).items() if k != "reid"}
    return {"id": e.id, "ts": models.iso(e.ts), "camera_id": e.camera_id, "kind": e.kind, "label": e.label,
            "confidence": round(e.confidence, 3), "severity": e.severity, "bbox": e.bbox,
            "has_snapshot": bool(e.snapshot), "meta": meta, "rules": e.rules, "searchable": bool((e.meta or {}).get("reid")),
            "acknowledged": e.acknowledged, "ack_by": e.ack_by, "ack_at": models.iso(e.ack_at)}


# ------------------------------------------------------------------ events
@router.get("/events")
def list_events(db: Session = Depends(get_db), _=Depends(require("viewer")),
                camera_id: int | None = None, kind: str | None = None, label: str | None = None,
                severity: str | None = None, unacked: bool = False, since: str | None = None,
                until: str | None = None, alerts_only: bool = False,
                limit: int = Query(100, le=500), before_id: int | None = None):
    q = select(models.Event).order_by(models.Event.id.desc()).limit(limit)
    if camera_id:
        q = q.where(models.Event.camera_id == camera_id)
    if kind:
        q = q.where(models.Event.kind == kind)
    if label:
        q = q.where(models.Event.label == label)
    if severity:
        q = q.where(models.Event.severity == severity)
    if unacked:
        q = q.where(models.Event.acknowledged.is_(False))
    if alerts_only:
        q = q.where(models.Event.severity.in_(["medium", "high", "critical"]))
    if since:
        q = q.where(models.Event.ts >= dt.datetime.fromisoformat(since.rstrip("Z")))
    if until:
        q = q.where(models.Event.ts <= dt.datetime.fromisoformat(until.rstrip("Z")))
    if before_id:
        q = q.where(models.Event.id < before_id)
    return [ev_out(e) for e in db.scalars(q)]


@router.get("/events/stats")
def stats(db: Session = Depends(get_db), _=Depends(require("viewer"))):
    since = models.now() - dt.timedelta(hours=24)
    by_label = db.execute(select(models.Event.label, func.count()).where(models.Event.ts >= since)
                          .group_by(models.Event.label)).all()
    by_hour = db.execute(select(models.Event.ts).where(models.Event.ts >= since)).scalars().all()
    hours = [0] * 24
    for t in by_hour:
        hours[min(23, int((t - since).total_seconds() // 3600))] += 1
    unacked = db.scalar(select(func.count()).select_from(models.Event).where(
        models.Event.acknowledged.is_(False), models.Event.severity.in_(["medium", "high", "critical"])))
    return {"total_24h": len(by_hour), "unacked_alerts": unacked,
            "by_label": sorted([{"label": l or "?", "count": c} for l, c in by_label], key=lambda x: -x["count"]),
            "by_hour": hours}


@router.get("/events/{eid}/snapshot")
def snapshot(eid: int, db: Session = Depends(get_db), _=Depends(require("viewer"))):
    e = db.get(models.Event, eid)
    root = os.path.realpath(settings.snapshot_dir)
    p = os.path.realpath(os.path.join(root, e.snapshot)) if e and e.snapshot else ""
    if not p or not p.startswith(root + os.sep) or not os.path.isfile(p) or not p.endswith(".svms"):
        raise HTTPException(404)
    with open(p, "rb") as f:
        data = media_decrypt(f.read())
    return Response(data, media_type="image/jpeg", headers={"Cache-Control": "private, no-store"})


@router.post("/events/{eid}/ack")
def ack(eid: int, request: Request, db: Session = Depends(get_db), u=Depends(require("operator"))):
    e = db.get(models.Event, eid)
    if not e:
        raise HTTPException(404)
    e.acknowledged, e.ack_by, e.ack_at = True, u.username, models.now()
    db.commit()
    audit(db, u.username, "event_ack", eid, request)
    return ev_out(e)


@router.post("/events/ack-all")
def ack_all(request: Request, db: Session = Depends(get_db), u=Depends(require("operator"))):
    n = 0
    for e in db.scalars(select(models.Event).where(models.Event.acknowledged.is_(False))):
        e.acknowledged, e.ack_by, e.ack_at = True, u.username, models.now()
        n += 1
    db.commit()
    audit(db, u.username, "event_ack_all", n, request)
    return {"acknowledged": n}


@router.post("/events/{eid}/similar")
def similar(eid: int, request: Request, db: Session = Depends(get_db), u=Depends(require("operator")),
            hours: int = Query(24, le=168), threshold: float | None = None):
    """Cross-camera re-identification: find the same person/vehicle in other events."""
    e = db.get(models.Event, eid)
    ref = (e.meta or {}).get("reid") if e else None
    if not ref:
        raise HTTPException(400, "Event has no re-ID signature")
    thr = threshold or settings.reid_match_threshold
    since = e.ts - dt.timedelta(hours=hours)
    out = []
    q = select(models.Event).where(models.Event.ts >= since, models.Event.label == e.label,
                                   models.Event.id != e.id).order_by(models.Event.id.desc()).limit(5000)
    for o in db.scalars(q):
        r = (o.meta or {}).get("reid")
        if r and len(r) == len(ref):
            s = cosine(ref, r)
            if s >= thr:
                out.append({**ev_out(o), "score": round(s, 3)})
    audit(db, u.username, "reid_search", eid, request, hits=len(out))
    return sorted(out, key=lambda x: -x["score"])[:100]


# ------------------------------------------------------------------- rules
class RuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    enabled: bool = True
    camera_ids: list[int] = []
    classes: list[str] = []
    zone: list[list[float]] | None = None
    min_conf: float = Field(default=0.5, ge=0, le=1)
    schedule: dict = {"days": [0, 1, 2, 3, 4, 5, 6], "start": "00:00", "end": "23:59"}
    cooldown_s: int = Field(default=60, ge=0, le=86400)
    severity: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    actions: dict = {}


def rule_out(r: models.Rule) -> dict:
    return {c.name: getattr(r, c.name) for c in models.Rule.__table__.columns}


@router.get("/rules")
def list_rules(db: Session = Depends(get_db), _=Depends(require("operator"))):
    return [rule_out(r) for r in db.scalars(select(models.Rule).order_by(models.Rule.id))]


@router.post("/rules")
def create_rule(body: RuleIn, request: Request, db: Session = Depends(get_db), a=Depends(require("admin"))):
    r = models.Rule(**body.model_dump())
    db.add(r)
    db.commit()
    audit(db, a.username, "rule_created", r.name, request)
    return rule_out(r)


@router.put("/rules/{rid}")
def update_rule(rid: int, body: RuleIn, request: Request, db: Session = Depends(get_db), a=Depends(require("admin"))):
    r = db.get(models.Rule, rid)
    if not r:
        raise HTTPException(404)
    for k, v in body.model_dump().items():
        setattr(r, k, v)
    db.commit()
    audit(db, a.username, "rule_updated", r.name, request)
    return rule_out(r)


@router.delete("/rules/{rid}")
def delete_rule(rid: int, request: Request, db: Session = Depends(get_db), a=Depends(require("admin"))):
    r = db.get(models.Rule, rid)
    if not r:
        raise HTTPException(404)
    db.delete(r)
    db.commit()
    audit(db, a.username, "rule_deleted", r.name, request)
    return {"ok": True}


# -------------------------------------------------------------- watchlists
def wl_out(w: models.Watchlist) -> dict:
    return {"id": w.id, "kind": w.kind, "label": w.label, "value": w.value, "list_type": w.list_type,
            "consent_ref": w.consent_ref, "created_by": w.created_by, "created_at": models.iso(w.created_at),
            "expires_at": models.iso(w.expires_at), "has_embedding": bool(w.embedding)}


@router.get("/watchlists")
def list_wl(db: Session = Depends(get_db), _=Depends(require("operator"))):
    return [wl_out(w) for w in db.scalars(select(models.Watchlist).order_by(models.Watchlist.id.desc()))]


@router.post("/watchlists/plate")
def add_plate(request: Request, label: str = Form(..., max_length=120), plate: str = Form(..., max_length=20),
              list_type: str = Form("deny", pattern="^(deny|allow)$"), days: int = Form(365, ge=1, le=3650),
              db: Session = Depends(get_db), a=Depends(require("admin"))):
    w = models.Watchlist(kind="plate", label=label, value=norm_plate(plate), list_type=list_type,
                         created_by=a.username, expires_at=models.now() + dt.timedelta(days=days))
    db.add(w)
    db.commit()
    audit(db, a.username, "watchlist_plate_added", w.value, request)
    return wl_out(w)


@router.post("/watchlists/face")
def add_face(request: Request, label: str = Form(..., max_length=120),
             consent_ref: str = Form(..., min_length=3, max_length=255),
             list_type: str = Form("deny", pattern="^(deny|allow)$"), days: int = Form(90, ge=1, le=365),
             image: UploadFile = File(...), db: Session = Depends(get_db), a=Depends(require("admin"))):
    """Face enrolment requires a recorded lawful basis / consent reference (DPDP Act 2023) and an expiry."""
    if not settings.enrich_url:
        raise HTTPException(503, "Enrichment service not configured")
    data = image.file.read(5_000_000)
    try:
        r = httpx.post(settings.enrich_url.rstrip("/") + "/embed/face", files={"image": ("f.jpg", data, "image/jpeg")},
                       headers={"Authorization": f"Bearer {settings.enrich_token}"}, timeout=30)
    except Exception as e:
        raise HTTPException(502, f"Enrichment unreachable: {e}")
    if r.status_code != 200:
        raise HTTPException(422, r.json().get("detail", "No usable face found"))
    w = models.Watchlist(kind="face", label=label, embedding=r.json()["embedding"], list_type=list_type,
                         consent_ref=consent_ref, created_by=a.username,
                         expires_at=models.now() + dt.timedelta(days=days))
    db.add(w)
    db.commit()  # the enrolment photo itself is not stored
    audit(db, a.username, "watchlist_face_added", label, request, consent_ref=consent_ref)
    return wl_out(w)


@router.delete("/watchlists/{wid}")
def del_wl(wid: int, request: Request, db: Session = Depends(get_db), a=Depends(require("admin"))):
    w = db.get(models.Watchlist, wid)
    if not w:
        raise HTTPException(404)
    db.delete(w)
    db.commit()
    audit(db, a.username, "watchlist_deleted", w.label, request)
    return {"ok": True}


# ------------------------------------------------------------------- audit
@router.get("/audit")
def audit_log(db: Session = Depends(get_db), _=Depends(require("admin")), limit: int = Query(200, le=1000)):
    rows = db.scalars(select(models.AuditLog).order_by(models.AuditLog.id.desc()).limit(limit))
    return [{"ts": models.iso(r.ts), "user": r.username, "action": r.action, "target": r.target,
             "ip": r.ip, "detail": r.detail} for r in rows]
