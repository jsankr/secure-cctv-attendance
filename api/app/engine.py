"""Event enrichment matching (watchlists) and rule evaluation."""
import datetime as dt
import threading
import time
from zoneinfo import ZoneInfo

import numpy as np
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models, notify
from .config import settings

TZ = ZoneInfo(settings.tz)
_cool: dict[tuple[int, int], float] = {}
_cool_lock = threading.Lock()
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def norm_plate(s: str) -> str:
    return "".join(ch for ch in s.upper() if ch.isalnum())


def cosine(a, b) -> float:
    a, b = np.asarray(a, dtype=np.float32), np.asarray(b, dtype=np.float32)
    d = float(np.linalg.norm(a) * np.linalg.norm(b))
    return float(a @ b / d) if d else 0.0


def match_watchlists(db: Session, meta: dict) -> list[dict]:
    """Match enrichment output against watchlists. Face embeddings are discarded afterwards
    (data minimisation): only match results are stored."""
    enrich = meta.get("enrich") or {}
    t = models.now()
    active = [w for w in db.scalars(select(models.Watchlist))
              if not w.expires_at or w.expires_at > t]
    hits = []
    plate = (enrich.get("plate") or {}).get("text")
    if plate:
        p = norm_plate(plate)
        for w in active:
            if w.kind == "plate" and w.value == p:
                hits.append({"kind": "plate", "id": w.id, "label": w.label, "list": w.list_type, "value": p})
    for f in enrich.pop("faces", []) or []:
        emb = f.get("embedding")
        best, score = None, settings.face_match_threshold
        for w in active:
            if w.kind == "face" and w.embedding:
                s = cosine(emb, w.embedding)
                if s > score:
                    best, score = w, s
        if best:
            hits.append({"kind": "face", "id": best.id, "label": best.label,
                         "list": best.list_type, "score": round(score, 3)})
    if enrich.get("reid"):
        meta["reid"] = enrich.pop("reid")
    meta["enrich"] = enrich
    return hits


def _in_schedule(sched: dict, when: dt.datetime) -> bool:
    local = when.replace(tzinfo=dt.timezone.utc).astimezone(TZ)
    if local.weekday() not in sched.get("days", list(range(7))):
        return False
    hm = local.strftime("%H:%M")
    s, e = sched.get("start", "00:00"), sched.get("end", "23:59")
    return s <= hm <= e if s <= e else (hm >= s or hm <= e)  # overnight windows


def _in_zone(zone, bbox) -> bool:
    if not zone or not bbox:
        return True
    x, y = (bbox[0] + bbox[2]) / 2, bbox[3]  # bottom-centre = where the object stands
    inside, n = False, len(zone)
    for i in range(n):
        x1, y1 = zone[i]
        x2, y2 = zone[(i + 1) % n]
        if (y1 > y) != (y2 > y) and x < (x2 - x1) * (y - y1) / ((y2 - y1) or 1e-9) + x1:
            inside = not inside
    return inside


def evaluate(db: Session, ev: models.Event, cam: models.Camera) -> list[dict]:
    fired = []
    for r in db.scalars(select(models.Rule).where(models.Rule.enabled.is_(True))):
        if r.camera_ids and ev.camera_id not in r.camera_ids:
            continue
        if r.classes and ev.label not in r.classes and ev.kind not in r.classes:
            continue
        if ev.kind == "object" and ev.confidence < r.min_conf:
            continue
        if not _in_schedule(r.schedule or {}, ev.ts) or not _in_zone(r.zone, ev.bbox):
            continue
        key, t = (r.id, ev.camera_id), time.time()
        with _cool_lock:
            if t - _cool.get(key, 0) < r.cooldown_s:
                continue
            _cool[key] = t
        fired.append({"id": r.id, "name": r.name, "severity": r.severity, "alarm": bool(r.actions.get("alarm"))})
        local = ev.ts.replace(tzinfo=dt.timezone.utc).astimezone(TZ).strftime("%d-%b %H:%M:%S")
        what = ev.label or ev.kind
        text = f"[{r.severity.upper()}] {what} detected at {cam.name} ({cam.site or 'site'}) {local}. Rule: {r.name}. Event #{ev.id}"
        notify.dispatch(r.actions or {}, cam, text, [what, cam.name, local, f"#{ev.id}"],
                        {"event_id": ev.id, "camera": cam.name, "label": what, "rule": r.name,
                         "severity": r.severity, "ts": models.iso(ev.ts)})
    if fired:
        top = max(fired, key=lambda f: SEV_RANK.get(f["severity"], 0))["severity"]
        if SEV_RANK.get(top, 0) > SEV_RANK.get(ev.severity, 0):
            ev.severity = top
    return fired
