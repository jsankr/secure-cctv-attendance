"""Campus attendance: people + consent, live (anti-spoof) kiosk check-in, CCTV passive attendance,
review queue, reports. Only face TEMPLATES are kept (encrypted); enrolment photos are discarded."""
import csv
import datetime as dt
import io
import threading
import time

import cv2
import numpy as np
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import facesvc, models
from .db import get_db
from .hardening import ImageRejected, csv_safe, decode_image
from .notify import security_alert
from .realtime import hub
from .routes_privacy import get_vault, local_tz
from .security import ROLES, audit, current_user, rate_limit, require, require_kiosk

import faceengine as F  # noqa: E402

router = APIRouter(prefix="/api", tags=["attendance"])
DEFAULTS = {"late_after": "09:15", "cctv_requires_liveness": "1"}
_challenges: dict[str, dict] = {}
_ch_lock = threading.Lock()
_fail_log: dict[int, list[float]] = {}


def get_setting(db, key: str) -> str:
    s = db.get(models.Setting, f"att.{key}")
    return s.value if s else DEFAULTS[key]


def local_now() -> dt.datetime:
    return dt.datetime.now(local_tz())


def to_local(d: dt.datetime) -> dt.datetime:
    return d.replace(tzinfo=dt.timezone.utc).astimezone(local_tz())


# ------------------------------------------------------------------ people
class PersonIn(BaseModel):
    code: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9/_.-]+$")
    name: str = Field(min_length=1, max_length=120)
    kind: str = Field(default="student", pattern="^(student|staff)$")
    department: str = Field(default="", max_length=120)
    section: str = Field(default="", max_length=120)
    is_minor: bool = False
    consent_ref: str = Field(min_length=3, max_length=255)
    guardian_consent_ref: str = Field(default="", max_length=255)
    active: bool = True


def person_out(p: models.Person) -> dict:
    return {"id": p.id, "code": p.code, "name": p.name, "kind": p.kind, "department": p.department, "section": p.section,
            "is_minor": p.is_minor, "consent_ref": p.consent_ref, "guardian_consent_ref": p.guardian_consent_ref,
            "consent_at": models.iso(p.consent_at), "enrolled": bool(p.templates), "template_source": p.template_source,
            "active": p.active, "created_by": p.created_by}


def _check_consent(body: PersonIn):
    if body.is_minor and len(body.guardian_consent_ref.strip()) < 3:
        raise HTTPException(422, "Under-18s need verifiable parent/guardian consent (DPDP Act 2023, s.9)")


@router.get("/persons")
def list_persons(db: Session = Depends(get_db), _=Depends(require("operator")), q: str = "", kind: str = "",
                 department: str = "", section: str = ""):
    stmt = select(models.Person).order_by(models.Person.code)
    if kind:
        stmt = stmt.where(models.Person.kind == kind)
    if department:
        stmt = stmt.where(models.Person.department == department)
    if section:
        stmt = stmt.where(models.Person.section == section)
    rows = [person_out(p) for p in db.scalars(stmt)]
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in r["code"].lower() or ql in r["name"].lower()]
    return rows


@router.post("/persons")
def create_person(body: PersonIn, request: Request, db: Session = Depends(get_db), a=Depends(require("admin"))):
    _check_consent(body)
    if db.scalar(select(models.Person).where(models.Person.code == body.code)):
        raise HTTPException(409, "That roll / employee number already exists")
    p = models.Person(**body.model_dump(), consent_at=models.now(), created_by=a.username)
    db.add(p)
    db.commit()
    audit(db, a.username, "person_created", p.code, request)
    return person_out(p)


@router.put("/persons/{pid}")
def update_person(pid: int, body: PersonIn, request: Request, db: Session = Depends(get_db), a=Depends(require("admin"))):
    _check_consent(body)
    p = db.get(models.Person, pid)
    if not p:
        raise HTTPException(404)
    for k, v in body.model_dump().items():
        setattr(p, k, v)
    db.commit()
    facesvc.invalidate()
    audit(db, a.username, "person_updated", p.code, request)
    return person_out(p)


@router.delete("/persons/{pid}")
def erase_person(pid: int, request: Request, mode: str = Query(pattern="^(biometrics|all)$"),
                 db: Session = Depends(get_db), a=Depends(require("admin"))):
    """biometrics: consent withdrawn — delete face templates, keep attendance history.
    all: right to erasure — delete the person, their attendance and evidence files."""
    p = db.get(models.Person, pid)
    if not p:
        raise HTTPException(404)
    code = p.code
    if mode == "biometrics":
        p.templates, p.template_source = "", ""
    else:
        for r in db.scalars(select(models.AttendanceRecord).where(models.AttendanceRecord.person_id == pid)):
            facesvc.remove_file(r.evidence_blur)
            facesvc.remove_file(r.evidence_raw)
        db.execute(delete(models.AttendanceRecord).where(models.AttendanceRecord.person_id == pid))
        db.delete(p)
    db.commit()
    facesvc.invalidate()
    audit(db, a.username, f"person_erased_{mode}", code, request)
    security_alert(db, "person_erased", a.username, f"{a.username} erased {'face data of' if mode == 'biometrics' else 'all records of'} {code}", severity="low")
    return {"ok": True}


@router.post("/persons/{pid}/enroll-photo")
def enroll_photo(pid: int, request: Request, image: UploadFile = File(...), db: Session = Depends(get_db),
                 a=Depends(require("admin"))):
    """Lower assurance than live enrolment (a photo could be anyone's). Flagged as 'photo'."""
    p = db.get(models.Person, pid)
    if not p:
        raise HTTPException(404)
    try:
        img = decode_image(image.file.read(6_000_000))
    except ImageRejected as e:
        raise HTTPException(422, str(e))
    with facesvc.locked_engine() as eng:
        faces = [f for f in eng.detect(img, 0.7) if f.width >= 80]
        if len(faces) != 1:
            raise HTTPException(422, "Need exactly one clear, frontal face at least 80 px wide")
        if abs(faces[0].pose()[0]) > 0.15:
            raise HTTPException(422, "Face must look straight at the camera")
        if eng.antispoof is None:
            raise HTTPException(503, f"Anti-spoof unavailable: {eng.antispoof_error}")
        sc = eng.antispoof_scores(img, faces)[0]
        if sc is None or sc.get("status") != "real":
            why = (sc or {}).get("quality") or "this looks like a photo of a screen or a print, not an original photo"
            audit(db, a.username, "enrol_photo_rejected", p.code, request, antispoof=sc)
            raise HTTPException(422, f"Photo rejected by the anti-spoof check: {why}")
        emb = eng.embed(img, faces[0])
    temps = facesvc.get_templates(p) + [emb]
    facesvc.set_templates(p, temps, "live" if p.template_source == "live" else "photo")
    db.commit()
    audit(db, a.username, "person_enrolled_photo", p.code, request)
    return person_out(p)


@router.get("/persons/{pid}/history")
def person_history(pid: int, db: Session = Depends(get_db), _=Depends(require("operator")), days: int = Query(60, le=400)):
    since = (local_now() - dt.timedelta(days=days)).strftime("%Y-%m-%d")
    rows = db.scalars(select(models.AttendanceRecord).where(models.AttendanceRecord.person_id == pid,
                                                            models.AttendanceRecord.day >= since)
                      .order_by(models.AttendanceRecord.day.desc())).all()
    return [rec_out(r) for r in rows]


# ------------------------------------------------------------------- kiosk
class ChallengeIn(BaseModel):
    purpose: str = Field(default="attend", pattern="^(attend|enroll)$")
    person_id: int | None = None


@router.post("/kiosk/challenge")
def kiosk_challenge(body: ChallengeIn, u: models.User = Depends(require_kiosk)):
    if body.purpose == "enroll" and ROLES.get(u.role, -1) < ROLES["admin"]:
        raise HTTPException(403, "Enrolment requires an admin")
    ch = F.new_challenge()
    with _ch_lock:
        now = time.time()
        for k in [k for k, v in _challenges.items() if v["exp"] < now]:
            _challenges.pop(k)
        _challenges[ch["id"]] = {**ch, "user": u.id, "exp": now + 90, "purpose": body.purpose, "person_id": body.person_id}
    return {"id": ch["id"], "steps": ch["steps"], "prompts": ch["prompts"], "fps": 8, "seconds_per_step": 2.4}


def _decode_frames(files: list[UploadFile]) -> list[np.ndarray]:
    if not 10 <= len(files) <= 90:
        raise HTTPException(422, "Expected 10-90 frames")
    out = []
    for f in files:
        b = f.file.read(500_001)
        if len(b) > 500_000:
            raise HTTPException(413, "Frame too large")
        try:
            out.append(decode_image(b, max_side=1920, max_pixels=1920 * 1080))
        except ImageRejected as e:
            raise HTTPException(422, f"Bad frame: {e}")
    return out


def _evidence(frame: np.ndarray, face: F.Face, eng: F.FaceEngine, pub: bytes | None) -> tuple[str, str]:
    blurred = F.anonymise(frame.copy(), [f.box for f in eng.detect(frame, 0.45)])
    ok, jpg = cv2.imencode(".jpg", blurred, [cv2.IMWRITE_JPEG_QUALITY, 80])
    blur_rel = facesvc.store_media(jpg.tobytes()) if ok else ""
    raw_rel = ""
    if pub:
        x, y, w, h = map(int, face.box)
        m = int(w * 0.35)
        ok, jpg = cv2.imencode(".jpg", frame[max(0, y - m):y + h + m, max(0, x - m):x + w + m], [cv2.IMWRITE_JPEG_QUALITY, 90])
        if ok:
            raw_rel = facesvc.seal(jpg.tobytes(), pub)
    return blur_rel, raw_rel


def mark(db: Session, person: models.Person, *, method: str, score: float, live: bool, liveness: dict,
         camera_id: int | None = None, device: str = "", evidence=("", "")) -> tuple[models.AttendanceRecord, bool]:
    now_l = local_now()
    day = now_l.strftime("%Y-%m-%d")
    rec = db.scalar(select(models.AttendanceRecord).where(models.AttendanceRecord.person_id == person.id,
                                                          models.AttendanceRecord.day == day))
    late = now_l.strftime("%H:%M") > get_setting(db, "late_after")
    status = ("late" if late else "present") if live else "review"
    if rec:
        rec.last_seen = models.now()
        if rec.status == "review" and live:  # upgraded by a live sighting
            rec.status, rec.method, rec.score, rec.liveness = status, method, score, liveness
            facesvc.remove_file(rec.evidence_blur)
            facesvc.remove_file(rec.evidence_raw)
            rec.evidence_blur, rec.evidence_raw = evidence
        else:
            for p in evidence:
                facesvc.remove_file(p)
        db.commit()
        return rec, False
    rec = models.AttendanceRecord(person_id=person.id, day=day, status=status, method=method, camera_id=camera_id,
                                  device=device, score=round(score, 4), liveness=liveness,
                                  evidence_blur=evidence[0], evidence_raw=evidence[1])
    db.add(rec)
    db.commit()
    hub.publish({"type": "attendance", "record": rec_out(rec, person)}, min_role="operator")
    return rec, True


@router.post("/kiosk/verify")
def kiosk_verify(request: Request, challenge_id: str = Form(...), frames: list[UploadFile] = File(...),
                 db: Session = Depends(get_db), u: models.User = Depends(require_kiosk)):
    rate_limit(f"kiosk:{u.id}", limit=30, window=60)
    with _ch_lock:
        ch = _challenges.pop(challenge_id, None)  # single use
    if not ch or ch["user"] != u.id or ch["exp"] < time.time():
        raise HTTPException(410, "Challenge expired; start again")
    imgs = _decode_frames(frames)
    vault = get_vault(db)
    pub = vault.public_key if vault else None
    with facesvc.locked_engine() as eng:
        res = F.verify_kiosk(eng, imgs, ch["steps"])
        if not res.live:
            audit(db, u.username, "kiosk_liveness_failed", ch["purpose"], request, reason=res.reason)
            fl = [t for t in _fail_log.get(u.id, []) if t > time.time() - 600] + [time.time()]
            _fail_log[u.id] = fl
            if len(fl) in (5, 15):
                security_alert(db, "possible_spoofing", u.username,
                               f"{len(fl)} failed liveness checks in 10 min at kiosk '{u.username}' (possible spoofing attempt)", severity="medium")
            return {"ok": False, "reason": res.reason}
        best = res.best_frame
        face = max(eng.detect(imgs[best], 0.6), key=lambda f: f.width)
        if ch["purpose"] == "enroll":
            if ROLES.get(u.role, -1) < ROLES["admin"]:
                raise HTTPException(403)
            p = db.get(models.Person, ch["person_id"] or 0)
            if not p:
                raise HTTPException(404, "Person not found")
            other, score, _ = facesvc.match(db, res.embedding)
            if other and other != p.id:
                o = db.get(models.Person, other)
                security_alert(db, "duplicate_enrolment", u.username, f"Enrolment of {p.code} blocked: face already enrolled as {o.code if o else other}")
                return {"ok": False, "reason": f"This face is already enrolled as {o.code if o else 'another person'}"}
            facesvc.set_templates(p, [t for t in facesvc.get_templates(p) if p.template_source == "live"] + [res.embedding], "live")
            db.commit()
            audit(db, u.username, "person_enrolled_live", p.code, request)
            return {"ok": True, "enrolled": person_out(p)}
        pid, score, second = facesvc.match(db, res.embedding)
        if not pid:
            audit(db, u.username, "kiosk_unrecognised", "", request, score=round(score, 3))
            return {"ok": False, "reason": "Face not recognised. Please contact the office to enrol."}
        p = db.get(models.Person, pid)
        evidence = _evidence(imgs[best], face, eng, pub)
    rec, new = mark(db, p, method="kiosk", score=score, live=True, liveness={"ok": True, **res.detail}, device=u.username,
                    evidence=evidence)
    audit(db, u.username, "kiosk_checkin", p.code, request, score=round(score, 3))
    t = to_local(rec.first_seen).strftime("%H:%M")
    a = res.detail.get("antispoof", {})
    return {"ok": True, "code": p.code, "name": p.name.split(" ")[0], "status": rec.status, "time": t, "already": not new,
            "antispoof": {"frames": a.get("frames"), "real_frames": a.get("real_frames")}}


# ---------------------------------------------------------- CCTV (internal)
def ingest_cctv(db: Session, data: dict, blurred: bytes | None, sealed: bytes | None) -> dict:
    embs = [np.asarray(e, dtype=np.float32) for e in data.get("embeddings", [])][:5]
    votes: dict[int, list[float]] = {}
    for e in embs:
        pid, score, _ = facesvc.match(db, e / (np.linalg.norm(e) + 1e-9))
        if pid:
            votes.setdefault(pid, []).append(score)
    if not votes:
        return {"matched": False}
    pid, scores = max(votes.items(), key=lambda kv: len(kv[1]))
    if len(scores) < 2:  # need two independent frames agreeing on the same person
        return {"matched": False, "reason": "no consensus"}
    p = db.get(models.Person, pid)
    live = bool(data.get("liveness", {}).get("ok"))
    if not live and get_setting(db, "cctv_requires_liveness") != "1":
        live = True
    evidence = (facesvc.store_media(blurred) if blurred else "", facesvc.store_sealed_blob(sealed) if sealed else "")
    rec, new = mark(db, p, method="cctv", score=max(scores), live=live, liveness=data.get("liveness", {}),
                    camera_id=int(data["camera_id"]), evidence=evidence)
    return {"matched": True, "record": rec.id, "new": new}


# ---------------------------------------------------------------- reports
def rec_out(r: models.AttendanceRecord, p: models.Person | None = None) -> dict:
    return {"id": r.id, "person_id": r.person_id, "day": r.day, "first_seen": models.iso(r.first_seen),
            "last_seen": models.iso(r.last_seen), "status": r.status, "method": r.method, "camera_id": r.camera_id,
            "device": r.device, "score": r.score, "liveness": r.liveness, "has_evidence": bool(r.evidence_blur),
            "has_raw": bool(r.evidence_raw), "reviewed_by": r.reviewed_by, "note": r.note,
            **({"person": {"code": p.code, "name": p.name}} if p else {})}


@router.get("/attendance/day")
def attendance_day(day: str = Query("", pattern=r"^(\d{4}-\d{2}-\d{2})?$"), kind: str = "", department: str = "",
                   section: str = "", db: Session = Depends(get_db), _=Depends(require("operator"))):
    day = day or local_now().strftime("%Y-%m-%d")
    stmt = select(models.Person).where(models.Person.active.is_(True)).order_by(models.Person.code)
    if kind:
        stmt = stmt.where(models.Person.kind == kind)
    if department:
        stmt = stmt.where(models.Person.department == department)
    if section:
        stmt = stmt.where(models.Person.section == section)
    people = db.scalars(stmt).all()
    recs = {r.person_id: r for r in db.scalars(select(models.AttendanceRecord).where(models.AttendanceRecord.day == day))}
    rows, counts = [], {"present": 0, "late": 0, "review": 0, "rejected": 0, "absent": 0}
    for p in people:
        r = recs.get(p.id)
        status = r.status if r else "absent"
        counts[status] = counts.get(status, 0) + 1
        rows.append({"person": person_out(p), "status": status, "record": rec_out(r) if r else None})
    depts = sorted({p.department for p in db.scalars(select(models.Person)) if p.department})
    sections = sorted({p.section for p in db.scalars(select(models.Person)) if p.section})
    return {"day": day, "counts": counts, "total": len(people), "rows": rows, "departments": depts, "sections": sections,
            "late_after": get_setting(db, "late_after")}


@router.get("/attendance/records/{rid}/evidence")
def evidence_image(rid: int, db: Session = Depends(get_db), _=Depends(require("operator"))):
    r = db.get(models.AttendanceRecord, rid)
    if not r or not r.evidence_blur:
        raise HTTPException(404)
    return Response(facesvc.read_media(r.evidence_blur), media_type="image/jpeg", headers={"Cache-Control": "private, no-store"})


class ReviewIn(BaseModel):
    action: str = Field(pattern="^(approve|reject)$")
    note: str = Field(default="", max_length=255)


@router.post("/attendance/records/{rid}/review")
def review(rid: int, body: ReviewIn, request: Request, db: Session = Depends(get_db), a=Depends(require("admin"))):
    r = db.get(models.AttendanceRecord, rid)
    if not r:
        raise HTTPException(404)
    if body.action == "approve":
        late = to_local(r.first_seen).strftime("%H:%M") > get_setting(db, "late_after")
        r.status = "late" if late else "present"
    else:
        r.status = "rejected"
    r.reviewed_by, r.note = a.username, body.note
    db.commit()
    audit(db, a.username, f"attendance_{body.action}", rid, request, note=body.note)
    return rec_out(r)


class ManualIn(BaseModel):
    person_id: int
    day: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    status: str = Field(pattern="^(present|late|absent)$")
    note: str = Field(min_length=3, max_length=255)


@router.post("/attendance/manual")
def manual(body: ManualIn, request: Request, db: Session = Depends(get_db), a=Depends(require("admin"))):
    p = db.get(models.Person, body.person_id)
    if not p:
        raise HTTPException(404)
    r = db.scalar(select(models.AttendanceRecord).where(models.AttendanceRecord.person_id == p.id, models.AttendanceRecord.day == body.day))
    if body.status == "absent":
        if r:
            db.delete(r)
    elif r:
        r.status, r.reviewed_by, r.note = body.status, a.username, f"manual: {body.note}"
    else:
        db.add(models.AttendanceRecord(person_id=p.id, day=body.day, status=body.status, method="manual",
                                       reviewed_by=a.username, note=f"manual: {body.note}"))
    db.commit()
    audit(db, a.username, "attendance_manual", p.code, request, day=body.day, status=body.status, note=body.note)
    security_alert(db, "attendance_manual", a.username, f"{a.username} manually set {p.code} to {body.status} on {body.day}: {body.note}", severity="low")
    return {"ok": True}


@router.get("/attendance/export.csv")
def export_csv(request: Request, start: str = Query(pattern=r"^\d{4}-\d{2}-\d{2}$"),
               end: str = Query(pattern=r"^\d{4}-\d{2}-\d{2}$"), kind: str = "", department: str = "", section: str = "",
               db: Session = Depends(get_db), u: models.User = Depends(current_user)):
    """Attendance data only (no images). Admins may export; every export is reported."""
    if ROLES.get(u.role, -1) < ROLES["admin"]:
        audit(db, u.username, "export_denied", "attendance csv", request)
        security_alert(db, "export_denied", u.username, f"{u.username} ({u.role}) tried to export attendance data; blocked")
        raise HTTPException(403, "Not permitted. Security has been notified.")
    if end < start or (dt.date.fromisoformat(end) - dt.date.fromisoformat(start)).days > 366:
        raise HTTPException(422, "Range must be 1-366 days")
    stmt = select(models.Person).order_by(models.Person.code)
    for col, v in (("kind", kind), ("department", department), ("section", section)):
        if v:
            stmt = stmt.where(getattr(models.Person, col) == v)
    people = db.scalars(stmt).all()
    recs = db.scalars(select(models.AttendanceRecord).where(models.AttendanceRecord.day >= start, models.AttendanceRecord.day <= end)).all()
    by = {(r.person_id, r.day): r for r in recs}
    days, d = [], dt.date.fromisoformat(start)
    while d <= dt.date.fromisoformat(end):
        days.append(d.isoformat())
        d += dt.timedelta(days=1)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["code", "name", "type", "department", "section", *days, "present", "late", "absent"])
    for p in people:
        marks = []
        for day in days:
            r = by.get((p.id, day))
            marks.append({"present": "P", "late": "L", "review": "R", "rejected": "X"}.get(r.status, "") if r else "A")
        w.writerow([csv_safe(x) for x in (p.code, p.name, p.kind, p.department, p.section)] +
                   [*marks, marks.count("P"), marks.count("L"), marks.count("A")])
    audit(db, u.username, "attendance_export", f"{start}..{end}", request)
    security_alert(db, "attendance_export", u.username, f"{u.username} exported attendance {start} to {end} ({len(people)} people)", severity="medium")
    return Response(buf.getvalue().encode("utf-8-sig"), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="attendance_{start}_{end}.csv"', "Cache-Control": "no-store"})


class SettingsIn(BaseModel):
    late_after: str = Field(pattern=r"^\d{2}:\d{2}$")
    cctv_requires_liveness: bool = True


@router.get("/attendance/settings")
def get_settings(db: Session = Depends(get_db), _=Depends(require("operator"))):
    return {"late_after": get_setting(db, "late_after"), "cctv_requires_liveness": get_setting(db, "cctv_requires_liveness") == "1",
            "vault": bool(get_vault(db))}


@router.put("/attendance/settings")
def put_settings(body: SettingsIn, request: Request, db: Session = Depends(get_db), a=Depends(require("admin"))):
    db.merge(models.Setting(key="att.late_after", value=body.late_after))
    db.merge(models.Setting(key="att.cctv_requires_liveness", value="1" if body.cctv_requires_liveness else "0"))
    db.commit()
    audit(db, a.username, "attendance_settings", "", request, **body.model_dump())
    return {"ok": True}

