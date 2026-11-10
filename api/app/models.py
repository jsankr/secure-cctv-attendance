import datetime as dt

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def now() -> dt.datetime:
    """Naive UTC everywhere in the DB; serialised with a trailing Z."""
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


def iso(d: dt.datetime | None) -> str | None:
    return d.isoformat(timespec="seconds") + "Z" if d else None


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    pw_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="viewer")  # kiosk|viewer|operator|admin|superadmin
    totp_secret: Mapped[str] = mapped_column(String(512), default="")  # Fernet-encrypted
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    last_totp: Mapped[str] = mapped_column(String(32), default="")  # replay protection
    failed: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    pw_version: Mapped[int] = mapped_column(Integer, default=1)  # bump = revoke sessions
    phone: Mapped[str] = mapped_column(String(32), default="")   # security alert contact (E.164)
    email: Mapped[str] = mapped_column(String(255), default="")  # security alert contact
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=now)


class Camera(Base):
    __tablename__ = "cameras"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    site: Mapped[str] = mapped_column(String(120), default="")
    main_url: Mapped[str] = mapped_column(String(2048))          # encrypted RTSP URL (with creds)
    sub_url: Mapped[str] = mapped_column(String(2048), default="")  # encrypted, optional
    onvif_host: Mapped[str] = mapped_column(String(255), default="")
    onvif_port: Mapped[int] = mapped_column(Integer, default=80)
    onvif_user: Mapped[str] = mapped_column(String(128), default="")
    onvif_pass: Mapped[str] = mapped_column(String(512), default="")  # encrypted
    relay_token: Mapped[str] = mapped_column(String(64), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    record: Mapped[bool] = mapped_column(Boolean, default=True)
    ai_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_ir: Mapped[bool] = mapped_column(Boolean, default=False)
    ir_mode: Mapped[str] = mapped_column(String(8), default="auto")  # auto|day|night
    lowlight_threshold: Mapped[int] = mapped_column(Integer, default=40)
    day_start: Mapped[str] = mapped_column(String(5), default="06:00")
    day_end: Mapped[str] = mapped_column(String(5), default="18:30")
    loiter_seconds: Mapped[int] = mapped_column(Integer, default=60)
    attendance: Mapped[bool] = mapped_column(Boolean, default=False)  # CCTV (passive) attendance point
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=now)


class Rule(Base):
    __tablename__ = "rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    camera_ids: Mapped[list] = mapped_column(JSON, default=list)   # [] = all cameras
    classes: Mapped[list] = mapped_column(JSON, default=list)      # labels or kinds
    zone: Mapped[list | None] = mapped_column(JSON, nullable=True)  # [[x,y],...] normalised
    min_conf: Mapped[float] = mapped_column(Float, default=0.5)
    schedule: Mapped[dict] = mapped_column(
        JSON, default=lambda: {"days": [0, 1, 2, 3, 4, 5, 6], "start": "00:00", "end": "23:59"})
    cooldown_s: Mapped[int] = mapped_column(Integer, default=60)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    actions: Mapped[dict] = mapped_column(JSON, default=dict)  # sms[], whatsapp[], alarm, webhook


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime, default=now, index=True)
    camera_id: Mapped[int] = mapped_column(Integer, index=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)  # object|loitering|tamper|video_loss|lowlight|watchlist
    label: Mapped[str] = mapped_column(String(64), default="")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    bbox: Mapped[list | None] = mapped_column(JSON, nullable=True)
    snapshot: Mapped[str] = mapped_column(String(512), default="")
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    rules: Mapped[list] = mapped_column(JSON, default=list)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    ack_by: Mapped[str] = mapped_column(String(64), default="")
    ack_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)


class Watchlist(Base):
    __tablename__ = "watchlist"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))           # face|plate
    label: Mapped[str] = mapped_column(String(120))
    value: Mapped[str] = mapped_column(String(64), default="")  # normalised plate text
    embedding: Mapped[list | None] = mapped_column(JSON, nullable=True)
    list_type: Mapped[str] = mapped_column(String(8), default="deny")  # deny|allow
    consent_ref: Mapped[str] = mapped_column(String(255), default="")  # lawful basis / consent record
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=now)
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime, default=now, index=True)
    username: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


# ===================================================================== campus attendance
class Person(Base):
    """A student or staff member. Face templates are encrypted with the media key; enrolment
    photos are never stored."""
    __tablename__ = "persons"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(64), unique=True)   # roll number / employee id
    name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(8), default="student")  # student|staff
    department: Mapped[str] = mapped_column(String(120), default="")
    section: Mapped[str] = mapped_column(String(120), default="")  # class / section / year
    is_minor: Mapped[bool] = mapped_column(Boolean, default=False)
    consent_ref: Mapped[str] = mapped_column(String(255), default="")
    guardian_consent_ref: Mapped[str] = mapped_column(String(255), default="")
    consent_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    templates: Mapped[str] = mapped_column(String, default="")   # encrypted JSON list of embeddings
    template_source: Mapped[str] = mapped_column(String(16), default="")  # live|photo
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=now)


class AttendanceRecord(Base):
    __tablename__ = "attendance"
    id: Mapped[int] = mapped_column(primary_key=True)
    person_id: Mapped[int] = mapped_column(Integer, index=True)
    day: Mapped[str] = mapped_column(String(10), index=True)     # local YYYY-MM-DD
    first_seen: Mapped[dt.datetime] = mapped_column(DateTime, default=now)
    last_seen: Mapped[dt.datetime] = mapped_column(DateTime, default=now)
    status: Mapped[str] = mapped_column(String(8), default="present")  # present|late|review|rejected
    method: Mapped[str] = mapped_column(String(8), default="kiosk")    # kiosk|cctv|manual
    camera_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    device: Mapped[str] = mapped_column(String(64), default="")
    score: Mapped[float] = mapped_column(Float, default=0.0)
    liveness: Mapped[dict] = mapped_column(JSON, default=dict)
    evidence_blur: Mapped[str] = mapped_column(String(512), default="")  # media-key encrypted JPEG
    evidence_raw: Mapped[str] = mapped_column(String(512), default="")   # vault-sealed face crop
    reviewed_by: Mapped[str] = mapped_column(String(64), default="")
    note: Mapped[str] = mapped_column(String(255), default="")


class Segment(Base):
    """Index of encrypted recording segments written by the recorder."""
    __tablename__ = "segments"
    id: Mapped[int] = mapped_column(primary_key=True)
    camera_id: Mapped[int] = mapped_column(Integer, index=True)
    kind: Mapped[str] = mapped_column(String(4), index=True)  # priv|raw
    start: Mapped[dt.datetime] = mapped_column(DateTime, index=True)
    end: Mapped[dt.datetime] = mapped_column(DateTime)
    path: Mapped[str] = mapped_column(String(512))
    size: Mapped[int] = mapped_column(Integer, default=0)


class UnblurRequest(Base):
    __tablename__ = "unblur_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=now)
    requester: Mapped[str] = mapped_column(String(64))
    person_id: Mapped[int] = mapped_column(Integer)
    attendance_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    camera_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    window_start: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    window_end: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    reason: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(12), default="pending")  # pending|rendering|ready|denied|failed|expired
    decided_by: Mapped[str] = mapped_column(String(64), default="")
    decided_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    result_video: Mapped[str] = mapped_column(String(512), default="")
    result_image: Mapped[str] = mapped_column(String(512), default="")
    detail: Mapped[str] = mapped_column(String(500), default="")
    views: Mapped[int] = mapped_column(Integer, default=0)


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime, default=now, index=True)
    kind: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(10), default="high")
    actor: Mapped[str] = mapped_column(String(64), default="")
    message: Mapped[str] = mapped_column(String(500))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    read_by: Mapped[list] = mapped_column(JSON, default=list)


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(2000), default="")


class Invite(Base):
    """Single-use registration (kind=invite) or password-reset (kind=reset) link. Only the SHA-256 of the
    token is stored, so a database leak does not expose usable links."""
    __tablename__ = "invites"
    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[str] = mapped_column(String(8), default="invite")  # invite|reset
    role: Mapped[str] = mapped_column(String(16), default="viewer")
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)  # reset: the account
    email: Mapped[str] = mapped_column(String(255), default="")
    phone: Mapped[str] = mapped_column(String(32), default="")
    note: Mapped[str] = mapped_column(String(255), default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=now)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime)
    used_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    used_by: Mapped[str] = mapped_column(String(64), default="")
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
