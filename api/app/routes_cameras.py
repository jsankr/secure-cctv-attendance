from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import mediamtx, models, onvif_ctl
from .config import settings
from .db import get_db
from .security import audit, dec, enc, make_token, require

router = APIRouter(prefix="/api", tags=["cameras"])


def _check_rtsp(v: str) -> str:
    if v and urlsplit(v).scheme not in ("rtsp", "rtsps"):
        raise ValueError("Stream URL must be rtsp:// or rtsps://")
    return v


class CamIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    site: str = Field(default="", max_length=120)
    main_url: str = Field(default="", max_length=2000)  # blank on update = keep existing
    sub_url: str = Field(default="", max_length=2000)
    onvif_host: str = Field(default="", max_length=255)
    onvif_port: int = Field(default=80, ge=1, le=65535)
    onvif_user: str = Field(default="", max_length=128)
    onvif_pass: str = Field(default="", max_length=256)
    relay_token: str = Field(default="", max_length=64)
    enabled: bool = True
    record: bool = True
    ai_enabled: bool = True
    auto_ir: bool = False
    lowlight_threshold: int = Field(default=40, ge=1, le=200)
    day_start: str = Field(default="06:00", pattern=r"^\d{2}:\d{2}$")
    day_end: str = Field(default="18:30", pattern=r"^\d{2}:\d{2}$")
    loiter_seconds: int = Field(default=60, ge=10, le=3600)
    attendance: bool = False

    @field_validator("main_url", "sub_url")
    @classmethod
    def _rtsp(cls, v: str) -> str:
        return _check_rtsp(v)


def _mask(url: str) -> str:
    p = urlsplit(url)
    if p.password:
        return url.replace(f":{p.password}@", ":•••@", 1)
    return url


def cam_out(c: models.Camera, detail=False) -> dict:
    d = {"id": c.id, "name": c.name, "site": c.site, "enabled": c.enabled, "record": c.record,
         "ai_enabled": c.ai_enabled, "auto_ir": c.auto_ir, "ir_mode": c.ir_mode,
         "ptz": bool(c.onvif_host), "has_sub": bool(c.sub_url), "attendance": c.attendance}
    if detail:
        d.update(main_url=_mask(dec(c.main_url)), sub_url=_mask(dec(c.sub_url)), onvif_host=c.onvif_host,
                 onvif_port=c.onvif_port, onvif_user=c.onvif_user, relay_token=c.relay_token,
                 lowlight_threshold=c.lowlight_threshold, day_start=c.day_start, day_end=c.day_end,
                 loiter_seconds=c.loiter_seconds)
    return d


def _get(db, cid) -> models.Camera:
    c = db.get(models.Camera, cid)
    if not c:
        raise HTTPException(404, "Camera not found")
    return c


@router.get("/cameras")
def list_cameras(db: Session = Depends(get_db), _=Depends(require("viewer"))):
    return [cam_out(c) for c in db.scalars(select(models.Camera).order_by(models.Camera.site, models.Camera.name))]


@router.get("/cameras/status")
def cameras_status(_=Depends(require("viewer"))):
    st = mediamtx.status()
    return {k[3:]: v for k, v in st.items() if k.startswith("cam") and not k.endswith("_sub")}


@router.get("/cameras/{cid}")
def get_camera(cid: int, db: Session = Depends(get_db), _=Depends(require("admin"))):
    return cam_out(_get(db, cid), detail=True)


@router.post("/cameras")
def create_camera(body: CamIn, request: Request, db: Session = Depends(get_db), a=Depends(require("admin"))):
    if not body.main_url:
        raise HTTPException(422, "main_url required")
    d = body.model_dump()
    c = models.Camera(**{**d, "main_url": enc(d["main_url"]), "sub_url": enc(d["sub_url"]),
                         "onvif_pass": enc(d["onvif_pass"])})
    db.add(c)
    db.commit()
    mediamtx.upsert(c)
    audit(db, a.username, "camera_created", c.name, request)
    return cam_out(c, True)


@router.put("/cameras/{cid}")
def update_camera(cid: int, body: CamIn, request: Request, db: Session = Depends(get_db),
                  a=Depends(require("admin"))):
    c = _get(db, cid)
    d = body.model_dump()
    for k in ("main_url", "sub_url", "onvif_pass"):
        v = d.pop(k)
        if v and "•••" not in v:
            setattr(c, k, enc(v))
    for k, v in d.items():
        setattr(c, k, v)
    db.commit()
    onvif_ctl.forget(c.id)
    mediamtx.upsert(c)
    audit(db, a.username, "camera_updated", c.name, request)
    return cam_out(c, True)


@router.delete("/cameras/{cid}")
def delete_camera(cid: int, request: Request, db: Session = Depends(get_db), a=Depends(require("admin"))):
    c = _get(db, cid)
    db.delete(c)
    db.commit()
    mediamtx.remove(cid)
    audit(db, a.username, "camera_deleted", c.name, request)
    return {"ok": True}


class ProbeIn(BaseModel):
    host: str = Field(max_length=255)
    port: int = Field(default=80, ge=1, le=65535)
    user: str = ""
    password: str = ""


@router.post("/cameras/probe")
def probe(body: ProbeIn, _=Depends(require("admin"))):
    return onvif_ctl.probe(body.host, body.port, body.user, body.password)


class PtzIn(BaseModel):
    action: str = Field(pattern="^(move|stop|goto_preset|presets)$")
    pan: float = Field(default=0, ge=-1, le=1)
    tilt: float = Field(default=0, ge=-1, le=1)
    zoom: float = Field(default=0, ge=-1, le=1)
    preset: str = ""


@router.post("/cameras/{cid}/ptz")
def ptz(cid: int, body: PtzIn, db: Session = Depends(get_db), _=Depends(require("operator"))):
    return {"result": onvif_ctl.ptz(_get(db, cid), body.action, body.pan, body.tilt, body.zoom, body.preset)}


class IrIn(BaseModel):
    mode: str = Field(pattern="^(day|night|auto)$")


@router.post("/cameras/{cid}/ir")
def ir(cid: int, body: IrIn, request: Request, db: Session = Depends(get_db), u=Depends(require("operator"))):
    c = _get(db, cid)
    onvif_ctl.set_ir(c, body.mode)
    c.ir_mode = body.mode
    db.commit()
    audit(db, u.username, "ir_mode", c.name, request, mode=body.mode)
    return {"ok": True, "ir_mode": c.ir_mode}


class RelayIn(BaseModel):
    active: bool


@router.post("/cameras/{cid}/relay")
def relay(cid: int, body: RelayIn, request: Request, db: Session = Depends(get_db), u=Depends(require("operator"))):
    c = _get(db, cid)
    onvif_ctl.set_relay(c, body.active)
    audit(db, u.username, "alarm_relay", c.name, request, active=body.active)
    return {"ok": True}


class StreamIn(BaseModel):
    camera_id: int


@router.post("/streams/token")
def stream_token(body: StreamIn, db: Session = Depends(get_db), u=Depends(require("viewer"))):
    """Browsers only ever get the face-blurred rendition (cam<N>_priv); MediaMTX enforces it too."""
    c = _get(db, body.camera_id)
    path = f"cam{c.id}_priv"
    tok = make_token({"typ": "stream", "sub": str(u.id), "path": path, "act": "read"}, settings.stream_token_seconds)
    return {"token": tok, "path": path, "expires_in": settings.stream_token_seconds}
