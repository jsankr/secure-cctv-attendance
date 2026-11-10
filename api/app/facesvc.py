"""API-side face services: one face engine (OpenCV DNN is not thread-safe -> lock), encrypted template
storage, the in-memory gallery used for matching, and encrypted evidence files."""
import json
import os
import threading
import uuid

import numpy as np
from sqlalchemy import select

from . import models
from .config import settings
from .security import media_decrypt, media_encrypt, vmscrypto

import faceengine as F  # noqa: E402  (shared/, put on sys.path by security.py)

_engine = None
_engine_lock = threading.Lock()
_gallery: dict[int, list[np.ndarray]] | None = None
_gallery_lock = threading.Lock()
MAX_TEMPLATES = 6


AS_DEFAULTS = {"variant": "int8", "threshold": 0.5, "frames": 3}


def as_config(db=None) -> dict:
    """Anti-spoof settings (admin-editable): model variant, probability threshold, consecutive frames."""
    from .db import SessionLocal
    own = db is None
    db = db or SessionLocal()
    try:
        cfg = dict(AS_DEFAULTS)
        for k in cfg:
            row = db.get(models.Setting, f"as.{k}")
            if row and row.value:
                cfg[k] = type(AS_DEFAULTS[k])(row.value)
        return cfg
    finally:
        if own:
            db.close()


def engine() -> F.FaceEngine:
    global _engine
    if _engine is None:
        if not (os.path.exists(settings.face_det_model) and os.path.exists(settings.face_rec_model)):
            raise RuntimeError("Face models are not installed")
        c = as_config()
        _engine = F.FaceEngine(settings.face_det_model, settings.face_rec_model, settings.antispoof_dir,
                               antispoof_variant=c["variant"], antispoof_threshold=c["threshold"], antispoof_frames=c["frames"])
    return _engine


def reset_engine():
    """Rebuild on next use (after anti-spoof settings change)."""
    global _engine
    with _engine_lock:
        _engine = None


class locked_engine:
    def __enter__(self) -> F.FaceEngine:
        _engine_lock.acquire()
        try:
            return engine()
        except Exception as e:
            _engine_lock.release()
            from fastapi import HTTPException
            raise HTTPException(503, f"Face recognition unavailable: {e}")

    def __exit__(self, *a):
        _engine_lock.release()


# ---------------------------------------------------------------- templates
def get_templates(p: models.Person) -> list[np.ndarray]:
    if not p.templates:
        return []
    data = json.loads(media_decrypt(bytes.fromhex(p.templates)))
    return [np.asarray(t, dtype=np.float32) for t in data]


def set_templates(p: models.Person, temps: list[np.ndarray], source: str):
    temps = temps[-MAX_TEMPLATES:]
    p.templates = media_encrypt(json.dumps([[round(float(v), 6) for v in t] for t in temps]).encode()).hex() if temps else ""
    p.template_source = source if temps else ""
    invalidate()


def invalidate():
    global _gallery
    with _gallery_lock:
        _gallery = None


def gallery(db) -> dict[int, list[np.ndarray]]:
    global _gallery
    with _gallery_lock:
        if _gallery is None:
            g = {}
            for p in db.scalars(select(models.Person).where(models.Person.active.is_(True), models.Person.templates != "")):
                try:
                    g[p.id] = get_templates(p)
                except Exception:
                    pass
            _gallery = g
        return _gallery


def match(db, emb: np.ndarray):
    return F.FaceEngine.match(emb, gallery(db), settings.attendance_match_threshold, settings.attendance_match_margin)


# ----------------------------------------------------------------- evidence
def _evidence_path(kind: str) -> tuple[str, str]:
    day = models.now().strftime("%Y-%m-%d")
    rel = os.path.join("evidence", day, f"{kind}-{uuid.uuid4().hex}.svms")
    full = os.path.join(settings.store_dir, rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    return rel, full


def store_media(data: bytes, kind: str = "blur") -> str:
    rel, full = _evidence_path(kind)
    with open(full, "wb") as f:
        f.write(media_encrypt(data))
    return rel


def store_sealed_blob(sealed: bytes) -> str:
    """Already sealed to the vault key by the privacy worker; verify the header before storing."""
    import io
    hdr, mode = vmscrypto.read_header(io.BytesIO(sealed))
    if mode != vmscrypto.MODE_SEALED:
        raise ValueError("expected a sealed blob")
    rel, full = _evidence_path("raw")
    with open(full, "wb") as f:
        f.write(sealed)
    return rel


def seal(data: bytes, pub: bytes) -> str:
    return store_sealed_blob(vmscrypto.encrypt_bytes(data, recipient_pub=pub))


def read_media(rel: str) -> bytes:
    return media_decrypt(read_file(rel))


def read_file(rel: str) -> bytes:
    root = os.path.realpath(settings.store_dir)
    full = os.path.realpath(os.path.join(root, rel))
    if not full.startswith(root + os.sep):
        raise ValueError("path outside store")
    with open(full, "rb") as f:
        return f.read()


def remove_file(rel: str):
    if not rel:
        return
    try:
        root = os.path.realpath(settings.store_dir)
        full = os.path.realpath(os.path.join(root, rel))
        if full.startswith(root + os.sep):
            os.remove(full)
    except OSError:
        pass
