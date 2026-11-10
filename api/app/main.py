import asyncio
import logging
import os
import threading
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket
from fastapi.responses import JSONResponse
from sqlalchemy import select

from . import mediamtx, models
from .config import settings
from .db import Base, SessionLocal, engine
from .realtime import hub
from .routes_auth import router as auth_router, users_router
from .routes_cameras import router as cam_router
from .routes_events import router as ev_router
from .routes_antispoof import router as as_router
from .routes_attendance import router as att_router
from .routes_internal import purge_old, purge_plaintext_snapshots, purge_store, router as internal_router
from .routes_privacy import purge_unblur, router as privacy_router
from .routes_setup import init_setup, router as setup_router
from .security import enc

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("vms")


NEW_COLUMNS = {  # columns added after first release; create_all() does not alter existing tables
    "users": {"phone": "VARCHAR(32) DEFAULT ''", "email": "VARCHAR(255) DEFAULT ''"},
    "cameras": {"attendance": "BOOLEAN DEFAULT 0"},
}


def upgrade_schema():
    from sqlalchemy import inspect, text
    insp = inspect(engine)
    with engine.begin() as conn:
        for table, cols in NEW_COLUMNS.items():
            if not insp.has_table(table):
                continue
            have = {c["name"] for c in insp.get_columns(table)}
            for name, ddl in cols.items():
                if name not in have:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
                    log.info("schema upgrade: %s.%s added", table, name)


def bootstrap():
    Base.metadata.create_all(engine)
    upgrade_schema()
    os.makedirs(settings.snapshot_dir, exist_ok=True)
    os.makedirs(settings.store_dir, exist_ok=True)
    if not settings.media_key:
        raise RuntimeError("VMS_MEDIA_KEY is required (privacy mode encrypts all stored media)")
    purge_plaintext_snapshots()
    db = SessionLocal()
    try:
        init_setup(db)  # no built-in account: first-run setup code or nothing
        if not db.scalar(select(models.User).where(models.User.role == "superadmin").limit(1)):
            first = db.scalar(select(models.User).where(models.User.role == "admin").order_by(models.User.id).limit(1))
            if first:  # upgrade from a pre-privacy install: the original admin becomes the super admin
                first.role = "superadmin"
                first.pw_version += 1
                db.commit()
                log.warning("promoted '%s' to superadmin (privacy upgrade)", first.username)
        sync_launcher_cameras(db)
    finally:
        db.close()


LAUNCHER_SITE = "This laptop"


def sync_launcher_cameras(db):
    """Laptop mode: the launcher owns the demo / simulated / webcam cameras (site "This laptop").
    Spec: "Name|rtsp://127.0.0.1:8554/path|record|attendance;..." (attendance applies at creation only, so
    the admin's later choice in the UI is kept). Cameras it no longer lists are disabled
    (kept, so their events and recordings remain browsable)."""
    if not settings.web_dir:
        return
    wanted = {}
    for item in filter(None, settings.demo_cameras.split(";")):
        name, url, *rest = item.split("|")
        wanted[name] = (url, (rest[0] if rest else "1") == "1", len(rest) > 1 and rest[1] == "1")
    for cam in db.scalars(select(models.Camera).where(models.Camera.site == LAUNCHER_SITE)):
        if cam.name in wanted:
            url, record, _ = wanted.pop(cam.name)
            cam.main_url, cam.record, cam.enabled = enc(url), record, True
        elif cam.enabled:
            cam.enabled = False
            log.info("disabled launcher camera no longer configured: %s", cam.name)
    for name, (url, record, attendance) in wanted.items():
        db.add(models.Camera(name=name, site=LAUNCHER_SITE, main_url=enc(url), record=record, attendance=attendance))
        log.info("added camera %s", name)
    db.commit()


def retention_loop():
    while True:
        db = SessionLocal()
        try:
            purge_old(db)
            purge_store(db)
            purge_unblur(db)
        except Exception as e:
            log.warning("retention failed: %s", e)
        finally:
            db.close()
        time.sleep(60)  # unblurred results expire within minutes


@asynccontextmanager
async def lifespan(app: FastAPI):
    bootstrap()
    hub.loop = asyncio.get_running_loop()
    mediamtx.sync_forever()
    threading.Thread(target=retention_loop, daemon=True).start()
    yield


app = FastAPI(title="Sentinel Attend", lifespan=lifespan,
              docs_url="/api/docs" if settings.debug else None, redoc_url=None,
              openapi_url="/api/openapi.json" if settings.debug else None)

for r in (setup_router, auth_router, users_router, cam_router, ev_router, privacy_router, att_router, as_router, internal_router):
    app.include_router(r)


@app.websocket("/api/ws")
async def ws(websocket: WebSocket):
    await hub.handle(websocket)


@app.get("/api/health")
def health():
    return {"ok": True}


@app.exception_handler(Exception)
async def unhandled(request, exc):
    log.exception("unhandled error on %s", request.url.path)
    return JSONResponse({"detail": "Internal error"}, status_code=500)  # never leak stack traces


if settings.web_dir:  # standalone laptop mode; must be registered after all API routes
    from .laptop import mount
    mount(app)
