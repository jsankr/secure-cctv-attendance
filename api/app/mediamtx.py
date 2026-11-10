"""Keeps MediaMTX paths in sync with the camera table. MediaMTX is never reachable from outside."""
import logging
import threading
import time
from urllib.parse import urlsplit, urlunsplit

import httpx

from . import models
from .config import settings
from .db import SessionLocal
from .security import dec

log = logging.getLogger("mediamtx")
_auth = ("internal", settings.internal_token)


def _client() -> httpx.Client:
    return httpx.Client(base_url=settings.mediamtx_api, auth=_auth, timeout=5)


def _internalize(url: str) -> str:
    """Loopback sources (demo / simulated / webcam streams published into this MediaMTX) are stored
    without credentials; the current internal identity is injected here, so the secret never lands
    in the database and can be rotated freely."""
    p = urlsplit(url)
    if p.hostname in ("127.0.0.1", "localhost") and p.scheme in ("rtsp", "rtsps"):
        host = p.netloc.rsplit("@", 1)[-1]
        return urlunsplit((p.scheme, f"internal:{settings.internal_token}@{host}", p.path, p.query, p.fragment))
    return url


def _paths(cam: models.Camera) -> dict[str, dict]:
    # Recording is done by the encrypting recorder, never by MediaMTX (which would write plaintext).
    p = {f"cam{cam.id}": {"source": _internalize(dec(cam.main_url)), "record": False,
                          "rtspTransport": "tcp", "sourceOnDemand": False}}
    if cam.sub_url:
        p[f"cam{cam.id}_sub"] = {"source": _internalize(dec(cam.sub_url)), "record": False,
                                 "rtspTransport": "tcp", "sourceOnDemand": False}
    else:  # alias: AI + grid tiles read the main stream when no substream exists
        p[f"cam{cam.id}_sub"] = {"source": f"rtsp://internal:{settings.internal_token}@127.0.0.1:8554/cam{cam.id}",
                                 "record": False, "sourceOnDemand": True}
    p[f"cam{cam.id}_priv"] = {"source": "publisher", "record": False}  # published by the privacy processor
    return p


def upsert(cam: models.Camera) -> bool:
    try:
        with _client() as c:
            for name, conf in _paths(cam).items():
                if not cam.enabled:
                    c.delete(f"/v3/config/paths/delete/{name}")
                    continue
                r = c.post(f"/v3/config/paths/replace/{name}", json=conf)
                if r.status_code == 404:
                    r = c.post(f"/v3/config/paths/add/{name}", json=conf)
                r.raise_for_status()
        return True
    except Exception as e:
        log.warning("mediamtx upsert cam%s failed: %s", cam.id, e)
        return False


def remove(cam_id: int):
    try:
        with _client() as c:
            for name in (f"cam{cam_id}", f"cam{cam_id}_sub", f"cam{cam_id}_priv"):
                c.delete(f"/v3/config/paths/delete/{name}")
    except Exception as e:
        log.warning("mediamtx remove cam%s failed: %s", cam_id, e)


def status() -> dict[str, dict]:
    """name -> {ready, readers, bytes} from MediaMTX runtime."""
    try:
        with _client() as c:
            items = c.get("/v3/paths/list", params={"itemsPerPage": 5000}).json().get("items", [])
        return {i["name"]: {"ready": i.get("ready", False), "readers": len(i.get("readers", [])),
                            "bytes": i.get("bytesReceived", 0)} for i in items}
    except Exception as e:
        log.debug("mediamtx status failed: %s", e)
        return {}


def sync_forever():
    """MediaMTX keeps dynamic paths in memory only, so re-push them after any restart."""
    def loop():
        while True:
            known = set(status().keys())
            db = SessionLocal()
            ok = True
            try:
                for cam in db.query(models.Camera).filter_by(enabled=True):
                    if f"cam{cam.id}" not in known:
                        ok = upsert(cam) and ok
            except Exception as e:
                log.warning("sync failed: %s", e)
            finally:
                db.close()
            time.sleep(30 if ok else 5)  # retry fast while MediaMTX is still starting
    threading.Thread(target=loop, daemon=True, name="mediamtx-sync").start()
