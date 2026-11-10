import asyncio
from urllib.parse import urlsplit

from fastapi import WebSocket, WebSocketDisconnect

from .db import SessionLocal
from . import models
from .security import COOKIE, ROLES, read_token


class Hub:
    def __init__(self):
        self.clients: dict[WebSocket, int] = {}  # ws -> role rank
        self.loop: asyncio.AbstractEventLoop | None = None

    async def handle(self, ws: WebSocket):
        # Cross-site WebSocket hijacking guard: Origin must match Host.
        origin = urlsplit(ws.headers.get("origin", "")).netloc
        if not origin or origin != ws.headers.get("host"):
            await ws.close(code=4403)
            return
        c = read_token(ws.cookies.get(COOKIE, ""), "session")
        db = SessionLocal()
        try:
            u = db.get(models.User, int(c["sub"])) if c else None
            ok = u and not u.disabled and c.get("pwv") == u.pw_version
            rank = ROLES.get(u.role, -1) if u else -1
        finally:
            db.close()
        if not ok:
            await ws.close(code=4401)
            return
        await ws.accept()
        self.clients[ws] = rank
        try:
            while True:
                await ws.receive_text()  # keepalive pings from the UI
        except WebSocketDisconnect:
            pass
        finally:
            self.clients.pop(ws, None)

    async def _send(self, msg: dict, min_rank: int):
        for c, rank in list(self.clients.items()):
            if rank < min_rank:
                continue
            try:
                await c.send_json(msg)
            except Exception:
                self.clients.pop(c, None)

    def publish(self, msg: dict, min_role: str = "viewer"):
        """Thread-safe: called from sync request handlers. Kiosk sessions never receive events."""
        if self.loop:
            asyncio.run_coroutine_threadsafe(self._send(msg, ROLES[min_role]), self.loop)


hub = Hub()
