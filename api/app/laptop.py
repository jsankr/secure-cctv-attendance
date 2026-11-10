"""Standalone (laptop) mode: replaces Caddy.

* serves the web console from VMS_WEB_DIR
* reverse-proxies /webrtc and /hls to MediaMTX on loopback (viewer tokens only open blurred paths)
* adds the same security headers Caddy sets
* refuses /internal/* calls made from a browser (any request carrying an Origin header)
"""
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.background import BackgroundTask

from .config import settings
from .hardening import MAX_BODY

FWD_REQ = {"authorization", "content-type", "range", "accept", "if-none-match", "if-modified-since"}
FWD_RES = {"content-type", "content-length", "content-range", "accept-ranges", "etag", "cache-control",
           "last-modified", "location"}


def _csp(request: Request) -> str:
    host = request.headers.get("host", "127.0.0.1")
    return ("default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; "
            "style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
            f"img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self' ws://{host}; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


def mount(app: FastAPI):
    client = httpx.AsyncClient(timeout=httpx.Timeout(30, read=None))
    # The MediaMTX playback server is deliberately NOT exposed: recordings are encrypted and served
    # only through /api/recordings (blurred) and approved /api/unblur results.
    targets = {"webrtc": settings.mtx_webrtc_url, "hls": settings.mtx_hls_url}

    @app.middleware("http")
    async def guard_and_headers(request: Request, call_next):
        if request.url.path.startswith("/internal") and request.headers.get("origin"):
            return JSONResponse({"detail": "Not found"}, status_code=404)
        try:
            too_big = int(request.headers.get("content-length") or 0) > MAX_BODY
        except ValueError:
            too_big = True
        if too_big:
            return JSONResponse({"detail": "Request too large"}, status_code=413)
        resp = await call_next(request)
        resp.headers.update({
            "Content-Security-Policy": _csp(request), "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "X-Robots-Tag": "noindex, nofollow",
            "Permissions-Policy": "camera=(self), microphone=(), geolocation=()",  # camera: kiosk page
        })
        return resp

    async def proxy(svc: str, path: str, request: Request):
        url = f"{targets[svc].rstrip('/')}/{path}"
        if request.url.query:
            url += "?" + request.url.query
        headers = {k: v for k, v in request.headers.items() if k.lower() in FWD_REQ}
        req = client.build_request(request.method, url, headers=headers, content=await request.body())
        try:
            r = await client.send(req, stream=True)
        except httpx.HTTPError:
            return JSONResponse({"detail": "Media server unavailable"}, status_code=502)
        out = {k: v for k, v in r.headers.items() if k.lower() in FWD_RES}
        return StreamingResponse(r.aiter_raw(), status_code=r.status_code, headers=out,
                                 background=BackgroundTask(r.aclose))

    def make_handler(svc: str):  # closure, so the target is not exposed as a query parameter
        async def handler(path: str, request: Request):
            return await proxy(svc, path, request)
        return handler

    for svc in targets:
        app.add_api_route(f"/{svc}/{{path:path}}", make_handler(svc),
                          methods=["GET", "HEAD", "POST", "PATCH", "DELETE"], include_in_schema=False)

    app.mount("/", StaticFiles(directory=settings.web_dir, html=True), name="web")
