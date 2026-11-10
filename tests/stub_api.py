"""Minimal stand-in for the API's /internal endpoints, used by the end-to-end pipeline tests.
Uses the product's real MediaMTX access decision (app.hardening.mediamtx_decision) and real JWTs."""
import http.server
import json
import os
import sys
from email.parser import BytesParser
from email.policy import default
from pathlib import Path

import jwt

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "api"))
from app.hardening import mediamtx_decision  # noqa: E402

TOK, SECRET, PUB, OUT, PORT = sys.argv[1], sys.argv[2], sys.argv[3], Path(sys.argv[4]), int(sys.argv[5])
STATE = {"pub": PUB, "attendance": True}
CRLF = bytes([13, 10])


def claims(t):
    try:
        c = jwt.decode(t, SECRET, algorithms=["HS256"])
        return c if c.get("typ") == "stream" else None
    except jwt.PyJWTError:
        return None


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _j(self, o, code=200):
        b = json.dumps(o).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/internal/cameras":
            return self._j([{"id": 1, "name": "Gate", "record": True, "attendance": STATE["attendance"], "ai_enabled": False}])
        if self.path == "/internal/vault/pubkey":
            return self._j({"public_key": STATE["pub"] or None})
        if self.path == "/internal/config":
            return self._j({"antispoof": {"variant": "int8", "threshold": 0.5, "frames": 3}})
        if self.path.startswith("/__set"):
            STATE["pub"] = PUB if "pub=1" in self.path else ""
            return self._j(STATE)
        self._j({}, 404)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path == "/internal/mediamtx-auth":
            b = json.loads(body)
            with open(OUT / "auth.jsonl", "a") as f:
                f.write(json.dumps({k: b.get(k) for k in ("user", "action", "path", "protocol")}) + "\n")
            self.send_response(200 if mediamtx_decision(b, TOK, claims) else 401)
            self.end_headers()
            return
        if self.path == "/internal/segments":
            with open(OUT / "segments.jsonl", "a") as f:
                f.write(body.decode() + "\n")
            return self._j({"ok": True})
        if self.path == "/internal/attendance":
            msg = BytesParser(policy=default).parsebytes(b"Content-Type: " + self.headers["Content-Type"].encode() + CRLF + CRLF + body)
            parts = {p.get_param("name", header="content-disposition"): p.get_payload(decode=True) for p in msg.iter_parts()}
            n = len(list(OUT.glob("att_*.json")))
            (OUT / f"att_{n}.json").write_text(parts["data"].decode())
            if parts.get("sealed"):
                (OUT / f"att_{n}.sealed").write_bytes(parts["sealed"])
            if parts.get("blurred"):
                (OUT / f"att_{n}.jpg").write_bytes(parts["blurred"])
            return self._j({"ok": True})
        self._j({}, 404)


os.makedirs(OUT, exist_ok=True)
http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
