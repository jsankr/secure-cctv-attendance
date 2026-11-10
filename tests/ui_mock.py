"""Mock API for console UI tests: serves web/ with the production security headers (laptop.py CSP)
and canned API responses. GET /__role?r=<role> switches the signed-in role. Records POST bodies."""
import datetime as dt
import functools
import http.server
import json
import os
import sys

import cv2
import numpy as np

WEB, PORT = sys.argv[1], int(sys.argv[2])
STATE = {"role": "superadmin", "posts": [], "setup": False}  # role "none" = signed out
now = dt.datetime.now(dt.UTC).replace(tzinfo=None)
iso = lambda d: d.isoformat() + "Z"  # noqa: E731
XSS = '<img src=x onerror="window.__xss=1">'
cams = [{"id": i, "name": n, "site": "Campus", "enabled": True, "record": True, "ai_enabled": True, "auto_ir": False,
         "ir_mode": "auto", "ptz": i == 1, "has_sub": True, "attendance": i == 1} for i, n in enumerate(["Main Gate", "Library"], 1)]
people = [{"id": 1, "code": "21CS045", "name": "Priya " + XSS, "kind": "student", "department": "CSE", "section": "III-A",
           "is_minor": False, "consent_ref": "CF-1", "guardian_consent_ref": "", "consent_at": None, "enrolled": True,
           "template_source": "live", "active": True, "created_by": "admin"},
          {"id": 2, "code": "24ME012", "name": "Divya M", "kind": "student", "department": "MECH", "section": "I-B",
           "is_minor": True, "consent_ref": "CF-2", "guardian_consent_ref": "GC-2", "consent_at": None, "enrolled": True,
           "template_source": "photo", "active": True, "created_by": "admin"}]
rec = {"id": 5, "person_id": 1, "day": now.strftime("%Y-%m-%d"), "first_seen": iso(now), "last_seen": iso(now), "status": "review",
       "method": "cctv", "camera_id": 1, "device": "", "score": 0.61, "liveness": {"ok": False}, "has_evidence": True,
       "has_raw": True, "reviewed_by": "", "note": ""}
R = {
    "/api/cameras": cams, "/api/cameras/status": {"1": {"ready": True, "readers": 1}},
    "/api/events/stats": {"total_24h": 3, "unacked_alerts": 1, "by_label": [{"label": "person", "count": 3}], "by_hour": [0] * 24},
    "/api/events": [], "/api/rules": [], "/api/watchlists": [], "/api/audit": [], "/api/persons": people,
    "/api/attendance/day": {"day": now.strftime("%Y-%m-%d"), "counts": {"present": 0, "late": 0, "review": 1, "rejected": 0, "absent": 1},
                            "total": 2, "late_after": "09:15", "departments": ["CSE"], "sections": ["III-A"],
                            "rows": [{"person": people[0], "status": "review", "record": rec}, {"person": people[1], "status": "absent", "record": None}]},
    "/api/attendance/settings": {"late_after": "09:15", "cctv_requires_liveness": True, "vault": True},
    "/api/notifications": {"unread": 1, "items": [{"id": 1, "ts": iso(now), "kind": "export_denied", "severity": "high", "actor": XSS, "message": "blocked " + XSS, "read": False}]},
    "/api/vault": {"configured": True, "fingerprint": "AAAA-BBBB", "created_by": "principal", "created_at": iso(now)},
    "/api/unblur": [{"id": 7, "created_at": iso(now), "requester": "hod", "person": {"id": 1, "code": "21CS045", "name": "Priya"},
                     "attendance_id": 5, "camera_id": 1, "reason": "dispute " + XSS, "status": "pending", "detail": "", "expires_at": None,
                     "has_video": False, "has_image": False, "views": 0}],
    "/api/recordings": [{"id": 11, "start": iso(now - dt.timedelta(minutes=10)), "end": iso(now - dt.timedelta(minutes=5)), "size": 100}],
    "/api/users": [{"id": 1, "username": "principal", "role": "superadmin", "mfa": True, "disabled": False, "locked": False,
                    "created_at": iso(now), "phone": "+919800000000", "email": ""}],
    "/api/users/invites": [{"id": 3, "kind": "invite", "role": "operator", "email": "hod@college.example", "phone": "", "note": "HOD " + XSS,
                            "created_by": "principal", "created_at": iso(now), "expires_at": iso(now + dt.timedelta(days=3)),
                            "used_by": "", "used_at": None, "state": "pending"}],
    "/api/antispoof/status": {"settings": {"variant": "int8", "threshold": 0.5, "frames": 3}, "loaded": True, "provider": "CPU",
                              "cpu": "Test CPU | 8 threads", "gpu": None, "error": None, "source_commit": "2f8dd93dd0fd9d120f08e83d9020719f67ffdb68",
                              "license": "Apache-2.0", "models": {},
                              "metrics": {"release": "98.20", "dataset": "CelebA-Spoof", "overall_accuracy": 98.2, "real_accuracy": 97.58,
                                          "spoof_accuracy": 98.73, "roc_auc": 0.9984, "trained_attacks": "prints, screens", "not_trained": "3D masks"}},
}
SNAP = cv2.imencode(".jpg", np.full((180, 320, 3), 90, np.uint8))[1].tobytes()
CSP = ("default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self' ws://127.0.0.1:%d; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'" % PORT)


class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def end_headers(self):
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Permissions-Policy", "camera=(self), microphone=(), geolocation=()")
        super().end_headers()

    def _send(self, code, body, ct="application/json"):
        b = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/__role":
            STATE["role"] = self.path.split("r=")[1]
            return self._send(200, {"ok": True})
        if p == "/__posts":
            return self._send(200, STATE["posts"])
        if p == "/__setup":
            STATE["setup"] = self.path.endswith("=1")
            return self._send(200, {"ok": True})
        if p == "/api/setup/status":
            return self._send(200, {"needs_setup": STATE["setup"]})
        if p == "/api/auth/me" and STATE["role"] == "none":
            return self._send(401, {"detail": "Not authenticated"})
        if p == "/api/auth/me":
            return self._send(200, {"user": {"id": 1, "username": f"test-{STATE['role']}", "role": STATE["role"], "mfa": True}, "csrf": "c"})
        if p.endswith("/snapshot") or p.endswith("/evidence") or p.endswith("/image"):
            return self._send(200, SNAP, "image/jpeg")
        if p in R:
            return self._send(200, R[p])
        if p.startswith("/api"):
            return self._send(200, [])
        if p == "/" or not os.path.exists(os.path.join(WEB, p.lstrip("/"))):
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        p = self.path.split("?")[0]
        rec_ = {"path": p, "csrf": self.headers.get("X-CSRF-Token"), "size": n}
        if self.headers.get("Content-Type", "").startswith("application/json"):
            rec_["body"] = json.loads(body or b"{}")
        else:
            rec_["frames"] = body.count(b'name="frames"')
        STATE["posts"].append(rec_)
        mfa = {"mfa_setup_required": True, "secret": "TESTSECRETTESTSECRET", "setup_token": "st", "username": "u",  # scan:allow mock
               "qr": "data:image/png;base64," + __import__("base64").b64encode(SNAP).decode()}
        if p == "/api/setup/register":
            return self._send(200, mfa) if rec_.get("body", {}).get("setup_code") == "GOOD-CODE-0000-0000" else self._send(401, {"detail": "Setup code is not valid"})
        if p == "/api/auth/mfa/enroll":
            STATE["role"] = "superadmin"
            return self._send(200, {"user": {"id": 1, "username": "principal", "role": "superadmin", "mfa": True}, "csrf": "c"})
        if p == "/api/register/check":
            code = rec_["body"]["code"]
            if code.startswith("bad"):
                return self._send(404, {"detail": "This link is invalid, used or expired; ask for a new one"})
            return self._send(200, {"kind": "reset" if code.startswith("reset") else "invite", "role": "operator", "email": "",
                                    "expires_at": iso(now + dt.timedelta(days=1)), "username": "hod" if code.startswith("reset") else ""})
        if p == "/api/register":
            return self._send(200, {"ok": True, "message": "Password set. Sign in."} if "username" not in rec_["body"] else mfa)
        if p == "/api/users/invites":
            return self._send(200, {"id": 9, "token": "t" * 43, "path": "/#/register?code=" + "t" * 43, "kind": "invite",
                                    "role": rec_["body"]["role"], "expires_at": iso(now + dt.timedelta(days=3))})
        if p == "/api/vault/setup":
            return self._send(200, {"fingerprint": "AAAA-BBBB", "recovery_code": "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567"})  # scan:allow mock
        if p == "/api/kiosk/challenge":
            return self._send(200, {"id": "c1", "steps": ["left", "up", "right"], "prompts": [], "fps": 8, "seconds_per_step": 2.4})
        if p == "/api/kiosk/verify":
            return self._send(200, {"ok": True, "code": "21CS045", "name": "Priya", "status": "present", "time": "08:52", "already": False,
                                    "antispoof": {"frames": 30, "real_frames": 30}})
        if p == "/api/antispoof/check":
            return self._send(200, {"width": 320, "height": 180, "faces": [
                {"box": [0.1, 0.2, 0.2, 0.4], "status": "real", "logit_diff": 5.1}, {"box": [0.6, 0.2, 0.2, 0.4], "status": "spoof", "logit_diff": -3.2}]})
        if p.startswith("/api/recordings/") and p.endswith("/export"):
            return self._send(200, b"\x00" * 64, "video/mp4")
        return self._send(200, {"ok": True})

    def do_PUT(self):
        self.do_POST()

    def do_DELETE(self):
        STATE["posts"].append({"path": self.path.split("?")[0], "csrf": self.headers.get("X-CSRF-Token"), "method": "DELETE"})
        return self._send(200, {"ok": True})


http.server.ThreadingHTTPServer(("127.0.0.1", PORT), functools.partial(H, directory=WEB)).serve_forever()
