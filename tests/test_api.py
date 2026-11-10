"""FN / AB / CY: the real FastAPI application in laptop mode (TestClient, temporary SQLite + store).

Runs wherever the app's dependencies are installed (python run.py --selftest uses the app's own
virtualenv). Tests share one application instance and run in file order.
"""
import base64
import datetime as dt
import json
import os
import time

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")
pytest.importorskip("jwt")

import cv2  # noqa: E402
import numpy as np  # noqa: E402

from conftest import AS_DIR, DET, REC, ROOT  # noqa: E402

SU_NAME = "principal"
SU_PW = "Gate-Ledger-Test-" + os.urandom(6).hex()  # must not contain the username (policy)  # generated per run; nothing is shipped
VAULT_PW = "api test vault passphrase 2026"
S: dict = {}


# ------------------------------------------------------------------ harness
@pytest.fixture(scope="module")
def app_env(tmp_path_factory):
    d = tmp_path_factory.mktemp("api")
    from cryptography.fernet import Fernet
    os.environ.update({
        "VMS_DATABASE_URL": f"sqlite:///{(d / 'vms.db').as_posix()}", "VMS_SECRET_KEY": os.urandom(32).hex(),
        "VMS_FERNET_KEY": Fernet.generate_key().decode(), "VMS_INTERNAL_TOKEN": "internal-" + os.urandom(16).hex(),
        "VMS_MEDIA_KEY": base64.b64encode(os.urandom(32)).decode(), "VMS_COOKIE_SECURE": "false",
        "VMS_SNAPSHOT_DIR": str(d / "snap"), "VMS_STORE_DIR": str(d / "store"), "VMS_SETUP_CODE_FILE": str(d / "setup-code.txt"),
        "VMS_MEDIAMTX_API": "http://127.0.0.1:9", "VMS_WEB_DIR": str(ROOT / "web"), "VMS_TZ": "Asia/Kolkata",
        "VMS_FACE_DET_MODEL": str(DET), "VMS_FACE_REC_MODEL": str(REC), "VMS_ANTISPOOF_DIR": str(AS_DIR),
        "VMS_UNBLUR_TTL_MINUTES": "15"})
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app, raise_server_exceptions=False) as c:
        yield {"app": app, "client": c, "dir": d, "internal": os.environ["VMS_INTERNAL_TOKEN"]}


class Acct:
    def __init__(self, env, username, password):
        from fastapi.testclient import TestClient
        self.env, self.username, self.password = env, username, password
        self.c = TestClient(env["app"], raise_server_exceptions=False)
        self.secret, self.last, self.csrf, self.id = "", -10, "", None

    def next_code(self):
        from app.hardening import hotp
        cur = int(time.time() // 30)
        step = max(self.last + 1, cur - 1)
        if step > cur + 1:
            time.sleep(max(0, (step - 1) * 30 - time.time()) + 0.5)
        self.last = step
        return hotp(self.secret, step)

    def enrol(self, d):
        """Complete MFA enrolment from a registration / setup response."""
        assert d.get("mfa_setup_required"), d
        self.secret = d["secret"]
        r = self.c.post("/api/auth/mfa/enroll", json={"setup_token": d["setup_token"], "totp": self.next_code()})
        assert r.status_code == 200, r.text
        self.csrf, self.id = r.json()["csrf"], r.json()["user"]["id"]
        return r

    def login(self):
        from app import security
        security._hits.clear()
        r = self.c.post("/api/auth/login", json={"username": self.username, "password": self.password,
                                                 "totp": self.next_code() if self.secret else ""})
        d = r.json()
        if d.get("mfa_setup_required"):
            self.secret = d["secret"]
            r = self.c.post("/api/auth/mfa/enroll", json={"setup_token": d["setup_token"], "totp": self.next_code()})
        assert r.status_code == 200, r.text
        self.csrf, self.id = r.json()["csrf"], r.json()["user"]["id"]
        return r

    def h(self):
        return {"X-CSRF-Token": self.csrf}

    def get(self, p, **kw):
        return self.c.get(p, **kw)

    def post(self, p, **kw):
        return self.c.post(p, headers={**self.h(), **kw.pop("headers", {})}, **kw)

    def put(self, p, **kw):
        return self.c.put(p, headers=self.h(), **kw)

    def patch(self, p, **kw):
        return self.c.patch(p, headers=self.h(), **kw)

    def delete(self, p, **kw):
        return self.c.delete(p, headers=self.h(), **kw)


@pytest.fixture(scope="module")
def su(app_env):
    """The first super admin registers through the first-run setup (no built-in account exists)."""
    c = app_env["client"]
    S["setup_before"] = c.get("/api/setup/status").json()
    code_file = app_env["dir"] / "setup-code.txt"
    S["code_file_mode"] = oct(code_file.stat().st_mode & 0o777) if code_file.exists() else None
    code = code_file.read_text().strip()
    S["wrong_code"] = c.post("/api/setup/register", json={"setup_code": "AAAA-BBBB-CCCC-DDDD", "username": SU_NAME,
                                                           "password": SU_PW}).status_code
    S["weak_setup"] = c.post("/api/setup/register", json={"setup_code": code, "username": SU_NAME,
                                                           "password": "password123"}).status_code
    a = Acct(app_env, SU_NAME, SU_PW)
    r = a.c.post("/api/setup/register", json={"setup_code": code, "username": SU_NAME, "password": SU_PW,
                                               "email": "principal@college.example"})
    assert r.status_code == 200, r.text
    S["setup_reply"] = r.json()
    S["boot_cookie"] = a.enrol(r.json()).headers.get("set-cookie", "")
    S["setup_code"] = code
    return a


def invite(inviter, role, **kw):
    r = inviter.post("/api/users/invites", json={"role": role, **kw})
    assert r.status_code == 200, r.text
    return r.json()


def redeem(env, link, name, password=None, expect=200):
    from app import security
    security._hits.clear()
    a = Acct(env, name, password or ("Tt9!" + os.urandom(9).hex()))
    r = a.c.post("/api/register", json={"code": link["token"], "username": name, "password": a.password})
    assert r.status_code == expect, r.text
    if expect == 200:
        a.enrol(r.json())
    return a


def make_user(env, su, name, role):
    """Invitation -> the invitee picks their own password -> mandatory MFA enrolment."""
    return redeem(env, invite(su, role), name)


@pytest.fixture(scope="module")
def users(app_env, su):
    return {r: make_user(app_env, su, f"t_{r}", r) for r in ("kiosk", "viewer", "operator", "admin")}


def internal(env):
    return {"X-Internal-Token": env["internal"]}


def notes(su, kind):
    return [n for n in su.get("/api/notifications?limit=500").json()["items"] if n["kind"] == kind]


def jpg(w=320, h=240, val=120):
    return cv2.imencode(".jpg", np.full((h, w, 3), val, np.uint8))[1].tobytes()


def unit(seed):
    v = np.random.default_rng(seed).normal(size=128).astype(np.float32)
    return v / np.linalg.norm(v)


def set_template(pid, vec):
    from app import facesvc, models
    from app.db import SessionLocal
    db = SessionLocal()
    facesvc.set_templates(db.get(models.Person, pid), [vec], "live")
    db.commit()
    db.close()


# ================================================================= FUNCTIONAL
def test_FN_01_first_run_setup(app_env, su):
    """First run: no account exists; the one-time setup code (0600 file) registers the super admin + MFA."""
    assert S["setup_before"] == {"needs_setup": True}
    assert S["code_file_mode"] == "0o600" or os.name == "nt"
    assert S["wrong_code"] == 401 and S["weak_setup"] == 422
    d = S["setup_reply"]
    assert d["mfa_setup_required"] and d["qr"].startswith("data:image/png;base64,") and len(d["secret"]) >= 32
    assert su.get("/api/auth/me").json()["user"]["role"] == "superadmin"
    assert app_env["client"].get("/api/setup/status").json() == {"needs_setup": False}
    assert not (app_env["dir"] / "setup-code.txt").exists()  # code destroyed after use


def test_FN_02_session_cookie_flags(su):
    """Session cookie is HttpOnly + SameSite=Strict with a bounded lifetime."""
    sc = S["boot_cookie"].lower()
    assert "httponly" in sc and "samesite=strict" in sc and "max-age=1800" in sc and "path=/" in sc


def test_FN_03_me_refresh_logout(app_env, su):
    """/me returns the user; refresh extends the session; logout ends it."""
    assert su.get("/api/auth/me").json()["user"]["username"] == SU_NAME
    assert su.post("/api/auth/refresh").status_code == 200
    tmp = make_user(app_env, su, "t_logout", "viewer")
    assert tmp.post("/api/auth/logout").status_code == 200
    assert tmp.get("/api/auth/me").status_code == 401


def test_FN_04_users_all_roles(users):
    """Users of every role join by invitation, choose their own password and must enrol MFA."""
    assert all(u.secret for u in users.values())


def test_FN_05_camera_crud(su, users):
    """Camera create / list / detail (password masked) / validation / delete."""
    r = su.post("/api/cameras", json={"name": "Gate", "main_url": "rtsp://cam:SuperSecretCamPw@10.0.0.5:554/s1", "attendance": True})  # scan:allow fake camera credential (encryption-at-rest test)
    assert r.status_code == 200 and "SuperSecretCamPw" not in r.text and "•••" in r.json()["main_url"]
    S["cam"] = r.json()["id"]
    assert any(c["id"] == S["cam"] for c in users["viewer"].get("/api/cameras").json())
    assert su.post("/api/cameras", json={"name": "Bad", "main_url": "http://10.0.0.6/video"}).status_code == 422
    tmp = su.post("/api/cameras", json={"name": "Tmp", "main_url": "rtsp://10.0.0.7/s"}).json()["id"]
    assert su.delete(f"/api/cameras/{tmp}").status_code == 200


def test_FN_06_stream_token_blurred_only(users):
    """Stream tokens are issued only for the face-blurred path."""
    import jwt
    r = users["viewer"].post("/api/streams/token", json={"camera_id": S["cam"]}).json()
    claims = jwt.decode(r["token"], os.environ["VMS_SECRET_KEY"], algorithms=["HS256"])
    assert r["path"] == f"cam{S['cam']}_priv" and claims["path"] == r["path"] and claims["act"] == "read"


def test_FN_07_people_and_consent(su):
    """People: create; under-18 needs guardian consent; duplicate roll number refused; update."""
    base = {"code": "21CS045", "name": "Priya R", "kind": "student", "department": "CSE", "section": "III-A", "consent_ref": "CF-001"}
    r = su.post("/api/persons", json=base)
    assert r.status_code == 200
    S["p1"] = r.json()["id"]
    assert su.post("/api/persons", json={**base, "code": "24ME012", "is_minor": True}).status_code == 422
    r = su.post("/api/persons", json={**base, "code": "24ME012", "name": "Divya M", "is_minor": True, "guardian_consent_ref": "GC-9"})
    S["p2"] = r.json()["id"]
    assert su.post("/api/persons", json=base).status_code == 409
    assert su.put(f"/api/persons/{S['p1']}", json={**base, "section": "III-B"}).json()["section"] == "III-B"
    r = su.post("/api/persons", json={**base, "code": "STF-1", "name": "=HYPERLINK(\"http://evil\",\"x\")", "kind": "staff"})
    S["p3"] = r.json()["id"]


def test_FN_08_vault_setup(su):
    """Vault set-up (super admin + MFA) returns a one-time recovery code; a second set-up is refused."""
    r = su.post("/api/vault/setup", json={"passphrase": VAULT_PW, "totp": su.next_code()})
    assert r.status_code == 200, r.text
    S["recovery"] = r.json()["recovery_code"]
    assert su.get("/api/vault").json()["configured"]
    assert su.post("/api/vault/setup", json={"passphrase": VAULT_PW, "totp": su.next_code()}).status_code == 409


def test_FN_09_cctv_attendance(app_env, su):
    """CCTV ingest: two agreeing samples + liveness -> present/late; no liveness -> review; one sample -> ignored."""
    import vmscrypto as C
    set_template(S["p1"], unit(1))
    set_template(S["p2"], unit(2))
    pub = base64.b64decode(su.c.get("/internal/vault/pubkey", headers=internal(app_env)).json()["public_key"])
    sealed = C.encrypt_bytes(jpg(160, 200, 90), recipient_pub=pub)
    noisy = lambda s: (unit(s) + np.random.default_rng(9).normal(scale=0.05, size=128)).tolist()  # noqa: E731
    data = {"camera_id": S["cam"], "embeddings": [noisy(1), noisy(1)], "liveness": {"ok": True}}
    r = su.c.post("/internal/attendance", headers=internal(app_env), data={"data": json.dumps(data)},
                  files={"blurred": ("b.jpg", jpg(), "image/jpeg"), "sealed": ("r.svms", sealed, "application/octet-stream")})
    assert r.json()["matched"] and r.json()["new"]
    S["rec1"] = r.json()["record"]
    data = {"camera_id": S["cam"], "embeddings": [noisy(2), noisy(2)], "liveness": {"ok": False}}
    S["rec2"] = su.c.post("/internal/attendance", headers=internal(app_env), data={"data": json.dumps(data)}).json()["record"]
    one = {"camera_id": S["cam"], "embeddings": [noisy(1)], "liveness": {"ok": True}}
    assert su.c.post("/internal/attendance", headers=internal(app_env), data={"data": json.dumps(one)}).json()["matched"] is False
    stranger = {"camera_id": S["cam"], "embeddings": [unit(77).tolist(), unit(77).tolist()], "liveness": {"ok": True}}
    assert su.c.post("/internal/attendance", headers=internal(app_env), data={"data": json.dumps(stranger)}).json()["matched"] is False


def test_FN_10_attendance_day(users):
    """Day view: statuses and counts include absentees."""
    d = users["operator"].get("/api/attendance/day").json()
    st = {r["person"]["code"]: r["status"] for r in d["rows"]}
    assert st["21CS045"] in ("present", "late") and st["24ME012"] == "review" and st["STF-1"] == "absent"
    assert d["counts"]["absent"] >= 1 and d["total"] == 3


def test_FN_11_review_and_manual(su):
    """Admin approves a review record; manual marks require a note and raise an alert."""
    assert su.post(f"/api/attendance/records/{S['rec2']}/review", json={"action": "approve"}).json()["status"] in ("present", "late")
    day = dt.date.today().isoformat()
    assert su.post("/api/attendance/manual", json={"person_id": S["p3"], "day": day, "status": "present"}).status_code == 422
    assert su.post("/api/attendance/manual", json={"person_id": S["p3"], "day": day, "status": "present", "note": "on duty"}).status_code == 200
    assert notes(su, "attendance_manual")


def test_FN_12_csv_export(su):
    """CSV export: header, marks and an alert; formula-looking names neutralised (D-08)."""
    day = dt.date.today().isoformat()
    r = su.get(f"/api/attendance/export.csv?start={day}&end={day}")
    assert r.status_code == 200 and r.text.lstrip("﻿").startswith("code,name,type")
    assert "'=HYPERLINK" in r.text and ",=HYPERLINK" not in r.text
    assert notes(su, "attendance_export")
    assert su.get(f"/api/attendance/export.csv?start={day}&end=2020-01-01").status_code == 422


def test_FN_13_evidence_blurred_and_encrypted(app_env, users):
    """Attendance evidence is served to operators and stored encrypted (not a JPEG on disk)."""
    r = users["operator"].get(f"/api/attendance/records/{S['rec1']}/evidence")
    assert r.status_code == 200 and r.content[:2] == b"\xff\xd8"
    files = list((app_env["dir"] / "store" / "evidence").rglob("*.svms"))
    assert files and all(f.read_bytes()[4:9] == b"SVMS1" for f in files)


def test_FN_14_recordings(app_env, su, users):
    """Encrypted recording segment: indexed, listed by local day, streamed with HTTP Range."""
    import vmscrypto as C
    mk = base64.b64decode(os.environ["VMS_MEDIA_KEY"])
    rel = "rec/cam1/priv/test/seg.svms"
    p = app_env["dir"] / "store" / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    import shutil
    import subprocess
    if shutil.which("ffmpeg"):  # a real (blurred-stream-like) fragmented MP4 so export can transcode it
        video = subprocess.run(["ffmpeg", "-v", "error", "-f", "lavfi", "-i", "testsrc2=size=320x240:rate=10", "-t", "3",
                                "-c:v", "libx264", "-g", "10", "-f", "mp4", "-movflags", "frag_keyframe+empty_moov+default_base_moof",
                                "pipe:1"], capture_output=True, check=True).stdout
    else:
        video = b"\x00\x00\x00\x18ftypisom" + os.urandom(5000)
    S["real_video"] = bool(shutil.which("ffmpeg"))
    p.write_bytes(C.encrypt_bytes(video, media_key=mk))
    now = dt.datetime.now(dt.timezone.utc)
    body = {"camera_id": S["cam"], "kind": "priv", "path": rel, "start": (now - dt.timedelta(minutes=5)).isoformat(),
            "end": now.isoformat(), "size": p.stat().st_size}
    assert su.c.post("/internal/segments", headers=internal(app_env), json=body).status_code == 200
    from zoneinfo import ZoneInfo
    day = now.astimezone(ZoneInfo("Asia/Kolkata")).date().isoformat()
    segs = users["viewer"].get(f"/api/recordings?camera_id={S['cam']}&day={day}").json()
    assert segs
    S["seg"] = segs[0]["id"]
    full = users["viewer"].get(f"/api/recordings/{S['seg']}/media")
    part = users["viewer"].get(f"/api/recordings/{S['seg']}/media", headers={"Range": "bytes=0-99"})
    assert full.status_code == 200 and part.status_code == 206 and len(part.content) == 100 and part.content == full.content[:100]


def test_FN_15_unblur_lifecycle(app_env, su, users):
    """Request -> super admin approves (MFA + passphrase) -> requester views face -> others refused -> expiry."""
    op = users["operator"]
    r = op.post("/api/unblur", json={"attendance_id": S["rec1"], "reason": "Verifying a disputed attendance record"})
    assert r.status_code == 200 and r.json()["status"] == "pending"
    S["req"] = r.json()["id"]
    assert notes(su, "unblur_requested")
    r = su.post(f"/api/unblur/{S['req']}/approve", json={"totp": su.next_code(), "passphrase": VAULT_PW})
    assert r.status_code == 200, r.text
    for _ in range(40):
        st = [x for x in op.get("/api/unblur").json() if x["id"] == S["req"]][0]
        if st["status"] in ("ready", "failed"):
            break
        time.sleep(0.5)
    assert st["status"] == "ready" and st["has_image"], st
    img = op.get(f"/api/unblur/{S['req']}/image")
    assert img.status_code == 200 and img.content[:2] == b"\xff\xd8"
    assert users["admin"].get(f"/api/unblur/{S['req']}/image").status_code == 403
    assert notes(su, "unblur_approved")
    from app import models
    from app.db import SessionLocal
    from app.routes_privacy import purge_unblur
    db = SessionLocal()
    db.get(models.UnblurRequest, S["req"]).expires_at = models.now() - dt.timedelta(seconds=1)
    db.commit()
    purge_unblur(db)
    db.close()
    assert op.get(f"/api/unblur/{S['req']}/image").status_code == 410


def test_FN_16_notifications(su):
    """Security alerts are listed with unread counts and can be marked read."""
    n = su.get("/api/notifications").json()
    assert n["unread"] >= 1
    su.post("/api/notifications/read")
    assert su.get("/api/notifications").json()["unread"] == 0


def test_FN_17_antispoof_admin(su, users):
    """Anti-spoof: status for operators; settings for admins (alerted); image check never stores data."""
    st = users["operator"].get("/api/antispoof/status").json()
    assert st["metrics"]["release"] == "98.20" and st["settings"]["variant"] == "int8"
    r = su.put("/api/antispoof/settings", json={"variant": "fp32", "threshold": 0.8, "frames": 5})
    assert r.status_code == 200 and r.json() == {"variant": "fp32", "threshold": 0.8, "frames": 5}
    assert notes(su, "antispoof_settings_changed")
    su.put("/api/antispoof/settings", json={"variant": "int8", "threshold": 0.5, "frames": 3})
    if DET.exists():
        r = users["operator"].post("/api/antispoof/check", files={"image": ("x.jpg", jpg(), "image/jpeg")})
        assert r.status_code == 200 and r.json()["faces"] == []
    b = su.post("/api/antispoof/benchmark").json()
    assert b["size_gate_60pct"] is True


def test_FN_18_events_snapshot_encrypted(app_env, users):
    """Event snapshots are encrypted at rest (.svms) and served decrypted to viewers."""
    data = {"camera_id": S["cam"], "kind": "object", "label": "person", "confidence": 0.9}
    r = users["viewer"].c.post("/internal/events", headers=internal(app_env), data={"data": json.dumps(data)},
                               files={"image": ("s.jpg", jpg(), "image/jpeg")})
    eid = r.json()["id"]
    snaps = list((app_env["dir"] / "snap").rglob("*"))
    assert any(s.suffix == ".svms" for s in snaps) and not any(s.suffix == ".jpg" for s in snaps)
    assert users["viewer"].get(f"/api/events/{eid}/snapshot").content[:2] == b"\xff\xd8"


def test_FN_19_kiosk_challenge(users):
    """Kiosk challenge: 3 moves, no immediate repeats, single use."""
    c = users["kiosk"].post("/api/kiosk/challenge", json={"purpose": "attend"}).json()
    assert len(c["steps"]) == 3 and all(a != b for a, b in zip(c["steps"], c["steps"][1:]))


def test_FN_20_schema_upgrade(tmp_path):
    """A database from the previous release (no phone/email/attendance columns) is upgraded in place."""
    import sqlalchemy as sa
    from app import main
    eng = sa.create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with eng.begin() as c:
        c.execute(sa.text("CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR(64))"))
        c.execute(sa.text("CREATE TABLE cameras (id INTEGER PRIMARY KEY, name VARCHAR(120))"))
    old, main.engine = main.engine, eng
    try:
        main.upgrade_schema()
    finally:
        main.engine = old
    cols = {c["name"] for c in sa.inspect(eng).get_columns("users")} | {c["name"] for c in sa.inspect(eng).get_columns("cameras")}
    assert {"phone", "email", "attendance"} <= cols


def test_FN_21_health(app_env):
    """Health endpoint answers without authentication."""
    assert app_env["client"].get("/api/health").json() == {"ok": True}


# ================================================================= ABUSE
@pytest.mark.parametrize("r", ["viewer", "operator", "admin"])
def test_AB_01_export_blocked_and_reported(su, users, r):
    """Non-super-admins cannot export video; every attempt is blocked AND reported."""
    before = len(notes(su, "export_denied"))
    res = users[r].post(f"/api/recordings/{S['seg']}/export", json={"totp": "000000", "reason": "trying"})
    assert res.status_code == 403 and len(notes(su, "export_denied")) == before + 1


def test_AB_02_snapshot_blocked_and_reported(su, users):
    """Live snapshots by non-super-admins are blocked and reported."""
    before = len(notes(su, "export_denied"))
    assert users["admin"].post("/api/audit/client-snapshot", json={"camera_id": S["cam"]}).status_code == 403
    assert len(notes(su, "export_denied")) == before + 1


def test_AB_03_viewer_and_kiosk_cannot_request_unblur(su, users):
    """Viewers and kiosks cannot request unblurring; attempts are reported."""
    before = len(notes(su, "unblur_denied"))
    for r in ("viewer", "kiosk"):
        assert users[r].post("/api/unblur", json={"attendance_id": S["rec1"], "reason": "curious about this person"}).status_code == 403
    assert len(notes(su, "unblur_denied")) == before + 2


def test_AB_04_admin_cannot_approve(su, users):
    """Admins cannot approve unblur requests (super admin only); attempt is reported."""
    r = users["operator"].post("/api/unblur", json={"attendance_id": S["rec1"], "reason": "second request for testing"})
    S["req2"] = r.json()["id"]
    before = len(notes(su, "unblur_denied"))
    assert users["admin"].post(f"/api/unblur/{S['req2']}/approve", json={"totp": "123456", "passphrase": VAULT_PW}).status_code == 403
    assert len(notes(su, "unblur_denied")) == before + 1


def test_AB_05_wrong_passphrase(su):
    """Approval with a wrong vault passphrase fails, is reported, and the request stays pending."""
    before = len(notes(su, "vault_unlock_failed"))
    r = su.post(f"/api/unblur/{S['req2']}/approve", json={"totp": su.next_code(), "passphrase": "wrong wrong wrong wrong"})
    assert r.status_code == 401 and len(notes(su, "vault_unlock_failed")) == before + 1
    assert [x for x in su.get("/api/unblur").json() if x["id"] == S["req2"]][0]["status"] == "pending"


def test_AB_06_wrong_or_replayed_totp(su):
    """Approval with a wrong or replayed authenticator code fails and is reported."""
    before = len(notes(su, "unblur_approval_mfa_failed"))
    from app.hardening import hotp
    replay = hotp(su.secret, su.last)  # the last code the super admin used
    assert su.post(f"/api/unblur/{S['req2']}/approve", json={"totp": replay, "passphrase": VAULT_PW}).status_code == 401
    assert su.post(f"/api/unblur/{S['req2']}/approve", json={"totp": "000000", "passphrase": VAULT_PW}).status_code == 401
    assert len(notes(su, "unblur_approval_mfa_failed")) >= before + 2


def test_AB_07_admin_cannot_touch_superadmins(su, users):
    """Admins cannot create, modify, reset or delete super admin accounts (privilege escalation)."""
    adm = users["admin"]
    assert adm.post("/api/users/invites", json={"role": "superadmin"}).status_code == 403
    assert adm.post("/api/users/invites", json={"role": "admin"}).status_code == 403
    assert adm.patch(f"/api/users/{users['viewer'].id}", json={"role": "superadmin"}).status_code == 403
    for body in ({"reset_mfa": True}, {"reset_password": True}, {"disabled": True}, {"role": "viewer"}):
        assert adm.patch(f"/api/users/{su.id}", json=body).status_code == 403
    assert adm.delete(f"/api/users/{su.id}").status_code == 403


def test_AB_08_last_superadmin_protected(su):
    """The last super admin cannot be demoted, disabled or deleted (vault lock-out prevention)."""
    assert su.patch(f"/api/users/{su.id}", json={"role": "admin"}).status_code == 400
    assert su.patch(f"/api/users/{su.id}", json={"disabled": True}).status_code == 400


def test_AB_09_operator_csv_export_blocked(su, users):
    """Operators cannot export attendance data; the attempt is reported."""
    before = len(notes(su, "export_denied"))
    day = dt.date.today().isoformat()
    assert users["operator"].get(f"/api/attendance/export.csv?start={day}&end={day}").status_code == 403
    assert len(notes(su, "export_denied")) == before + 1


def test_AB_10_kiosk_least_privilege(users):
    """Kiosk accounts reach only the kiosk endpoints; enrolment needs an admin."""
    k = users["kiosk"]
    for p in ("/api/cameras", "/api/persons", "/api/attendance/day", "/api/events", "/api/recordings?camera_id=1&day=2026-01-01"):
        assert k.get(p).status_code == 403, p
    assert k.post("/api/kiosk/challenge", json={"purpose": "enroll", "person_id": S["p1"]}).status_code == 403


def test_AB_11_kiosk_challenge_abuse(users):
    """Challenges are single-use, bound to the issuing account, and frame counts are enforced."""
    k, op = users["kiosk"], users["operator"]
    ch = k.post("/api/kiosk/challenge", json={"purpose": "attend"}).json()["id"]
    frames = [("frames", (f"f{i}.jpg", jpg(), "image/jpeg")) for i in range(10)]
    assert op.post("/api/kiosk/verify", data={"challenge_id": ch}, files=frames).status_code == 410  # other account
    ch = k.post("/api/kiosk/challenge", json={"purpose": "attend"}).json()["id"]
    first = k.post("/api/kiosk/verify", data={"challenge_id": ch}, files=frames)
    assert first.status_code in (200, 503)
    assert k.post("/api/kiosk/verify", data={"challenge_id": ch}, files=frames).status_code == 410  # reuse
    ch = k.post("/api/kiosk/challenge", json={"purpose": "attend"}).json()["id"]
    assert k.post("/api/kiosk/verify", data={"challenge_id": ch}, files=frames[:5]).status_code == 422


def test_AB_12_kiosk_bad_and_bomb_frames(users):
    """Non-image frames and decompression bombs are rejected before decoding (D-12)."""
    import io

    from PIL import Image
    k = users["kiosk"]
    buf = io.BytesIO()
    Image.new("RGB", (6000, 6000), (9, 9, 9)).save(buf, "JPEG", quality=5)
    for bad in (b"not an image", buf.getvalue()):
        ch = k.post("/api/kiosk/challenge", json={"purpose": "attend"}).json()["id"]
        frames = [("frames", ("f.jpg", bad, "image/jpeg"))] + [("frames", (f"f{i}.jpg", jpg(), "image/jpeg")) for i in range(10)]
        assert k.post("/api/kiosk/verify", data={"challenge_id": ch}, files=frames).status_code in (413, 422)


def test_AB_13_stepup_bruteforce_limited(app_env, su):
    """Repeated wrong MFA codes on a sensitive action are rate-limited (5 per 15 min)."""
    sa2 = make_user(app_env, su, "t_super2", "superadmin")
    codes = [sa2.post(f"/api/recordings/{S['seg']}/export", json={"totp": "000000", "reason": "brute force test"}).status_code
             for _ in range(6)]
    assert codes[:5] == [401] * 5 and codes[5] == 429


def test_AB_14_antispoof_weakening_alerted(su):
    """Weakening anti-spoof settings raises a HIGH alert; out-of-range values are refused."""
    assert su.put("/api/antispoof/settings", json={"variant": "int8", "threshold": 0.2, "frames": 3}).status_code == 422
    assert su.put("/api/antispoof/settings", json={"variant": "int8", "threshold": 0.5, "frames": 6}).status_code == 422
    su.put("/api/antispoof/settings", json={"variant": "int8", "threshold": 0.4, "frames": 3})
    assert any("WEAKER" in n["message"] and n["severity"] == "high" for n in notes(su, "antispoof_settings_changed"))
    su.put("/api/antispoof/settings", json={"variant": "int8", "threshold": 0.5, "frames": 3})


def test_AB_15_withdrawn_consent_stops_matching(app_env, su):
    """Erasing a person's biometrics stops recognition immediately (consent withdrawal)."""
    assert su.delete(f"/api/persons/{S['p2']}?mode=biometrics").status_code == 200
    data = {"camera_id": S["cam"], "embeddings": [unit(2).tolist(), unit(2).tolist()], "liveness": {"ok": True}}
    assert su.c.post("/internal/attendance", headers=internal(app_env), data={"data": json.dumps(data)}).json()["matched"] is False


def test_AB_16_unblur_reason_required(users):
    """Unblur requests need a meaningful reason (>= 10 chars)."""
    assert users["operator"].post("/api/unblur", json={"attendance_id": S["rec1"], "reason": "x"}).status_code == 422


# ================================================================= CYBER
OPEN = {"/api/health", "/api/auth/login", "/api/auth/mfa/enroll",  # public by design; each is token- or code-gated:
        "/api/setup/status", "/api/setup/register", "/api/register/check", "/api/register"}


def test_CY_01_every_api_route_requires_auth(app_env):
    """Unauthenticated sweep of every /api route: nothing is served without a session."""
    from fastapi.testclient import TestClient
    from starlette.routing import Route
    anon = TestClient(app_env["app"], raise_server_exceptions=False)
    served = []
    for r in app_env["app"].routes:
        if not isinstance(r, Route) or not r.path.startswith("/api") or r.path in OPEN:
            continue
        path = r.path.replace("{path:path}", "x")
        for k in ("rid", "sid", "eid", "cid", "pid", "uid", "wid", "iid"):
            path = path.replace("{" + k + "}", "1")
        for m in r.methods - {"HEAD"}:
            code = anon.request(m, path).status_code
            if code < 400 or code == 404:
                served.append((m, path, code))
    assert not served, served


def test_CY_02_csrf(users):
    """State-changing requests without / with a wrong CSRF token are refused."""
    op = users["operator"]
    assert op.c.post("/api/unblur", json={"attendance_id": S["rec1"], "reason": "no csrf header here"}).status_code == 403
    assert op.c.post("/api/unblur", headers={"X-CSRF-Token": "forged"},
                     json={"attendance_id": S["rec1"], "reason": "wrong csrf header here"}).status_code == 403


def test_CY_03_jwt_tampering(app_env, su):
    """Forged session tokens (wrong key, alg=none, expired, tampered) are rejected."""
    import jwt
    from fastapi.testclient import TestClient
    now = int(time.time())
    claims = {"typ": "session", "sub": str(su.id), "role": "superadmin", "csrf": "x", "pwv": 1, "auth_time": now, "iat": now, "exp": now + 600}
    forged = [jwt.encode(claims, "not-the-key-" * 4, algorithm="HS256"),
              jwt.encode(claims, None, algorithm="none") if "none" in jwt.algorithms.get_default_algorithms() else "x.y.z",
              jwt.encode({**claims, "exp": now - 10}, os.environ["VMS_SECRET_KEY"], algorithm="HS256")]
    good = su.c.cookies.get("vms_session")
    forged.append(good[:-3] + ("AAA" if not good.endswith("AAA") else "BBB"))
    for t in forged:
        c = TestClient(app_env["app"], raise_server_exceptions=False)
        c.cookies.set("vms_session", t)
        assert c.get("/api/auth/me").status_code == 401


def test_CY_04_token_type_confusion(app_env, users):
    """Stream tokens and MFA set-up tokens cannot be used as session cookies."""
    from fastapi.testclient import TestClient
    st = users["viewer"].post("/api/streams/token", json={"camera_id": S["cam"]}).json()["token"]
    c = TestClient(app_env["app"], raise_server_exceptions=False)
    c.cookies.set("vms_session", st)
    assert c.get("/api/auth/me").status_code == 401


def test_CY_05_session_revocation(app_env, su):
    """Role change, disabling and password change revoke existing sessions immediately."""
    v = make_user(app_env, su, "t_revoke", "operator")
    assert v.get("/api/auth/me").status_code == 200
    su.patch(f"/api/users/{v.id}", json={"role": "viewer"})
    assert v.get("/api/auth/me").status_code == 401
    v.login()
    su.patch(f"/api/users/{v.id}", json={"disabled": True})
    assert v.get("/api/auth/me").status_code == 401


def test_CY_06_lockout_and_rate_limit(app_env, su):
    """5 wrong passwords lock the account; >10 login attempts per IP in 5 min are throttled."""
    from app import security
    v = make_user(app_env, su, "t_lock", "viewer")
    security._hits.clear()
    for _ in range(5):
        assert v.c.post("/api/auth/login", json={"username": "t_lock", "password": "wrong"}).status_code == 401
    security._hits.clear()
    r = v.c.post("/api/auth/login", json={"username": "t_lock", "password": v.password, "totp": v.next_code()})
    assert r.status_code == 423
    security._hits.clear()
    codes = [v.c.post("/api/auth/login", json={"username": "nobody", "password": "x"}).status_code for _ in range(11)]
    assert codes[-1] == 429


def test_CY_07_no_username_enumeration(app_env):
    """Unknown user and wrong password produce identical responses."""
    from app import security
    security._hits.clear()
    a = app_env["client"].post("/api/auth/login", json={"username": "t_viewer", "password": "wrong-password"})
    b = app_env["client"].post("/api/auth/login", json={"username": "no_such_user_x", "password": "wrong-password"})
    assert (a.status_code, a.json()) == (b.status_code, b.json()) == (401, {"detail": "Invalid credentials"})


def test_CY_08_totp_replay_at_login(app_env, su):
    """A login code cannot be replayed for a second login (D-07)."""
    from app import security
    from app.hardening import hotp
    v = make_user(app_env, su, "t_replay", "viewer")
    used = hotp(v.secret, v.last)
    security._hits.clear()
    r = v.c.post("/api/auth/login", json={"username": "t_replay", "password": v.password, "totp": used})
    assert r.status_code == 401


def test_CY_09_internal_endpoints(app_env):
    """Internal endpoints need the internal token, and refuse any browser request (Origin header)."""
    c = app_env["client"]
    assert c.get("/internal/cameras").status_code == 401
    assert c.get("/internal/cameras", headers={"X-Internal-Token": "wrong"}).status_code == 401
    assert c.get("/internal/cameras", headers={**internal(app_env), "Origin": "http://evil.example"}).status_code == 404
    assert c.get("/internal/cameras", headers=internal(app_env)).status_code == 200


def test_CY_10_media_server_hook(app_env, users):
    """MediaMTX hook via the API: viewer token reads only the blurred path; no raw, publish or playback."""
    tok = users["viewer"].post("/api/streams/token", json={"camera_id": S["cam"]}).json()["token"]
    c, p = app_env["client"], f"cam{S['cam']}"
    hook = lambda **b: c.post("/internal/mediamtx-auth", json=b).status_code  # noqa: E731
    assert hook(action="read", path=f"{p}_priv", query=f"jwt={tok}") == 200
    assert hook(action="read", path=p, query=f"jwt={tok}") == 401
    assert hook(action="publish", path=f"{p}_priv", query=f"jwt={tok}") == 401
    assert hook(action="playback", path=f"{p}_priv", query=f"jwt={tok}") == 401
    assert hook(user="internal", password="guess", action="publish", path=p) == 401


def test_CY_11_path_traversal(app_env):
    """Path traversal in segment paths and stored file references is refused."""
    c = app_env["client"]
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    for bad in ("../../etc/passwd", "rec/../../../x.svms"):
        r = c.post("/internal/segments", headers=internal(app_env), json={"camera_id": 1, "kind": "priv", "path": bad, "start": now, "end": now})
        assert r.status_code == 422
    from app import facesvc
    with pytest.raises(ValueError):
        facesvc.read_file("../../../../etc/passwd")


def test_CY_12_injection_payloads(users):
    """SQL-injection style payloads in query parameters are handled as data."""
    op = users["operator"]
    assert op.get("/api/persons?q=' OR 1=1 --").json() == []
    assert op.get("/api/events?label=' OR '1'='1").json() == []
    assert op.get("/api/attendance/day?day=2026-01-01' OR 1=1").status_code == 422


def test_CY_13_security_headers(app_env):
    """CSP, framing, sniffing, referrer, permissions and robots headers are set on pages and API."""
    for p in ("/", "/api/health"):
        h = app_env["client"].get(p).headers
        assert "default-src 'self'" in h["content-security-policy"] and "frame-ancestors 'none'" in h["content-security-policy"]
        assert h["x-frame-options"] == "DENY" and h["x-content-type-options"] == "nosniff"
        assert h["referrer-policy"] == "no-referrer" and "camera=(self)" in h["permissions-policy"] and "noindex" in h["x-robots-tag"]


def test_CY_14_oversized_request(app_env):
    """Requests larger than 64 MiB are refused before parsing."""
    r = app_env["client"].post("/api/kiosk/verify", content=b"x" * (64 * 1024 * 1024 + 1), headers={"Content-Type": "application/octet-stream"})
    assert r.status_code == 413


def test_CY_15_no_error_leakage(app_env):
    """Unexpected errors return a generic message without stack traces."""
    r = app_env["client"].post("/internal/events", headers=internal(app_env), data={"data": "{not json"})
    assert r.status_code == 500 and r.json() == {"detail": "Internal error"} and "Traceback" not in r.text


def test_CY_16_websocket_origin_and_auth(app_env, users):
    """WebSocket refuses foreign origins (CSWSH) and anonymous clients."""
    from fastapi.testclient import TestClient
    for client, origin in ((users["viewer"].c, "http://evil.example"), (TestClient(app_env["app"]), "http://testserver")):
        with pytest.raises(Exception):
            with client.websocket_connect("/api/ws", headers={"origin": origin}) as ws:
                ws.receive_text()


def test_CY_17_secrets_encrypted_at_rest(app_env, su):
    """Camera passwords, face templates and the vault private key never appear in plaintext in the database."""
    raw = (app_env["dir"] / "vms.db").read_bytes()
    assert b"SuperSecretCamPw" not in raw
    from app import models
    from app.db import SessionLocal
    db = SessionLocal()
    p = db.get(models.Person, S["p1"])
    blob = bytes.fromhex(p.templates)
    assert blob[4:9] == b"SVMS1"
    with pytest.raises(Exception):
        json.loads(blob)  # not readable JSON / floats without the media key
    vault = json.loads(db.get(models.Setting, "vault").value)
    assert set(vault) == {"v", "public_key", "salt", "params", "wp", "wr"}  # private key only wrapped
    db.close()


def test_CY_18_password_hashing(app_env):
    """Passwords are Argon2id PHC (64 MiB, t=3, p=4); hashes from the previous release still verify."""
    from app import models, security
    from app.db import SessionLocal
    db = SessionLocal()
    h = db.query(models.User).filter_by(username=SU_NAME).one().pw_hash
    db.close()
    assert h.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    legacy = "$argon2id$v=19$m=65536,t=3,p=4$MIIRqgvgQbgj220jfp0MPA$YfwJSVjtjSU0zzV/P3S9nnQ/USre2wvJMjfCIjrTQbg"
    assert security.verify_pw(legacy, "correct horse battery staple") and not security.verify_pw(legacy, "wrong")


def test_CY_19_mass_assignment(app_env, su):
    """Extra fields cannot set privileged attributes (role, pre-enabled MFA, password hash)."""
    link = invite(su, "viewer")
    from app import security
    security._hits.clear()
    r = app_env["client"].post("/api/register", json={"code": link["token"], "username": "t_mass", "password": "Mass-Assign-9x!z",
                                                      "role": "superadmin", "totp_enabled": True, "pw_hash": "x"})
    assert r.status_code == 200 and r.json()["mfa_setup_required"] is True
    from app import models
    from app.db import SessionLocal
    db = SessionLocal()
    u = db.query(models.User).filter_by(username="t_mass").one()
    assert u.role == "viewer" and not u.totp_enabled and u.pw_hash.startswith("$argon2id$")
    db.close()


def test_CY_21_logout_revokes_token(app_env, su):
    """D-13 regression: a session cookie copied before logout is rejected after logout."""
    from fastapi.testclient import TestClient
    v = make_user(app_env, su, "t_logout2", "viewer")
    stolen = v.c.cookies.get("vms_session")
    v.post("/api/auth/logout")
    c = TestClient(app_env["app"], raise_server_exceptions=False)
    c.cookies.set("vms_session", stolen)
    assert c.get("/api/auth/me").status_code == 401


def test_CY_22_stepup_success_not_throttled(app_env, su):
    """D-14 regression: successful step-ups do not count towards the failure limit."""
    if not S.get("real_video"):
        pytest.skip("ffmpeg needed to export a real segment")
    sa3 = make_user(app_env, su, "t_super3", "superadmin")
    codes = [sa3.post(f"/api/recordings/{S['seg']}/export", json={"totp": "000000", "reason": "wrong code on purpose"}).status_code for _ in range(2)]
    for _ in range(4):  # the previous release counted these too and returned 429 on the 6th call
        r = sa3.post(f"/api/recordings/{S['seg']}/export", json={"totp": sa3.next_code(), "reason": "repeat export"})
        codes.append(r.status_code)
        if r.status_code == 200:
            assert r.headers["content-disposition"].startswith("attachment") and len(r.content) > 1000
    assert codes == [401, 401, 200, 200, 200, 200], codes
    assert len(notes(su, "export")) >= 4


def test_CY_20_unicode_totp_no_crash(su):
    """Unicode digits in an MFA field are rejected cleanly, not with a server error (D-09)."""
    r = su.post(f"/api/unblur/{S['req2']}/approve", json={"totp": "１２３４５６", "passphrase": VAULT_PW})
    assert r.status_code in (401, 429)


# ================================================================= REGISTRATION (first-run + invitations)
def test_FN_22_invite_lifecycle(app_env, su):
    """Invite -> check -> register -> MFA; the link is single-use and listed as used."""
    link = invite(su, "operator", email="hod@college.example", note="HOD CSE")
    assert link["path"].startswith("/#/register?code=") and link["kind"] == "invite"
    c = app_env["client"]
    chk = c.post("/api/register/check", json={"code": link["token"]}).json()
    assert chk["role"] == "operator" and chk["kind"] == "invite"
    a = redeem(app_env, link, "t_invited")
    assert a.get("/api/auth/me").json()["user"]["role"] == "operator"
    assert c.post("/api/register", json={"code": link["token"], "username": "t_again", "password": "Again-Reuse-77!x"}).status_code == 404
    row = [i for i in su.get("/api/users/invites").json() if i["id"] == link["id"]][0]
    assert row["state"] == "used" and row["used_by"] == "t_invited" and "token" not in row


def test_FN_23_password_reset_link(app_env, su):
    """Reset issues a single-use link; the old password stops working; nobody else learns the new one."""
    v = make_user(app_env, su, "t_reset", "viewer")
    r = su.patch(f"/api/users/{v.id}", json={"reset_password": True})
    assert r.status_code == 200 and "temporary_password" not in r.json()
    path = r.json()["reset_link"]["path"]
    assert v.get("/api/auth/me").status_code == 401  # sessions revoked
    from app import security
    security._hits.clear()
    assert v.c.post("/api/auth/login", json={"username": "t_reset", "password": v.password, "totp": v.next_code()}).status_code == 401
    token = path.split("code=")[1]
    chk = app_env["client"].post("/api/register/check", json={"code": token}).json()
    assert chk == {**chk, "kind": "reset", "username": "t_reset"}
    v.password = "Brand-New-Secret-42!"
    r = app_env["client"].post("/api/register", json={"code": token, "password": v.password})
    assert r.status_code == 200 and r.json()["ok"] is True  # MFA kept
    v.login()
    assert app_env["client"].post("/api/register", json={"code": token, "password": "Another-Try-55!x"}).status_code == 404


def test_FN_24_superadmin_invites_admin(app_env, su):
    """A super admin can invite admins; the invitation and the registration alert all super admins."""
    before = len(notes(su, "privileged_invite")), len(notes(su, "privileged_user_registered"))
    adm = redeem(app_env, invite(su, "admin", email="dean@college.example"), "t_dean")
    assert adm.get("/api/auth/me").json()["user"]["role"] == "admin"
    assert len(notes(su, "privileged_invite")) == before[0] + 1
    assert len(notes(su, "privileged_user_registered")) == before[1] + 1


def test_AB_17_admin_invite_scope(app_env, su, users):
    """Admins may invite operator/viewer/kiosk only, and never see or revoke privileged invitations."""
    adm = users["admin"]
    assert adm.post("/api/users/invites", json={"role": "operator"}).status_code == 200
    priv = invite(su, "superadmin")
    assert all(i["role"] not in ("admin", "superadmin") for i in adm.get("/api/users/invites").json())
    assert adm.delete(f"/api/users/invites/{priv['id']}").status_code == 403
    assert users["operator"].post("/api/users/invites", json={"role": "viewer"}).status_code == 403
    su.delete(f"/api/users/invites/{priv['id']}")


def test_AB_18_setup_closed_and_no_default_accounts(app_env, su):
    """After first registration the setup endpoint is closed (even with the old code); no default logins exist."""
    from app import security
    c = app_env["client"]
    security._hits.clear()
    r = c.post("/api/setup/register", json={"setup_code": S["setup_code"], "username": "attacker", "password": "Attacker-Pass-99!"})
    assert r.status_code == 409
    for user, pw in (("admin", "admin"), ("admin", "password"), ("root", "root"), ("superadmin", "superadmin"),
                     ("administrator", "changeme")):
        security._hits.clear()
        assert c.post("/api/auth/login", json={"username": user, "password": pw}).status_code == 401


def test_AB_19_expired_and_revoked_links(app_env, su):
    """Expired or revoked invitations cannot be redeemed."""
    from app import models
    from app.db import SessionLocal
    exp, rev = invite(su, "viewer"), invite(su, "viewer")
    db = SessionLocal()
    db.get(models.Invite, exp["id"]).expires_at = models.now() - dt.timedelta(minutes=1)
    db.commit()
    db.close()
    assert su.delete(f"/api/users/invites/{rev['id']}").status_code == 200
    for link in (exp, rev):
        redeem(app_env, link, "t_dead_" + str(link["id"]), expect=404)


def test_AB_20_duplicate_username(app_env, su, users):
    """An invitation cannot take over an existing username (case-insensitive)."""
    redeem(app_env, invite(su, "viewer"), "T_VIEWER", expect=409)


def test_CY_23_password_policy(app_env, su):
    """Weak, common, short or username-containing passwords are refused at registration and change."""
    link = invite(su, "viewer")
    c = app_env["client"]
    from app import security
    for pw in ("short1!", "password1234", "aaaaaaaaaaaaaaaa", "t_weakling-2026-X!", "alllowercaseletters"[:15]):
        security._hits.clear()
        r = c.post("/api/register", json={"code": link["token"], "username": "t_weakling", "password": pw})
        assert r.status_code == 422, (pw, r.text)
    assert su.post("/api/auth/password", json={"old_password": SU_PW, "new_password": "qwerty123456"}).status_code == 422


def test_CY_24_link_tokens_hashed_at_rest(app_env, su):
    """Only SHA-256 hashes of invitation tokens are stored; the database never holds a usable link."""
    link = invite(su, "viewer")
    raw = (app_env["dir"] / "vms.db").read_bytes()
    assert link["token"].encode() not in raw
    import hashlib
    assert hashlib.sha256(link["token"].encode()).hexdigest().encode() in raw


def test_CY_25_setup_code_bruteforce_rotates(app_env, monkeypatch):
    """10 wrong setup codes replace the code (written only to the local 0600 file); per-IP rate limit applies."""
    from app import routes_setup as R
    from app.hardening import normalise_code, token_hash
    known = "ABCD-EFGH-JKLM-NPQR"
    monkeypatch.setitem(R._setup, "hash", token_hash(normalise_code(known)))
    monkeypatch.setitem(R._setup, "fails", 0)
    for _ in range(R.MAX_SETUP_FAILS):
        assert not R._consume_setup("WRONG-CODE-0000-0000")
    assert R._setup["hash"] != token_hash(normalise_code(known))
    assert not R._consume_setup(known)
    new = R.setup_code_path().read_text().strip()
    assert R._consume_setup(new) and not R.setup_code_path().exists()
    from app import security
    security._hits.clear()
    codes = [app_env["client"].post("/api/setup/register", json={"setup_code": "X" * 19, "username": "zz_brute",
                                                                  "password": "Brute-Force-11!x"}).status_code for _ in range(6)]
    assert codes[-1] == 429


def test_CY_26_register_endpoints_rate_limited(app_env):
    """Guessing invitation tokens is throttled per IP."""
    from app import security
    security._hits.clear()
    codes = [app_env["client"].post("/api/register/check", json={"code": "g" * 43}).status_code for _ in range(21)]
    assert codes[:20] == [404] * 20 and codes[-1] == 429
