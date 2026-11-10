"""HD: framework-free security helpers (TOTP, CSV export safety, registration, repository hygiene)."""
import base64
import time

from app import hardening as H

RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()  # RFC 6238 Appendix B (SHA-1)


def test_HD_01_rfc6238_vectors():
    """TOTP matches RFC 6238 SHA-1 test vectors (last 6 digits)."""
    for t, code8 in ((59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                     (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")):
        assert H.totp_at(RFC_SECRET, t) == code8[-6:]


def test_HD_02_current_code_accepted_once():
    """A valid code is accepted once; the identical code is rejected afterwards (replay)."""
    now = 1_800_000_000
    code = H.totp_at(RFC_SECRET, now)
    ok, m = H.totp_verify(RFC_SECRET, code, "", now)
    assert ok
    ok2, _ = H.totp_verify(RFC_SECRET, code, m, now + 5)
    assert not ok2


def test_HD_03_older_code_rejected_after_newer():
    """Defect D-07 regression: an observed OLDER code cannot be replayed after a newer one was used."""
    now = 1_800_000_000
    old = H.totp_at(RFC_SECRET, now - 30)   # previous step (still inside the +/-1 drift window)
    cur = H.totp_at(RFC_SECRET, now)
    ok, m = H.totp_verify(RFC_SECRET, cur, "", now)
    assert ok
    ok_old, _ = H.totp_verify(RFC_SECRET, old, m, now + 1)
    assert not ok_old


def test_HD_04_clock_drift_window():
    """Codes one step either side are accepted (drift); two steps away are rejected."""
    now = 1_800_000_000
    assert H.totp_verify(RFC_SECRET, H.totp_at(RFC_SECRET, now + 30), "", now)[0]
    assert H.totp_verify(RFC_SECRET, H.totp_at(RFC_SECRET, now - 30), "", now)[0]
    assert not H.totp_verify(RFC_SECRET, H.totp_at(RFC_SECRET, now + 60), "", now)[0]
    assert not H.totp_verify(RFC_SECRET, H.totp_at(RFC_SECRET, now - 60), "", now)[0]


def test_HD_05_malformed_codes():
    """Defect D-09 regression: malformed codes (incl. Unicode digits) are rejected without exceptions."""
    for bad in ("", "12345", "1234567", "abcdef", "12 456", None, "１２３４５６"):
        assert not H.totp_verify(RFC_SECRET, bad, "", time.time())[0]


def test_HD_06_corrupt_marker_tolerated():
    """A corrupt stored marker does not crash verification."""
    now = time.time()
    assert H.totp_verify(RFC_SECRET, H.totp_at(RFC_SECRET, now), "garbage:xx", now)[0]


def test_HD_07_provisioning_uri():
    """Provisioning URI follows the Key URI format apps expect."""
    u = H.provisioning_uri("JBSWY3DPEHPK3PXP", "alice@college", "Sentinel Attend")  # scan:allow well-known example secret
    assert u.startswith("otpauth://totp/Sentinel%20Attend:alice%40college?secret=JBSWY3DPEHPK3PXP")  # scan:allow
    assert "period=30" in u and "digits=6" in u


def test_HD_08_secret_entropy():
    """Generated TOTP secrets are 160-bit and unique."""
    secrets = {H.random_base32() for _ in range(200)}
    assert len(secrets) == 200 and all(len(base64.b32decode(s + "=" * (-len(s) % 8))) == 20 for s in secrets)


def test_HD_09_csv_formula_injection():
    """Defect D-08 regression: cells starting with = + - @ TAB CR LF are neutralised."""
    for v in ("=HYPERLINK(\"http://x\",\"y\")", "+cmd|' /C calc'!A0", "-2+3", "@SUM(A1)", "\t=1", "\r=1", "\n=1"):
        assert H.csv_safe(v).startswith("'")
    for v in ("Priya R", "21CS045", "", None, "a=b"):
        assert not H.csv_safe(v).startswith("'")


def _claims(tok):
    return {"good": {"path": "cam1_priv", "act": "read"}, "raw": {"path": "cam1", "act": "read"},
            "pb": {"path": "cam1_priv", "act": "playback"}}.get(tok)


def test_HD_10_stream_access_policy():
    """MediaMTX hook: viewer tokens read only their own blurred path; never raw, publish, playback or API."""
    d = lambda **b: H.mediamtx_decision(b, "INTERNAL", _claims)  # noqa: E731
    assert d(action="read", path="cam1_priv", query="jwt=good")
    assert d(action="read", path="cam1_priv", token="good")
    assert not d(action="read", path="cam2_priv", query="jwt=good")        # other camera
    assert not d(action="read", path="cam1", query="jwt=raw")              # raw path, even with a raw-scoped token
    assert not d(action="read", path="cam1_sub", query="jwt=good")
    assert not d(action="publish", path="cam1_priv", query="jwt=good")
    assert not d(action="playback", path="cam1_priv", query="jwt=pb")
    assert not d(action="api", path="", query="jwt=good")
    assert not d(action="read", path="cam1_priv")                          # anonymous
    assert not d(action="read", path="cam1_priv", query="jwt=forged")
    assert not d(user="internal", password="wrong", action="publish", path="cam1")
    assert d(user="internal", password="INTERNAL", action="publish", path="cam1")  # scan:allow test fixture


def test_HD_11_decompression_bomb_rejected():
    """Defect D-12 regression: images declaring huge dimensions are refused before pixel decoding."""
    import io
    import warnings

    import pytest
    from PIL import Image
    warnings.simplefilter("ignore")
    for side in (5000, 16000):
        buf = io.BytesIO()
        Image.new("RGB", (side, side), (120, 120, 120)).save(buf, "JPEG", quality=5)
        with pytest.raises(H.ImageRejected):
            H.decode_image(buf.getvalue(), max_side=1920, max_pixels=1920 * 1080)
    for bad in (b"", b"GIF89a....", b"<svg/>", b"\xff\xd8\xff\xe0" + b"\0" * 50):
        with pytest.raises(H.ImageRejected):
            H.decode_image(bad)
    ok = io.BytesIO()
    Image.new("RGB", (640, 480), (1, 2, 3)).save(ok, "JPEG")
    assert H.decode_image(ok.getvalue()).shape == (480, 640, 3)


def test_HD_12_password_policy():
    """Account passwords: 12+ chars, not common, not containing the username, not repetitive; long passphrases OK."""
    bad = ["", "short", "Password1234", "password1234!", "qwerty123456", "aaaaaaaaaaaaaaaa", "principal-Rocks-9!",
           "alllowercase12", "x" * 300]
    for pw in bad:
        assert H.password_problem(pw, "principal"), pw
    for pw in ("Kx9!vTq2#mLw", "correct horse battery staple", "Campus-Gate-2026!"):
        assert H.password_problem(pw, "principal") is None, pw


def test_HD_13_setup_code_and_token_hash():
    """Setup codes carry 80 random bits, are normalised for typing, and are compared by hash only."""
    codes = {H.new_setup_code() for _ in range(2000)}
    assert len(codes) == 2000
    c = next(iter(codes))
    assert len(c) == 19 and c.count("-") == 3
    assert H.normalise_code(c.lower().replace("-", " ")) == c.replace("-", "")
    assert H.token_hash("x") == "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
    assert H.normalise_code("ＡＢ１２") == ""  # full-width input cannot alias ASCII codes


def test_HD_14_repository_has_no_secrets():
    """Pre-push secret scan: no keys, tokens, passwords, databases or .env files in the repository."""
    import subprocess
    import sys
    from conftest import ROOT
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "secret_scan.py"), str(ROOT)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


def test_HD_15_no_default_credentials_in_code():
    """No built-in username/password pair or bootstrap password remains in the code base."""
    import re
    from conftest import ROOT
    rx = re.compile(r"(?i)(bootstrap_password|admin_password|temporary_password|FIRST-LOGIN\.txt\b.*write|"
                    r"username\s*=\s*[\"']admin[\"'].*role\s*=\s*[\"']superadmin)")
    hits = []
    for p in list((ROOT / "api").rglob("*.py")) + list((ROOT / "web").rglob("*.js")) + [ROOT / "run.py", ROOT / ".env.example"]:
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if rx.search(line) and "older versions" not in line:
                hits.append(f"{p.relative_to(ROOT)}:{n}: {line.strip()}")
    assert not hits, hits
