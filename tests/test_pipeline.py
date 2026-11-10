"""PL: end-to-end privacy pipeline on the real MediaMTX binary (camera -> blur -> viewers / encrypted recorder).

Starts: stub internal API (real access policy), MediaMTX (a looping face video as camera 1), the privacy
processor and the encrypted recorder; observes for ~70 s. Needs ffmpeg, the mediamtx binary, face models
and VMS_TEST_FACES/enrol.jpg.
"""
import base64
import glob
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

import cv2
import jwt
import numpy as np
import pytest

import vmscrypto as C
from conftest import AS_DIR, DET, FACES, MEDIAMTX, REC, ROOT

pytestmark = pytest.mark.skipif(not (shutil.which("ffmpeg") and MEDIAMTX.exists() and DET.exists() and FACES
                                     and (FACES / "enrol.jpg").exists()),
                                reason="needs ffmpeg, mediamtx, face models and VMS_TEST_FACES/enrol.jpg")
TOK, SECRET, PORT = "internaltoken0123456789", "jwt-secret-for-pipeline-tests-0123456789", 8097
PASS = "pipeline test vault passphrase"


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    d = tmp_path_factory.mktemp("pl")
    rec, _ = C.create_vault(PASS)
    mk = os.urandom(32)
    # camera: the enrolment photo slowly zoomed/panned (a face that never turns its head)
    subprocess.run(["ffmpeg", "-v", "error", "-loop", "1", "-i", str(FACES / "enrol.jpg"), "-vf",
                    "scale=1280:-2,zoompan=z='1.05+0.05*sin(on/20)':d=1:s=1280x720:fps=15", "-t", "20",
                    "-c:v", "libx264", "-g", "15", "-pix_fmt", "yuv420p", str(d / "cam.mp4")], check=True)
    (d / "mtx.yml").write_text(f"""logLevel: warn
authMethod: http
authHTTPAddress: http://127.0.0.1:{PORT}/internal/mediamtx-auth
authHTTPExclude: []
api: yes
apiAddress: 127.0.0.1:9997
rtspAddress: 127.0.0.1:8554
protocols: [tcp]
hls: yes
hlsAddress: 127.0.0.1:8888
webrtc: no
playback: no
rtmp: no
srt: no
paths:
  cam1:
    runOnInit: ffmpeg -v error -re -stream_loop -1 -i {d / 'cam.mp4'} -c copy -f rtsp -rtsp_transport tcp rtsp://internal:{TOK}@127.0.0.1:8554/cam1
    runOnInitRestart: yes
  cam1_sub:
    source: rtsp://internal:{TOK}@127.0.0.1:8554/cam1
    sourceOnDemand: yes
  cam1_priv:
    source: publisher
  cam2_priv:
    source: publisher
""")
    env = {**os.environ, "VMS_API_URL": f"http://127.0.0.1:{PORT}", "VMS_INTERNAL_TOKEN": TOK,
           "VMS_MEDIA_KEY": base64.b64encode(mk).decode(), "VMS_RTSP_BASE": "rtsp://127.0.0.1:8554",
           "VMS_STORE_DIR": str(d / "store"), "VMS_SEGMENT_SECONDS": "10", "VMS_FACE_DET_MODEL": str(DET),
           "VMS_FACE_REC_MODEL": str(REC), "VMS_ANTISPOOF_DIR": str(AS_DIR)}
    procs = [subprocess.Popen([sys.executable, str(ROOT / "tests" / "stub_api.py"), TOK, SECRET,
                               base64.b64encode(rec.public_key).decode(), str(d / "out"), str(PORT)]),
             subprocess.Popen([str(MEDIAMTX), str(d / "mtx.yml")], cwd=d, stdout=open(d / "mtx.log", "w"), stderr=subprocess.STDOUT)]
    time.sleep(2)
    procs += [subprocess.Popen([sys.executable, str(ROOT / "worker" / "privacy.py")], env=env, stdout=open(d / "privacy.log", "w"), stderr=subprocess.STDOUT),
              subprocess.Popen([sys.executable, str(ROOT / "worker" / "recorder.py")], env=env, stdout=open(d / "recorder.log", "w"), stderr=subprocess.STDOUT)]
    time.sleep(55)
    yield {"dir": d, "mk": mk, "vault": rec, "procs": procs}
    for p in reversed(procs):
        p.terminate()
    for p in procs:
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()


@pytest.fixture(scope="module")
def eng():
    import faceengine as F
    return F.FaceEngine(str(DET), str(REC), str(AS_DIR))


def _token(path, act="read"):
    return jwt.encode({"typ": "stream", "sub": "1", "path": path, "act": act, "exp": int(time.time()) + 300}, SECRET, algorithm="HS256")


def _http(url):
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def _grab(url):
    p = subprocess.run(["ffmpeg", "-v", "error", "-i", url, "-frames:v", "1", "-f", "image2pipe", "-c:v", "png", "pipe:1"],
                       capture_output=True, timeout=40)
    return cv2.imdecode(np.frombuffer(p.stdout, np.uint8), 1) if p.stdout else None


def _faces(eng, img):
    return [f for f in eng.detect(img, 0.6) if f.score > 0.75]


def _decode_frames(mp4, every=15):
    import mediatools as M
    out = []
    M.transcode(mp4, lambda f, i: (out.append(f.copy()) if i % every == 0 else None) or f)
    return out


def test_PL_01_viewer_stream_is_blurred(run, eng):
    """A viewer's stream (HLS with a scoped token) contains no detectable face while the camera does."""
    raw = _grab(f"rtsp://internal:{TOK}@127.0.0.1:8554/cam1")
    view = _grab(f"http://127.0.0.1:8888/cam1_priv/index.m3u8?jwt={_token('cam1_priv')}")
    assert raw is not None and view is not None
    assert len(_faces(eng, raw)) >= 1 and len(_faces(eng, view)) == 0


def test_PL_02_raw_stream_denied_to_viewers(run):
    """A viewer token cannot open the raw path, another camera, or anything without a token."""
    assert _http(f"http://127.0.0.1:8888/cam1/index.m3u8?jwt={_token('cam1_priv')}") == 401
    assert _http(f"http://127.0.0.1:8888/cam1/index.m3u8?jwt={_token('cam1')}") == 401
    assert _http(f"http://127.0.0.1:8888/cam2_priv/index.m3u8?jwt={_token('cam1_priv')}") == 401
    assert _http("http://127.0.0.1:8888/cam1_priv/index.m3u8") == 401
    assert _http(f"http://127.0.0.1:8888/cam1_priv/index.m3u8?jwt={_token('cam1_priv')[:-4]}AAAA") == 401


def test_PL_03_mediamtx_api_locked(run):
    """The MediaMTX control API refuses anonymous callers."""
    assert _http("http://127.0.0.1:9997/v3/paths/list") == 401


def test_PL_04_blurred_recording(run, eng):
    """Recorded blurred segments decrypt with the media key and contain no detectable faces."""
    segs = sorted(glob.glob(str(run["dir"] / "store/rec/cam1/priv/*/*.svms")))
    assert segs
    frames = _decode_frames(C.decrypt_file(segs[0], media_key=run["mk"]))
    assert frames and sum(len(_faces(eng, f)) for f in frames) == 0


def test_PL_05_raw_recording_sealed(run, eng):
    """Raw segments are sealed: the media key fails, the unlocked vault opens them and faces are present."""
    segs = sorted(glob.glob(str(run["dir"] / "store/rec/cam1/raw/*/*.svms")))
    assert segs
    with pytest.raises(C.CryptoError):
        C.decrypt_file(segs[0], media_key=run["mk"])
    priv = C.unlock_vault(run["vault"], passphrase=PASS)
    frames = _decode_frames(C.decrypt_file(segs[0], private_key=priv))
    assert sum(len(_faces(eng, f)) for f in frames) >= len(frames) * 0.8


def test_PL_06_no_plaintext_at_rest(run):
    """Nothing in the store is plaintext video (no MP4 boxes in any file, .part included)."""
    files = [p for p in (run["dir"] / "store").rglob("*") if p.is_file()]
    assert files
    for p in files:
        assert b"ftyp" not in p.read_bytes()[:4096] and p.read_bytes()[:4] != b"\x00\x00\x00\x1c"


def test_PL_07_segments_indexed(run):
    """Every closed segment is reported to the API with camera, kind, times and size."""
    rows = [json.loads(x) for x in (run["dir"] / "out" / "segments.jsonl").read_text().splitlines()]
    assert {r["kind"] for r in rows} == {"priv", "raw"} and all(r["size"] > 0 and r["start"] < r["end"] for r in rows)


def test_PL_08_cctv_photo_not_live(run):
    """CCTV attendance: a face that never turns (a photo) is reported NOT live, with anti-spoof evidence."""
    atts = [json.loads(p.read_text()) for p in sorted((run["dir"] / "out").glob("att_*.json"))]
    assert atts, "no attendance post"
    a = atts[0]
    assert a["liveness"]["ok"] is False and a["liveness"]["movement_ok"] is False
    assert "antispoof" in a["liveness"] and len(a["embeddings"]) >= 2


def test_PL_09_attendance_evidence(run, eng):
    """Attendance evidence: the scene image is blurred; the face crop is sealed to the vault."""
    jpg = cv2.imread(str(next((run["dir"] / "out").glob("att_*.jpg"))))
    assert len(_faces(eng, jpg)) == 0
    sealed = next((run["dir"] / "out").glob("att_*.sealed")).read_bytes()
    with pytest.raises(C.CryptoError):
        C.decrypt_bytes(sealed, media_key=run["mk"])
    crop = cv2.imdecode(np.frombuffer(C.decrypt_bytes(sealed, private_key=C.unlock_vault(run["vault"], passphrase=PASS)), np.uint8), 1)
    assert crop is not None and len(_faces(eng, crop)) == 1


def test_PL_10_no_raw_without_vault(run):
    """With no vault configured, raw footage stops being recorded (fail closed); blurred continues."""
    urllib.request.urlopen(f"http://127.0.0.1:{PORT}/__set?pub=0").read()
    time.sleep(24)   # recorder refresh interval is 20 s
    t0 = time.time()
    time.sleep(22)
    raw_new = [p for p in glob.glob(str(run["dir"] / "store/rec/cam1/raw/*/*")) if os.path.getmtime(p) > t0]
    priv_new = [p for p in glob.glob(str(run["dir"] / "store/rec/cam1/priv/*/*")) if os.path.getmtime(p) > t0]
    assert not raw_new and priv_new


def test_PL_11_privacy_fails_closed_without_models(tmp_path):
    """If face models are missing, the privacy processor refuses to publish any stream."""
    env = {**os.environ, "VMS_API_URL": "http://127.0.0.1:9", "VMS_INTERNAL_TOKEN": "x",
           "VMS_FACE_DET_MODEL": str(tmp_path / "missing.onnx"), "VMS_FACE_REC_MODEL": str(tmp_path / "missing2.onnx")}
    p = subprocess.Popen([sys.executable, str(ROOT / "worker" / "privacy.py")], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(4)
    p.terminate()
    out = p.communicate(timeout=10)[0].decode()
    assert "refusing to publish" in out
