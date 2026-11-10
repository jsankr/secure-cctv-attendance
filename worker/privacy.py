"""Privacy processor — the only component that sees unblurred live video.

Per camera:
  raw substream --decode--> detect faces --blur (persistent, fail-closed)--> encode --> cam{id}_priv
Viewers, the AI object worker and the playback recorder only ever receive cam{id}_priv.

CCTV attendance (cameras with attendance enabled): faces are tracked; each track needs passive
liveness evidence (natural head movement) and frontal templates before a probe embedding is sent to
the API, which matches it against the enrolled gallery (the gallery never leaves the API). Evidence:
a blurred scene image (API encrypts it) and the raw face crop SEALED to the vault key here.
"""
import base64
import datetime as dt
import json
import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

os.environ.setdefault("OPENCV_FFMPEG_CAPTURE_OPTIONS", "rtsp_transport;tcp|stimeout;5000000")
import cv2  # noqa: E402
import numpy as np  # noqa: E402
import requests  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "shared"))
import faceengine as F  # noqa: E402
import vmscrypto as C  # noqa: E402
from mediatools import FFMPEG, NO_WINDOW  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s privacy: %(message)s")
log = logging.getLogger("privacy")

API = os.environ.get("VMS_API_URL", "http://api:8000")
TOKEN = os.environ["VMS_INTERNAL_TOKEN"]
RTSP = os.environ.get("VMS_RTSP_BASE", "rtsp://mediamtx:8554").replace("rtsp://", f"rtsp://internal:{TOKEN}@")
DET = os.environ.get("VMS_FACE_DET_MODEL", "/models/face_detection_yunet_2023mar.onnx")
REC = os.environ.get("VMS_FACE_REC_MODEL", "/models/face_recognition_sface_2021dec.onnx")
ANTISPOOF_DIR = os.environ.get("VMS_ANTISPOOF_DIR", "/models/antispoof")
MAX_W = int(os.environ.get("VMS_PRIV_MAX_WIDTH", "1280"))
KBPS = int(os.environ.get("VMS_PRIV_KBPS", "900"))
H = {"X-Internal-Token": TOKEN}
_vault = {"pub": None, "at": 0.0}


def vault_pub() -> bytes | None:
    if time.time() - _vault["at"] > 30:
        try:
            v = requests.get(f"{API}/internal/vault/pubkey", headers=H, timeout=5).json()
            _vault["pub"] = base64.b64decode(v["public_key"]) if v.get("public_key") else None
            _vault["at"] = time.time()
        except requests.RequestException:
            pass
    return _vault["pub"]


class Track:
    def __init__(self, box, t):
        self.box, self.first, self.last = box, t, t
        self.live = F.PassiveLiveness()
        self.samples: list[tuple[float, np.ndarray, bytes]] = []  # (|yaw|, embedding, raw crop jpg)
        self.posted = False
        self.scene: np.ndarray | None = None


class CameraPrivacy(threading.Thread):
    def __init__(self, cam: dict, engine: F.FaceEngine):
        super().__init__(daemon=True, name=f"priv-cam{cam['id']}")
        self.cam, self.engine, self.running = cam, engine, True
        self.tracks: list[Track] = []

    def _encoder(self, w, h, fps):
        url = f"rtsp://internal:{TOKEN}@{RTSP.split('@', 1)[1]}/cam{self.cam['id']}_priv"
        return subprocess.Popen(
            [FFMPEG, "-v", "error", "-f", "rawvideo", "-pix_fmt", "bgr24", "-s", f"{w}x{h}", "-r", f"{fps:.2f}",
             "-i", "pipe:0", "-c:v", "libx264", "-preset", "veryfast", "-tune", "zerolatency", "-g", str(int(fps * 2)),
             "-b:v", f"{KBPS}k", "-maxrate", f"{int(KBPS * 1.3)}k", "-bufsize", f"{KBPS * 2}k", "-pix_fmt", "yuv420p",
             "-f", "rtsp", "-rtsp_transport", "tcp", url],
            stdin=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=NO_WINDOW)

    def run(self):
        backoff = 2
        while self.running:
            cap = cv2.VideoCapture(f"{RTSP}/cam{self.cam['id']}_sub", cv2.CAP_FFMPEG)
            ok, frame = cap.read() if cap.isOpened() else (False, None)
            if not ok:
                cap.release()
                time.sleep(backoff)
                backoff = min(30, backoff * 2)
                continue
            backoff = 2
            fps = cap.get(cv2.CAP_PROP_FPS)
            fps = fps if 4 <= fps <= 30 else 15.0
            h, w = frame.shape[:2]
            scale = min(1.0, MAX_W / w)
            ow, oh = int(w * scale) // 2 * 2, int(h * scale) // 2 * 2
            enc = self._encoder(ow, oh, fps)
            blur = F.PersistentBlur(hold=max(4, int(fps * 0.6)))
            n = 0
            try:
                while self.running and ok:
                    if scale < 1 or (ow, oh) != (w, h):
                        frame = cv2.resize(frame, (ow, oh), interpolation=cv2.INTER_AREA)
                    out = self.process(frame, blur, n, time.time())
                    enc.stdin.write(out.tobytes())
                    n += 1
                    ok, frame = cap.read()
            except (BrokenPipeError, OSError) as e:
                log.warning("cam%s encoder stopped: %s", self.cam["id"], e)
            finally:
                cap.release()
                try:
                    enc.stdin.close()
                except OSError:
                    pass
                enc.terminate()

    def process(self, frame: np.ndarray, blur: F.PersistentBlur, n: int, t: float) -> np.ndarray:
        try:
            det_scale = min(1.0, 960 / frame.shape[1])
            small = frame if det_scale == 1 else cv2.resize(frame, None, fx=det_scale, fy=det_scale)
            faces = self.engine.detect(small, 0.45)
            if det_scale != 1:
                for f in faces:
                    f.box = tuple(v / det_scale for v in f.box)
                    f.lm = f.lm / det_scale
                    f.raw = f.raw.copy()
                    f.raw[:14] = f.raw[:14] / det_scale
            boxes = blur.update([f.box for f in faces])
            out = F.anonymise(frame.copy(), boxes)
        except Exception as e:  # never publish an unprocessed frame
            log.warning("cam%s detection failed, blurring whole frame: %s", self.cam["id"], e)
            return F.blur_full(frame)
        if self.cam.get("attendance") and n % 3 == 0:
            try:
                self.attend(frame, out, faces, t)
            except Exception as e:
                log.warning("cam%s attendance error: %s", self.cam["id"], e)
        return out

    def attend(self, frame, blurred, faces, t):
        good = [f for f in faces if f.score >= 0.75 and f.width >= 48]
        # texture anti-spoof on near-frontal faces (batched per frame), as the reference recommends (±30°)
        scores = self.engine.antispoof_scores(frame, [f for f in good]) if good else []
        for f, sc in zip(good, scores):
            tr = max(self.tracks, key=lambda k: F._iou(k.box, f.box), default=None)
            if tr is None or F._iou(tr.box, f.box) < 0.25:
                tr = Track(f.box, t)
                self.tracks.append(tr)
            tr.box, tr.last = f.box, t
            tr.live.add(t, f, sc if abs(f.pose()[0]) <= 0.35 else None)
            yaw = abs(f.pose()[0])
            if yaw < 0.15 and len(tr.samples) < 6:
                x, y, w, h = map(int, f.box)
                m = int(w * 0.35)
                crop = frame[max(0, y - m):y + h + m, max(0, x - m):x + w + m]
                ok, jpg = cv2.imencode(".jpg", crop, [cv2.IMWRITE_JPEG_QUALITY, 90])
                tr.samples.append((yaw, self.engine.embed(frame, f), jpg.tobytes() if ok else b""))
                tr.scene = blurred
            live, detail = tr.live.verdict(self.engine)
            if not tr.posted and len(tr.samples) >= 2 and (live or t - tr.first > 8):
                tr.posted = True
                threading.Thread(target=self.post, args=(tr, live, detail), daemon=True).start()
        self.tracks = [k for k in self.tracks if t - k.last < 3]

    def post(self, tr: Track, live: bool, detail: dict):
        best = sorted(tr.samples, key=lambda s: s[0])[:3]
        files = {}
        if tr.scene is not None:
            ok, jpg = cv2.imencode(".jpg", tr.scene, [cv2.IMWRITE_JPEG_QUALITY, 80])
            if ok:
                files["blurred"] = ("b.jpg", jpg.tobytes(), "image/jpeg")
        pub = vault_pub()
        if pub and best[0][2]:
            files["sealed"] = ("r.svms", C.encrypt_bytes(best[0][2], recipient_pub=pub), "application/octet-stream")
        # Individual samples, not an average: the API requires >= 2 samples to agree on one person,
        # so a single bad frame can neither cause a false match nor drag a true match below threshold.
        data = {"camera_id": self.cam["id"], "embeddings": [[round(float(v), 6) for v in b[1]] for b in best],
                "liveness": {"ok": live, **detail}, "ts": dt.datetime.now(dt.timezone.utc).isoformat()}
        try:
            requests.post(f"{API}/internal/attendance", headers=H, data={"data": json.dumps(data)}, files=files, timeout=15)
        except requests.RequestException as e:
            log.warning("attendance post failed: %s", e)


def main():
    if not (os.path.exists(DET) and os.path.exists(REC)):
        log.error("face models missing (%s, %s): refusing to publish any stream unblurred", DET, REC)
        while True:
            time.sleep(3600)
    workers: dict[int, CameraPrivacy] = {}
    as_cfg = {}
    while True:
        try:
            cfg = requests.get(f"{API}/internal/config", headers=H, timeout=10).json().get("antispoof", {})
            new = {"antispoof_variant": cfg.get("variant", "int8"), "antispoof_threshold": float(cfg.get("threshold", 0.5)),
                   "antispoof_frames": int(cfg.get("frames", 3))}
            if new != as_cfg:
                as_cfg = new
                for w in workers.values():  # apply new anti-spoof settings: rebuild engines
                    w.engine = F.FaceEngine(DET, REC, ANTISPOOF_DIR, **as_cfg)
                log.info("anti-spoof settings: %s", as_cfg)
            cams = {c["id"]: c for c in requests.get(f"{API}/internal/cameras", headers=H, timeout=10).json()}
            for cid in list(workers):
                if cid not in cams:
                    workers.pop(cid).running = False
            for cid, c in cams.items():
                if cid in workers:
                    workers[cid].cam = c
                else:
                    # each camera gets its own engine: OpenCV DNN objects are not thread-safe
                    workers[cid] = CameraPrivacy(c, F.FaceEngine(DET, REC, ANTISPOOF_DIR, **as_cfg))
                    workers[cid].start()
        except Exception as e:
            log.warning("camera refresh failed: %s", e)
        time.sleep(15)


if __name__ == "__main__":
    main()
