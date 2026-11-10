"""Sentinel Attend AI worker (CPU-only).

Per camera: read the substream from MediaMTX, sample at VMS_AI_FPS, and
  * motion-gate (frame diff) so the detector only runs when something moves
  * detect objects (ONNX) and track them (IoU); emit one event per new object, plus loitering
  * detect tamper (lens covered / sprayed) and video loss
  * measure light level and request IR night/day switching with hysteresis
  * send event crops (never live video) to the cloud enrichment service for face / ANPR / re-ID
Scale out with VMS_WORKER_SHARD=i/N across several worker containers or hosts.
"""
import datetime as dt
import json
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from zoneinfo import ZoneInfo

os.environ.setdefault("OPENCV_FFMPEG_CAPTURE_OPTIONS", "rtsp_transport;tcp|stimeout;5000000")
import cv2  # noqa: E402
import numpy as np  # noqa: E402
import requests  # noqa: E402

from detector import DEFAULT_CLASSES, Detector  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("worker")

API = os.environ.get("VMS_API_URL", "http://api:8000")
TOKEN = os.environ["VMS_INTERNAL_TOKEN"]
RTSP = os.environ.get("VMS_RTSP_BASE", "rtsp://mediamtx:8554").replace("rtsp://", f"rtsp://internal:{TOKEN}@")
FPS = float(os.environ.get("VMS_AI_FPS", "2"))
MODEL = os.environ.get("VMS_MODEL_PATH", "/models/detector.onnx")
ENRICH = os.environ.get("VMS_ENRICH_URL", "").rstrip("/")
ENRICH_TOKEN = os.environ.get("VMS_ENRICH_TOKEN", "")
ENRICH_CLASSES = {"person", "car", "motorcycle", "bus", "truck"}
TZ = ZoneInfo(os.environ.get("VMS_TZ", "Asia/Kolkata"))
SHARD_I, SHARD_N = (int(x) for x in os.environ.get("VMS_WORKER_SHARD", "0/1").split("/"))
H = {"X-Internal-Token": TOKEN}
pool = ThreadPoolExecutor(max_workers=int(os.environ.get("VMS_POST_THREADS", "16")))


# ----------------------------------------------------------------- helpers
def iou(a, b) -> float:
    ix = max(0.0, min(a[2], b[2]) - max(a[0], b[0]))
    iy = max(0.0, min(a[3], b[3]) - max(a[1], b[1]))
    inter = ix * iy
    u = (a[2] - a[0]) * (a[3] - a[1]) + (b[2] - b[0]) * (b[3] - b[1]) - inter
    return inter / u if u > 0 else 0.0


class Tracker:
    """Greedy IoU tracker. An object is 'confirmed' after 2 hits, so single-frame noise never alerts."""

    def __init__(self, ttl=6.0, min_hits=2):
        self.tracks: dict[int, dict] = {}
        self.next_id, self.ttl, self.min_hits = 1, ttl, min_hits

    def update(self, dets, now: float, loiter_s: float):
        for t in self.tracks.values():
            t["matched"] = False
        for box, conf, label in sorted(dets, key=lambda d: -d[1]):
            best, best_iou = None, 0.3
            for tid, t in self.tracks.items():
                if t["label"] == label and not t["matched"]:
                    v = iou(box, t["box"])
                    if v > best_iou:
                        best, best_iou = tid, v
            if best is None:
                best = self.next_id
                self.next_id += 1
                self.tracks[best] = {"label": label, "first": now, "hits": 0, "new_sent": False, "loiter_sent": False}
            t = self.tracks[best]
            t.update(box=box, conf=conf, last=now, matched=True)
            t["hits"] += 1
        self.tracks = {k: t for k, t in self.tracks.items() if now - t["last"] < self.ttl}
        out = []
        for tid, t in self.tracks.items():
            if not t["matched"]:
                continue
            if t["hits"] >= self.min_hits and not t["new_sent"]:
                t["new_sent"] = True
                out.append(("object", tid, t))
            if t["label"] == "person" and now - t["first"] > loiter_s and not t["loiter_sent"]:
                t["loiter_sent"] = True
                out.append(("loitering", tid, t))
        return out


def in_day_window(cam: dict) -> bool:
    hm = dt.datetime.now(TZ).strftime("%H:%M")
    return cam["day_start"] <= hm <= cam["day_end"]


def annotate(frame, box, text) -> bytes:
    h, w = frame.shape[:2]
    img = frame.copy()
    p1, p2 = (int(box[0] * w), int(box[1] * h)), (int(box[2] * w), int(box[3] * h))
    cv2.rectangle(img, p1, p2, (80, 220, 255), 2)
    cv2.putText(img, text, (p1[0], max(16, p1[1] - 6)), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (80, 220, 255), 2)
    return cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 82])[1].tobytes()


def crop(frame, box, margin=0.12) -> bytes:
    h, w = frame.shape[:2]
    bw, bh = box[2] - box[0], box[3] - box[1]
    x1, y1 = max(0, int((box[0] - bw * margin) * w)), max(0, int((box[1] - bh * margin) * h))
    x2, y2 = min(w, int((box[2] + bw * margin) * w)), min(h, int((box[3] + bh * margin) * h))
    return cv2.imencode(".jpg", frame[y1:y2, x1:x2], [cv2.IMWRITE_JPEG_QUALITY, 92])[1].tobytes()


def post_event(payload: dict, jpg: bytes | None = None, crop_jpg: bytes | None = None):
    try:
        if crop_jpg and ENRICH and payload.get("label") in ENRICH_CLASSES:
            try:
                r = requests.post(f"{ENRICH}/enrich", files={"image": ("c.jpg", crop_jpg, "image/jpeg")},
                                  data={"cls": payload["label"]},
                                  headers={"Authorization": f"Bearer {ENRICH_TOKEN}"}, timeout=8)
                if r.ok:
                    payload.setdefault("meta", {})["enrich"] = r.json()
            except requests.RequestException as e:
                log.debug("enrich failed: %s", e)
        files = {"image": ("s.jpg", jpg, "image/jpeg")} if jpg else None
        requests.post(f"{API}/internal/events", data={"data": json.dumps(payload)}, files=files,
                      headers=H, timeout=10).raise_for_status()
    except Exception as e:
        log.warning("event post failed: %s", e)


# ------------------------------------------------------------ camera loop
class CameraWorker(threading.Thread):
    def __init__(self, cam: dict, det: Detector | None):
        super().__init__(daemon=True, name=f"cam{cam['id']}")
        self.cam, self.det, self.running = cam, det, True
        self.tracker = Tracker()
        self.prev = None
        self.night = cam.get("ir_mode") == "night"
        self.dark_since = self.light_since = self.flat_since = None
        self.tamper_sent = self.loss_sent = False

    def run(self):
        backoff = 2
        while self.running:
            cap = cv2.VideoCapture(f"{RTSP}/cam{self.cam['id']}_priv", cv2.CAP_FFMPEG)  # blurred stream only
            if not cap.isOpened():
                self._video_loss()
                time.sleep(backoff)
                backoff = min(60, backoff * 2)
                continue
            backoff, self.loss_sent = 2, False
            last = 0.0
            while self.running:
                if not cap.grab():  # keep draining so we always analyse the live frame
                    break
                now = time.time()
                if now - last < 1.0 / FPS:
                    continue
                last = now
                ok, frame = cap.retrieve()
                if ok:
                    try:
                        self.process(frame, now)
                    except Exception:
                        log.exception("process failed cam%s", self.cam["id"])
            cap.release()
            self._video_loss()

    def _video_loss(self):
        if not self.loss_sent and self.running:
            self.loss_sent = True
            pool.submit(post_event, {"camera_id": self.cam["id"], "kind": "video_loss", "label": "video_loss",
                                     "severity": "high"})

    def process(self, frame, now):
        cam = self.cam
        small = cv2.cvtColor(cv2.resize(frame, (160, 90)), cv2.COLOR_BGR2GRAY)
        luma, std = float(small.mean()), float(small.std())
        self._lowlight(luma, now)
        self._tamper(luma, std, now, frame)

        blur = cv2.GaussianBlur(small, (5, 5), 0)
        moving = True
        if self.prev is not None:
            moving = (cv2.absdiff(blur, self.prev) > 18).mean() > 0.004
        self.prev = blur
        if not cam.get("ai_enabled") or self.det is None or (not moving and not self.tracker.tracks):
            return
        dets = self.det(frame)
        for kind, tid, t in self.tracker.update(dets, now, cam.get("loiter_seconds", 60)):
            label = t["label"]
            payload = {"camera_id": cam["id"], "kind": kind, "label": label if kind == "object" else "loitering",
                       "confidence": round(t["conf"], 3), "bbox": [round(v, 4) for v in t["box"]],
                       "severity": "low" if kind == "object" else "medium",
                       "meta": {"track_id": tid, "object": label, "dwell_s": round(now - t["first"], 1)}}
            text = f"{label} {t['conf']:.2f}" if kind == "object" else f"loitering {int(now - t['first'])}s"
            pool.submit(post_event, payload, annotate(frame, t["box"], text),
                        crop(frame, t["box"]) if kind == "object" else None)

    def _lowlight(self, luma, now):
        cam = self.cam
        if not cam.get("auto_ir"):
            return
        thr = cam.get("lowlight_threshold", 40)
        if not self.night:
            self.dark_since = (self.dark_since or now) if luma < thr else None
            if self.dark_since and now - self.dark_since > 30:
                self._switch(True, luma)
        else:
            # In IR mode the image is lit by the camera's own LEDs, so brightness alone cannot prove
            # daylight returned. Require the configured day window AND sustained brightness.
            bright = luma > thr + 25 and in_day_window(cam)
            self.light_since = (self.light_since or now) if bright else None
            if self.light_since and now - self.light_since > 60:
                self._switch(False, luma)

    def _switch(self, dark: bool, luma: float):
        self.night, self.dark_since, self.light_since = dark, None, None
        try:
            requests.post(f"{API}/internal/lowlight", json={"camera_id": self.cam["id"], "dark": dark,
                                                            "luma": round(luma, 1)}, headers=H, timeout=10)
        except requests.RequestException as e:
            log.warning("lowlight post failed: %s", e)

    def _tamper(self, luma, std, now, frame):
        flat = std < 6 and luma > 12  # uniform image that is not simply night = covered/sprayed/defocused
        self.flat_since = (self.flat_since or now) if flat else None
        if self.flat_since and now - self.flat_since > 15 and not self.tamper_sent:
            self.tamper_sent = True
            jpg = cv2.imencode(".jpg", frame)[1].tobytes()
            pool.submit(post_event, {"camera_id": self.cam["id"], "kind": "tamper", "label": "tamper",
                                     "severity": "high", "meta": {"std": round(std, 2)}}, jpg)
        elif not flat:
            self.tamper_sent = False


# ------------------------------------------------------------------- main
def main():
    det = None
    if os.path.exists(MODEL):
        det = Detector(MODEL, conf=float(os.environ.get("VMS_DET_CONF", "0.45")),
                       classes=os.environ.get("VMS_DET_CLASSES", DEFAULT_CLASSES))
        log.info("detector loaded: %s providers=%s", MODEL, det.sess.get_providers())
    else:
        log.warning("no model at %s: running motion/tamper/low-light only", MODEL)
    workers: dict[int, CameraWorker] = {}
    while True:
        try:
            cams = requests.get(f"{API}/internal/cameras", headers=H, timeout=10).json()
            mine = {c["id"]: c for c in cams if c["id"] % SHARD_N == SHARD_I}
            for cid in list(workers):
                if cid not in mine:
                    workers.pop(cid).running = False
            for cid, c in mine.items():
                if cid in workers:
                    workers[cid].cam = c  # live config update
                else:
                    workers[cid] = CameraWorker(c, det)
                    workers[cid].start()
            log.info("shard %d/%d handling %d cameras", SHARD_I, SHARD_N, len(workers))
        except Exception as e:
            log.warning("camera refresh failed: %s", e)
        time.sleep(30)


if __name__ == "__main__":
    main()
