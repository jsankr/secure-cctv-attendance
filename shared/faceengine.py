"""Face detection, irreversible blurring, recognition and liveness (presentation-attack detection).

Models (both commercially usable):
  * YuNet  face detector    (opencv_zoo, MIT)        -> boxes + 5 landmarks
  * SFace  face recogniser  (opencv_zoo, Apache-2.0) -> 128-d embeddings, cosine similarity

Liveness layers
  1. Kiosk ACTIVE challenge: random ordered head movements (left/right/up). A printed photo, a photo on
     a screen or a rigid 3D print rotated in front of the camera stays geometrically planar or rigid:
     the nose never shifts relative to the eyes the way a real head turning does, so the pose proxies
     do not change. Random order defeats pre-recorded video.
  2. Continuity: identity must stay the same in every frame, the face may not jump, and turns must pass
     through intermediate poses (defeats swapping between photos of different poses).
  3. Passive CCTV mode: a tracked face must show natural head-pose variation over time before
     attendance is accepted; otherwise it is recorded as "needs review", never silently as present.
  4. Passive texture anti-spoofing (MiniFASNetV2-SE from suriAI/face-antispoof-onnx, see antispoof.py):
     every scored frame is classified real/spoof; a sequence needs N consecutive "real" frames.
     Mandatory (fail closed): no model -> no liveness pass.

What RGB liveness cannot guarantee: a realistic silicone mask worn by an accomplice, or a live
deepfake injected through a virtual camera. Countermeasures: supervised kiosks, IR/depth cameras,
and a certified (ISO/IEC 30107-3) presentation-attack-detection SDK for high-stakes use.
"""
from __future__ import annotations

import random
import secrets
from dataclasses import dataclass, field

import cv2
import numpy as np

CHALLENGES = {"left": "Turn your head to YOUR left", "right": "Turn your head to YOUR right",
              "up": "Tilt your head up"}


@dataclass
class Face:
    box: tuple[float, float, float, float]  # x, y, w, h (pixels)
    score: float
    lm: np.ndarray  # 5x2: right eye, left eye, nose tip, right mouth corner, left mouth corner
    raw: np.ndarray = field(repr=False)

    @property
    def width(self) -> float:
        return self.box[2]

    @property
    def center(self) -> tuple[float, float]:
        return self.box[0] + self.box[2] / 2, self.box[1] + self.box[3] / 2

    def pose(self) -> tuple[float, float]:
        """(yaw, pitch) proxies from landmarks; scale-invariant.
        yaw  : ~0 frontal; > 0 when the person turns to THEIR left (nose moves to image right).
        pitch: ratio of eye->nose to eye->mouth vertical distance; decreases when tilting up."""
        re, le, nose, rm, lm = self.lm
        eye_mid = (re + le) / 2
        iod = max(1e-3, float(np.linalg.norm(le - re)))
        yaw = float(nose[0] - eye_mid[0]) / iod
        mouth_mid = (rm + lm) / 2
        denom = max(1e-3, float(mouth_mid[1] - eye_mid[1]))
        pitch = float(nose[1] - eye_mid[1]) / denom
        return yaw, pitch


class FaceEngine:
    def __init__(self, yunet_path: str, sface_path: str, antispoof_dir: str = "", antispoof_variant: str = "int8",
                 antispoof_threshold: float = 0.5, antispoof_frames: int = 3):
        self.det = cv2.FaceDetectorYN.create(yunet_path, "", (320, 320), 0.45, 0.3, 5000)
        self.rec = cv2.FaceRecognizerSF.create(sface_path, "")
        self.antispoof = None
        self.antispoof_frames = max(3, min(5, int(antispoof_frames)))
        self.antispoof_error = "anti-spoof model not configured"
        if antispoof_dir:
            try:
                from antispoof import AntiSpoof
                self.antispoof = AntiSpoof(antispoof_dir, antispoof_variant, antispoof_threshold)
                self.antispoof_error = ""
            except Exception as e:
                self.antispoof_error = str(e)

    # ---------------------------------------------------------- detection
    def detect(self, img: np.ndarray, min_score: float = 0.45) -> list[Face]:
        h, w = img.shape[:2]
        self.det.setInputSize((w, h))
        self.det.setScoreThreshold(min_score)
        _, faces = self.det.detect(img)
        out = []
        if faces is not None:
            for f in faces:
                out.append(Face(tuple(float(v) for v in f[:4]), float(f[14]),
                                np.array(f[4:14], dtype=np.float32).reshape(5, 2), f))
        return out

    # -------------------------------------------------------- recognition
    def embed(self, img: np.ndarray, face: Face) -> np.ndarray:
        crop = self.rec.alignCrop(img, face.raw)
        v = self.rec.feature(crop).flatten().astype(np.float32)
        return v / (np.linalg.norm(v) + 1e-9)

    @staticmethod
    def match(emb: np.ndarray, gallery: dict[int, list[np.ndarray]], threshold: float, margin: float):
        """Best person by max cosine over their templates. Returns (person_id|None, score, second_score)."""
        scores = []
        for pid, temps in gallery.items():
            if temps:
                scores.append((max(float(emb @ t) for t in temps), pid))
        if not scores:
            return None, 0.0, 0.0
        scores.sort(reverse=True)
        best, pid = scores[0]
        second = scores[1][0] if len(scores) > 1 else 0.0
        if best >= threshold and best - second >= margin:
            return pid, best, second
        return None, best, second

    # ------------------------------------------------- passive anti-spoof
    def antispoof_scores(self, img: np.ndarray, faces: list["Face"]) -> list[dict | None]:
        if self.antispoof is None:
            return [None] * len(faces)
        return self.antispoof.score_faces(img, [f.box for f in faces])


# ------------------------------------------------------------------ blur
def _expand(box, W, H, side=0.35, top=0.55, bottom=0.25):
    x, y, w, h = box
    x1, x2 = max(0, int(x - w * side)), min(W, int(x + w * (1 + side)))
    y1, y2 = max(0, int(y - h * top)), min(H, int(y + h * (1 + bottom)))
    return x1, y1, x2, y2


def anonymise(img: np.ndarray, boxes, keep: set[int] | None = None) -> np.ndarray:
    """Irreversible: pixelate each (expanded) face region to a coarse grid, then smooth it.
    Pixelation discards the detail outright; it is not an invertible filter."""
    H, W = img.shape[:2]
    out = img
    for i, b in enumerate(boxes):
        if keep and i in keep:
            continue
        x1, y1, x2, y2 = _expand(b, W, H)
        if x2 - x1 < 2 or y2 - y1 < 2:
            continue
        roi = out[y1:y2, x1:x2]
        # 4 cells across regardless of face size (D-11: up to 7 cells left larger faces detectable and,
        # in one case, matchable at cosine 0.44 > 0.42). Measured: 0/305 re-detected, identity <= 0.34.
        cells = 4
        small = cv2.resize(roi, (cells, max(3, int(cells * (y2 - y1) / (x2 - x1)))), interpolation=cv2.INTER_AREA)
        block = cv2.resize(small, (x2 - x1, y2 - y1), interpolation=cv2.INTER_NEAREST)
        k = max(3, ((x2 - x1) // 3) | 1)
        out[y1:y2, x1:x2] = cv2.GaussianBlur(block, (k, k), 0)
    return out


def blur_full(img: np.ndarray) -> np.ndarray:
    """Fail-closed fallback: used whenever face detection could not run on a frame."""
    h, w = img.shape[:2]
    small = cv2.resize(img, (max(8, w // 40), max(6, h // 40)), interpolation=cv2.INTER_AREA)
    return cv2.GaussianBlur(cv2.resize(small, (w, h), interpolation=cv2.INTER_LINEAR), (31, 31), 0)


class PersistentBlur:
    """Keeps blurring a face for `hold` frames after the detector last saw it, so a single missed
    detection (motion blur, a turned head) never exposes a face for even one frame."""

    def __init__(self, hold: int = 8):
        self.hold, self.tracks = hold, []  # [box, ttl]

    def update(self, boxes):
        nxt = [[b, self.hold] for b in boxes]
        for b, ttl in self.tracks:
            if ttl > 1 and not any(_iou(b, n[0]) > 0.2 for n in nxt):
                nxt.append([b, ttl - 1])
        self.tracks = nxt
        return [b for b, _ in self.tracks]


def _iou(a, b) -> float:
    ax2, ay2, bx2, by2 = a[0] + a[2], a[1] + a[3], b[0] + b[2], b[1] + b[3]
    iw, ih = max(0, min(ax2, bx2) - max(a[0], b[0])), max(0, min(ay2, by2) - max(a[1], b[1]))
    inter = iw * ih
    u = a[2] * a[3] + b[2] * b[3] - inter
    return inter / u if u > 0 else 0.0


class SelectiveUnblur:
    """Frame function for approved unblur renders: every face is anonymised EXCEPT the one matching
    the requested person. The match is re-verified every `recheck` frames; between checks the kept
    face is followed by box overlap, and if the track is lost the face is blurred again."""

    def __init__(self, engine: "FaceEngine", templates: list[np.ndarray], threshold: float, recheck: int = 5):
        self.engine, self.temps, self.thr, self.recheck = engine, templates, threshold, recheck
        self.keep_box = None
        self.frames_kept = 0

    def __call__(self, frame: np.ndarray, i: int) -> np.ndarray:
        faces = self.engine.detect(frame, 0.45)
        keep = None
        if faces and self.temps:
            if self.keep_box is not None and i % self.recheck:
                k = max(range(len(faces)), key=lambda j: _iou(faces[j].box, self.keep_box))
                if _iou(faces[k].box, self.keep_box) > 0.3:
                    keep = k
            if keep is None:
                best, best_s = None, self.thr
                for k, f in enumerate(faces):
                    if f.width >= 36 and f.score >= 0.6:
                        s = max(float(self.engine.embed(frame, f) @ t) for t in self.temps)
                        if s >= best_s:
                            best, best_s = k, s
                keep = best
        self.keep_box = faces[keep].box if keep is not None else None
        self.frames_kept += keep is not None
        return anonymise(frame, [f.box for f in faces], keep={keep} if keep is not None else None)


# -------------------------------------------------------------- liveness
YAW_TURN, YAW_CENTER, PITCH_UP_DROP = 0.22, 0.10, 0.12


def new_challenge(n_steps: int = 3) -> dict:
    """n random movements, no movement twice in a row (3 steps from 3 movements -> 12 sequences,
    up from 6 with two distinct steps): a pre-recorded or replayed sequence matches only by chance."""
    rnd, steps = random.SystemRandom(), []
    while len(steps) < n_steps:
        c = rnd.choice([k for k in CHALLENGES if not steps or k != steps[-1]])
        steps.append(c)
    return {"id": secrets.token_urlsafe(16), "steps": steps, "prompts": [CHALLENGES[s] for s in steps]}


@dataclass
class LivenessResult:
    live: bool
    reason: str
    best_frame: int = -1
    embedding: np.ndarray | None = None
    detail: dict = field(default_factory=dict)


def verify_kiosk(engine: FaceEngine, frames: list[np.ndarray], steps: list[str]) -> LivenessResult:
    """frames: ~5 fps captures covering 'look straight' then each step in order."""
    if len(frames) < 10:
        return LivenessResult(False, "Not enough frames captured")
    seq, faces_per_frame = [], []
    for img in frames:
        fs = [f for f in engine.detect(img, 0.6) if f.score >= 0.75]
        faces_per_frame.append(fs)
        seq.append(fs[0] if len(fs) == 1 else None)
    multi = sum(1 for fs in faces_per_frame if len(fs) > 1)
    if multi > len(frames) * 0.2:
        return LivenessResult(False, "More than one face in view; only one person at a time")
    valid = [(i, f) for i, f in enumerate(seq) if f is not None]
    if len(valid) < len(frames) * 0.7:
        return LivenessResult(False, "Face not visible clearly enough; move closer and keep your face in the frame")
    if min(f.width for _, f in valid) < 60:
        return LivenessResult(False, "Face too small; move closer to the camera")

    poses = {i: f.pose() for i, f in valid}
    # Neutral pitch comes from the opening "look straight" frames only (later frames include the tilt).
    opening = [poses[i][1] for i, _ in valid[:6] if abs(poses[i][0]) < YAW_CENTER][:3]
    base_pitch = float(np.median(opening)) if opening else 0.55

    def state(i):
        yaw, pitch = poses[i]
        if yaw > YAW_TURN:
            return "left"
        if yaw < -YAW_TURN:
            return "right"
        if base_pitch - pitch > PITCH_UP_DROP and abs(yaw) < YAW_TURN:
            return "up"
        if abs(yaw) < YAW_CENTER and abs(pitch - base_pitch) < PITCH_UP_DROP / 2:
            return "center"
        return "between"

    states = [(i, state(i)) for i, _ in valid]
    # Ordered plan: center, step1, step2 — each held for >= 2 frames. Every movement must pass through
    # intermediate poses: a real head rotates continuously, a swapped photo jumps between poses.
    plan, k, run, saw_between = ["center", *steps], 0, 0, False
    for i, s in states:
        if k >= len(plan):
            break
        target = plan[k]
        if s == target:
            if target != "center" and run == 0 and not saw_between:
                return LivenessResult(False, "Movement was too abrupt; turn your head slowly and smoothly",
                                      detail={"states": states})
            run += 1
            if run >= 2:
                k, run, saw_between = k + 1, 0, False
        else:
            run = 0
            if s == "between":
                saw_between = True
            elif k > 0 and s in steps and s != plan[k - 1]:
                return LivenessResult(False, "Movements were not in the requested order", detail={"states": states})
    if k < len(plan):
        missing = plan[k]
        msg = "Look straight at the camera first" if missing == "center" else f"Did not detect: {CHALLENGES[missing].lower()}"
        return LivenessResult(False, msg, detail={"states": states})

    # Continuity: no teleporting faces; identity constant in every usable frame.
    for (i, a), (j, b) in zip(valid, valid[1:]):
        (ax, ay), (bx, by) = a.center, b.center
        if np.hypot(bx - ax, by - ay) > 0.6 * max(a.width, b.width) * (j - i):
            return LivenessResult(False, "Face moved discontinuously (possible photo swap)")
    frontal = sorted((abs(poses[i][0]), i) for i, _ in valid)[:3]
    embs = [engine.embed(frames[i], seq[i]) for _, i in frontal]
    ref = embs[0]
    for i, f in valid[:: max(1, len(valid) // 8)]:
        if float(engine.embed(frames[i], f) @ ref) < 0.25:
            return LivenessResult(False, "A different face appeared during the check")
    if any(float(e @ ref) < 0.45 for e in embs[1:]):
        return LivenessResult(False, "Face identity was inconsistent")

    detail = {"yaw_range": [round(min(p[0] for p in poses.values()), 3), round(max(p[0] for p in poses.values()), 3)]}
    if engine.antispoof is None:  # fail closed: the texture check is mandatory
        return LivenessResult(False, f"Anti-spoof check unavailable ({engine.antispoof_error})", detail=detail)
    near_frontal = [(i, f) for i, f in valid if abs(poses[i][0]) <= 0.35]  # model works best within ~±30°
    results = []
    for i, f in near_frontal:
        results.append(engine.antispoof_scores(frames[i], [f])[0])
    v = engine.antispoof.verdict(results, required_consecutive=engine.antispoof_frames)
    detail["antispoof"] = v.as_dict()
    if not v.live:
        return LivenessResult(False, v.reason, detail=detail)
    emb = np.mean(embs, axis=0)
    return LivenessResult(True, "live", frontal[0][1], emb / (np.linalg.norm(emb) + 1e-9), detail)


class PassiveLiveness:
    """CCTV mode: per-track evidence of a live face = natural head movement over time AND the texture
    anti-spoof model passing N consecutive frames. Either failing -> the sighting goes to review."""

    def __init__(self, need_range: float = 0.18, need_seconds: float = 1.2):
        self.need_range, self.need_seconds = need_range, need_seconds
        self.yaws: list[tuple[float, float]] = []
        self.spoof: list[dict | None] = []

    def add(self, t: float, face: Face, antispoof: dict | None = None):
        self.yaws.append((t, face.pose()[0]))
        self.yaws = self.yaws[-60:]
        if antispoof is not None:
            self.spoof.append(antispoof)
            self.spoof = self.spoof[-30:]

    def verdict(self, engine: "FaceEngine | None" = None) -> tuple[bool, dict]:
        if len(self.yaws) < 5:
            return False, {"reason": "too few observations"}
        ys = [y for _, y in self.yaws]
        span = self.yaws[-1][0] - self.yaws[0][0]
        rng = max(ys) - min(ys)
        distinct = len({round(y / 0.05) for y in ys})
        moving = span >= self.need_seconds and rng >= self.need_range and distinct >= 3
        d = {"yaw_range": round(rng, 3), "seconds": round(span, 1), "distinct_poses": distinct, "movement_ok": moving}
        if engine is None or engine.antispoof is None:
            d["antispoof"] = {"live": False, "reason": "anti-spoof unavailable"}
            return False, d
        v = engine.antispoof.verdict(self.spoof, required_consecutive=engine.antispoof_frames)
        d["antispoof"] = v.as_dict()
        return moving and v.live, d
