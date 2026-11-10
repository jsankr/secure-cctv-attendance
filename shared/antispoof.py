"""Passive face anti-spoofing (presentation-attack detection) — runtime port of suriAI/face-antispoof-onnx.

Source: https://github.com/suriAI/face-antispoof-onnx (Apache-2.0), commit in models/antispoof/SOURCE_COMMIT.
Model: MiniFASNetV2-SE, 128x128 RGB, 2 logits [real, spoof]; "98.20" release, FP32 and INT8.
Based on MiniFAS from Minivision's Silent-Face-Anti-Spoofing (Apache-2.0).

Ported runtime features (behaviour kept identical to the reference implementation):
  * load_model      provider auto-selection (CUDA > OpenVINO > CPU), full graph optimisation
  * crop            square crop, 1.5x bbox expansion, BORDER_REFLECT_101 padding at image edges
  * preprocess      letterbox to 128 (LANCZOS4 up / AREA down), REFLECT_101 border, /255, CHW float32
  * preprocess_batch / infer   batched inference, output-shape validation, [] on empty input
  * process_with_logits        logit_diff = real - spoof; real if >= logit(threshold); confidence = |diff|
  * threshold                  probability threshold -> logit (0.5 balanced, 0.8 high security)
  * detect filter   min face 60 px (64 recommended), 5 px edge margin, detector conf 0.8
  * TemporalFilter  N consecutive "real" frames required (docs: 3-5 for video)
  * system info     CPU / GPU / execution provider; benchmark (p50/p95 latency, throughput, size gate)
Additions for this product: quality gate (low light / backlight / blur), frame-sequence verdicts.
Not shipped (development-only, need PyTorch): dataset preparation, training, checkpoint export,
quantisation scripts, legacy MobileNetV4 code and .pth checkpoints.
"""
from __future__ import annotations

import hashlib
import math
import os
import platform
import statistics
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import cv2
import numpy as np

MODEL_IMG_SIZE = 128
BBOX_EXPANSION = 1.5
MIN_FACE = 60          # reference detect() default
MIN_FACE_RECOMMENDED = 64  # LIMITATIONS.md: below this, spoof artefacts are lost when upscaling
EDGE_MARGIN = 5
DEFAULT_THRESHOLD = 0.5
HIGH_SECURITY_THRESHOLD = 0.8
MODEL_SHA256 = {
    "minifas_98.20_fp32.onnx": "af2381b88f38769222ed93379e12444e2a50814575de1c46170de570c55a42b6",
    "minifas_98.20_int8.onnx": "fde20585635cae62ed1d41796f76b6f8bc4b92cd91ec1cf0f1bc6485d2d587a9",
}


# ------------------------------------------------------------ reference port
def load_model(model_path: str):
    """Return (session, input_name) or (None, None). Refuses files whose SHA-256 is not pinned."""
    import onnxruntime as ort
    p = Path(model_path)
    if not p.exists():
        return None, None
    want = MODEL_SHA256.get(p.name)
    if want and hashlib.sha256(p.read_bytes()).hexdigest() != want:
        raise RuntimeError(f"anti-spoof model {p.name} failed its integrity check")
    try:
        so = ort.SessionOptions()
        so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        so.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        avail = ort.get_available_providers()
        providers = [x for x in ("CUDAExecutionProvider", "OpenVINOExecutionProvider", "CPUExecutionProvider") if x in avail]
        sess = ort.InferenceSession(str(p), sess_options=so, providers=providers or avail)
        return sess, sess.get_inputs()[0].name
    except Exception:
        return None, None


def preprocess(img: np.ndarray, model_img_size: int = MODEL_IMG_SIZE) -> np.ndarray:
    """Resize with letterboxing, normalize to [0,1], convert to CHW. (img is RGB HxWx3 uint8.)"""
    new_size = model_img_size
    old_size = img.shape[:2]
    ratio = float(new_size) / max(old_size)
    scaled_shape = tuple([int(x * ratio) for x in old_size])
    interpolation = cv2.INTER_LANCZOS4 if ratio > 1.0 else cv2.INTER_AREA
    img = cv2.resize(img, (scaled_shape[1], scaled_shape[0]), interpolation=interpolation)
    delta_w = new_size - scaled_shape[1]
    delta_h = new_size - scaled_shape[0]
    top, bottom = delta_h // 2, delta_h - (delta_h // 2)
    left, right = delta_w // 2, delta_w - (delta_w // 2)
    img = cv2.copyMakeBorder(img, top, bottom, left, right, cv2.BORDER_REFLECT_101)
    return img.transpose(2, 0, 1).astype(np.float32) / 255.0


def preprocess_batch(face_crops: list[np.ndarray], model_img_size: int = MODEL_IMG_SIZE) -> np.ndarray:
    if not face_crops:
        raise ValueError("face_crops list cannot be empty")
    batch = np.zeros((len(face_crops), 3, model_img_size, model_img_size), dtype=np.float32)
    for i, c in enumerate(face_crops):
        batch[i] = preprocess(c, model_img_size)
    return batch


def crop(img: np.ndarray, bbox: tuple, bbox_expansion_factor: float = BBOX_EXPANSION) -> np.ndarray:
    """Square face crop from bbox (x1, y1, x2, y2) with expansion; edges padded by reflection."""
    original_height, original_width = img.shape[:2]
    x, y, w, h = bbox
    w = w - x
    h = h - y
    if w <= 0 or h <= 0:
        raise ValueError("Invalid bbox dimensions")
    max_dim = max(w, h)
    center_x = x + w / 2
    center_y = y + h / 2
    x = int(center_x - max_dim * bbox_expansion_factor / 2)
    y = int(center_y - max_dim * bbox_expansion_factor / 2)
    crop_size = int(max_dim * bbox_expansion_factor)
    crop_x1, crop_y1 = max(0, x), max(0, y)
    crop_x2, crop_y2 = min(original_width, x + crop_size), min(original_height, y + crop_size)
    top_pad, left_pad = int(max(0, -y)), int(max(0, -x))
    bottom_pad = int(max(0, (y + crop_size) - original_height))
    right_pad = int(max(0, (x + crop_size) - original_width))
    if crop_x2 > crop_x1 and crop_y2 > crop_y1:
        img = img[crop_y1:crop_y2, crop_x1:crop_x2, :]
    else:
        img = np.zeros((0, 0, 3), dtype=img.dtype)
    result = cv2.copyMakeBorder(img, top_pad, bottom_pad, left_pad, right_pad, cv2.BORDER_REFLECT_101)
    if result.shape[0] != crop_size or result.shape[1] != crop_size:
        raise ValueError(f"Crop size mismatch: expected {crop_size}x{crop_size}, got {result.shape[0]}x{result.shape[1]}")
    return result


def infer(face_crops, ort_session, input_name, model_img_size: int = MODEL_IMG_SIZE) -> list[np.ndarray]:
    if not face_crops or ort_session is None:
        return []
    batch_input = preprocess_batch(face_crops, model_img_size)
    logits = ort_session.run([], {input_name: batch_input})[0]
    if logits.shape != (len(face_crops), 2):
        raise ValueError("Model output shape mismatch")
    return [logits[i] for i in range(len(face_crops))]


def process_with_logits(raw_logits: np.ndarray, threshold: float) -> dict:
    """threshold is a LOGIT threshold (see prob_to_logit)."""
    real_logit, spoof_logit = float(raw_logits[0]), float(raw_logits[1])
    logit_diff = real_logit - spoof_logit
    is_real = logit_diff >= threshold
    return {"is_real": bool(is_real), "status": "real" if is_real else "spoof", "logit_diff": float(logit_diff),
            "real_logit": real_logit, "spoof_logit": spoof_logit, "confidence": float(abs(logit_diff))}


def prob_to_logit(p: float) -> float:
    p = max(1e-6, min(1 - 1e-6, p))
    return float(np.log(p / (1 - p)))


def detect_filter(boxes_xywh, img_w: int, img_h: int, min_face: int = MIN_FACE, margin: int = EDGE_MARGIN):
    """Reference detect() filtering: drop faces outside the frame, within `margin` px of an edge,
    or smaller than `min_face` px."""
    keep = []
    for i, (x, y, w, h) in enumerate(boxes_xywh):
        x, y, w, h = int(x), int(y), int(w), int(h)
        if x < 0 or y < 0 or x + w > img_w or y + h > img_h:
            continue
        if min(x, img_w - (x + w), y, img_h - (y + h)) < margin:
            continue
        if w >= min_face and h >= min_face:
            keep.append(i)
    return keep


class TemporalFilter:
    """Require N consecutive 'real' predictions before accepting (reference LIMITATIONS.md)."""

    def __init__(self, required_frames: int = 3):
        self.required_frames = required_frames
        self.history: deque = deque(maxlen=required_frames)

    def update(self, is_real: bool) -> bool:
        self.history.append(is_real)
        if len(self.history) < self.required_frames:
            return False
        return all(self.history)


# --------------------------------------------------------------- system info
def get_cpu_info() -> str:
    name = platform.processor() or ""
    try:
        if platform.system() == "Linux":
            for line in open("/proc/cpuinfo"):
                if line.startswith("model name"):
                    name = line.split(":", 1)[1].strip()
                    break
        elif platform.system() == "Windows":
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as k:
                name = winreg.QueryValueEx(k, "ProcessorNameString")[0].strip()
        elif platform.system() == "Darwin":
            import subprocess
            name = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True, timeout=2).stdout.strip() or name
    except Exception:
        pass
    return f"{name or 'Unknown CPU'} | {os.cpu_count()} threads"


def get_gpu_info() -> str | None:
    try:
        import subprocess
        r = subprocess.run(["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"], capture_output=True, text=True, timeout=2)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip().split("\n")[0]
    except Exception:
        pass
    return None


def get_execution_provider_name(session) -> str:
    try:
        provs = session.get_providers()
        for k, v in (("CUDAExecutionProvider", "CUDA"), ("OpenVINOExecutionProvider", "OpenVINO"), ("CPUExecutionProvider", "CPU")):
            if k in provs:
                return v
        return provs[0].replace("ExecutionProvider", "") if provs else "Unknown"
    except Exception:
        return "Unknown"


# --------------------------------------------------------- product wrapper
def quality(face_rgb: np.ndarray, context_rgb: np.ndarray) -> tuple[bool, str]:
    """LIMITATIONS.md: low light, harsh backlight and motion blur cause misclassification.
    face_rgb = the detector's face box only; context_rgb = the 1.5x crop around it (its surroundings).
    Returns (ok, reason). A failed quality check means 'retry', never 'real'."""
    g = cv2.cvtColor(face_rgb, cv2.COLOR_RGB2GRAY)
    face_l = float(g.mean())
    if face_l < 45:
        return False, "Face is too dark; improve the lighting"
    ctx_l = float(cv2.cvtColor(context_rgb, cv2.COLOR_RGB2GRAY).mean())
    if face_l < 110 and ctx_l - face_l > 60:
        return False, "Strong backlight behind you; face the light"
    if cv2.Laplacian(g, cv2.CV_64F).var() < 12:
        return False, "Image is blurred; hold still"
    return True, ""


@dataclass
class Verdict:
    live: bool
    reason: str
    frames: int = 0
    real_frames: int = 0
    max_consecutive_real: int = 0
    mean_prob_real: float = 0.0
    min_logit_diff: float = 0.0
    detail: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"live": self.live, "reason": self.reason, "frames": self.frames, "real_frames": self.real_frames,
                "max_consecutive_real": self.max_consecutive_real, "mean_prob_real": round(self.mean_prob_real, 4),
                "min_logit_diff": round(self.min_logit_diff, 3)}


class AntiSpoof:
    def __init__(self, model_dir: str, variant: str = "int8", threshold: float = DEFAULT_THRESHOLD):
        self.variant = variant if variant in ("int8", "fp32") else "int8"
        self.path = Path(model_dir) / f"minifas_98.20_{self.variant}.onnx"
        self.session, self.input_name = load_model(str(self.path))
        if self.session is None:
            raise RuntimeError(f"anti-spoof model not found or unloadable: {self.path}")
        self.set_threshold(threshold)

    def set_threshold(self, p: float):
        self.threshold = float(max(0.05, min(0.99, p)))
        self.logit_threshold = prob_to_logit(self.threshold)

    @property
    def provider(self) -> str:
        return get_execution_provider_name(self.session)

    def score_faces(self, frame_bgr: np.ndarray, boxes_xywh) -> list[dict | None]:
        """Score faces in one frame. Returns one result per box (None if too small / at the edge /
        un-croppable). Faces are cropped from the RGB frame exactly as the reference does."""
        h, w = frame_bgr.shape[:2]
        rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
        keep = set(detect_filter(boxes_xywh, w, h))
        crops, idx = [], []
        out: list[dict | None] = [None] * len(boxes_xywh)
        for i, (x, y, bw, bh) in enumerate(boxes_xywh):
            if i not in keep:
                continue
            try:
                c = crop(rgb, (x, y, x + bw, y + bh), BBOX_EXPANSION)
            except ValueError:
                continue
            fx, fy = max(0, int(x)), max(0, int(y))
            ok, why = quality(rgb[fy:fy + int(bh), fx:fx + int(bw)], c)
            if not ok:
                out[i] = {"status": "unknown", "is_real": False, "quality": why}
                continue
            crops.append(c)
            idx.append(i)
        for i, logits in zip(idx, infer(crops, self.session, self.input_name)):
            r = process_with_logits(logits, self.logit_threshold)
            r["prob_real"] = 1.0 / (1.0 + math.exp(-r["logit_diff"]))
            r["small"] = min(boxes_xywh[i][2], boxes_xywh[i][3]) < MIN_FACE_RECOMMENDED
            out[i] = r
        return out

    def verdict(self, results: list[dict | None], required_consecutive: int = 3, min_real_ratio: float = 0.8) -> Verdict:
        """Sequence decision: >= N consecutive 'real' frames (TemporalFilter) AND >= min_real_ratio of the
        scored frames real. Frames without a usable score are neither real nor spoof."""
        scored = [r for r in results if r and r.get("status") in ("real", "spoof")]
        if not scored:
            qual = [r["quality"] for r in results if r and r.get("quality")]
            return Verdict(False, qual[0] if qual else "Face too small or too close to the edge for the texture check")
        tf, best, run = TemporalFilter(required_consecutive), 0, 0
        for r in scored:
            run = run + 1 if r["is_real"] else 0
            best = max(best, run)
            tf.update(r["is_real"])
        real = sum(1 for r in scored if r["is_real"])
        v = Verdict(False, "", len(scored), real, best, statistics.fmean(r["prob_real"] for r in scored),
                    min(r["logit_diff"] for r in scored))
        if best < required_consecutive or real / len(scored) < min_real_ratio:
            v.reason = "Presentation attack detected (texture check: printed photo or screen suspected)"
            return v
        v.live, v.reason = True, "real"
        return v


def benchmark(model_dir: str, runs: int = 200, batch: int = 1) -> dict:
    """Mirror of the reference Arm64 benchmark workflow: FP32 vs INT8 size, p50/p95 latency, throughput,
    and the >= 60% size-reduction gate. Uses deterministic synthetic tensors (speed, not accuracy)."""
    rng = np.random.default_rng(0)
    x = rng.random((batch, 3, MODEL_IMG_SIZE, MODEL_IMG_SIZE), dtype=np.float32)
    out = {"cpu": get_cpu_info(), "gpu": get_gpu_info(), "batch": batch, "runs": runs, "models": {}}
    for v in ("fp32", "int8"):
        p = Path(model_dir) / f"minifas_98.20_{v}.onnx"
        s, name = load_model(str(p))
        if s is None:
            continue
        for _ in range(10):
            s.run(None, {name: x})
        t = []
        for _ in range(runs):
            t0 = time.perf_counter()
            s.run(None, {name: x})
            t.append((time.perf_counter() - t0) * 1000)
        t.sort()
        out["models"][v] = {"size_kb": round(p.stat().st_size / 1024, 1), "provider": get_execution_provider_name(s),
                            "p50_ms": round(t[len(t) // 2], 3), "p95_ms": round(t[int(len(t) * 0.95) - 1], 3),
                            "throughput_fps": round(1000 * batch / statistics.fmean(t), 1)}
    m = out["models"]
    if "fp32" in m and "int8" in m:
        red = 1 - m["int8"]["size_kb"] / m["fp32"]["size_kb"]
        out["size_reduction_pct"] = round(red * 100, 1)
        out["size_gate_60pct"] = red >= 0.60
        out["speedup_int8"] = round(m["fp32"]["p50_ms"] / m["int8"]["p50_ms"], 2)
    return out
