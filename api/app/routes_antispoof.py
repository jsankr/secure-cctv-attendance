"""Anti-spoof (presentation-attack detection) administration and diagnostics.

Mirrors the reference project's runtime features inside the product:
  * status:     model variant, provider (CUDA/OpenVINO/CPU), CPU/GPU, pinned hashes, source commit, metrics
  * settings:   FP32/INT8, probability threshold (0.5 balanced / 0.8 high security), 3-5 consecutive frames
  * check:      single image or live webcam frames -> per-face real/spoof + logit diff (like demo.py)
  * benchmark:  FP32 vs INT8 size, p50/p95 latency, throughput, >= 60 % size-reduction gate
Images sent to /check are processed in memory and never stored.
"""
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from . import facesvc, models
from .config import settings
from .db import get_db
from .notify import security_alert
from .hardening import ImageRejected, decode_image
from .security import audit, rate_limit, require

import antispoof as A  # noqa: E402  (shared/)

router = APIRouter(prefix="/api/antispoof", tags=["antispoof"])
REFERENCE_METRICS = {"release": "98.20", "dataset": "CelebA-Spoof (71,338 validation samples)", "overall_accuracy": 98.20,
                     "real_accuracy": 97.58, "spoof_accuracy": 98.73, "roc_auc": 0.9984, "average_precision": 0.9987,
                     "trained_attacks": "printed photos, screen displays", "not_trained": "3D silicone masks, prosthetics"}


@router.get("/status")
def status(db: Session = Depends(get_db), _=Depends(require("operator"))):
    cfg = facesvc.as_config(db)
    d = Path(settings.antispoof_dir)
    out = {"settings": cfg, "metrics": REFERENCE_METRICS, "cpu": A.get_cpu_info(), "gpu": A.get_gpu_info(),
           "models": {n: {"present": (d / n).exists(), "sha256": h} for n, h in A.MODEL_SHA256.items()},
           "source_commit": (d / "SOURCE_COMMIT").read_text().strip() if (d / "SOURCE_COMMIT").exists() else None,
           "license": "Apache-2.0 (suriAI/face-antispoof-onnx; MiniFAS from Minivision Silent-Face-Anti-Spoofing)"}
    try:
        with facesvc.locked_engine() as eng:
            out["loaded"] = eng.antispoof is not None
            out["provider"] = eng.antispoof.provider if eng.antispoof else None
            out["error"] = eng.antispoof_error or None
    except HTTPException as e:
        out["loaded"], out["error"] = False, e.detail
    return out


class SettingsIn(BaseModel):
    variant: str = Field(pattern="^(int8|fp32)$")
    threshold: float = Field(ge=0.3, le=0.95)
    frames: int = Field(ge=3, le=5)


@router.put("/settings")
def put_settings(body: SettingsIn, request: Request, db: Session = Depends(get_db), a=Depends(require("admin"))):
    old = facesvc.as_config(db)
    for k, v in body.model_dump().items():
        db.merge(models.Setting(key=f"as.{k}", value=str(v)))
    db.commit()
    facesvc.reset_engine()
    audit(db, a.username, "antispoof_settings", "", request, old=old, new=body.model_dump())
    weaker = body.threshold < old["threshold"] or body.frames < old["frames"]
    security_alert(db, "antispoof_settings_changed", a.username,
                   f"{a.username} changed anti-spoof settings {old} -> {body.model_dump()}" + (" (WEAKER)" if weaker else ""),
                   severity="high" if weaker else "low")
    return facesvc.as_config(db)


@router.post("/check")
def check(request: Request, image: UploadFile = File(...), db: Session = Depends(get_db), u=Depends(require("operator"))):
    """Diagnostics: score every face in one image/frame. Not stored; does not mark attendance."""
    rate_limit(f"ascheck:{u.id}", limit=240, window=60)
    try:
        img = decode_image(image.file.read(4_000_000), max_side=2048, max_pixels=2048 * 2048)
    except ImageRejected as e:
        raise HTTPException(422, str(e))
    with facesvc.locked_engine() as eng:
        if eng.antispoof is None:
            raise HTTPException(503, f"Anti-spoof unavailable: {eng.antispoof_error}")
        faces = [f for f in eng.detect(img, 0.8)]
        scores = eng.antispoof_scores(img, faces)
    h, w = img.shape[:2]
    out = []
    for f, r in zip(faces, scores):
        x, y, bw, bh = f.box
        item = {"box": [round(x / w, 4), round(y / h, 4), round(bw / w, 4), round(bh / h, 4)], "det_score": round(f.score, 3)}
        if r is None:
            item["status"], item["note"] = "skipped", "face smaller than 60 px or within 5 px of the edge"
        else:
            item.update({k: (round(v, 4) if isinstance(v, float) else v) for k, v in r.items()})
        out.append(item)
    return {"width": w, "height": h, "faces": out}


@router.post("/benchmark")
def run_benchmark(request: Request, db: Session = Depends(get_db), a=Depends(require("admin"))):
    rate_limit(f"asbench:{a.id}", limit=3, window=300)
    with facesvc.locked_engine():  # do not compete with live kiosk checks
        res = A.benchmark(settings.antispoof_dir, runs=150)
    audit(db, a.username, "antispoof_benchmark", "", request)
    return res

