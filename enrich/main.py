"""Cloud enrichment service: face embeddings, Indian ANPR, re-ID signatures and colour attributes.

Receives ONLY event crops (never live video) over HTTPS from site workers. Stateless: it stores
nothing; watchlist matching happens on-prem. Deploy behind TLS with a bearer token (add mTLS or a
private link for production). Each model is optional and degrades gracefully if not installed.
"""
import logging
import os
import re
import secrets

import cv2
import numpy as np
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("enrich")
TOKEN = os.environ["ENRICH_TOKEN"]
REID_MODEL = os.environ.get("REID_MODEL_PATH", "")  # e.g. OSNet ONNX (input 1x3x256x128)
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

# Indian plates: standard (TN09AB1234) and Bharat series (22BH1234AA)
PLATE_RE = re.compile(r"([A-Z]{2}\d{1,2}[A-Z]{0,3}\d{4}|\d{2}BH\d{4}[A-Z]{1,2})")
VEHICLES = {"car", "motorcycle", "bus", "truck"}
_face = _ocr = _reid = None


def auth(request: Request):
    if not secrets.compare_digest(request.headers.get("authorization", ""), f"Bearer {TOKEN}"):
        raise HTTPException(401)


def face_model():
    global _face
    if _face is None:
        try:
            from insightface.app import FaceAnalysis
            fa = FaceAnalysis(name=os.environ.get("FACE_MODEL", "buffalo_l"), providers=["CPUExecutionProvider"])
            fa.prepare(ctx_id=-1, det_size=(320, 320))
            _face = fa
        except Exception as e:
            log.warning("face model unavailable: %s", e)
            _face = False
    return _face


def ocr_model():
    global _ocr
    if _ocr is None:
        try:
            from rapidocr_onnxruntime import RapidOCR
            _ocr = RapidOCR()
        except Exception as e:
            log.warning("OCR unavailable: %s", e)
            _ocr = False
    return _ocr


def reid_model():
    global _reid
    if _reid is None:
        try:
            import onnxruntime as ort
            _reid = ort.InferenceSession(REID_MODEL, providers=["CPUExecutionProvider"]) if REID_MODEL else False
        except Exception as e:
            log.warning("re-ID model unavailable: %s", e)
            _reid = False
    return _reid


def decode(data: bytes) -> np.ndarray:
    img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise HTTPException(422, "Bad image")
    return img


COLOURS = [("red", 0), ("orange", 18), ("yellow", 30), ("green", 60), ("cyan", 90), ("blue", 115),
           ("purple", 140), ("pink", 165), ("red", 180)]


def colour_name(region: np.ndarray) -> str:
    if region.size == 0:
        return "unknown"
    hsv = cv2.cvtColor(region, cv2.COLOR_BGR2HSV).reshape(-1, 3).astype(np.float32)
    h, s, v = np.median(hsv[:, 0]), np.median(hsv[:, 1]), np.median(hsv[:, 2])
    if v < 50:
        return "black"
    if s < 40:
        return "white" if v > 180 else "grey"
    return min(COLOURS, key=lambda c: abs(c[1] - h))[0]


def attributes(img, cls) -> dict:
    hh = img.shape[0]
    if cls == "person":
        return {"upper_colour": colour_name(img[int(hh * .2):int(hh * .5)]),
                "lower_colour": colour_name(img[int(hh * .55):int(hh * .9)])}
    if cls in VEHICLES:
        return {"colour": colour_name(img[int(hh * .25):int(hh * .75)])}
    return {}


def reid_signature(img) -> list[float]:
    m = reid_model()
    if m:
        x = cv2.resize(img, (128, 256))[:, :, ::-1].astype(np.float32) / 255.0
        x = ((x - [0.485, 0.456, 0.406]) / [0.229, 0.224, 0.225]).transpose(2, 0, 1)[None].astype(np.float32)
        v = m.run(None, {m.get_inputs()[0].name: x})[0].flatten()
    else:  # fallback: spatial HSV histogram (coarse, same-day appearance matching only)
        hsv = cv2.cvtColor(cv2.resize(img, (64, 128)), cv2.COLOR_BGR2HSV)
        v = np.concatenate([cv2.calcHist([part], [0, 1], None, [12, 4], [0, 180, 0, 256]).flatten()
                            for part in np.array_split(hsv, 3, axis=0)])
    v = v / (np.linalg.norm(v) + 1e-9)
    return [round(float(x), 5) for x in v]


def read_plate(img) -> dict | None:
    ocr = ocr_model()
    if not ocr:
        return None
    hh = img.shape[0]
    res, _ = ocr(img[int(hh * .35):])  # plates sit in the lower part of a vehicle crop
    if not res:
        return None
    lines = [("".join(ch for ch in t.upper() if ch.isalnum()), float(c)) for _, t, c in res]
    candidates = lines + [(a[0] + b[0], min(a[1], b[1])) for a, b in zip(lines, lines[1:])]  # 2-line plates
    for text, conf in sorted(candidates, key=lambda x: -x[1]):
        m = PLATE_RE.search(text)
        if m:
            return {"text": m.group(1), "conf": round(conf, 3)}
    return None


def faces(img) -> list[dict]:
    fa = face_model()
    if not fa:
        return []
    out = []
    for f in fa.get(img):
        x1, y1, x2, y2 = f.bbox
        if f.det_score >= 0.6 and min(x2 - x1, y2 - y1) >= 40:  # too-small faces give unreliable matches
            out.append({"embedding": [round(float(x), 5) for x in f.normed_embedding],
                        "det_score": round(float(f.det_score), 3)})
    return out


@app.post("/enrich", dependencies=[Depends(auth)])
async def enrich(image: UploadFile = File(...), cls: str = Form(...)):
    img = decode(await image.read())
    out = {"attributes": attributes(img, cls), "reid": reid_signature(img)}
    if cls == "person":
        out["faces"] = faces(img)
    elif cls in VEHICLES:
        p = read_plate(img)
        if p:
            out["plate"] = p
    return out


@app.post("/embed/face", dependencies=[Depends(auth)])
async def embed_face(image: UploadFile = File(...)):
    fs = faces(decode(await image.read()))
    if not fs:
        raise HTTPException(422, "No clear face found (needs a frontal face >= 40px)")
    return {"embedding": max(fs, key=lambda f: f["det_score"])["embedding"]}


@app.get("/health")
def health():
    return {"ok": True}
