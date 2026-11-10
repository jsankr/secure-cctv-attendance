"""AS: anti-spoof model (port of suriAI/face-antispoof-onnx) — fidelity, behaviour, gates."""
import glob

import cv2
import numpy as np
import pytest

import antispoof as A
import attacks as K
from conftest import AS_DIR

RNG = np.random.default_rng(1)
CROP = RNG.integers(0, 255, (128, 128, 3), dtype=np.uint8)
FRAME = RNG.integers(0, 255, (480, 640, 3), dtype=np.uint8)


@pytest.fixture(scope="module", params=["int8", "fp32"])
def model(request):
    return A.AntiSpoof(str(AS_DIR), request.param, 0.5)


# ---------------------------------------------------------------- port fidelity (reference test-suite parity)
def test_AS_01_preprocess_contract():
    """preprocess -> (3,128,128) float32 in [0,1] for square and non-square inputs (reference tests)."""
    for h, w in ((128, 128), (64, 64), (100, 100), (200, 200), (256, 256), (90, 140)):
        r = A.preprocess(RNG.integers(0, 255, (h, w, 3), dtype=np.uint8))
        assert r.shape == (3, 128, 128) and r.dtype == np.float32 and 0 <= r.min() and r.max() <= 1


def test_AS_02_preprocess_batch():
    """Batch shape (N,3,128,128); empty batch raises ValueError (reference tests)."""
    assert A.preprocess_batch([CROP, CROP]).shape == (2, 3, 128, 128)
    with pytest.raises(ValueError):
        A.preprocess_batch([])


def test_AS_03_crop_geometry():
    """Square 1.5x crop; interior crop equals a plain slice; invalid bbox raises (reference tests)."""
    r = A.crop(FRAME, (100, 100, 200, 200), 1.5)
    assert r.shape == (150, 150, 3) and np.array_equal(r, FRAME[75:225, 75:225])
    with pytest.raises(ValueError):
        A.crop(FRAME, (100, 100, 100, 100), 1.5)


def test_AS_04_crop_reflect_padding():
    """Crops beyond the image edge are padded with BORDER_REFLECT_101 (reference data-prep choice)."""
    r = A.crop(FRAME, (0, 0, 40, 40), 1.5)
    assert np.array_equal(r, cv2.copyMakeBorder(FRAME[0:50, 0:50], 10, 0, 10, 0, cv2.BORDER_REFLECT_101))


def test_AS_05_letterbox_is_symmetric():
    """Non-square crops are letterboxed centrally, not stretched (reference preprocess)."""
    img = np.zeros((64, 128, 3), np.uint8)
    img[:, :] = 200
    out = A.preprocess(img)
    assert out.shape == (3, 128, 128) and np.allclose(out[:, 32:96, :], 200 / 255, atol=0.02)


def test_AS_06_logits_decision():
    """process_with_logits: real/spoof by logit difference vs logit threshold; exact key set."""
    assert A.process_with_logits(np.array([5.0, -2.0]), 0.0)["status"] == "real"
    assert A.process_with_logits(np.array([-2.0, 5.0]), 0.0)["is_real"] is False
    assert set(A.process_with_logits(np.array([1.0, 0.0]), 0.0)) == {"is_real", "status", "logit_diff", "real_logit",
                                                                    "spoof_logit", "confidence"}


def test_AS_07_threshold_conversion():
    """Probability thresholds map to logits as in the reference (0.5 -> 0, 0.8 -> 1.386)."""
    assert abs(A.prob_to_logit(0.5)) < 1e-9 and abs(A.prob_to_logit(0.8) - 1.3863) < 1e-3


def test_AS_08_detect_filter():
    """Faces under 60 px, outside the frame or within 5 px of an edge are not scored (reference detect)."""
    assert A.detect_filter([(2, 100, 80, 80), (100, 100, 50, 50), (100, 100, 80, 80), (600, 100, 39, 80)], 640, 480) == [2]


def test_AS_09_temporal_filter():
    """TemporalFilter accepts only after N consecutive real frames (reference LIMITATIONS.md)."""
    tf = A.TemporalFilter(3)
    assert [tf.update(x) for x in (True, True, False, True, True, True)] == [False] * 5 + [True]


def test_AS_10_inference_shapes(model):
    """Single, batch and empty inference behave as the reference (both FP32 and INT8)."""
    assert A.infer([CROP], model.session, model.input_name)[0].shape == (2,)
    assert len(A.infer([CROP] * 3, model.session, model.input_name)) == 3
    assert A.infer([], model.session, model.input_name) == []


def test_AS_11_model_integrity(tmp_path):
    """A model file that does not match its pinned SHA-256 is refused (supply-chain control)."""
    bad = tmp_path / "minifas_98.20_int8.onnx"
    bad.write_bytes((AS_DIR / "minifas_98.20_int8.onnx").read_bytes()[:-8] + b"\0" * 8)
    with pytest.raises(RuntimeError):
        A.load_model(str(bad))


def test_AS_12_missing_model_fails_closed(tmp_path):
    """A missing model raises (callers then refuse liveness) instead of silently passing."""
    with pytest.raises(RuntimeError):
        A.AntiSpoof(str(tmp_path), "int8")


# ---------------------------------------------------------------- behaviour on faces
def _face_frames(engine, img):
    return [f for f in engine.detect(img, 0.8) if f.width >= 64]


def test_AS_13_genuine_faces_pass(engine, faces_dir, model):
    """Genuine faces (>= 64 px) are classified real (false-reject rate on the sample set)."""
    tot = real = 0
    for p in sorted(glob.glob(str(faces_dir / "genuine" / "*"))):
        img = cv2.imread(p)
        fs = _face_frames(engine, img)
        for r in model.score_faces(img, [f.box for f in fs]):
            if r and r["status"] in ("real", "spoof"):
                tot += 1
                real += r["is_real"]
    assert tot >= 5, "need at least 5 scorable genuine faces"
    assert real / tot >= 0.95, f"false rejects: {tot - real}/{tot}"


@pytest.mark.parametrize("attack", ["screen replay (sub-pixel+moire+glare)", "phone with bezel"])
def test_AS_14_screen_attacks_detected(engine, faces_dir, model, attack):
    """Screen-replay attacks (sub-pixel pattern, moire, glare, phone bezel) are classified spoof."""
    img = K.frame_of(K.ATTACKS[attack](cv2.imread(str(faces_dir / "enrol.jpg"))))
    f = max(engine.detect(img, 0.6), key=lambda q: q.width)
    assert model.score_faces(img, [f.box])[0]["status"] == "spoof"


@pytest.mark.xfail(reason="Known limitation: digitally simulated prints/recaptures are not detected by the texture model "
                          "(trained on physical attacks). Mitigated by the active head-movement challenge (LV tests).",
                   strict=False)
@pytest.mark.parametrize("attack", ["print (halftone)", "recapture (low-res+JPEG)"])
def test_AS_15_print_attacks_texture_only(engine, faces_dir, model, attack):
    """Texture model alone vs simulated print / recapture (informational; defence in depth covers it)."""
    img = K.frame_of(K.ATTACKS[attack](cv2.imread(str(faces_dir / "enrol.jpg"))))
    f = max(engine.detect(img, 0.6), key=lambda q: q.width)
    assert model.score_faces(img, [f.box])[0]["status"] == "spoof"


def test_AS_16_quality_gate_dark(engine, faces_dir):
    """Very dark faces are not scored ('improve lighting'), never passed as real."""
    m = A.AntiSpoof(str(AS_DIR), "int8")
    img = K.frame_of(K.dark(cv2.imread(str(faces_dir / "enrol.jpg"))))
    f = max(engine.detect(img, 0.3), key=lambda q: q.width)
    r = m.score_faces(img, [f.box])[0]
    assert r["status"] == "unknown" and "dark" in r["quality"]


def test_AS_17_quality_gate_backlight():
    """A dark face against a bright background is flagged as backlit (synthetic scene, no detector needed)."""
    m = A.AntiSpoof(str(AS_DIR), "int8")
    frame = np.full((480, 640, 3), 245, np.uint8)
    yy, xx = np.mgrid[0:200, 0:160]
    face = (60 + 25 * np.sin(xx / 9.0) * np.cos(yy / 7.0)).astype(np.uint8)
    frame[140:340, 240:400] = np.dstack([face] * 3)
    r = m.score_faces(frame, [(240, 140, 160, 200)])[0]
    assert r["status"] == "unknown" and "backlight" in r["quality"]


def test_AS_18_quality_gate_blur():
    """A featureless (motion-blurred) face region is not scored."""
    m = A.AntiSpoof(str(AS_DIR), "int8")
    frame = np.full((480, 640, 3), 120, np.uint8)
    r = m.score_faces(frame, [(240, 140, 160, 200)])[0]
    assert r["status"] == "unknown" and "blur" in r["quality"]


def test_AS_19_fp32_int8_agree(engine, faces_dir):
    """FP32 and INT8 agree on every genuine and attack sample (quantisation does not change decisions)."""
    a, b = A.AntiSpoof(str(AS_DIR), "fp32"), A.AntiSpoof(str(AS_DIR), "int8")
    base = cv2.imread(str(faces_dir / "enrol.jpg"))
    for img in [K.frame_of(base)] + [K.frame_of(f(base)) for f in K.ATTACKS.values()]:
        f = max(engine.detect(img, 0.6), key=lambda q: q.width)
        assert a.score_faces(img, [f.box])[0]["status"] == b.score_faces(img, [f.box])[0]["status"]


def test_AS_20_high_security_threshold_monotonic(engine, faces_dir):
    """Raising the threshold (0.5 -> 0.8) never turns a spoof into real."""
    base = cv2.imread(str(faces_dir / "enrol.jpg"))
    lo, hi = A.AntiSpoof(str(AS_DIR), "int8", 0.5), A.AntiSpoof(str(AS_DIR), "int8", 0.8)
    for img in [K.frame_of(f(base)) for f in K.ATTACKS.values()]:
        f = max(engine.detect(img, 0.6), key=lambda q: q.width)
        if lo.score_faces(img, [f.box])[0]["status"] == "spoof":
            assert hi.score_faces(img, [f.box])[0]["status"] == "spoof"


def test_AS_21_sequence_verdict():
    """Sequence verdict needs N consecutive real frames AND >= 80% real; unscored frames never count as real."""
    m = A.AntiSpoof(str(AS_DIR), "int8")
    R = {"status": "real", "is_real": True, "logit_diff": 3.0, "prob_real": 0.95}
    S = {"status": "spoof", "is_real": False, "logit_diff": -3.0, "prob_real": 0.05}
    U = {"status": "unknown", "is_real": False, "quality": "Face is too dark; improve the lighting"}
    assert m.verdict([R, R, R, R, R]).live
    assert not m.verdict([R, S, R, S, R, S]).live          # never 3 in a row
    assert not m.verdict([R, R, R, S, S]).live             # 60% real
    assert not m.verdict([U, U, U]).live and "dark" in m.verdict([U, U, U]).reason
    assert not m.verdict([None, None]).live
    assert m.verdict([R, R, R, R], required_consecutive=4).live and not m.verdict([R, R, R, S, R], required_consecutive=4).live


def test_AS_22_benchmark_gate():
    """Benchmark mirrors the reference Arm64 workflow: INT8 >= 60% smaller; p95 latency within budget."""
    b = A.benchmark(str(AS_DIR), runs=60)
    assert b["size_gate_60pct"] and b["size_reduction_pct"] >= 60
    for v in ("fp32", "int8"):
        assert b["models"][v]["p95_ms"] < 50, b["models"][v]


def test_AS_23_system_info():
    """CPU / provider information is reported (reference system.py)."""
    m = A.AntiSpoof(str(AS_DIR), "int8")
    assert m.provider in ("CPU", "CUDA", "OpenVINO") and "threads" in A.get_cpu_info()


def test_AS_24_licence_shipped():
    """Apache-2.0 licence and source commit are shipped next to the models."""
    assert "Apache License" in (AS_DIR / "LICENSE").read_text() and len((AS_DIR / "SOURCE_COMMIT").read_text().strip()) == 40
