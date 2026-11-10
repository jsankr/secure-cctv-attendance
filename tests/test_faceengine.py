"""FE: recognition, blurring, selective unblur.  LV: liveness and spoofing abuse cases."""
import itertools

import cv2
import numpy as np
import pytest

import antispoof as A
import faceengine as F
from conftest import AS_DIR


# ================================================================= FE
def _biggest(engine, img):
    return max(engine.detect(img, 0.6), key=lambda f: f.width)


def test_FE_01_recognises_enrolled_person(engine, faces_dir):
    """The enrolled person is matched in a group photo; margin over the next face is respected."""
    enrol, group = cv2.imread(str(faces_dir / "enrol.jpg")), cv2.imread(str(faces_dir / "group.jpg"))
    ref = engine.embed(enrol, _biggest(engine, enrol))
    scores = sorted((float(engine.embed(group, f) @ ref) for f in engine.detect(group, 0.6)), reverse=True)
    assert scores[0] >= 0.42 and scores[0] - scores[1] >= 0.06, scores


def test_FE_02_impostors_rejected(engine, faces_dir):
    """Nobody else in the group photo crosses the match threshold (false-accept check)."""
    enrol, group = cv2.imread(str(faces_dir / "enrol.jpg")), cv2.imread(str(faces_dir / "group.jpg"))
    ref = engine.embed(enrol, _biggest(engine, enrol))
    gallery = {1: [ref]}
    hits = [F.FaceEngine.match(engine.embed(group, f), gallery, 0.42, 0.06)[0] for f in engine.detect(group, 0.6)]
    assert hits.count(1) == 1


def test_FE_03_blur_removes_faces(engine, faces_dir):
    """After anonymise(), the detector finds (almost) no confident faces in genuine images."""
    for p in sorted((faces_dir / "genuine").glob("*")):
        img = cv2.imread(str(p))
        before = len([f for f in engine.detect(img, 0.6) if f.score > 0.75])
        out = F.anonymise(img.copy(), [f.box for f in engine.detect(img, 0.45)])
        after = len([f for f in engine.detect(out, 0.6) if f.score > 0.75])
        assert after == 0, (p.name, before, after)


def test_FE_04_blur_irreversible_identity(engine, faces_dir):
    """Defect D-11 regression: no blurred face matches its original (identity cosine < 0.42, all images)."""
    imgs = [cv2.imread(str(p)) for p in sorted((faces_dir / "genuine").glob("*"))]
    g = cv2.imread(str(faces_dir / "group.jpg"))
    imgs.append(cv2.resize(g, (1280, int(g.shape[0] * 1280 / g.shape[1]))))
    worst = 0.0
    for img in imgs:
        fs = engine.detect(img, 0.45)
        out = F.anonymise(img.copy(), [f.box for f in fs])
        worst = max([worst] + [float(engine.embed(img, f) @ engine.embed(out, f)) for f in fs if f.width >= 40])
    assert worst < 0.42, worst


def test_FE_05_persistent_blur_covers_missed_frames():
    """A face missed by the detector for a few frames stays blurred (PersistentBlur hold)."""
    pb = F.PersistentBlur(hold=4)
    box = (100, 100, 80, 80)
    assert pb.update([box]) == [box]
    assert all(pb.update([]) == [box] for _ in range(3))
    assert pb.update([]) == []


def test_FE_06_fail_closed_full_blur():
    """blur_full destroys detail across the whole frame (used when detection fails)."""
    img = np.random.default_rng(0).integers(0, 255, (360, 640, 3), dtype=np.uint8)
    out = F.blur_full(img)
    assert cv2.Laplacian(cv2.cvtColor(out, cv2.COLOR_BGR2GRAY), cv2.CV_64F).var() < 5


def test_FE_07_selective_unblur_only_target(engine, faces_dir):
    """Approved unblur reveals ONLY the requested person; everyone else stays blurred."""
    enrol, group = cv2.imread(str(faces_dir / "enrol.jpg")), cv2.imread(str(faces_dir / "group.jpg"))
    group = cv2.resize(group, (1280, int(group.shape[0] * 1280 / group.shape[1])))
    ref = engine.embed(enrol, _biggest(engine, enrol))
    sel = F.SelectiveUnblur(engine, [ref], 0.38)
    out = sel(group.copy(), 0)
    visible = [f for f in engine.detect(out, 0.6) if f.score > 0.75]
    assert len(visible) == 1 and float(engine.embed(out, visible[0]) @ ref) >= 0.42


def test_FE_08_selective_unblur_unknown_person(engine, faces_dir):
    """If the requested person is not in the footage, every face remains blurred."""
    group = cv2.imread(str(faces_dir / "group.jpg"))
    sel = F.SelectiveUnblur(engine, [np.eye(128, dtype=np.float32)[5]], 0.38)
    out = sel(cv2.resize(group, (1280, int(group.shape[0] * 1280 / group.shape[1]))), 0)
    assert not [f for f in engine.detect(out, 0.6) if f.score > 0.75] and sel.frames_kept == 0


# ================================================================= LV
IOD, DM = 60.0, 70.0
R = {"status": "real", "is_real": True, "logit_diff": 4.0, "prob_real": 0.98}
S = {"status": "spoof", "is_real": False, "logit_diff": -4.0, "prob_real": 0.02}


def face(yaw, pitch=0.55, cx=320, cy=240):
    lm = np.float32([[-IOD / 2, 0], [IOD / 2, 0], [yaw * IOD, pitch * DM], [-0.35 * IOD, DM], [0.35 * IOD, DM]]) + [cx, cy - 30]
    return F.Face((cx - 60, cy - 80, 120.0, 150.0), 0.95, lm, np.zeros(15, np.float32))


class Fake:
    """Engine stub: frames are indices; detection, identity and texture scores are scripted.
    The real AntiSpoof sequence logic is used for the verdict."""

    def __init__(self, seq, ids=None, spoof=None, antispoof=True):
        self.seq, self.ids = seq, ids or [0] * len(seq)
        self.spoof = spoof or [R] * len(seq)
        self.antispoof = A.AntiSpoof(str(AS_DIR), "int8") if antispoof else None
        self.antispoof_frames, self.antispoof_error = 3, "" if antispoof else "model missing"

    def detect(self, img, s=0.45):
        f = self.seq[int(img[0, 0, 0])]
        return [f] if f else []

    def embed(self, img, f):
        v = np.zeros(128, np.float32)
        v[self.ids[int(img[0, 0, 0])]] = 1
        return v

    def antispoof_scores(self, img, faces):
        return [self.spoof[int(img[0, 0, 0])]]


def run(seq, steps, **kw):
    fs = [face(y, p) if y is not None else None for y, p in seq]
    return F.verify_kiosk(Fake(fs, **kw), [np.full((4, 4, 3), i, np.uint8) for i in range(len(fs))], steps)


def sm(a, b, p=.55):
    return [(a + (b - a) * t / 4, p) for t in range(1, 5)]


def pose_of(step, p0=.55):
    return {"left": (.35, p0), "right": (-.35, p0), "up": (0, p0 - .16)}[step]


def seq_for(steps, p0=.55):
    out, cur = [(0, p0)] * 3, (0, p0)
    for s in steps:
        tgt = pose_of(s, p0)
        out += [(cur[0] + (0 - cur[0]) * t / 3, cur[1] + (p0 - cur[1]) * t / 3) for t in range(1, 4)]  # back to centre
        out += [(tgt[0] * t / 4, p0 + (tgt[1] - p0) * t / 4) for t in range(1, 5)] + [tgt] * 2
        cur = tgt
    return out


def test_LV_01_challenge_entropy():
    """Challenges are 3 random moves, never the same move twice in a row: 12 possible sequences."""
    seen = {tuple(F.new_challenge()["steps"]) for _ in range(3000)}
    assert len(seen) == 12 and all(a != b for s in seen for a, b in zip(s, s[1:]))


@pytest.mark.parametrize("steps", sorted({s for s in itertools.product(F.CHALLENGES, repeat=3) if s[0] != s[1] and s[1] != s[2]}))
def test_LV_02_genuine_user_every_sequence(steps):
    """A real user performing the requested sequence passes (all 12 sequences)."""
    r = run(seq_for(list(steps)), list(steps))
    assert r.live, r.reason


@pytest.mark.parametrize("p0", [0.45, 0.55, 0.65])
def test_LV_03_face_geometry_variation(p0):
    """Users with different neutral face geometry pass (no bias from a fixed pitch baseline)."""
    steps = ["up", "left", "right"]
    assert run(seq_for(steps, p0), steps).live


def test_LV_04_printed_photo_moved():
    """Printed photo waved / tilted in front of the camera fails (pose never changes like a head)."""
    r = run([(0.03 * np.sin(i), .55) for i in range(40)], ["left", "up", "right"])
    assert not r.live


def test_LV_05_photo_swap():
    """Swapping between photos of different poses fails (no intermediate poses)."""
    r = run([(0, .55)] * 4 + [(.35, .55)] * 4 + [(0, .39)] * 4 + [(-.35, .55)] * 4, ["left", "up", "right"])
    assert not r.live and "abrupt" in r.reason


def test_LV_06_camera_covered_during_swap():
    """Covering the camera while swapping photos fails."""
    r = run([(0, .55)] * 4 + [(None, 0)] * 3 + [(.35, .55)] * 4 + [(None, 0)] * 2 + [(-.35, .55)] * 4, ["left", "right", "left"])
    assert not r.live


def test_LV_07_prerecorded_wrong_order():
    """A pre-recorded video with the movements in another order fails."""
    r = run(seq_for(["right", "left", "up"]), ["left", "right", "up"])
    assert not r.live and "order" in r.reason


def test_LV_08_person_swap_mid_check():
    """A different person taking over mid-check fails."""
    seq = seq_for(["left", "right", "up"])
    ids = [0] * 10 + [7] * (len(seq) - 10)
    assert not run(seq, ["left", "right", "up"], ids=ids).live


def test_LV_09_screen_replay_of_genuine_moves():
    """Correct moves shown on a phone/monitor (replay or live relay) fail on the texture check."""
    seq = seq_for(["left", "up", "right"])
    r = run(seq, ["left", "up", "right"], spoof=[S] * len(seq))
    assert not r.live and "Presentation attack" in r.reason


def test_LV_10_intermittent_spoof_frames():
    """A sequence where texture flips real/spoof (no 3 consecutive real) fails."""
    seq = seq_for(["left", "up", "right"])
    assert not run(seq, ["left", "up", "right"], spoof=[R if i % 2 else S for i in range(len(seq))]).live


def test_LV_11_antispoof_missing_fails_closed():
    """With the anti-spoof model unavailable, liveness never passes (fail closed)."""
    seq = seq_for(["left", "up", "right"])
    r = run(seq, ["left", "up", "right"], antispoof=False)
    assert not r.live and "unavailable" in r.reason


def test_LV_12_too_few_frames_and_multi_face():
    """Too few frames, or two faces in view, are rejected."""
    assert not run([(0, .55)] * 6, ["left", "up", "right"]).live
    fs = [face(0)] * 20
    eng = Fake(fs)
    eng.detect = lambda img, s=0.45: [face(0, cx=200), face(0, cx=440)]
    assert not F.verify_kiosk(eng, [np.full((4, 4, 3), i, np.uint8) for i in range(20)], ["left", "up", "right"]).live


def test_LV_13_planar_photo_geometry(engine, faces_dir):
    """A real photo rotated as a rigid plane (+/-50 deg) never reaches the yaw a head turn produces."""
    img = cv2.imread(str(faces_dir / "enrol.jpg"))
    h, w = img.shape[:2]
    for deg in (-50, -30, 30, 50):
        a, f = np.deg2rad(deg), w * 1.2
        src = np.float32([[0, 0], [w, 0], [w, h], [0, h]])
        dst = []
        for x, y in src - [w / 2, h / 2]:
            X, Z = x * np.cos(a), x * np.sin(a) + f
            dst.append([X * f / Z + w / 2, y * f / Z + h / 2])
        warped = cv2.warpPerspective(img, cv2.getPerspectiveTransform(src, np.float32(dst)), (w, h))
        fs = engine.detect(warped, 0.6)
        if fs:
            assert abs(max(fs, key=lambda q: q.width).pose()[0]) < F.YAW_TURN


def test_LV_14_passive_cctv_needs_movement_and_texture():
    """CCTV liveness = natural head movement AND anti-spoof; either missing -> review."""
    eng = Fake([])
    moving = [(t * 0.3, face(0.25 * np.sin(t))) for t in range(12)]
    still = [(t * 0.3, face(0.01)) for t in range(12)]
    for track, scores, expect in ((moving, [R] * 12, True), (moving, [S] * 12, False), (still, [R] * 12, False)):
        p = F.PassiveLiveness()
        for (t, f), sc in zip(track, scores):
            p.add(t, f, sc)
        assert p.verdict(eng)[0] is expect
    p = F.PassiveLiveness()
    for t, f in moving:
        p.add(t, f, R)
    assert p.verdict(None)[0] is False  # no anti-spoof engine -> never live
