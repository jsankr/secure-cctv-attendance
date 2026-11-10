"""Shared fixtures + a result collector for the test report.

Test IDs: <PREFIX>_<NN> in the function name; the docstring's first line is the test's purpose.
Prefixes: HD hardening, CR crypto, AS anti-spoof, FE face engine, LV liveness/spoof abuse, MT media,
PL privacy pipeline (end to end), FN API functional, AB API abuse, CY API cyber, UI console.
Optional inputs (tests skip, never fail, when absent):
  VMS_TEST_FACES   folder with face images (genuine faces >= 64 px; see tests/README.md)
  VMS_MODELS_DIR   folder holding the YuNet / SFace models (default: the launcher's data folder)
  VMS_MEDIAMTX     path to the mediamtx binary (default: the launcher's data folder)
"""
import json
import os
import platform
import re
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "shared"), str(ROOT / "api"), str(ROOT / "tests")]


def data_home() -> Path:
    if os.environ.get("VMS_HOME"):
        return Path(os.environ["VMS_HOME"])
    if os.name == "nt":
        return Path(os.environ.get("USERPROFILE", Path.home())) / "SentinelAttend"
    if platform.system() == "Darwin":
        return Path.home() / "Library" / "Application Support" / "SentinelAttend"
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "SentinelAttend"


MODELS = Path(os.environ.get("VMS_MODELS_DIR") or data_home() / "models")
DET = MODELS / "face_detection_yunet_2023mar.onnx"
REC = MODELS / "face_recognition_sface_2021dec.onnx"
AS_DIR = ROOT / "models" / "antispoof"
FACES = Path(os.environ["VMS_TEST_FACES"]) if os.environ.get("VMS_TEST_FACES") else None
MEDIAMTX = Path(os.environ.get("VMS_MEDIAMTX") or data_home() / "bin" / ("mediamtx.exe" if os.name == "nt" else "mediamtx"))


@pytest.fixture(scope="session")
def engine():
    if not (DET.exists() and REC.exists()):
        pytest.skip(f"face models not found in {MODELS}")
    import faceengine as F
    return F.FaceEngine(str(DET), str(REC), str(AS_DIR))


@pytest.fixture(scope="session")
def faces_dir():
    if not FACES or not FACES.exists():
        pytest.skip("VMS_TEST_FACES not set (genuine face images needed)")
    return FACES


# ------------------------------------------------------------- report plugin
_RESULTS: list[dict] = []
_ID = re.compile(r"test_([A-Z]{2})_(\d+)")


def pytest_runtest_logreport(report):
    if report.when != "call" and not (report.when == "setup" and report.outcome in ("skipped", "failed")):
        return
    m = _ID.search(report.nodeid)
    doc = ""
    item = getattr(report, "_doc", "")
    if item:
        doc = item
    entry = {"nodeid": report.nodeid, "id": f"{m.group(1)}-{m.group(2)}" if m else report.nodeid.split("::")[-1],
             "prefix": m.group(1) if m else "", "outcome": report.outcome, "duration_s": round(report.duration, 3),
             "title": doc, "message": ""}
    if hasattr(report, "wasxfail"):
        entry["outcome"] = "xfailed" if report.skipped else "xpassed"
        entry["message"] = str(report.wasxfail)
    elif report.failed:
        entry["message"] = str(report.longrepr)[-1500:]
    elif report.skipped:
        lr = report.longrepr
        entry["message"] = lr[2] if isinstance(lr, tuple) and len(lr) == 3 else str(lr)
    _RESULTS.append(entry)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    fn = getattr(item, "function", None)
    rep._doc = ((fn.__doc__ or "").strip().splitlines() or [""])[0] if fn else ""


def pytest_sessionfinish(session, exitstatus):
    out = os.environ.get("VMS_TEST_REPORT_JSON") or str(ROOT / "tests" / ".last_results.json")
    meta = {"started": time.strftime("%Y-%m-%d %H:%M:%S"), "python": platform.python_version(),
            "platform": f"{platform.system()} {platform.release()} {platform.machine()}", "host": platform.node()}
    Path(out).write_text(json.dumps({"meta": meta, "results": _RESULTS}, indent=1))
