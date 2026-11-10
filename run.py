#!/usr/bin/env python3
"""Sentinel Attend — single-file installer + launcher (Windows, macOS, Linux). No Docker, no shell scripts.

    python run.py                  install on first run, then start everything
    python run.py --setup-ai       also export an object-detection model (one-off, ~1 GB)
    python run.py --webcam         add this laptop's webcam as a camera
    python run.py --simulate 8     add 8 synthetic cameras (connectivity / live-wall load test)
    python run.py --videos C:/clips  stream every video in a folder as a looping camera (AI demo)
    python run.py --clear-sims     remove simulated / video / webcam cameras
    python run.py --selftest [--test-faces DIR]   run all functional / abuse / cyber tests + HTML report
    python run.py --port 9000      serve the console on another port
    python run.py --no-browser     do not open the browser
    python run.py --reset          wipe local data (users, events, snapshots, recordings)

Only prerequisite: Python 3.10+ (3.12 recommended). Everything else (packages, MediaMTX, ffmpeg)
is installed by this script. Everything binds to 127.0.0.1. Data lives in your local app-data folder (never a synced folder).
Simulation choices are remembered between runs.
"""
import argparse
import base64
import hashlib
import io
import json
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import time
import urllib.request
import webbrowser
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WIN = os.name == "nt"


def _default_home() -> Path:
    """Per-user local data folder, never inside OneDrive/Dropbox/iCloud-synced folders, so footage,
    the database and secrets are not uploaded anywhere. Override with VMS_HOME.

    Windows uses %USERPROFILE%\\SentinelAttend rather than %LOCALAPPDATA%: Microsoft Store Python
    silently redirects AppData writes into its private package cache, which splits files between
    the sandboxed and real paths. The profile root is neither redirected nor synced by OneDrive."""
    if os.environ.get("VMS_HOME"):
        return Path(os.environ["VMS_HOME"]).expanduser().resolve()
    if WIN:
        return Path(os.environ.get("USERPROFILE") or Path.home()) / "SentinelAttend"
    elif platform.system() == "Darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "SentinelAttend"


HOME = _default_home()
LEGACY_HOME = ROOT / ".laptop"


def previous_homes() -> list[Path]:
    """Locations used by earlier versions (and Store-Python sandbox copies of them)."""
    out = [LEGACY_HOME]
    if WIN:
        local = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        out.append(local / "SentinelAttend")
        out += sorted((local / "Packages").glob("PythonSoftwareFoundation.Python.*/LocalCache/Local/SentinelAttend"))
    return out


CLOUD_MARKERS = ("onedrive", "dropbox", "google drive", "googledrive", "icloud", "box sync", "nextcloud")
VENV = HOME / "venv"
BIN = HOME / "bin"
DATA = HOME / "data"
LOGS = HOME / "logs"
MODELS = HOME / "models"
VPY = VENV / ("Scripts/python.exe" if WIN else "bin/python")
MTX_VERSION = "v1.9.3"
# SHA-256 of each official MediaMTX v1.9.3 release archive (the release publishes no checksum file).
MTX_SHA256 = {
    "mediamtx_v1.9.3_linux_amd64.tar.gz": "0b885dbfa4ef9c14cd00191c57d90d804255ff50403a28b85ceee7988c535b60",
    "mediamtx_v1.9.3_linux_arm64v8.tar.gz": "f2f02109dd3d88773d7de5ae84385d41041bc9d60d0459eb6c61462cb2da0d1e",
    "mediamtx_v1.9.3_linux_armv7.tar.gz": "387a84bf47a0c3066d0159f84c8b9ea1da73a0233b4fc67f22731bc8001a6f74",
    "mediamtx_v1.9.3_darwin_amd64.tar.gz": "935ed174245004b425a93f6b7c1eac52310d833d4ebbca041d0f19195291eaf6",
    "mediamtx_v1.9.3_darwin_arm64.tar.gz": "562b7f8fe24d9005510efe1d15589119a2bf4e77e6a4d3fe35b1d3f55c75263c",
    "mediamtx_v1.9.3_windows_amd64.zip": "af2ce0dce3201e10c39dae4e6d8e52c983d6940b1fa0fdd7f3d16c87ac764626",
}
REQUIREMENTS = """\
# Standalone laptop mode (API + AI worker in one virtualenv). Lower bounds only, so pip picks
# wheels that exist for your Python version (3.10 - 3.14 supported).
fastapi>=0.115
uvicorn[standard]>=0.32
sqlalchemy>=2.0.36
pydantic-settings>=2.6
pyjwt>=2.10
cryptography>=47          # Argon2id with PHC strings (password hashes)
qrcode[pil]>=8.0
httpx>=0.27
onvif-zeep>=0.2.12
python-multipart>=0.0.18
numpy>=1.26
opencv-python-headless>=4.10
onnxruntime>=1.20
requests>=2.32
certifi
tzdata          # IANA time zones on Windows
"""
MTX_PORTS = {"rtsp": 8554, "hls": 8888, "webrtc": 8889, "api": 9997}
# Face models (opencv_zoo): YuNet detector (MIT), SFace recogniser (Apache-2.0). Pinned SHA-256.
FACE_MODELS = {
    "face_detection_yunet_2023mar.onnx": (
        "https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx",
        "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4"),
    "face_recognition_sface_2021dec.onnx": (
        "https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx",
        "0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79"),
}


def say(msg, kind="•"):
    print(f"  {kind} {msg}", flush=True)


def die(msg):
    print(f"\n  ✗ {msg}\n", flush=True)
    pause()
    sys.exit(1)


def pause():
    """A double-clicked run.py on Windows closes its window instantly; keep errors readable."""
    if WIN and sys.stdin and sys.stdin.isatty() and not os.environ.get("VMS_NO_PAUSE"):
        try:
            input("  Press Enter to close…")
        except EOFError:
            pass


# ------------------------------------------------------------------ stage 1
def in_synced_folder(p: Path) -> bool:
    return any(m in str(p).lower() for m in CLOUD_MARKERS)


def migrate_legacy():
    """Move data from older locations (project/.laptop, possibly inside OneDrive; %LOCALAPPDATA%) into
    HOME, drop everything else (venv and logs are rebuilt), and rotate secrets that may have synced."""
    rotate = False
    for old in previous_homes():
        try:
            if not old.exists() or old.resolve() == HOME.resolve():
                continue
        except OSError:
            continue
        say(f"Moving local data from {old} to {HOME}")
        HOME.mkdir(parents=True, exist_ok=True)
        for item in ("data", "secrets.json", "FIRST-LOGIN.txt", "settings.env", "models", "bin", "launcher.json"):
            src = old / item
            if src.exists() and not (HOME / item).exists():
                shutil.move(str(src), str(HOME / item))
        shutil.rmtree(old, ignore_errors=True)
        if in_synced_folder(old):
            rotate = True
    sf = HOME / "secrets.json"
    if rotate and sf.exists():
        sec = json.loads(sf.read_text())
        sec["secret_key"], sec["internal_token"] = secrets.token_hex(32), secrets.token_hex(32)
        sf.write_text(json.dumps(sec, indent=2))
        say("Rotated session and internal secrets (you will need to sign in again)", "✓")
        say("The old folder was inside a cloud-synced directory. Empty its copies from the OneDrive/"
            "Dropbox recycle bin and version history. Use --reset before adding real cameras, which also "
            "replaces the encryption key that protected camera passwords.", "!")


def is_store_python(path: str) -> bool:
    """Microsoft Store Python lives under ...\\WindowsApps\\ and sandboxes AppData writes."""
    return WIN and "windowsapps" in path.lower()


def find_python() -> list[str] | None:
    """A python.org (non-Store) 3.10-3.14 interpreter, preferring 3.12, then 3.13, 3.14, 3.11, 3.10."""
    for v in ("3.12", "3.13", "3.14", "3.11", "3.10"):
        c = ["py", f"-{v}"] if WIN else [f"python{v}"]
        if not shutil.which(c[0]):
            continue
        try:
            r = subprocess.run(c + ["-c", "import sys, venv; print(sys.base_prefix); print(sys.executable)"],
                               capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode == 0 and not is_store_python(r.stdout):
            return c
    return None


def venv_healthy() -> bool:
    if not (VPY.exists() and (VENV / "pyvenv.cfg").exists()):
        return False
    try:
        return subprocess.run([str(VPY), "-c", "import sys"], capture_output=True, timeout=60).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def find_python() -> list[str] | None:
    """Prefer 3.12, then 3.13/3.11/3.10: these have wheels for every dependency."""
    cands = []
    for v in ("3.12", "3.13", "3.11", "3.10"):
        cands += [["py", f"-{v}"]] if WIN else [[f"python{v}"]]
    for c in cands:
        if shutil.which(c[0]):
            try:
                if subprocess.run(c + ["-c", "import venv"], capture_output=True, timeout=20).returncode == 0:
                    return c
            except (OSError, subprocess.SubprocessError):
                pass
    return None


def stage_bootstrap(argv):
    """Runs on whatever Python started the script: pick a supported interpreter, build the venv,
    install packages, then re-run this file inside the venv."""
    supported = (3, 10) <= sys.version_info < (3, 15)
    store = is_store_python(sys.base_prefix) or is_store_python(sys.executable)
    if (not supported or store) and not os.environ.get("VMS_REEXEC"):
        better = find_python()
        if better:
            why = "Microsoft Store Python" if store else f"Python {platform.python_version()}"
            say(f"{why} is not suitable; switching to {' '.join(better)}")
            env = {**os.environ, "VMS_REEXEC": "1"}
            sys.exit(subprocess.call(better + [str(Path(__file__).resolve()), *argv], env=env))
    if store:
        say("Running on Microsoft Store Python. It works here (data is kept outside AppData), but the "
            "python.org installer is recommended: winget install Python.Python.3.12", "!")
    if sys.version_info < (3, 10):
        die(f"Python 3.10+ required (found {platform.python_version()}). Install Python 3.12:\n"
            "    Windows: winget install Python.Python.3.12   (or python.org, tick 'Add to PATH')\n"
            "    macOS:   brew install python@3.12             (or python.org)\n"
            "    Linux:   sudo apt install python3 python3-venv")
    if sys.version_info >= (3, 15):
        say(f"Python {platform.python_version()} is very new; some wheels may be missing. 3.12 is the safest.", "!")
    try:
        import venv  # noqa: F401
        import ensurepip  # noqa: F401
    except ImportError:
        die("Python's venv module is missing. On Debian/Ubuntu: sudo apt install python3-venv")

    migrate_legacy()
    HOME.mkdir(parents=True, exist_ok=True)
    if in_synced_folder(HOME):
        say(f"{HOME} is inside a cloud-synced folder: recordings and secrets would be uploaded. "
            "Set VMS_HOME to a local folder.", "!")
    stamp = HOME / ".deps-hash"
    if not venv_healthy():
        if VENV.exists():
            say("Existing virtual environment is broken; rebuilding it")
            shutil.rmtree(VENV, ignore_errors=True)
            stamp.unlink(missing_ok=True)
        say(f"Creating Python virtual environment (Python {platform.python_version()})…")
        if subprocess.call([sys.executable, "-m", "venv", str(VENV)]) or not venv_healthy():
            die(f"Could not create a working virtual environment in {VENV}. "
                "If this is Microsoft Store Python, install Python from python.org and rerun.")
    want = hashlib.sha256(REQUIREMENTS.encode()).hexdigest()
    if not stamp.exists() or stamp.read_text().strip() != want:
        say("Installing Python packages (first run takes a few minutes)…")
        req = HOME / "requirements.txt"
        req.write_text(REQUIREMENTS)
        if subprocess.call([str(VPY), "-m", "pip", "install", "-q", "--upgrade", "pip"]):
            die("Could not update pip inside the virtual environment (see output above).")
        if subprocess.call([str(VPY), "-m", "pip", "install", "-q", "-r", str(req)]):
            die("Package installation failed (see pip output above). Behind a corporate proxy? "
                "Set HTTPS_PROXY and, if your company re-signs TLS, PIP_CERT=<corporate CA .pem>.")
        stamp.write_text(want)
    child = subprocess.Popen([str(VPY), str(Path(__file__).resolve()), "--inner", *argv])
    while True:  # Ctrl+C reaches the child too; just wait for its clean shutdown
        try:
            sys.exit(child.wait())
        except KeyboardInterrupt:
            continue


# ------------------------------------------------------------------ stage 2
def http_get(url: str, accept: str = "") -> bytes:
    import certifi
    import requests
    headers = {"User-Agent": "sentinel-vms-launcher"}
    if accept:
        headers["Accept"] = accept
    r = requests.get(url, headers=headers, timeout=120, verify=os.environ.get("REQUESTS_CA_BUNDLE") or certifi.where())
    r.raise_for_status()
    return r.content


def mtx_asset_tokens():
    sysname = {"Windows": "windows", "Darwin": "darwin", "Linux": "linux"}.get(platform.system())
    m = platform.machine().lower()
    arch = (["amd64"] if m in ("x86_64", "amd64") or (sysname == "windows" and m == "arm64")
            else ["arm64v8", "arm64"] if m in ("arm64", "aarch64")
            else ["armv7"] if m.startswith("armv7") else [])
    if not sysname or not arch:
        die(f"Unsupported platform for MediaMTX: {platform.system()} {platform.machine()}")
    return sysname, arch


def ensure_mediamtx() -> Path:
    """Download from the plain release URL (no GitHub API: often blocked or rate-limited) and verify SHA-256."""
    import requests
    exe = BIN / ("mediamtx.exe" if WIN else "mediamtx")
    if exe.exists():
        return exe
    say(f"Downloading MediaMTX {MTX_VERSION} (streaming server)…")
    sysname, arch = mtx_asset_tokens()
    base = f"https://github.com/bluenviron/mediamtx/releases/download/{MTX_VERSION}"
    ext = "zip" if sysname == "windows" else "tar.gz"
    blob = name = None
    for a in arch:
        name = f"mediamtx_{MTX_VERSION}_{sysname}_{a}.{ext}"
        try:
            blob = http_get(f"{base}/{name}")
            break
        except requests.HTTPError:
            continue
    if blob is None:
        die(f"No MediaMTX build found for {sysname}/{arch}. Download it manually from "
            f"{base} and place the binary in {BIN}")
    if MTX_SHA256.get(name) != hashlib.sha256(blob).hexdigest():
        die(f"Checksum mismatch for {name} — download refused (corrupted, or altered in transit).")
    say("Checksum verified", "✓")
    BIN.mkdir(parents=True, exist_ok=True)
    if ext == "zip":
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            exe.write_bytes(z.read(exe.name))
    else:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as t:
            exe.write_bytes(t.extractfile(t.getmember(exe.name)).read())
    exe.chmod(0o755)
    if platform.system() == "Darwin":  # unsigned binary downloaded by a script: clear quarantine
        subprocess.call(["xattr", "-d", "com.apple.quarantine", str(exe)], stderr=subprocess.DEVNULL)
    return exe


def ensure_face_models() -> bool:
    """Privacy blurring cannot run without the face detector, so these are mandatory."""
    ok = True
    MODELS.mkdir(parents=True, exist_ok=True)  # a first-ever `run.py --selftest` reaches here before anything else creates it
    for name, (url, sha) in FACE_MODELS.items():
        dst = MODELS / name
        if dst.exists() and hashlib.sha256(dst.read_bytes()).hexdigest() == sha:
            continue
        say(f"Downloading face model {name}…")
        try:
            blob = http_get(url)
        except Exception as e:
            say(f"Could not download {name}: {e}", "!")
            ok = False
            continue
        if hashlib.sha256(blob).hexdigest() != sha:
            say(f"Checksum mismatch for {name}; refused", "✗")
            ok = False
            continue
        dst.write_bytes(blob)
        say(f"{name} verified", "✓")
    if not ok:
        say(f"Face models missing: live view stays OFF (faces cannot be blurred). Download them manually into {MODELS}:\n"
            + "\n".join(f"      {u}" for u, _ in FACE_MODELS.values()), "!")
    return ok


def ensure_secrets() -> dict:
    f = HOME / "secrets.json"
    if f.exists():
        s = json.loads(f.read_text())
        changed = False
        if "media_key" not in s:  # upgrade: key for encrypting blurred media + face templates
            s["media_key"] = base64.b64encode(os.urandom(32)).decode()
            changed = True
        if s.pop("admin_password", None) is not None:  # older versions kept an initial password here
            changed = True
        if changed:
            f.write_text(json.dumps(s, indent=2))
        (HOME / "FIRST-LOGIN.txt").unlink(missing_ok=True)
        return s
    s = {"secret_key": secrets.token_hex(32), "internal_token": secrets.token_hex(32),
         "media_key": base64.b64encode(os.urandom(32)).decode(),
         "fernet_key": base64.urlsafe_b64encode(os.urandom(32)).decode()}
    f.write_text(json.dumps(s, indent=2))
    try:
        f.chmod(0o600)
    except OSError:
        pass
    return s  # no account is created here: the first super admin registers with a one-time setup code


def first_run_banner(port: int) -> str:
    """No built-in login exists. Until the first super admin registers, show the one-time setup code here
    (on the machine's own terminal) and nowhere else."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/setup/status", timeout=5) as r:
            pending = json.loads(r.read()).get("needs_setup")
    except Exception:
        pending = False
    code_file = DATA / "setup-code.txt"
    if pending and code_file.exists():
        code = code_file.read_text().strip()
        return (f"    FIRST-RUN SETUP — no accounts exist yet.\n"
                f"      1. Open the console and choose \"Set up this system\".\n"
                f"      2. Enter this one-time setup code:   {code}\n"
                f"      3. Create the super admin account and scan the MFA QR code.\n"
                f"    The code is valid until the first registration and is never shown in the browser.\n"
                f"    Invite other admins later from Users → Invite.\n")
    return "    Sign in with your own account. New people join through invitation links (Users → Invite).\n"


def setup_ai():
    out = MODELS / "detector.onnx"
    if out.exists():
        say(f"Model already present: {out}", "✓")
        return
    say("Setting up the AI model (one-off, downloads ~1 GB of tooling)…")
    say("Licence: Ultralytics YOLO weights are AGPL-3.0 — fine for evaluation; check before commercial use.", "!")
    ev = HOME / "export-venv"
    epy = ev / ("Scripts/python.exe" if WIN else "bin/python")
    if not epy.exists():
        subprocess.check_call([sys.executable, "-m", "venv", str(ev)])
    subprocess.check_call([str(epy), "-m", "pip", "install", "-q", "ultralytics", "onnx", "onnxslim"])
    MODELS.mkdir(parents=True, exist_ok=True)
    code = ("from ultralytics import YOLO; import shutil;"
            "p=YOLO('yolo11n.pt').export(format='onnx', imgsz=640, opset=17, simplify=True);"
            f"shutil.move(p, r'{out}')")
    subprocess.check_call([str(epy), "-c", code], cwd=str(MODELS))
    say(f"Model ready: {out}", "✓")


def webcam_input(ffmpeg: str, device: str | None) -> list[str] | None:
    sysname = platform.system()
    if sysname == "Darwin":
        return ["-f", "avfoundation", "-framerate", "30", "-video_size", "1280x720", "-i", f"{device or '0'}:none"]
    if sysname == "Linux":
        return ["-f", "v4l2", "-framerate", "15", "-video_size", "1280x720", "-i", device or "/dev/video0"]
    if sysname == "Windows":
        if not device:
            p = subprocess.run([ffmpeg, "-hide_banner", "-list_devices", "true", "-f", "dshow", "-i", "dummy"],
                               capture_output=True, text=True)
            found = re.findall(r'"([^"]+)"\s+\(video\)', p.stderr)
            if not found:
                say("No webcam found by DirectShow", "!")
                return None
            device = found[0]
            say(f"Using webcam: {device}")
        return ["-f", "dshow", "-rtbufsize", "64M", "-i", f"video={device}"]
    return None


def q(s: str) -> str:
    return f'"{s}"' if (" " in s or "=" in s) else s


VIDEO_EXT = {".mp4", ".mkv", ".mov", ".avi", ".m4v", ".webm", ".ts"}
SYNTH = ["testsrc2=size=640x360:rate=10",
         "life=size=640x360:rate=10:mold=10:ratio=0.08:life_color=lime:death_color=black",
         "cellauto=size=640x360:rate=10:rule=30",
         "gradients=size=640x360:rate=10:speed=0.03",
         "rgbtestsrc=size=640x360:rate=10"]


def load_prefs() -> dict:
    f = HOME / "launcher.json"
    return json.loads(f.read_text()) if f.exists() else {}


def save_prefs(prefs: dict):
    (HOME / "launcher.json").write_text(json.dumps(prefs, indent=2))


def expand_videos(items: list[str]) -> list[Path]:
    out = []
    for it in items:
        p = Path(it)
        if p.is_dir():
            out += sorted(f for f in p.iterdir() if f.suffix.lower() in VIDEO_EXT)
        elif p.is_file() and p.suffix.lower() in VIDEO_EXT:
            out.append(p)
        else:
            say(f"Skipping {it}: not a video file or folder", "!")
    return out


def build_streams(prefs: dict, ffmpeg: str) -> list[dict]:
    """Each stream is published into MediaMTX by ffmpeg and registered as a camera:
    {path, name, input (ffmpeg input args), kbps}."""
    streams = [{"path": "demo", "name": "Demo test pattern", "kbps": 1000,
                "input": "-re -f lavfi -i testsrc2=size=1280x720:rate=15"}]
    for k in range(1, int(prefs.get("simulate", 0)) + 1):
        streams.append({"path": f"sim{k}", "name": f"Simulated camera {k:02d}", "kbps": 500,
                        "input": f"-re -f lavfi -i {SYNTH[(k - 1) % len(SYNTH)]}"})
    seen = set()
    for f in expand_videos(prefs.get("videos", [])):
        name = f"Video · {f.stem[:40]}"
        while name in seen:
            name += "+"
        seen.add(name)
        streams.append({"path": "vid_" + hashlib.sha1(str(f).encode()).hexdigest()[:10], "name": name, "kbps": 1500,
                        "input": f"-re -stream_loop -1 -fflags +genpts -i {q(str(f))} -an -vf scale=-2:720,fps=15"})
    if "webcam" in prefs:
        cam = webcam_input(ffmpeg, prefs["webcam"] or None)
        if cam:
            streams.append({"path": "webcam", "name": "Laptop webcam", "kbps": 1500,
                            "input": " ".join(q(x) for x in cam)})
    return streams


def write_mtx_config(sec: dict, api_port: int, ffmpeg: str | None, streams: list[dict], retention_h: int) -> Path:
    rec = (DATA / "recordings").as_posix()
    publish = f"rtsp://internal:{sec['internal_token']}@127.0.0.1:{MTX_PORTS['rtsp']}"
    lines = [
        "logLevel: info", "logDestinations: [stdout]",
        "authMethod: http", f"authHTTPAddress: http://127.0.0.1:{api_port}/internal/mediamtx-auth", "authHTTPExclude: []",
        "api: yes", f"apiAddress: 127.0.0.1:{MTX_PORTS['api']}", "metrics: no", "pprof: no",
        "rtsp: yes", f"rtspAddress: 127.0.0.1:{MTX_PORTS['rtsp']}", "protocols: [tcp]",
        "rtmp: no", "srt: no",
        "hls: yes", f"hlsAddress: 127.0.0.1:{MTX_PORTS['hls']}", "hlsVariant: lowLatency",
        "webrtc: yes", f"webrtcAddress: 127.0.0.1:{MTX_PORTS['webrtc']}", "webrtcLocalUDPAddress: 127.0.0.1:8189",
        "webrtcIPsFromInterfaces: no", "webrtcAdditionalHosts: [127.0.0.1]",
        "playback: no",  # recordings are written ENCRYPTED by recorder.py, never by MediaMTX
        "pathDefaults:", "  record: no",
        "paths:" + ("" if (ffmpeg and streams) else " {}"),
    ]
    if ffmpeg:
        for st in streams:
            k = st["kbps"]
            enc = (f"-c:v libx264 -preset veryfast -tune zerolatency -g 30 -b:v {k}k -maxrate {int(k * 1.3)}k "
                   f"-bufsize {k * 2}k -pix_fmt yuv420p -f rtsp -rtsp_transport tcp")
            cmd = f"{q(ffmpeg)} -hide_banner -loglevel error {st['input']} {enc} {publish}/{st['path']}"
            lines += [f"  {st['path']}:", f"    runOnInit: {json.dumps(cmd)}", "    runOnInitRestart: yes"]
    cfg = HOME / "mediamtx.yml"
    cfg.write_text("\n".join(lines) + "\n")
    return cfg


def port_free(port: int) -> bool:
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def wait_http(url: str, seconds: int) -> bool:
    import requests
    end = time.time() + seconds
    while time.time() < end:
        try:
            if requests.get(url, timeout=2).ok:
                return True
        except requests.RequestException:
            pass
        time.sleep(0.5)
    return False


def tail(path: Path, n=25) -> str:
    try:
        return "\n".join(path.read_text(errors="replace").splitlines()[-n:])
    except OSError:
        return ""


def find_ffmpeg() -> str | None:
    p = shutil.which("ffmpeg")
    if p or not WIN:
        return p
    links = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Links" / "ffmpeg.exe"
    if links.exists():
        return str(links)
    try:  # PATH as just updated in the registry by an installer (this process still has the old one)
        import winreg
        parts = []
        for root, key in ((winreg.HKEY_CURRENT_USER, "Environment"),
                          (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")):
            try:
                with winreg.OpenKey(root, key) as k:
                    parts += os.path.expandvars(winreg.QueryValueEx(k, "Path")[0]).split(";")
            except OSError:
                pass
        return shutil.which("ffmpeg", path=";".join(parts))
    except ImportError:
        return None


def ensure_ffmpeg(allow_install: bool) -> str | None:
    """ffmpeg drives the demo camera and webcam capture. Installed via the OS package manager."""
    ff = find_ffmpeg()
    if ff or not allow_install:
        return ff
    marker = HOME / ".ffmpeg-attempted"
    if marker.exists():  # do not retry a failed install on every start
        return None
    marker.write_text(time.ctime())
    sysname = platform.system()
    cmd = None
    if sysname == "Windows" and shutil.which("winget"):
        cmd = ["winget", "install", "-e", "--id", "Gyan.FFmpeg", "--scope", "user",
               "--accept-package-agreements", "--accept-source-agreements"]
    elif sysname == "Darwin" and shutil.which("brew"):
        cmd = ["brew", "install", "ffmpeg"]
    elif sysname == "Linux":
        sudo = [] if os.geteuid() == 0 else ["sudo"]
        if shutil.which("apt-get"):
            cmd = sudo + ["apt-get", "install", "-y", "ffmpeg"]
        elif shutil.which("dnf"):
            cmd = sudo + ["dnf", "install", "-y", "ffmpeg"]
        elif shutil.which("pacman"):
            cmd = sudo + ["pacman", "-S", "--noconfirm", "ffmpeg"]
    if not cmd:
        return None
    say(f"Installing ffmpeg: {' '.join(cmd)}")
    try:
        subprocess.call(cmd)
    except OSError:
        return None
    return find_ffmpeg()


def run_selftest(args):
    """Runs the full test suite inside this virtualenv and writes an HTML report."""
    print("\n  Sentinel Attend · self-test\n")
    busy = [p for p in (args.port, 8097, *MTX_PORTS.values()) if not port_free(p)]
    if busy:
        die(f"Ports in use: {busy}. Stop Sentinel Attend (Ctrl+C) before running the self-test.")
    if subprocess.call([sys.executable, "-c", "import pytest"], stderr=subprocess.DEVNULL):
        say("Installing pytest into the app's environment…")
        if subprocess.call([sys.executable, "-m", "pip", "install", "-q", "pytest"]):
            die("Could not install pytest")
    mtx = ensure_mediamtx()
    ensure_face_models()
    out = HOME / "selftest"
    out.mkdir(exist_ok=True)
    env = {**os.environ, "VMS_MODELS_DIR": str(MODELS), "VMS_MEDIAMTX": str(mtx), "VMS_HOME": str(HOME),
           "VMS_TEST_REPORT_JSON": str(out / "results.json"), "PYTHONPATH": str(ROOT / "shared")}
    ff = find_ffmpeg()
    if ff:
        env["PATH"] = os.path.dirname(ff) + os.pathsep + env.get("PATH", "")
    if args.test_faces:
        env["VMS_TEST_FACES"] = str(Path(args.test_faces).expanduser().resolve())
    else:
        say("No --test-faces folder given: face-image tests will be skipped (see tests/README.md)", "!")
    say("Running tests (about 5 minutes; the pipeline test streams video for ~2 minutes)…")
    code = subprocess.call([sys.executable, "-m", "pytest", str(ROOT / "tests"), "-q", "-rfEx", "-p", "no:cacheprovider"],
                           cwd=str(ROOT), env=env)
    subprocess.call([sys.executable, str(ROOT / "tests" / "report.py"), str(out / "results.json"), "-o", str(out / "report.html")])
    say(f"Report: {out / 'report.html'}", "✓" if code == 0 else "!")
    if not args.no_browser:
        webbrowser.open((out / "report.html").as_uri())
    pause()
    sys.exit(code)


def stage_run(args):
    print("\n  Sentinel Attend · laptop mode\n")
    if args.reset:
        ans = input("  This deletes local events, snapshots, recordings and users. Type RESET to confirm: ")
        if ans.strip() == "RESET":
            shutil.rmtree(DATA, ignore_errors=True)
            for f in ("secrets.json", "FIRST-LOGIN.txt", "mediamtx.yml"):
                (HOME / f).unlink(missing_ok=True)
            say("Local data wiped", "✓")
    legacy = DATA / "recordings"
    if legacy.exists():  # pre-privacy MediaMTX recordings: plaintext and unblurred
        shutil.rmtree(legacy, ignore_errors=True)
        say("Deleted old unencrypted recordings (privacy mode stores only encrypted footage)", "✓")
    for d in (DATA / "snapshots", DATA / "store", LOGS, MODELS):
        d.mkdir(parents=True, exist_ok=True)

    mtx = ensure_mediamtx()
    faces_ok = ensure_face_models()
    sec = ensure_secrets()
    if args.setup_ai:
        setup_ai()

    prefs = load_prefs()
    if args.clear_sims:
        prefs = {k: v for k, v in prefs.items() if k == "retention_hours"}
    if args.simulate is not None:
        prefs["simulate"] = max(0, min(16, args.simulate))
    if args.videos is not None:
        prefs["videos"] = [str(Path(v).expanduser().resolve()) for v in args.videos]
    if args.webcam is not None:
        prefs["webcam"] = args.webcam
    if args.no_webcam:
        prefs.pop("webcam", None)
    if args.retention_hours:
        prefs["retention_hours"] = max(1, args.retention_hours)
    save_prefs(prefs)
    retention = int(prefs.get("retention_hours", 6))

    ffmpeg = ensure_ffmpeg(not args.no_ffmpeg)
    streams = []
    if not ffmpeg:
        say("ffmpeg not available: demo, simulated, video and webcam cameras are disabled. "
            "Install it (winget install Gyan.FFmpeg | brew install ffmpeg | sudo apt install ffmpeg) and rerun.", "!")
    else:
        streams = build_streams(prefs, ffmpeg)

    busy = [p for p in [args.port, *MTX_PORTS.values()] if not port_free(p)]
    if busy:
        die(f"Ports already in use on 127.0.0.1: {busy}. Is Sentinel Attend already running? "
            "Close it, or use --port for the console.")

    cfg = write_mtx_config(sec, args.port, ffmpeg, streams, retention)
    # loopback URLs carry no credentials; the API injects the internal identity at runtime
    # Name|url|record|attendance (attendance on by default for real-footage sources: videos, webcam)
    demo = [f"{st['name']}|rtsp://127.0.0.1:{MTX_PORTS['rtsp']}/{st['path']}|1|{int(st['path'].startswith(('vid_', 'webcam')))}"
            for st in streams]
    gb = sum(st["kbps"] for st in streams) * 1000 / 8 * 3600 * retention / 1e9

    env = {**os.environ,
           "VMS_DATABASE_URL": f"sqlite:///{(DATA / 'vms.db').as_posix()}",
           "VMS_SECRET_KEY": sec["secret_key"], "VMS_FERNET_KEY": sec["fernet_key"],
           "VMS_INTERNAL_TOKEN": sec["internal_token"], "VMS_SETUP_CODE_FILE": str(DATA / "setup-code.txt"),
           "VMS_COOKIE_SECURE": "false", "VMS_SNAPSHOT_DIR": str(DATA / "snapshots"),
           "VMS_MEDIAMTX_API": f"http://127.0.0.1:{MTX_PORTS['api']}",
           "VMS_MTX_WEBRTC_URL": f"http://127.0.0.1:{MTX_PORTS['webrtc']}",
           "VMS_MTX_HLS_URL": f"http://127.0.0.1:{MTX_PORTS['hls']}",
           "VMS_MEDIA_KEY": sec["media_key"], "VMS_STORE_DIR": str(DATA / "store"),
           "VMS_FACE_DET_MODEL": str(ROOT / "models" / "antispoof" / "yunet_2023mar_int8.onnx") if args.int8_detector
                                 else str(MODELS / "face_detection_yunet_2023mar.onnx"),
           "VMS_FACE_REC_MODEL": str(MODELS / "face_recognition_sface_2021dec.onnx"),
           "VMS_ANTISPOOF_DIR": str(ROOT / "models" / "antispoof"),
           "VMS_FFMPEG": ffmpeg or "", "VMS_RECORDING_RETENTION_HOURS": str(retention),
           "PYTHONPATH": os.pathsep.join(filter(None, [str(ROOT / "shared"), os.environ.get("PYTHONPATH", "")])),
           "VMS_WEB_DIR": str(ROOT / "web"), "VMS_DEMO_CAMERAS": ";".join(demo),
           "VMS_API_URL": f"http://127.0.0.1:{args.port}",
           "VMS_RTSP_BASE": f"rtsp://127.0.0.1:{MTX_PORTS['rtsp']}",
           "VMS_MODEL_PATH": str(MODELS / "detector.onnx"),
           "VMS_TZ": os.environ.get("VMS_TZ", "Asia/Kolkata"), "VMS_AI_FPS": os.environ.get("VMS_AI_FPS", "2"),
           "VMS_ORT_THREADS": os.environ.get("VMS_ORT_THREADS", "2"), "PYTHONUNBUFFERED": "1"}
    user_env = HOME / "settings.env"  # optional: alert keys etc. (VMS_TWILIO_SID=… one per line)
    if user_env.exists():
        for line in user_env.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()

    procs: dict[str, subprocess.Popen] = {}
    crashed = False

    def spawn(name, cmd, cwd):
        log = open(LOGS / f"{name}.log", "a", buffering=1)
        log.write(f"\n===== start {time.ctime()} =====\n")
        procs[name] = subprocess.Popen(cmd, cwd=str(cwd), env=env, stdout=log, stderr=subprocess.STDOUT)

    def stop_all():
        for p in procs.values():
            if p.poll() is None:
                p.terminate()
        for p in procs.values():
            try:
                p.wait(timeout=8)
            except subprocess.TimeoutExpired:
                p.kill()

    try:
        say("Starting API and web console…")
        spawn("api", [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
                      "--port", str(args.port), "--no-server-header"], ROOT / "api")
        if not wait_http(f"http://127.0.0.1:{args.port}/api/health", 60):
            die(f"API did not start. Last log lines:\n{tail(LOGS / 'api.log')}")
        say("Starting MediaMTX…")
        spawn("mediamtx", [str(mtx), str(cfg)], HOME)
        say("Starting AI worker…")
        spawn("worker", [sys.executable, "worker.py"], ROOT / "worker")
        say("Starting privacy processor (face blurring) and encrypted recorder…")
        spawn("privacy", [sys.executable, "privacy.py"], ROOT / "worker")
        spawn("recorder", [sys.executable, "recorder.py"], ROOT / "worker")
        time.sleep(2)
        for n, p in procs.items():
            if p.poll() is not None:
                die(f"{n} exited immediately. Last log lines:\n{tail(LOGS / f'{n}.log')}")

        url = f"http://127.0.0.1:{args.port}"
        print(f"""
  ✓ Sentinel Attend is running →  {url}

{first_run_banner(args.port)}    AI model:    {'loaded' if (MODELS / 'detector.onnx').exists() else 'not installed — run again with --setup-ai'}
    Cameras:     {', '.join(st['name'] for st in streams) or 'none yet — add yours under Cameras'}
    Recording:   {retention} h retention, encrypted · up to ~{2 * gb:.1f} GB disk (blurred + sealed raw; --retention-hours)
    Privacy:     {'faces blurred on every view and recording' if faces_ok else 'FACE MODELS MISSING: live view disabled'}
    Next steps:  Privacy → Encryption vault (super admin) · People → add + Enrol live · Kiosk
    Data folder: {HOME}
    Logs:        {LOGS}

    Press Ctrl+C to stop.
""")
        if not args.no_browser:
            webbrowser.open(url)
        while True:
            time.sleep(2)
            for n, p in procs.items():
                if p.poll() is not None:
                    say(f"{n} stopped unexpectedly (exit {p.returncode}). Last log lines:", "✗")
                    print(tail(LOGS / f"{n}.log"))
                    crashed = True
                    raise KeyboardInterrupt
    except KeyboardInterrupt:
        pass
    finally:
        say("Stopping…")
        stop_all()
        say("Stopped", "✓")
        if crashed:
            pause()


def main():
    ap = argparse.ArgumentParser(description="Sentinel Attend laptop launcher")
    ap.add_argument("--inner", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--setup-ai", action="store_true")
    ap.add_argument("--webcam", nargs="?", const="", default=None, metavar="DEVICE")
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--no-ffmpeg", action="store_true", help="never try to install ffmpeg")
    ap.add_argument("--simulate", type=int, metavar="N", help="add N synthetic cameras (0 removes them; max 16)")
    ap.add_argument("--videos", nargs="+", metavar="PATH", help="video files or folders to stream as looping cameras")
    ap.add_argument("--no-webcam", action="store_true", help="remove the webcam camera")
    ap.add_argument("--clear-sims", action="store_true", help="remove all simulated, video and webcam cameras")
    ap.add_argument("--retention-hours", type=int, metavar="H", help="recording retention (default 6)")
    ap.add_argument("--int8-detector", action="store_true",
                    help="use the quantised YuNet face detector (~35%% faster; same recall in tests) for blurring and kiosk")
    ap.add_argument("--selftest", action="store_true", help="run the functional / abuse / cyber test suite and write a report")
    ap.add_argument("--test-faces", metavar="DIR", help="folder with genuine face images for the self-test (tests/README.md)")
    args = ap.parse_args()
    if not args.inner:
        stage_bootstrap(sys.argv[1:])
    if args.selftest:
        run_selftest(args)
    stage_run(args)


if __name__ == "__main__":
    main()
