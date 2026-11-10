"""Encrypted recorder. Plaintext video never touches the disk.

For each camera it runs two ffmpeg remux pipelines (no re-encode) into an in-process segmenter:
  * cam{id}_priv  (faces blurred)  -> AES-256-GCM under the media key      -> routine playback
  * cam{id}       (raw, unblurred) -> SEALED to the super-admin vault key  -> only via approved unblur
If no vault exists yet, raw footage is NOT recorded at all (fail closed).

Files: <store>/rec/<camera>/<kind>/<YYYY-MM-DD>/<HHMMSS>-<rand>.svms ; index posted to the API.
"""
import datetime as dt
import logging
import os
import secrets
import subprocess
import sys
import threading
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "shared"))
import vmscrypto as C  # noqa: E402
from mediatools import FFMPEG, NO_WINDOW, FMP4Segmenter  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s recorder: %(message)s")
log = logging.getLogger("recorder")

API = os.environ.get("VMS_API_URL", "http://api:8000")
TOKEN = os.environ["VMS_INTERNAL_TOKEN"]
MEDIA_KEY = C.base64.b64decode(os.environ["VMS_MEDIA_KEY"])
RTSP = os.environ.get("VMS_RTSP_BASE", "rtsp://mediamtx:8554").replace("rtsp://", f"rtsp://internal:{TOKEN}@")
STORE = Path(os.environ.get("VMS_STORE_DIR", "/data/store"))
SEGMENT_S = int(os.environ.get("VMS_SEGMENT_SECONDS", "300"))
RETENTION_H = int(os.environ.get("VMS_RECORDING_RETENTION_HOURS", "720"))
H = {"X-Internal-Token": TOKEN}


class Pipeline(threading.Thread):
    def __init__(self, cam_id: int, kind: str, pub: bytes | None):
        super().__init__(daemon=True, name=f"rec-cam{cam_id}-{kind}")
        self.cam_id, self.kind, self.pub, self.running = cam_id, kind, pub, True
        self.proc = None

    def stop(self):
        self.running = False
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()

    def run(self):
        path = f"cam{self.cam_id}_priv" if self.kind == "priv" else f"cam{self.cam_id}"
        backoff = 2
        while self.running:
            self.proc = subprocess.Popen(
                [FFMPEG, "-v", "error", "-rtsp_transport", "tcp", "-i", f"{RTSP}/{path}", "-map", "0:v:0",
                 "-c", "copy", "-f", "mp4", "-movflags", "frag_keyframe+empty_moov+default_base_moof", "pipe:1"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=NO_WINDOW)
            state = {}

            def on_start(init: bytes):
                now = dt.datetime.now(dt.timezone.utc)
                d = STORE / "rec" / f"cam{self.cam_id}" / self.kind / now.strftime("%Y-%m-%d")
                d.mkdir(parents=True, exist_ok=True)
                final = d / f"{now.strftime('%H%M%S')}-{secrets.token_hex(3)}.svms"
                f = open(final.with_suffix(".part"), "wb")
                enc = C.Encryptor(f, media_key=MEDIA_KEY) if self.kind == "priv" else C.Encryptor(f, recipient_pub=self.pub)
                enc.write(init)
                state.update(f=f, enc=enc, final=final, start=now)

            def on_data(b: bytes):
                state["enc"].write(b)

            def on_end():
                enc, f, final, start = state.pop("enc"), state.pop("f"), state.pop("final"), state.pop("start")
                enc.close()
                f.close()
                part = final.with_suffix(".part")
                os.replace(part, final)
                end = dt.datetime.now(dt.timezone.utc)
                try:
                    requests.post(f"{API}/internal/segments", headers=H, timeout=10, json={
                        "camera_id": self.cam_id, "kind": self.kind, "path": str(final.relative_to(STORE)),
                        "start": start.isoformat(), "end": end.isoformat(), "size": final.stat().st_size,
                        "sealed": self.kind == "raw"})
                except requests.RequestException as e:
                    log.warning("index post failed: %s", e)

            seg = FMP4Segmenter(SEGMENT_S, on_start, on_data, on_end, clock=time.monotonic)
            got = False
            try:
                while self.running:
                    b = self.proc.stdout.read(1 << 16)
                    if not b:
                        break
                    got = True
                    seg.feed(b)
            except Exception as e:
                log.warning("cam%s %s: %s", self.cam_id, self.kind, e)
            finally:
                try:
                    seg.close()
                except Exception as e:
                    log.warning("segment close failed: %s", e)
                if self.proc.poll() is None:
                    self.proc.terminate()
            if self.running:
                backoff = 2 if got else min(30, backoff * 2)
                time.sleep(backoff)


def cleanup():
    """Delete encrypted segments past retention and orphaned .part files from crashes."""
    cut = time.time() - RETENTION_H * 3600
    root = STORE / "rec"
    if not root.exists():
        return
    for p in root.rglob("*"):
        try:
            if p.is_file() and (p.stat().st_mtime < cut or (p.suffix == ".part" and p.stat().st_mtime < time.time() - SEGMENT_S * 3)):
                p.unlink()
        except OSError:
            pass


def main():
    pipes: dict[tuple[int, str], Pipeline] = {}
    last_clean = 0.0
    while True:
        try:
            cams = requests.get(f"{API}/internal/cameras", headers=H, timeout=10).json()
            v = requests.get(f"{API}/internal/vault/pubkey", headers=H, timeout=10).json()
            pub = C.base64.b64decode(v["public_key"]) if v.get("public_key") else None
            want = {}
            for c in cams:
                if not c.get("record"):
                    continue
                want[(c["id"], "priv")] = None
                if pub:
                    want[(c["id"], "raw")] = pub
            for k in list(pipes):
                if k not in want or (k[1] == "raw" and pipes[k].pub != want[k]):
                    pipes.pop(k).stop()
            for k, p in want.items():
                if k not in pipes:
                    pipes[k] = Pipeline(k[0], k[1], p)
                    pipes[k].start()
            if not pub and cams:
                log.info("vault not set up: recording blurred streams only (raw footage is not kept)")
            if time.time() - last_clean > 600:
                cleanup()
                last_clean = time.time()
        except Exception as e:
            log.warning("refresh failed: %s", e)
        time.sleep(20)


if __name__ == "__main__":
    main()
