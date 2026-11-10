"""Media helpers that never put plaintext video on disk.

* FMP4Segmenter: splits ffmpeg's fragmented-MP4 output (from a pipe) into independently playable
  segments (init + fragments, cut only on keyframe fragment boundaries), handing bytes to encryptors.
* probe / transcode: decode an in-memory MP4, run a per-frame Python function (blur, watermark), and
  re-encode to an in-memory MP4 — used by unblur rendering and watermarked export.
"""
from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import threading
from typing import Callable

import numpy as np

FFMPEG = os.environ.get("VMS_FFMPEG") or shutil.which("ffmpeg") or "ffmpeg"


def ffprobe_path() -> str:
    d, name = os.path.split(FFMPEG)
    cand = os.path.join(d, name.replace("ffmpeg", "ffprobe")) if d else "ffprobe"
    return cand if (not d or os.path.exists(cand)) else (shutil.which("ffprobe") or "ffprobe")


NO_WINDOW = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW


class FMP4Segmenter:
    """Feed raw bytes from `ffmpeg ... -f mp4 -movflags frag_keyframe+empty_moov+default_base_moof pipe:1`.
    Calls on_start(init_bytes) when a segment opens, on_data(bytes) for each fragment, on_end() when
    it closes. A new segment starts at the first fragment after `seconds` have elapsed (each fragment
    starts on a keyframe, so every segment decodes on its own)."""

    def __init__(self, seconds: float, on_start: Callable[[bytes], None], on_data: Callable[[bytes], None],
                 on_end: Callable[[], None], clock: Callable[[], float]):
        self.seconds, self.on_start, self.on_data, self.on_end, self.clock = seconds, on_start, on_data, on_end, clock
        self.buf = bytearray()
        self.init = bytearray()
        self.init_done = False
        self.open_since: float | None = None
        self.pending_moof: bytes | None = None

    def _boxes(self):
        while True:
            if len(self.buf) < 8:
                return
            size, typ = struct.unpack(">I4s", self.buf[:8])
            hdr = 8
            if size == 1:
                if len(self.buf) < 16:
                    return
                size = struct.unpack(">Q", self.buf[8:16])[0]
                hdr = 16
            if size < hdr:
                raise ValueError(f"corrupt MP4 box {typ!r} size {size}")
            if len(self.buf) < size:
                return
            box = bytes(self.buf[:size])
            del self.buf[:size]
            yield typ, box

    def feed(self, data: bytes):
        self.buf += data
        for typ, box in self._boxes():
            if not self.init_done:
                if typ == b"moof":
                    self.init_done = True
                else:
                    self.init += box
                    continue
            if typ == b"moof":
                self.pending_moof = box
                continue
            if typ == b"mdat" and self.pending_moof is not None:
                now = self.clock()
                if self.open_since is None or now - self.open_since >= self.seconds:
                    if self.open_since is not None:
                        self.on_end()
                    self.open_since = now
                    self.on_start(bytes(self.init))
                self.on_data(self.pending_moof + box)
                self.pending_moof = None
            elif self.open_since is not None:
                self.on_data(box)  # e.g. sidx/styp/free between fragments

    def close(self):
        if self.open_since is not None:
            self.on_end()
            self.open_since = None


def probe(data: bytes) -> dict:
    p = subprocess.run([ffprobe_path(), "-v", "error", "-select_streams", "v:0", "-show_entries",
                        "stream=width,height,avg_frame_rate,r_frame_rate", "-of", "json", "-i", "pipe:0"],
                       input=data, capture_output=True, creationflags=NO_WINDOW)
    try:
        s = json.loads(p.stdout)["streams"][0]
    except (ValueError, KeyError, IndexError):
        raise RuntimeError(f"ffprobe failed: {p.stderr.decode(errors='replace')[-300:]}")
    fps = 15.0
    for k in ("avg_frame_rate", "r_frame_rate"):
        try:
            n, d = s.get(k, "0/0").split("/")
            if float(d) and 1 <= float(n) / float(d) <= 60:
                fps = float(n) / float(d)
                break
        except ValueError:
            pass
    return {"width": int(s["width"]), "height": int(s["height"]), "fps": fps}


def transcode(data: bytes, frame_fn: Callable[[np.ndarray, int], np.ndarray], **kw) -> bytes:
    return transcode_many([(data, None, None)], frame_fn, **kw)


def transcode_many(parts: list[tuple[bytes, float | None, float | None]],
                   frame_fn: Callable[[np.ndarray, int], np.ndarray], *, max_height: int = 720, crf: int = 23) -> bytes:
    """Decode one or more MP4 byte strings (each optionally trimmed: offset, duration in seconds),
    run frame_fn(frame_bgr, index) on every frame, and encode everything into ONE H.264 MP4
    (fragmented, browser-playable). Nothing touches the disk."""
    info = probe(parts[0][0])
    w, h, fps = info["width"], info["height"], info["fps"]
    if h > max_height:
        w, h = int(round(w * max_height / h / 2) * 2), max_height
    w, h = w - w % 2, h - h % 2
    enc = subprocess.Popen([FFMPEG, "-v", "error", "-f", "rawvideo", "-pix_fmt", "bgr24", "-s", f"{w}x{h}",
                            "-r", f"{fps:.3f}", "-i", "pipe:0", "-c:v", "libx264", "-preset", "veryfast",
                            "-crf", str(crf), "-pix_fmt", "yuv420p", "-f", "mp4",
                            "-movflags", "frag_keyframe+empty_moov+default_base_moof", "pipe:1"],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           creationflags=NO_WINDOW)
    out: list[bytes] = []

    def drain():
        while True:
            b = enc.stdout.read(1 << 16)
            if not b:
                return
            out.append(b)

    t_out = threading.Thread(target=drain, daemon=True)
    t_out.start()
    frame_bytes, i = w * h * 3, 0
    try:
        for data, off, dur in parts:
            trim = (["-ss", f"{off:.3f}"] if off else []) + (["-t", f"{dur:.3f}"] if dur else [])
            dec = subprocess.Popen([FFMPEG, "-v", "error", "-i", "pipe:0", *trim, "-an",
                                    "-vf", f"scale={w}:{h},fps={fps:.3f}", "-f", "rawvideo", "-pix_fmt", "bgr24", "pipe:1"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   creationflags=NO_WINDOW)

            def feed(d=data, p=dec):
                try:
                    p.stdin.write(d)
                except (BrokenPipeError, OSError):
                    pass
                finally:
                    try:
                        p.stdin.close()
                    except OSError:
                        pass

            t_in = threading.Thread(target=feed, daemon=True)
            t_in.start()
            while True:
                raw = dec.stdout.read(frame_bytes)
                if len(raw) < frame_bytes:
                    break
                frame = np.frombuffer(raw, np.uint8).reshape(h, w, 3).copy()
                enc.stdin.write(frame_fn(frame, i).tobytes())
                i += 1
            t_in.join(timeout=30)
            dec.wait(timeout=30)
    finally:
        try:
            enc.stdin.close()
        except OSError:
            pass
        t_out.join(timeout=120)
        enc.wait(timeout=120)
    if i == 0:
        raise RuntimeError("no frames decoded")
    return b"".join(out)


def watermark(frame: np.ndarray, lines: list[str]) -> np.ndarray:
    """Burned-in, semi-transparent banner + diagonal repeat; deters screen-capture leaks."""
    import cv2
    lines = ["".join(c if 32 <= ord(c) < 127 else "|" if c == "·" else "-" for c in ln) for ln in lines]  # Hershey = ASCII
    h, w = frame.shape[:2]
    s = max(0.45, w / 1400)
    band = int(26 * s * len(lines)) + 12
    ov = frame.copy()
    cv2.rectangle(ov, (0, h - band), (w, h), (0, 0, 0), -1)
    frame = cv2.addWeighted(ov, 0.55, frame, 0.45, 0)
    for k, line in enumerate(lines):
        cv2.putText(frame, line, (10, h - band + int(24 * s * (k + 1))), cv2.FONT_HERSHEY_SIMPLEX, 0.6 * s,
                    (255, 255, 255), max(1, int(1.5 * s)), cv2.LINE_AA)
    tag = lines[0][:48]
    for y in range(int(80 * s), h - band, int(220 * s)):
        cv2.putText(frame, tag, (int(w * 0.08), y), cv2.FONT_HERSHEY_SIMPLEX, 0.9 * s, (255, 255, 255),
                    max(1, int(1.2 * s)), cv2.LINE_AA)
    return frame
