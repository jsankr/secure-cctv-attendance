"""MT: in-memory media handling (segmenter, transcode, watermark)."""
import io
import os
import shutil
import subprocess

import numpy as np
import pytest

import mediatools as M
import vmscrypto as C

pytestmark = pytest.mark.skipif(not shutil.which("ffmpeg"), reason="ffmpeg not installed")


def _fmp4(seconds=24, gop=15):
    return subprocess.run(["ffmpeg", "-v", "error", "-f", "lavfi", "-i", "testsrc2=size=640x360:rate=15", "-t", str(seconds),
                           "-c:v", "libx264", "-g", str(gop), "-f", "mp4", "-movflags",
                           "frag_keyframe+empty_moov+default_base_moof", "pipe:1"], capture_output=True, check=True).stdout


def _frames(mp4):
    r = subprocess.run(["ffprobe", "-v", "error", "-count_frames", "-select_streams", "v:0", "-show_entries",
                        "stream=nb_read_frames", "-of", "csv=p=0", "-i", "pipe:0"], input=mp4, capture_output=True)
    return int(r.stdout.decode().strip() or 0), r.stderr.decode().strip()


def _segment(data, seconds, read_size):
    k, segs, cur, t = os.urandom(32), [], {}, [0.0]

    def start(init):
        cur["b"] = io.BytesIO()
        cur["e"] = C.Encryptor(cur["b"], media_key=k)
        cur["e"].write(init)

    def chunk(b):
        cur["e"].write(b)
        t[0] += 1.0

    def end():
        cur["e"].close()
        segs.append(cur["b"].getvalue())

    s = M.FMP4Segmenter(seconds, start, chunk, end, clock=lambda: t[0])
    for i in range(0, len(data), read_size):
        s.feed(data[i:i + read_size])
    s.close()
    return k, segs


def test_MT_01_segments_complete_and_independent():
    """Segmenter output: all frames preserved, every encrypted segment decodes on its own without errors."""
    k, segs = _segment(_fmp4(), 10, 7777)
    counts = []
    for s in segs:
        n, err = _frames(C.decrypt_bytes(s, media_key=k))
        assert not err
        counts.append(n)
    assert len(segs) == 3 and sum(counts) == 24 * 15


@pytest.mark.parametrize("read_size", [1, 13, 4096, 1 << 20])
def test_MT_02_any_pipe_read_size(read_size):
    """Boxes split across arbitrary pipe reads (1 byte .. 1 MiB) are reassembled correctly."""
    data = _fmp4(seconds=4)
    k, segs = _segment(data, 100, read_size)
    assert _frames(C.decrypt_bytes(segs[0], media_key=k))[0] == 60


def test_MT_03_corrupt_stream_rejected():
    """A corrupt MP4 box size raises instead of writing garbage."""
    s = M.FMP4Segmenter(10, lambda i: None, lambda b: None, lambda: None, clock=lambda: 0)
    with pytest.raises(ValueError):
        s.feed(b"\x00\x00\x00\x02moof")


def test_MT_04_trimmed_multi_part_transcode():
    """transcode_many trims and concatenates parts into one playable clip with the expected length."""
    data = _fmp4(seconds=6)
    out = M.transcode_many([(data, 1.0, 2.0), (data, 3.0, 1.0)], lambda f, i: f)
    n, err = _frames(out)
    assert not err and abs(n - 45) <= 2


def test_MT_05_watermark_ascii_safe():
    """Watermark renders non-ASCII text safely and changes the frame."""
    f = np.zeros((360, 640, 3), np.uint8)
    out = M.watermark(f.copy(), ["EXPORTED · ünïcødé · ✓", "line two"])
    assert out.shape == f.shape and out.any()


def test_MT_06_no_plaintext_written(tmp_path):
    """Encrypted segment files contain no MP4 signatures (no plaintext video at rest)."""
    k, segs = _segment(_fmp4(seconds=4), 100, 65536)
    for s in segs:
        assert b"ftyp" not in s and b"moof" not in s and b"mdat" not in s
