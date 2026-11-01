"""squashfs: images from the test-only writer (data/made, see make_fixtures.py: gzip, xz and zstd,
which 7-Zip has to read back, and LZ4, compressed by the reference lz4 library, which 7-Zip
doesn't read), go-diskfs's zstd image with 4 KB blocks (data/go-diskfs, MIT), the LZ4 decoder
against lz4 itself, and damaged images."""

import hashlib
import json
import random
from pathlib import Path

import pytest
from conftest import needs_zstd, zstd_marked

import packport
from packport import PackportError
from packport.squashfs import lz4_block

MADE = Path(__file__).parent / "data" / "made"
GODISKFS = Path(__file__).parent / "data" / "go-diskfs"
EXPECTED = {k: v for k, v in json.loads((MADE / "expected.json").read_text(encoding="utf-8")).items()
            if k.endswith(".sqfs")}
GO = json.loads((GODISKFS / "expected.json").read_text(encoding="utf-8"))


def _hashes(src) -> dict:
    with packport.open(src) as a:
        return {m.name: hashlib.sha256(s.read()).hexdigest() for m, s in a.files()}


@pytest.mark.parametrize("name", zstd_marked(sorted(EXPECTED)))
def test_same_files_as_written(name):
    assert _hashes(MADE / name) == EXPECTED[name]


@needs_zstd
def test_mksquashfs_image_with_small_blocks():
    assert _hashes(GODISKFS / "dir_read.sqs") == GO["dir_read.sqs"]


def test_holes_and_folders():
    with packport.open(MADE / "gzip.sqfs") as a:
        kinds = {m.name: (m.is_dir, m.size) for m in a.members}
        assert kinds["sub/empty dir"] == (True, 0)
        assert a.read("sub/holes.bin") == b"start" + bytes(20000) + b"end" * 2000


def test_lz4_blocks_decode_as_lz4_itself_wrote_them():
    lz4 = pytest.importorskip("lz4.block")
    rng = random.Random(2)
    words = [bytes(rng.choice(b"abcdef") for _ in range(rng.randint(1, 12))) for _ in range(500)]
    for data in (b"", b"a", b"ab" * 40_000, rng.randbytes(70_000), b" ".join(rng.choice(words) for _ in range(30_000))):
        packed = lz4.compress(data, store_size=False)
        assert lz4_block(packed, len(data) + 1) == data


def test_lzo_is_refused_by_name():
    data = bytearray((MADE / "gzip.sqfs").read_bytes())
    data[20] = 3  # the compressor: LZO
    with pytest.raises(PackportError, match="LZO"):
        packport.open(bytes(data))


def test_formats_are_told_apart():
    assert packport.detect(MADE / "xz.sqfs") == "squashfs"


@pytest.mark.parametrize("name", ["gzip.sqfs", "lz4.sqfs", "zstd.sqfs"])
def test_damaged_images_raise_only_packport_error(name):
    rng = random.Random(name)
    data = (MADE / name).read_bytes()
    bad = []
    for _ in range(60):
        b = bytearray(data)
        for _ in range(rng.randint(1, 8)):
            b[rng.randrange(len(b))] = rng.randrange(256)
        if rng.random() < 0.2:
            b = b[:rng.randrange(96, len(b))]
        try:
            with packport.open(bytes(b)) as a:
                for _m, s in a.files():
                    s.read()
        except PackportError:
            pass
        except Exception as e:  # noqa: BLE001
            bad.append(f"{type(e).__name__}: {e}")
    assert bad == []
