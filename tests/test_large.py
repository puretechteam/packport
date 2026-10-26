"""Files of 2 to 4 GiB (32-bit sizes with the top bit set, which trips readers that treat them as
signed) and over 4 GiB (RAR's HIGH_PACK_SIZE / HIGH_UNP_SIZE). The sources are sparse files, but
each archive is a real multi-gigabyte write that every extractor reads in full, so these only run
with PACKPORT_SLOW=1 (a few minutes on an SSD)."""

import hashlib
import os
import struct
import subprocess
import zlib

import pytest
from conftest import BSDTAR, CALIBRE_DEBUG, SEVEN_ZIP, run, sparse_file, unrar

import packport
from packport.rar import FHD_LARGE, FHD_UNICODE

pytestmark = [pytest.mark.slow,
              pytest.mark.skipif(os.environ.get("PACKPORT_SLOW") != "1", reason="set PACKPORT_SLOW=1 to run")]

OVER_4 = (1 << 32) + 4099
OVER_2 = (3 << 30) + 4099


def marks(size: int) -> dict:
    out = {0: b"start", (1 << 31) - 4: b"across 2 GiB", size - 3: b"end"}
    if size > 1 << 32:
        out[(1 << 32) - 4] = b"across 4 GiB"
    return out


def digest(stream) -> tuple[int, str, int]:
    h, n, crc = hashlib.sha256(), 0, 0
    while chunk := stream.read(1 << 20):
        h.update(chunk)
        crc = zlib.crc32(chunk, crc)
        n += len(chunk)
    return n, h.hexdigest(), crc


def piped(*args) -> tuple[int, str, int]:
    with subprocess.Popen([str(a) for a in args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as p:
        result = digest(p.stdout)
    assert p.returncode == 0, args
    return result


def check_extractors(archive, expected, name, bsdtar_options=()):
    checked = 0
    if SEVEN_ZIP:
        run(SEVEN_ZIP, "t", archive)
        assert piped(SEVEN_ZIP, "e", "-so", archive) == expected
        checked += 1
    if BSDTAR:
        assert piped(BSDTAR, *bsdtar_options, "-xOf", archive) == expected
        checked += 1
    if CALIBRE_DEBUG and archive.suffix == ".rar":
        # RARLAB's unrar reads every byte and checks it against the CRC (nothing is written)
        heads = unrar("verify", archive, name, expected[2])["headers"]
        assert heads[0]["unpack_size"] == expected[0] and heads[0]["file_crc"] == expected[2]
        checked += 1
    if not checked:
        pytest.skip("no extractor is installed")


@pytest.mark.parametrize("size", [OVER_2, OVER_4], ids=["3 GiB", "4 GiB+"])
def test_big_rar(tmp_path, size):
    src = sparse_file(tmp_path / "big ü.bin", size, marks(size))
    with open(src, "rb") as f:
        expected = digest(f)
    assert expected[0] == size
    archive = tmp_path / "big.rar"
    packport.write_rar(archive, [src])
    with open(archive, "rb") as f:
        head = f.read(100)
    flags, = struct.unpack_from("<H", head, 20 + 3)
    assert flags & FHD_UNICODE
    assert bool(flags & FHD_LARGE) == (size > 0xFFFFFFFF)
    lo, = struct.unpack_from("<I", head, 20 + 7)
    hi = struct.unpack_from("<I", head, 20 + 32)[0] if flags & FHD_LARGE else 0
    assert hi << 32 | lo == size
    check_extractors(archive, expected, src.name)


def test_3_gib_cpio(tmp_path):
    src = sparse_file(tmp_path / "big ü.bin", OVER_2, marks(OVER_2))
    with open(src, "rb") as f:
        expected = digest(f)
    archive = tmp_path / "big.cpio"
    packport.write_cpio(archive, [src])
    with open(archive, "rb") as f:
        assert int(f.read(110)[54:62], 16) == OVER_2
    check_extractors(archive, expected, src.name, ["--options", "hdrcharset=UTF-8"])
