"""A file over 4 GiB in a RAR archive (HIGH_PACK_SIZE / HIGH_UNP_SIZE). The source is a sparse
file, but the archive is a real 4 GB write and each extractor reads all of it, so this only runs
with PACKPORT_SLOW=1 (about a minute on an SSD)."""

import hashlib
import os
import struct
import subprocess

import pytest
from conftest import BSDTAR, SEVEN_ZIP, run, sparse_file

import packport
from packport.rar import FHD_LARGE, FHD_UNICODE

pytestmark = [pytest.mark.slow,
              pytest.mark.skipif(os.environ.get("PACKPORT_SLOW") != "1", reason="set PACKPORT_SLOW=1 to run")]

SIZE = (1 << 32) + 4099
MARKS = {0: b"start", (1 << 32) - 4: b"across the 4 GiB line", SIZE - 3: b"end"}


def digest(stream) -> tuple[int, str]:
    h, n = hashlib.sha256(), 0
    while chunk := stream.read(1 << 20):
        h.update(chunk)
        n += len(chunk)
    return n, h.hexdigest()


def piped(*args) -> tuple[int, str]:
    with subprocess.Popen([str(a) for a in args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as p:
        result = digest(p.stdout)
    assert p.returncode == 0, args
    return result


def test_rar_over_4_gib(tmp_path):
    src = sparse_file(tmp_path / "big ü.bin", SIZE, MARKS)
    with open(src, "rb") as f:
        expected = digest(f)
    assert expected[0] == SIZE
    archive = tmp_path / "big.rar"
    packport.write_rar(archive, [src])
    with open(archive, "rb") as f:
        head = f.read(100)
    flags, = struct.unpack_from("<H", head, 20 + 3)
    assert flags & FHD_LARGE and flags & FHD_UNICODE
    lo, = struct.unpack_from("<I", head, 20 + 7)
    hi, = struct.unpack_from("<I", head, 20 + 32)
    assert hi << 32 | lo == SIZE
    if SEVEN_ZIP:
        run(SEVEN_ZIP, "t", archive)  # checks the CRC of all 4 GB
        assert piped(SEVEN_ZIP, "e", "-so", archive) == expected
    if BSDTAR:
        assert piped(BSDTAR, "-xOf", archive) == expected
    if not (SEVEN_ZIP or BSDTAR):
        pytest.skip("neither 7-Zip nor bsdtar is installed")
