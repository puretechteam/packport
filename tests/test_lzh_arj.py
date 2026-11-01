"""LZH and ARJ: big archives from the test-only encoders (data/made, see make_fixtures.py), which
7-Zip has to read back, plus self-extractors, garbled members, Unix modes and damaged input."""

import hashlib
import json
import random
import stat
import struct
import zlib
from pathlib import Path

import pytest
from conftest import SEVEN_ZIP, needs_7z, run
from lzss_writer import arj_archive, lzh_archive

import packport
from packport import EncryptedError, PackportError

MADE = Path(__file__).parent / "data" / "made"
COMMONS = Path(__file__).parent / "data" / "commons-compress"
EXPECTED = json.loads((MADE / "expected.json").read_text(encoding="utf-8"))
WRITTEN_HERE = ["lh5.lzh", "lh6.lzh", "lh7.lzh", "method1.arj", "method4.arj", "ppmd_cut_off.zip", "shrink.zip"]


def _hashes(src) -> dict:
    with packport.open(src) as a:
        return {m.name: hashlib.sha256(s.read()).hexdigest() for m, s in a.files()}


@needs_7z
@pytest.mark.parametrize("name", WRITTEN_HERE)
def test_7zip_reads_the_fixtures_written_here(tmp_path, name):
    # from test-only encoders (7-Zip writes none of these): 7-Zip is the judge
    run(SEVEN_ZIP, "x", "-y", f"-o{tmp_path}", MADE / name)
    theirs = {p.relative_to(tmp_path).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in tmp_path.rglob("*") if p.is_file()}
    assert theirs == EXPECTED[name]


@pytest.mark.parametrize("name, fmt", [("lh7.lzh", "lzh"), ("method4.arj", "arj")])
def test_formats_are_told_apart(name, fmt):
    assert packport.detect(MADE / name) == fmt


@pytest.mark.parametrize("name", ["lh5.lzh", "method1.arj"])
def test_a_self_extractor_is_read(name):
    data = (MADE / name).read_bytes()
    assert _hashes(b"MZ" + bytes(3000) + data) == EXPECTED[name]


def test_folders_come_through():
    with packport.open(MADE / "lh6.lzh") as a:
        names = {m.name for m in a.members}
    assert {"sub/code.bin", "sub/empty.txt", "one byte.txt"} <= names


def test_a_garbled_arj_member_is_refused():
    data = bytearray(arj_archive({"secret.txt": b"hidden"}, 0))
    at = data.find(b"\x60\xea", 4)  # the member's header
    size = struct.unpack_from("<H", data, at + 2)[0]
    data[at + 4 + 4] |= 0x01  # flags: garbled
    struct.pack_into("<I", data, at + 4 + size, zlib.crc32(data[at + 4:at + 4 + size]))
    with packport.open(bytes(data)) as a:
        assert a.members[0].encrypted
        with pytest.raises(EncryptedError):
            a.read("secret.txt")


def test_unix_arj_files_are_plain_files():
    # ARJ for Unix stores a mode whose type bits read as a FIFO: the member is a file all the same
    with packport.open(COMMONS / "bla.unix.arj") as a:
        assert [(m.name, stat.S_ISREG(m.mode), oct(m.mode & 0o777)) for m in a.members] == \
            [("test1.xml", True, "0o664"), ("test2.xml", True, "0o664")]


def test_a_bad_lzh_checksum_is_caught():
    data = bytearray(lzh_archive({"a.txt": b"hello " * 500}, "lh5"))
    data[-3] ^= 0x40  # inside the packed data
    with pytest.raises(PackportError):
        _hashes(bytes(data))


@pytest.mark.parametrize("name", ["lh5.lzh", "lh7.lzh", "method1.arj", "method4.arj"])
def test_damaged_archives_raise_only_packport_error(name):
    rng = random.Random(name)
    data = (MADE / name).read_bytes()
    bad = []
    for _ in range(40):
        b = bytearray(data)
        for _ in range(rng.randint(1, 8)):
            b[rng.randrange(len(b))] = rng.randrange(256)
        if rng.random() < 0.3:
            b = b[:rng.randrange(len(b))]
        try:
            with packport.open(bytes(b)) as a:
                for _m, s in a.files():
                    s.read()
        except PackportError:
            pass
        except Exception as e:  # noqa: BLE001
            bad.append(f"{type(e).__name__}: {e}")
    assert bad == []
