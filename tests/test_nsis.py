"""NSIS installers: small ones put together here from the format's description (solid or not;
LZMA, zlib or bzip2; ANSI or Unicode strings), which 7-Zip has to read as packport does, and
Ghostscript's real installer when PACKPORT_NSIS_SAMPLE points at it (ConvertAll unpacks it)."""

import bz2
import hashlib
import lzma
import os
import struct
import zlib
from pathlib import Path

import pytest
from conftest import extract_7z, needs_7z, read_tree

import packport
from packport import PackportError

SAMPLE = os.environ.get("PACKPORT_NSIS_SAMPLE")
FILES = {"bin/tool.exe": b"MZ\x90\x00" + bytes(range(256)) * 40, "doc/readme.txt": b"read me\r\n" * 300,
         "doc/empty.txt": b""}


def _pack(method: str, data: bytes) -> bytes:
    if method == "lzma":
        packed = lzma.compress(data, format=lzma.FORMAT_ALONE, preset=6)
        return packed[:5] + packed[13:]  # NSIS keeps the properties, not the 8-byte size
    if method == "bzip2":
        return bz2.compress(data)[4:]   # without "BZh9"
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def _strings(unicode: bool):
    table = bytearray(b"\0\0" if unicode else b"\0")

    def add(parts) -> int:
        """parts: text, or ("var", n) for a variable; returns the string's offset (in characters)."""
        at = len(table) // (2 if unicode else 1)
        for p in parts:
            if isinstance(p, tuple):
                n = p[1]
                if unicode:
                    table.extend(b"\x03\x00" + bytes([(n & 0x7F) | 0x80, (n >> 7) | 0x80]))
                else:
                    table.extend(bytes([3, (n & 0x7F) | 0x80, (n >> 7) | 0x80]))
            else:
                table.extend(p.encode("utf-16-le" if unicode else "cp1252"))
        table.extend(b"\0\0" if unicode else b"\0")
        return at
    return table, add


def _installer(method: str, solid: bool, unicode: bool) -> bytes:
    table, add = _strings(unicode)
    instdir = ("var", 21)
    entries = []
    data = bytearray()
    for folder in ("bin", "doc"):
        entries.append((11, add([instdir, "\\" + folder]), 1))
        for name, content in FILES.items():
            if name.startswith(folder + "/"):
                entries.append((20, 0, add([name.split("/")[1]]), len(data)))
                if solid:
                    data += struct.pack("<I", len(content)) + content
                else:
                    packed = _pack(method, content)
                    data += struct.pack("<I", len(packed) | 0x80000000) + packed
    raw_entries = b""
    for e in entries:
        if e[0] == 11:
            raw_entries += struct.pack("<7I", 11, e[1], e[2], 0, 0, 0, 0)
        else:
            raw_entries += struct.pack("<7I", 20, 0x3, e[2], e[3], 0, 0, 0)
    head_fixed = 4 + 8 * 8 + 300  # flags, the block table, then room for the fields that follow it
    blocks = [(head_fixed, 0)] * 8
    blocks[2] = (head_fixed, len(entries))
    blocks[3] = (head_fixed + len(raw_entries), 0)
    for k in (4, 5, 6, 7):
        blocks[k] = (head_fixed + len(raw_entries) + len(table), 0)
    header = bytearray(struct.pack("<I", 0) + b"".join(struct.pack("<II", *b) for b in blocks))
    header += bytes(head_fixed - len(header)) + raw_entries + table
    if solid:
        body = _pack(method, struct.pack("<I", len(header)) + bytes(header) + bytes(data))
    else:
        packed = _pack(method, bytes(header))
        body = struct.pack("<I", len(packed) | 0x80000000) + packed + bytes(data)
    first = struct.pack("<II12sII", 0, 0xDEADBEEF, b"NullsoftInst", len(header), 28 + len(body))
    stub = b"MZ" + bytes(510)
    return stub + first + body


@pytest.mark.parametrize("method", ["lzma", "zlib", "bzip2"])
@pytest.mark.parametrize("solid", [True, False])
@pytest.mark.parametrize("unicode", [True, False])
def test_installers(method, solid, unicode):
    raw = _installer(method, solid, unicode)
    assert packport.detect(raw) == "nsis"
    with packport.open(raw) as a:
        got = {m.name: s.read() for m, s in a.files()}
    assert got == FILES


@needs_7z
def test_7zip_reads_them_as_we_do(tmp_path):
    for method in ("lzma", "zlib"):
        (tmp_path / f"{method}.exe").write_bytes(_installer(method, True, True))
        got = read_tree(extract_7z(tmp_path / f"{method}.exe", tmp_path / method))
        assert {k: v for k, v in got.items() if v is not None} == FILES


def test_damaged_installers_raise_only_packport_error():
    import random
    rng = random.Random(8)
    bad = []
    for sample in (_installer("lzma", True, True), _installer("zlib", False, False)):
        for _ in range(200):
            b = bytearray(sample)
            for _ in range(rng.randint(1, 6)):
                b[512 + rng.randrange(len(b) - 512)] = rng.randrange(256)
            if rng.random() < 0.3:
                b = b[:512 + rng.randrange(len(b) - 512)]
            try:
                with packport.open(bytes(b)) as a:
                    for _m, s in a.files():
                        s.read()
            except PackportError:
                pass
            except Exception as e:  # noqa: BLE001
                bad.append(f"{type(e).__name__}: {e}")
    assert bad == []


@pytest.mark.skipif(not SAMPLE or not Path(SAMPLE).is_file(), reason="set PACKPORT_NSIS_SAMPLE to gs10080w64.exe")
def test_ghostscripts_installer():
    with packport.open(SAMPLE) as a:
        files = {m.name: hashlib.sha256(s.read()).hexdigest() for m, s in a.files()}
    assert len(files) == 653
    assert {"bin/gswin64c.exe", "bin/gsdll64.dll"} <= set(files)
