"""WIM: packport reads 7-Zip's WIMs and 7-Zip reads packport's, and compressed WIMs (XPRESS chunks
from Windows' own compressor, LZX chunks in WIM's framing) read the same in both."""

import ctypes
import os
import random
import struct
from pathlib import Path

import pytest
from conftest import SEVEN_ZIP, extract_7z, needs_7z, read_tree, run

import packport
from packport import PackportError
from packport.wim import (
    FLAG_LZMS,
    FLAG_LZX,
    FLAG_XPRESS,
    RES_COMPRESSED,
    RES_METADATA,
    write_wim,
)

needs_winapi = pytest.mark.skipif(os.name != "nt", reason="Windows' Compression API is needed")


def _tree(root: Path) -> Path:
    rng = random.Random(9)
    words = [bytes(rng.choice(b"abcdefgh") for _ in range(rng.randint(1, 8))) for _ in range(300)]
    files = {"text.txt": b" ".join(rng.choice(words) for _ in range(40_000)), "random.bin": rng.randbytes(90_000),
             "sub/same.txt": b"twice\n" * 500, "sub/again.txt": b"twice\n" * 500, "sub/deep/zero.bin": b"",
             "ünïcödé/naïve.txt": "naïve".encode()}
    for name, data in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(data)
    (root / "empty folder").mkdir()
    return root


def _read(path) -> dict:
    with packport.open(path) as a:
        out = {m.name: None for m in a.members if m.is_dir}
        out.update({m.name: s.read() for m, s in a.files()})
    return out


@needs_7z
def test_we_read_7zips_wim(tmp_path):
    src = _tree(tmp_path / "src")
    run(SEVEN_ZIP, "a", "-twim", tmp_path / "7z.wim", str(src) + os.sep + "*")
    assert packport.detect(tmp_path / "7z.wim") == "wim"
    assert _read(tmp_path / "7z.wim") == read_tree(src)


@needs_7z
def test_7zip_reads_our_wim(tmp_path):
    src = _tree(tmp_path / "src")
    write_wim(tmp_path / "ours.wim", packport.tree(src))
    run(SEVEN_ZIP, "t", tmp_path / "ours.wim")
    assert read_tree(extract_7z(tmp_path / "ours.wim", tmp_path / "out")) == read_tree(src)


def test_our_wim_round_trips_and_stores_each_file_once(tmp_path):
    src = _tree(tmp_path / "src")
    write_wim(tmp_path / "ours.wim", packport.tree(src))
    assert _read(tmp_path / "ours.wim") == read_tree(src)
    data = (tmp_path / "ours.wim").read_bytes()
    assert data.count(b"twice\n" * 500) == 1  # two files with the same contents, stored once


# ---- compressed WIMs, made from an uncompressed one


def _windows_xpress(chunk: bytes) -> bytes:
    c = ctypes.WinDLL("cabinet.dll")
    h = ctypes.c_void_p()
    assert c.CreateCompressor(4 | 0x20000000, None, ctypes.byref(h))  # XPRESS Huffman, raw
    try:
        out = ctypes.create_string_buffer(len(chunk) * 2 + 1024)
        n = ctypes.c_size_t()
        assert c.Compress(h, chunk, len(chunk), out, len(out), ctypes.byref(n))
        return out.raw[:n.value]
    finally:
        c.CloseCompressor(h)


def _lzx_stored(chunk: bytes) -> bytes:
    """One chunk as an uncompressed LZX block, framed the WIM way: type 3, a "32 KB" bit or a
    16-bit size, padding to 16 bits, the three repeat offsets, the bytes (padded to even)."""
    bits = [(3, 3)]
    bits += [(1, 1)] if len(chunk) == 32768 else [(0, 1), (len(chunk), 16)]
    acc = n = 0
    words = bytearray()
    for value, width in bits:
        acc, n = acc << width | value, n + width
    pad = -n % 16 or 16
    acc, n = acc << pad, n + pad
    for k in range(n // 16):
        words += ((acc >> (n - 16 * (k + 1))) & 0xFFFF).to_bytes(2, "little")
    return bytes(words) + struct.pack("<III", 1, 1, 1) + chunk + bytes(len(chunk) % 2)


def _recompress(wim: bytes, flag: int, compress) -> bytes:
    """The WIM with every file resource re-written in 32 KB compressed chunks."""
    head = bytearray(wim[:208])
    size, off, _ = struct.unpack_from("<QQQ", head, 48)
    table = wim[off:off + (size & ((1 << 56) - 1))]
    out = bytearray(head)
    entries = bytearray()
    for at in range(0, len(table), 50):
        e = table[at:at + 50]
        a, roff, rorig = struct.unpack_from("<QQQ", e)
        rflags, rsize = a >> 56, a & ((1 << 56) - 1)
        data = wim[roff:roff + rsize]
        if rflags & RES_METADATA:
            new = data
        else:
            chunks = [data[k:k + 32768] for k in range(0, len(data), 32768)]
            packed = [compress(c) for c in chunks]
            packed = [p if len(p) < len(c) else c for p, c in zip(packed, chunks)]  # no gain: stored
            starts, total = [], 0
            for p in packed[:-1]:
                total += len(p)
                starts.append(total)
            new = struct.pack(f"<{len(starts)}I", *starts) + b"".join(packed)
            rflags |= RES_COMPRESSED
        place = len(out)
        out += new
        entries += struct.pack("<QQQ", len(new) | rflags << 56, place, rorig) + e[24:]
    xml_size, xml_off, _ = struct.unpack_from("<QQQ", head, 72)
    xml = wim[xml_off:xml_off + (xml_size & ((1 << 56) - 1))]
    table_at = len(out)
    out += entries
    xml_at = len(out)
    out += xml
    struct.pack_into("<I", out, 16, struct.unpack_from("<I", head, 16)[0] | 0x2 | flag)
    struct.pack_into("<I", out, 20, 32768)
    struct.pack_into("<QQQ", out, 48, len(entries) | RES_METADATA << 56, table_at, len(entries))
    struct.pack_into("<QQQ", out, 72, len(xml) | RES_METADATA << 56, xml_at, len(xml))
    return bytes(out)


@needs_winapi
@needs_7z
def test_xpress_wim(tmp_path):
    src = _tree(tmp_path / "src")
    write_wim(tmp_path / "plain.wim", packport.tree(src))
    (tmp_path / "xpress.wim").write_bytes(_recompress((tmp_path / "plain.wim").read_bytes(), FLAG_XPRESS,
                                                      _windows_xpress))
    assert read_tree(extract_7z(tmp_path / "xpress.wim", tmp_path / "7z")) == read_tree(src)
    assert _read(tmp_path / "xpress.wim") == read_tree(src)


@needs_7z
def test_lzx_wim_framing(tmp_path):
    src = _tree(tmp_path / "src")
    write_wim(tmp_path / "plain.wim", packport.tree(src))
    (tmp_path / "lzx.wim").write_bytes(_recompress((tmp_path / "plain.wim").read_bytes(), FLAG_LZX, _lzx_stored))
    assert read_tree(extract_7z(tmp_path / "lzx.wim", tmp_path / "7z")) == read_tree(src)
    assert _read(tmp_path / "lzx.wim") == read_tree(src)


def test_lzms_and_spanned_wims_are_refused(tmp_path):
    src = _tree(tmp_path / "src")
    write_wim(tmp_path / "plain.wim", packport.tree(src))
    data = bytearray((tmp_path / "plain.wim").read_bytes())
    lzms = bytearray(data)
    struct.pack_into("<I", lzms, 16, FLAG_LZMS | 0x2)
    with pytest.raises(PackportError, match="LZMS"):
        packport.open(bytes(lzms))
    spanned = bytearray(data)
    struct.pack_into("<HH", spanned, 40, 1, 2)
    with pytest.raises(PackportError, match="spanned"):
        packport.open(bytes(spanned))


def test_damaged_wims_raise_only_packport_error(tmp_path):
    src = _tree(tmp_path / "src")
    write_wim(tmp_path / "plain.wim", packport.tree(src))
    data = (tmp_path / "plain.wim").read_bytes()
    samples = [data, _recompress(data, FLAG_LZX, _lzx_stored)]
    rng = random.Random(4)
    bad = []
    for sample in samples:
        for _ in range(150):
            b = bytearray(sample)
            for _ in range(rng.randint(1, 6)):
                b[rng.randrange(len(b))] = rng.randrange(256)
            if rng.random() < 0.3:
                b = b[:rng.randrange(len(b))]
            try:
                _read(bytes(b))
            except PackportError:
                pass
            except Exception as e:  # noqa: BLE001
                bad.append(f"{type(e).__name__}: {e}")
    assert bad == []
