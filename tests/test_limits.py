"""Small hostile files that used to fill memory, the disk or the CPU, and the other damage found
in the 0.3.2 review: each is refused or read within a budget now. Hangs run in a subprocess with
a time limit, so one coming back can't stop the suite."""

import bz2
import gzip
import io
import lzma
import os
import struct
import subprocess
import sys
import time
import tracemalloc
import zipfile
import zlib
from pathlib import Path

import pytest
from test_readers import _gnu_ar, _rpm, _tar

import packport
from packport import PackportError, archive, entries

SRC = str(Path(__file__).resolve().parent.parent / "src")


def _finishes(code: str, seconds: float = 20) -> str:
    """Run code in a fresh Python; it must finish within seconds. Its output."""
    try:
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=seconds, check=False,
                           env={**os.environ, "PYTHONPATH": SRC})
    except subprocess.TimeoutExpired:
        pytest.fail(f"still running after {seconds} s")
    assert r.returncode == 0, r.stderr
    return r.stdout


def _peak(fn) -> int:
    """Python's peak allocation, in bytes, while fn runs."""
    tracemalloc.start()
    try:
        fn()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


# ---- archives unpacked ahead into a temporary file stop at a limit

def _nsis(packed_zeros_mb: int) -> bytes:
    from packport import nsis
    body = bz2.compress(bytes(packed_zeros_mb << 20), 9)[4:]  # NSIS's bzip2 has no "BZh9"
    head = struct.pack("<I", 0) + nsis.SIG + struct.pack("<II", 1000, 28 + len(body))
    return b"MZ" + bytes(510) + head + body


def test_a_solid_nsis_bomb_stops_at_the_limit():
    """778 bytes that unpack to 300 MB were all written to a temporary file as the installer opened."""
    data = _nsis(80)
    assert len(data) < 2000
    with pytest.raises(entries.TooBig, match="more than 67,108,864 bytes"):
        packport.open(data)
    with pytest.raises(entries.TooBig, match="more than 1,048,576 bytes"):
        packport.open(data, max_size=1 << 20)


def test_an_explicit_none_lifts_the_spool_limit(monkeypatch, tmp_path):
    """The 200x cap is for callers who said nothing. A legitimate payload that unpacks to more than that (here
    1 MB from a few hundred bytes, with the cap lowered to match) opens with max_size=None, or a number big enough."""
    rpm = _rpm({"./data.bin": bytes(1 << 20)}, "xz")
    monkeypatch.setattr(entries, "SPOOL_FLOOR", 1000)
    with pytest.raises(entries.TooBig):
        packport.open(rpm)  # nothing said: capped
    with pytest.raises(entries.TooBig):
        packport.extract(rpm, tmp_path / "default")  # extract()'s "free" default: capped too
    with pytest.raises(entries.TooBig):
        packport.open(rpm, max_size=1 << 19)  # their own, smaller number
    with packport.open(rpm, max_size=None) as a:
        assert [m.size for m in a.members if m.is_file] == [1 << 20]
    with packport.open(rpm, max_size=2 << 20) as a:
        assert len(a.members) == 1
    packport.extract(rpm, tmp_path / "all", max_size=None)
    assert [p.stat().st_size for p in (tmp_path / "all").rglob("*") if p.is_file()] == [1 << 20]


def test_an_rpm_payload_bomb_stops_at_the_limit():
    data = _rpm({}, "xz", raw=bytes(80 << 20))  # xz-compressed by _rpm: about 12 KB
    with pytest.raises(entries.TooBig):
        packport.open(data)


def test_many_rpm_header_tags_are_not_copied_each():
    """Each tag kept a copy of the rest of the header's data: 2,000 tags of a 4 MB header peaked at
    8 GB (2.1 s), now 10 MB. Checked by memory, not time, so a busy machine can't fail it."""
    count, size = 2000, 4 << 20
    lead = b"\xed\xab\xee\xdb" + bytes(92)
    sig = b"\x8e\xad\xe8\x01" + bytes(4) + struct.pack(">II", 0, 0)
    index = b"".join(struct.pack(">IIII", 1000 + k, 7, 1, 1) for k in range(count))
    main = b"\x8e\xad\xe8\x01" + bytes(4) + struct.pack(">II", count, size) + index + bytes(size)
    peak = _peak(lambda: pytest.raises(PackportError, packport.open, lead + sig + main))
    assert peak < 64 << 20


def test_a_pkg_pbzx_payload_bomb_stops_at_the_limit():
    from packport.xar import pbzx
    xz = lzma.compress(bytes(80 << 20), preset=0)
    stream = b"pbzx" + struct.pack(">Q", 1 << 24) + struct.pack(">QQ", 1 << 24, len(xz)) + xz
    with pytest.raises(entries.TooBig):
        for _ in pbzx(io.BytesIO(stream), 1 << 20):
            pass
    assert b"".join(pbzx(io.BytesIO(stream[:12] + struct.pack(">QQ", 3, 3) + b"abc"))) == b"abc"


def test_nsis_strings_are_capped_and_kept():
    from packport.nsis import MAX_STRING, _strings
    text = _strings(b"A" * (1 << 20), False)
    assert len(text(0)) == MAX_STRING
    assert text(0) is text(0)  # worked out once


# ---- decoders stop at what the file says it holds

def test_a_huge_xpress_match_is_cut_to_the_size():
    """275 bytes asking for one 64 MB match, of which 10 bytes are wanted."""
    code = (
        "import ctypes, ctypes.wintypes as w, struct\n"
        "from packport import xpress\n"
        "class P(ctypes.Structure):\n"
        "    _fields_ = [('cb', w.DWORD), ('f', w.DWORD)] + [(n, ctypes.c_size_t) for n in 'abcdefgh']\n"
        "def peak():\n"
        "    p = P(); p.cb = ctypes.sizeof(p)\n"
        "    ctypes.windll.kernel32.K32GetProcessMemoryInfo(w.HANDLE(-1), ctypes.byref(p), p.cb)\n"
        "    return p.h\n"
        "t = bytearray(256); t[0] = 0x01; t[135] = 0x10\n"
        "data = bytes(t) + b'\\x00\\x40\\x00\\x00' + b'\\xff\\x00\\x00' + struct.pack('<I', (64 << 20) + 15) + bytes(8)\n"
        "before = peak()\n"
        "out = xpress.decompress(data, 10)\n"
        "print(len(out), (peak() - before) >> 20)\n")
    for pure in ("", "1"):
        os.environ["PACKPORT_PURE"] = pure
        try:
            got, grew = map(int, _finishes(code).split())
        finally:
            os.environ.pop("PACKPORT_PURE")
        assert got == 10 and grew < 16


def _rar5_block(repeats: int) -> bytes:
    """A RAR 5 block: tables, a literal, a 4,097-byte match, then repeats one-bit "repeat the last
    match" symbols (4 KB each)."""
    bits: list[int] = []

    def put(v, n):
        bits.extend((v >> (n - 1 - k)) & 1 for k in range(n))

    def code(s):
        bits.extend(int(c) for c in s)
    bc = [0] * 20
    bc[1] = bc[2] = 2
    bc[19] = 1
    for n in bc:
        put(n, 4)

    def zeros(k):
        while k:
            r = min(k, 138)
            code("0")
            put(r - 11, 7)
            k -= r
    zeros(65); code("11"); zeros(138); zeros(53); code("10"); zeros(47); code("11")
    code("10"); zeros(112); zeros(11)
    code("10"); code("11"); put(511, 9); code("0")
    bits.extend([0] * repeats)
    nbits = len(bits)
    bits += [0] * (-len(bits) % 8)
    data = bytes(int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8))
    flags = 0x80 | 0x40 | (1 << 3) | ((nbits - 1) % 8)
    raw = len(data).to_bytes(2, "little")
    return bytes([flags, (0x5A ^ flags ^ raw[0] ^ raw[1]) & 0xFF]) + raw + data


@pytest.mark.parametrize("pure", [True, False])
def test_a_rar5_block_stops_past_the_file_size(pure):
    """2 KB of block decoded to 65 MB of history before the size of a 100-byte file was checked."""
    from packport import rar5
    dec = rar5.Unpack5(4 << 20)
    if pure:
        dec.native = None
    elif dec.native is None:
        pytest.skip("packport-native isn't installed")
    packed = io.BytesIO(_rar5_block(16000))

    def run():
        with pytest.raises(PackportError, match="more data than its stated size"):
            b"".join(dec.unpack(packed, 100))
    assert _peak(run) < 16 << 20


def test_a_7z_header_size_never_sizes_a_buffer(tmp_path):
    """A 52-byte 7z file saying its header is 1.5 GB: the read allocated 1.5 GB before finding it short."""
    tail = struct.pack("<QQI", 0, 1_500_000_000, 0)
    path = tmp_path / "big_header.7z"
    path.write_bytes(b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", zlib.crc32(tail)) + tail + b"\x01\x00")
    assert _peak(lambda: pytest.raises(PackportError, packport.open, path)) < 16 << 20


def test_a_7z_folder_with_a_million_streams_is_refused():
    from packport import sevenzip
    n_out = 1_000_000
    num = bytes([0xC0 | (n_out >> 16), n_out & 0xFF, (n_out >> 8) & 0xFF])
    data = b"\x01\x11\x00\x01" + num + b"\x00\x00" * 64
    with pytest.raises(PackportError, match="too many streams"):
        sevenzip._read_folder(sevenzip._In(data))


def test_the_lzma_dictionary_is_no_bigger_than_the_data():
    from packport.sevenzip import _dictionary
    assert _dictionary(1 << 30, 5000) == 5000
    assert _dictionary(1 << 20, 1 << 30) == 1 << 20
    assert _dictionary(100, 10) == 4096  # liblzma's smallest
    assert _dictionary(0xFFFFFFFF, None) == 0xFFFFFFFF


# ---- ZIP

def test_a_zip_full_of_false_descriptors_opens_in_one_pass(tmp_path):
    """No central directory and 40,000 false descriptor signatures (160 KB) took 11.5 s: each read
    up to 1 MB again from the file."""
    lh = b"PK\x03\x04" + struct.pack("<HHHHHIIIHH", 20, 8, 0, 0, 0, 0, 0, 0, 1, 0) + b"a"
    path = tmp_path / "descriptors.zip"
    path.write_bytes(lh + b"PK\x07\x08" * 40000)
    reads = []
    original = archive.Source.read_at
    start = time.perf_counter()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(archive.Source, "read_at", lambda self, at, n: reads.append(n) or original(self, at, n))
        with pytest.raises(PackportError):
            packport.open(path)
    assert time.perf_counter() - start < 1.0 and len(reads) < 50


def test_measuring_a_deflate_member_holds_little():
    """A member whose sizes follow its data is inflated to find its end: it held the whole output."""
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    body = c.compress(bytes(64 << 20)) + c.flush()
    crc = zlib.crc32(bytes(64 << 20))
    lh = b"PK\x03\x04" + struct.pack("<HHHHHIIIHH", 20, 8, 8, 0, 0, 0, 0, 0, 1, 0) + b"a"
    data = lh + body + b"PK\x07\x08" + struct.pack("<III", crc, len(body), 64 << 20)
    box = {}
    peak = _peak(lambda: box.setdefault("a", packport.open(data)))
    assert box["a"].members[0].size == 64 << 20 and peak < 16 << 20


def _overlapping_zip(n: int) -> bytes:
    """One stored member, and n central entries all pointing at it (a "non-recursive" ZIP bomb)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a", b"x" * 100)
    data = buf.getvalue()
    cd = data.index(b"PK\x01\x02")
    end = data.index(b"PK\x05\x06")
    entry = data[cd:end]
    entries_ = b"".join(entry.replace(b"a", bytes([97 + k % 26]), 1) for k in range(n))
    tail = bytearray(data[end:])
    struct.pack_into("<HHII", tail, 8, n, n, len(entries_), cd)
    return data[:cd] + entries_ + bytes(tail)


def test_zip_members_that_overlap_are_refused():
    with pytest.raises(PackportError, match="overlap"):
        packport.open(_overlapping_zip(3))


# ---- extract()

def test_a_damaged_file_isnt_left_half_written(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("good.txt", b"fine")
        z.writestr("bad.txt", b"y" * 5000)
    data = bytearray(buf.getvalue())
    at = data.index(b"y" * 100)
    data[at] = ord("z")  # the CRC no longer matches
    with pytest.raises(PackportError, match="checksum"):
        packport.extract(bytes(data), tmp_path / "out")
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == ["good.txt"]


def test_extract_stops_before_the_disk_is_full(tmp_path, monkeypatch):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("big", bytes(3 << 20))
    usage = type("U", (), {"free": 2 << 20})  # a drive with 2 MB free: by default 1.8 MB may be written
    monkeypatch.setattr(archive.shutil, "disk_usage", lambda p: usage)
    assert archive.free_space(tmp_path) == (2 << 20) - (2 << 20) // 10
    with pytest.raises(PackportError, match="unpacks to more than 1,887,437 bytes"):
        packport.extract(buf.getvalue(), tmp_path / "a")
    assert not (tmp_path / "a" / "big").exists()
    with pytest.raises(PackportError, match="unpacks to more than 1,048,576 bytes"):
        packport.extract(buf.getvalue(), tmp_path / "b", max_size=1 << 20)
    assert packport.extract(buf.getvalue(), tmp_path / "c", max_size=None)


def test_the_command_line_takes_a_size_limit(tmp_path, capsys):
    from packport.__main__ import main, size_arg
    assert (size_arg("500M"), size_arg("2g"), size_arg("none"), size_arg("1024")) == (500 << 20, 2 << 30, None, 1024)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("big", bytes(300 << 10))
    (tmp_path / "a.zip").write_bytes(buf.getvalue())
    assert main(["--extract", str(tmp_path / "a.zip"), str(tmp_path / "x"), "--max-size", "100K"]) == 1
    assert "more than 102,400 bytes" in capsys.readouterr().err
    assert main(["--extract", str(tmp_path / "a.zip"), str(tmp_path / "y")]) == 0


@pytest.mark.skipif(os.name != "nt", reason="Windows refuses these names")
def test_a_name_the_file_system_refuses_is_skipped(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("ok.txt", b"1")
        z.writestr("x" * 300 + ".txt", b"2")
        z.writestr("also.txt", b"3")
    skipped = []
    written = packport.extract(buf.getvalue(), tmp_path / "out", on_skip=skipped.append)
    assert sorted(p.name for p in written) == ["also.txt", "ok.txt"] and len(skipped) == 1


def test_anything_a_reader_raises_comes_out_as_packport_error(monkeypatch):
    from packport import zipformat
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a", b"1")

    def boom(self):
        raise ZeroDivisionError("division by zero")
        yield
    monkeypatch.setattr(zipformat.ZipArchive, "_files", boom)
    with packport.open(buf.getvalue()) as a, pytest.raises(PackportError, match="ZeroDivisionError"):
        list(a.files())

    def no_volume(self, source):
        raise OSError(24, "Too many open files")
    monkeypatch.setattr(zipformat.ZipArchive, "__init__", no_volume)
    with pytest.raises(PackportError, match="couldn't be read"):
        packport.open(buf.getvalue())


# ---- file systems and discs

def test_a_looping_fat32_chain_with_a_huge_cluster_count_stops():
    """A FAT32 boot sector saying 2^32 sectors and a root folder whose chain points at itself."""
    code = (
        "import struct\n"
        "from packport.archive import Source\n"
        "from packport.fs.fat import Fat\n"
        "from packport.entries import PackportError\n"
        "boot = bytearray(512); boot[0] = 0xEB\n"
        "struct.pack_into('<HBHBHHBH', boot, 11, 512, 1, 32, 1, 0, 0, 0xF8, 0)\n"
        "struct.pack_into('<II', boot, 32, 0xFFFFFFFF, 1); struct.pack_into('<I', boot, 44, 2)\n"
        "boot[510:512] = b'\\x55\\xaa'\n"
        "img = bytearray(64 * 512); img[:512] = boot\n"
        "struct.pack_into('<I', img, 32 * 512 + 8, 2)\n"
        "try:\n"
        "    Fat(Source(bytes(img)))\n"
        "except PackportError as e:\n"
        "    print(e)\n")
    assert "loops" in _finishes(code)


def test_an_ext_extent_tree_that_points_back_is_refused():
    from packport.fs import ext

    def node(level, entries, target=0):
        out = struct.pack("<HHHHI", 0xF30A, entries, entries, level, 0)
        return out + b"".join(struct.pack("<IIHH", 0, target, 0, 0) for _ in range(entries))
    blocks = {1: node(1, 340, 2), 2: node(0, 0)}

    class Dev:
        reads = 0

        def read_at(self, at, n):
            Dev.reads += 1
            return blocks[at // 4096].ljust(4096, b"\0")
    fs = ext.Ext.__new__(ext.Ext)
    fs.dev, fs.bs = Dev(), 4096
    with pytest.raises(PackportError, match="points back"):
        fs._tree(node(2, 4, 1), [], 0, set())
    assert Dev.reads <= 3


def test_a_huge_sparse_compressed_ntfs_run_is_cut_to_the_file():
    """A 1 KB file whose runlist claims 2^40 bytes was split into 2^24 compression units first."""
    code = (
        "from packport.fs.ntfs import Ntfs\n"
        "from packport.archive import Item, Stream\n"
        "fs = Ntfs.__new__(Ntfs); fs.cluster, fs.dev = 4096, None\n"
        "attr = {'unit': 4, 'pieces': [(0, [(None, 1 << 40)])]}\n"
        "item = Item('f', 1024)\n"
        "print(len(Stream('f', fs._lznt1(item, attr), 1024).read()))\n")
    assert _finishes(code, 10).strip() == "1024"


def test_a_udf_sparing_table_keeps_one_entry_per_packet():
    from packport import udf
    lvd = bytearray(200)
    struct.pack_into("<HB", lvd, 40, 1024, 1)
    struct.pack_into("<II", lvd, 44, 1 << 16, 2)
    table = bytearray(56 + 8 * 1000)
    table[17:35] = b"*UDF Sparing Table"
    struct.pack_into("<H", table, 48, 1000)
    for e in range(1000):
        struct.pack_into("<II", table, 56 + 8 * e, e * 1024, 5_000_000 + e * 1024)
    disc = udf.UdfArchive.__new__(udf.UdfArchive)
    disc.source, disc.bs = archive.Source(bytes(2 * 2048) + bytes(table)), 2048
    packet, remap = disc._sparing(bytes(lvd), 0)
    assert packet == 1024 and len(remap) == 1000
    disc.maps = [("sparable", 0, (packet, remap))]
    assert disc._sector(3 * 1024 + 7, 0) == 5_000_000 + 3 * 1024 + 7
    assert disc._sector(2_000_000, 0) == 2_000_000


def test_an_hfs_block_table_never_unpacks_past_the_size():
    """A decmpfs table listing one 64 KB zlib block of zeros 2,000 times, for a 64 KB file."""
    from packport.fs import hfs
    block = zlib.compress(bytes(65536))
    count = 2000
    fork = struct.pack(">I", 0x100 - 4) + bytes(0x100 - 4)
    table = struct.pack("<I", count) + struct.pack("<II", 4 + 8 * count, len(block)) * count
    fork += table + block
    fs = hfs.Hfs.__new__(hfs.Hfs)
    fs.dev = archive.Source(fork)
    fs.decmpfs = {7: b"fpmc" + struct.pack("<IQ", 4, 65536)}
    fs._fork_runs = lambda fork_, fid, kind: [(0, len(fork))]
    rsrc = type("F", (), {"size": len(fork)})
    box = {}
    peak = _peak(lambda: box.setdefault("out", fs._decompress(packport.Item("f", 65536), 7, rsrc)))
    assert box["out"] == bytes(65536) and peak < 8 << 20


def test_a_squashfs_metadata_offset_past_its_block_is_refused():
    from packport import squashfs
    sq = squashfs.SquashfsArchive.__new__(squashfs.SquashfsArchive)
    sq._meta_block = lambda at: (b"x" * 8192, at + 8194)
    with pytest.raises(PackportError, match="metadata offset"):
        sq._meta(0, 0, 9000, 10)
    assert sq._meta(0, 0, 8190, 4) == b"xxxx"


def test_readers_stop_listing_at_the_member_limit(monkeypatch):
    from packport import cpio
    buf = io.BytesIO()
    packport.write_cpio(buf, {f"f{k}": b"1" for k in range(5)})
    monkeypatch.setattr(cpio, "MAX_ITEMS", 3)
    with pytest.raises(PackportError, match="more than 3 members"):
        packport.open(buf.getvalue())


def test_a_qcow2_with_an_external_data_file_is_refused():
    h = bytearray(112)
    h[:4] = b"QFI\xfb"
    struct.pack_into(">IQII", h, 4, 3, 0, 0, 16)
    struct.pack_into(">QIIQ", h, 24, 1 << 20, 0, 1, 0)
    struct.pack_into(">Q", h, 72, 0x04)
    struct.pack_into(">I", h, 100, 104)
    from packport import vdisk
    with pytest.raises(PackportError, match="external file"):
        vdisk.Qcow2(archive.Source(bytes(h) + bytes(1 << 16)))


def test_vhdx_reads_only_what_a_file_system_asks_for(monkeypatch):
    """A few KB read from a VHDX read its whole 32 MB block each time (281 MB for 191 bytes of files)."""
    data = Path(__file__).parent / "data" / "dfvfs" / "ext2.vhdx.Z"
    if not data.is_file():
        pytest.skip("no ext2.vhdx sample")
    image = packport.decompress(data.read_bytes())
    read = []
    original = archive.Source.read_at
    monkeypatch.setattr(archive.Source, "read_at", lambda self, at, n: read.append(n) or original(self, at, n))
    with packport.open(image) as a:
        got = sum(len(s.read()) for _, s in a.files())
    assert got > 0 and sum(read) < 8 << 20


# ---- headers and names

def test_a_level3_lzh_header_of_size_0_doesnt_hang():
    code = (
        "import struct, packport\n"
        "h = struct.pack('<H5sIIIBBHBI', 4, b'-lh0-', 0, 0, 0, 0x20, 3, 0, ord('U'), 0) + struct.pack('<I', 0) + bytes(8)\n"
        "try:\n"
        "    packport.open(h)\n"
        "except packport.PackportError as e:\n"
        "    print(e)\n")
    assert "level 3 header" in _finishes(code, 10)


def _lzh0(name: bytes, data: bytes, crc: bool = True) -> bytearray:
    """A level-0 LZH member, stored (-lh0-)."""
    from packport.lzh import crc16
    body = b"-lh0-" + struct.pack("<IIIBB", len(data), len(data), 0, 0x20, 0) + bytes([len(name)]) + name
    if crc:
        body += struct.pack("<H", crc16(data, 0))
    return bytearray(bytes([len(body), sum(body) & 0xFF]) + body + data) + b"\0"


def test_an_lzh_level0_header_is_checked():
    """A bad header checksum was never noticed, and a header too short for its CRC read the data unchecked."""
    good = _lzh0(b"a.txt", b"hello")
    with packport.open(bytes(good)) as a:
        assert a.read("a.txt") == b"hello"
    bad = bytearray(good)
    bad[1] ^= 0x55
    with pytest.raises(PackportError, match="checksum"):
        packport.open(bytes(bad))
    with pytest.raises(PackportError, match="member header"):
        packport.open(bytes(_lzh0(b"a.txt", b"hello", crc=False)))


def test_a_deb_keeps_leading_dots_in_names():
    payload = {"./": None, "./.profile": b"PATH=1\n", "./etc/.hidden": b"h"}
    deb = _gnu_ar({"debian-binary": b"2.0\n", "control.tar.gz": _tar({"./control": b"Package: x\n"}, gzip.compress),
                   "data.tar": _tar(payload, lambda b: b)})
    with packport.open(deb) as a:
        names = {m.name for m in a.members}
    assert ".profile" in names and "etc/.hidden" in names


def test_rar_permissions_without_a_file_type_are_a_file():
    path = Path(__file__).parent / "data" / "libarchive" / "test_read_format_rar3_lowdist_reset.rar"
    with packport.open(path) as a:
        assert [m.name for m, _ in a.files()] == ["lowdist-reset.bin"]


def test_a_solid_rar4_members_decoder_lives_as_long_as_its_stream(tmp_path, monkeypatch):
    """open_member() on a solid member returned from inside the decoding loop, which let the
    decoder go (its history cleared) before the stream was read."""
    from packport import rar3
    src = Path(__file__).parent / "data" / "libarchive" / "test_read_format_rar_compress_normal.rar"
    b = bytearray(src.read_bytes())
    pos = 7
    while True:  # mark the first file solid (it decodes the same: nothing comes before it)
        _crc, htype, flags, hsize = struct.unpack_from("<HBHH", b, pos)
        add = struct.unpack_from("<I", b, pos + 7)[0] if flags & 0x8000 else 0
        if htype == 0x74:
            struct.pack_into("<H", b, pos + 3, flags | 0x10)
            struct.pack_into("<H", b, pos, zlib.crc32(b[pos + 2:pos + hsize]) & 0xFFFF)
            break
        pos += hsize + add
    released = []
    original = rar3.Unpack29.release
    monkeypatch.setattr(rar3.Unpack29, "release", lambda self: released.append(1) or original(self))
    with packport.open(bytes(b)) as a:
        good = next(iter(a.files()))[1].read()
        released.clear()
        stream = a.open_member(a.members[0])
        assert released == []
        assert stream.read() == good


def test_an_over_full_lzx_code_is_damage():
    from packport.lzx import _Tree
    _Tree([1, 1, 0, 0], 6)
    with pytest.raises(PackportError, match="over-full"):
        _Tree([1, 1, 1, 0], 6)


def test_a_packport_native_of_another_version_is_named(tmp_path):
    (tmp_path / "packport_native.py").write_text("__version__ = '0.0.1'\n")
    r = subprocess.run([sys.executable, "-m", "packport", "--version"], capture_output=True, text=True, check=False,
                       env={**os.environ, "PYTHONPATH": os.pathsep.join([str(tmp_path), SRC]), "PACKPORT_PURE": ""})
    assert "packport-native 0.0.1 is installed but doesn't match" in " ".join(r.stdout.split())
    assert "decoded by the (much slower) Python decoders" in r.stderr


def test_extract_keeps_its_default_limit_on_what_opens_unpack_ahead(tmp_path):
    """The default max_size (the drive's free space) is for what extract writes; it must not become
    the limit on the temporary file a solid installer is unpacked into as it opens (64 MB here)."""
    data = _nsis(80)
    with pytest.raises(entries.TooBig, match="more than 67,108,864 bytes"):
        packport.extract(data, tmp_path / "out")  # it spooled all 80 MB first and failed later on the damaged script


def test_a_squashfs_inode_whose_header_ends_a_metadata_block_reads_on_in_the_next():
    from packport import squashfs
    sq = squashfs.SquashfsArchive.__new__(squashfs.SquashfsArchive)
    blocks = {0: (b"a" * 8192, 1), 1: (b"b" * 100, 2)}
    sq._meta_block = lambda at: blocks[at]
    assert sq._meta(0, 0, 8192, 4) == b"bbbb"  # the inode started 16 bytes before the end: its fields are in the next block
    assert sq._meta(0, 0, 8192 + 16, 4) == b"bbbb"
    with pytest.raises(PackportError, match="metadata offset"):
        sq._meta(0, 0, 8192 + 256, 4)  # far past the block is damage
