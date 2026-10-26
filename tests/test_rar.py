import io
import random
import struct
import zlib

import pytest
from conftest import MTIME, read_tree

import packport
from packport import Entry, PackportError, RarWriter, read_rar, write_rar
from packport.rar import (
    FHD_DIRECTORY,
    FHD_LARGE,
    FHD_UNICODE,
    LONG_BLOCK,
    decode_name,
    dos_time,
    encode_name,
)


def blocks(data: bytes):
    """(type, flags, header bytes) for every block after the marker."""
    pos, out = 7, []
    while pos < len(data):
        crc, htype, flags, size = struct.unpack_from("<HBHH", data, pos)
        assert zlib.crc32(data[pos + 2:pos + size]) & 0xFFFF == crc
        add = struct.unpack_from("<I", data, pos + 7)[0] if flags & LONG_BLOCK else 0
        if htype == 0x74 and flags & FHD_LARGE:
            add |= struct.unpack_from("<I", data, pos + 32)[0] << 32
        out.append((htype, flags, data[pos:pos + size]))
        pos += size + add
    return out


def test_layout_matches_the_technote():
    out = io.BytesIO()
    with RarWriter(out) as rar:
        rar.add("a.txt", b"hello", mtime=MTIME)
        rar.add("dir", is_dir=True, mtime=MTIME)
    data = out.getvalue()
    assert data[:7] == b"Rar!\x1a\x07\x00"
    assert data[7:20] == bytes.fromhex("cf90 7300 000d 00 0000 00000000".replace(" ", ""))  # WinRAR's own
    assert data[-7:] == bytes.fromhex("c43d7b00400700")  # end of archive, as WinRAR writes it
    _, (t1, f1, h1), (t2, f2, h2), (t3, _, _) = blocks(data)
    assert (t1, t2, t3) == (0x74, 0x74, 0x7B)
    pack, unp, host, crc, ftime, ver, method, nsize, attr = struct.unpack_from("<IIBIIBBHI", h1, 7)
    assert (pack, unp, host, crc, ver, method, nsize, attr) == (5, 5, 2, zlib.crc32(b"hello"), 20, 0x30, 5, 0x20)
    assert ftime == dos_time(MTIME)
    assert h1[32:] == b"a.txt" and f1 == LONG_BLOCK
    assert f2 == LONG_BLOCK | FHD_DIRECTORY and struct.unpack_from("<I", h2, 28)[0] == 0x10


def test_round_trip(unicode_tree):
    entries = write_rar(unicode_tree.parent / "out.rar", packport.tree(unicode_tree))
    back = read_rar(unicode_tree.parent / "out.rar")
    assert [m.name for m in back] == [e.name for e in entries]
    assert {m.name: (None if m.is_dir else m.data) for m in back} == read_tree(unicode_tree)
    readme = next(m for m in back if m.name == "readme.txt")
    assert readme.mtime == pytest.approx(MTIME, abs=2)


def test_folder_source_keeps_its_name(unicode_tree, tmp_path):
    write_rar(tmp_path / "a.rar", unicode_tree)
    names = [m.name for m in read_rar(tmp_path / "a.rar")]
    assert names[0] == "src" and all(n.startswith("src/") for n in names[1:])
    write_rar(tmp_path / "b.rar", [unicode_tree / "readme.txt", ("extra/x.bin", b"\0\1")])
    assert [m.name for m in read_rar(tmp_path / "b.rar")] == ["readme.txt", "extra/x.bin"]


def test_non_seekable_output_reads_files_twice(unicode_tree, tmp_path):
    class Pipe(io.RawIOBase):
        def __init__(self):
            self.buf = bytearray()

        def writable(self):
            return True

        def write(self, b):
            self.buf += b
            return len(b)

    pipe = Pipe()
    write_rar(pipe, packport.tree(unicode_tree))
    write_rar(tmp_path / "seek.rar", packport.tree(unicode_tree))
    assert bytes(pipe.buf) == (tmp_path / "seek.rar").read_bytes()


@pytest.mark.parametrize("name", ["plain.txt", "café.txt", "日本語/ファイル.txt", "emoji 😀.txt", "mixé日本😀ab",
                                  "Ελληνικά", "ĀāĂăĄą"])
def test_unicode_names(name):
    field, unicode = encode_name(name)
    assert unicode == (not name.isascii())
    assert decode_name(field, unicode) == name.replace("/", "\\")
    if unicode:
        plain = field.split(b"\0")[0]
        assert plain.isascii() and len(plain) == len(name)


def test_unicode_name_flag_in_header(tmp_path):
    write_rar(tmp_path / "u.rar", {"日本.txt": b"x"})
    (_, _, _), (_, flags, _), _ = blocks((tmp_path / "u.rar").read_bytes())
    assert flags & FHD_UNICODE


def test_unicode_names_fuzz():
    rng = random.Random(7)
    pools = ["abcXYZ019 ._-", "éüñßøåÆ", "日本語中文漢字", "αβγδΩ", "😀🎉🎈🚀", "Ѐ-ѯ"]
    for _ in range(500):
        name = "".join(rng.choice(rng.choice(pools)) for _ in range(rng.randint(1, 40)))
        field, unicode = encode_name(name)
        assert decode_name(field, unicode) == name


def test_decodes_run_modes_other_writers_use():
    # mode 3: copy a run from the plain name, with and without a correction added to each byte
    assert decode_name(b"abcdef\0" + bytes([0x00, 0b11000000, 0x04]), True) == "abcdef"
    assert decode_name(b"ABC\0" + bytes([0x04, 0b11000000, 0x81, 0x10]), True) == "\u0451\u0452\u0453"


def test_large_file_header():
    head = RarWriter._header(b"big.bin", False, 0x20, 0, (5 << 32) + 7, 0x12345678, False)
    flags = struct.unpack_from("<H", head, 3)[0]
    assert flags & FHD_LARGE
    pack, unp = struct.unpack_from("<II", head, 7)
    hi_pack, hi_unp = struct.unpack_from("<II", head, 32)
    assert (pack, unp, hi_pack, hi_unp) == (7, 7, 5, 5)
    assert head[40:] == b"big.bin"
    assert head[24] == 29  # needs RAR 2.9 to extract


def test_dos_time_limits():
    assert dos_time(0) == 1 << 21 | 1 << 16
    assert dos_time(2 ** 33) >> 25 == 127


@pytest.mark.parametrize("bad", ["", "/abs/path", "../up", "a/../../b", "C:/x", "a\0b"])
def test_bad_names_are_refused(bad):
    with pytest.raises(PackportError):
        Entry(bad, b"")


def test_names_are_cleaned():
    assert Entry("./a\\b//c/", b"").name == "a/b/c"


def test_duplicates_are_refused(tmp_path):
    with pytest.raises(PackportError, match="twice"):
        write_rar(tmp_path / "d.rar", [("a.txt", b"1"), ("a.txt", b"2")])
    assert not (tmp_path / "d.rar").exists()  # a failed write leaves no half-written file


def test_file_that_shrinks_while_read_is_an_error():
    from packport.entries import copy
    with pytest.raises(PackportError, match="shorter"):
        copy(io.BytesIO(b"x" * 10), io.BytesIO(), 100, "f.bin")


def test_reader_refuses_what_it_cannot_read(tmp_path):
    with pytest.raises(PackportError, match="RAR 5"):
        read_rar(b"Rar!\x1a\x07\x01\x00" + bytes(20))
    with pytest.raises(PackportError, match="Not a RAR"):
        read_rar(b"PK\3\4")
    out = io.BytesIO()
    with RarWriter(out) as rar:
        rar.add("a.txt", b"hello")
    data = bytearray(out.getvalue())
    data[20 + 25] = 0x33  # method byte -> "normal" compression
    data[20:22] = struct.pack("<H", zlib.crc32(data[22:20 + 37]) & 0xFFFF)
    with pytest.raises(PackportError, match="compressed"):
        read_rar(bytes(data))


def test_names_too_long_for_a_header(tmp_path):
    with pytest.raises(PackportError, match="too long"):
        write_rar(tmp_path / "long.rar", {"x" * 70000: b""})
    assert not (tmp_path / "long.rar").exists()


def test_files_are_streamed_not_loaded(tmp_path):
    import tracemalloc

    from conftest import sparse_file
    big = sparse_file(tmp_path / "big.bin", 300_000_000, {150_000_000: b"middle"})
    for write in (write_rar, packport.write_cpio):
        tracemalloc.start()
        write(tmp_path / "out", [big])
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        assert peak < 20_000_000, (write.__name__, peak)  # a few 1 MB chunks, not 300 MB
