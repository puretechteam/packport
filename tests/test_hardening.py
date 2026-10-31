"""Hostile and edge-case inputs from the 0.2.1 review: each archive here is built in code."""

import inspect
import io
import os
import stat
import tarfile
import tracemalloc

import pytest
from conftest import MTIME

import packport
from packport import (
    Entry,
    PackportError,
    ZDecompressor,
    compress,
    decompress,
    extract_cpio,
    lzw,
    read_cpio,
)
from packport import cpio as cpio_module
from packport.cpio import _header

REG = stat.S_IFREG | 0o644
DIR = stat.S_IFDIR | 0o755


def _raw(*members) -> bytes:
    """A newc archive from (name, mode, data, nlink, ino) tuples, names unchecked."""
    out = b""
    for name, mode, data, nlink, ino in members:
        out += _header(ino, mode, nlink, MTIME, len(data), name.encode()) + data + bytes(-len(data) % 4)
    return out + _header(0, 0, 1, 0, 0, b"TRAILER!!!")


def _files(dest) -> dict[str, bytes | None]:
    return {p.relative_to(dest).as_posix(): (None if p.is_dir() else p.read_bytes()) for p in dest.rglob("*")}


# CPIO extraction

def test_duplicate_names_are_numbered_without_rescanning(tmp_path, monkeypatch):
    # n copies of one name: trying "a (1)", "a (2)"... from the start each time is n*n/2 opens
    n = 300
    data = _raw(*[("a.txt", REG, b"%d" % i, 1, i + 1) for i in range(n)])
    tries = []
    real_open = open

    def counting_open(file, mode="r", *args, **kw):
        if mode == "xb":
            tries.append(file)
        return real_open(file, mode, *args, **kw)

    monkeypatch.setattr(cpio_module, "open", counting_open, raising=False)
    extract_cpio(data, tmp_path / "x")
    got = _files(tmp_path / "x")
    assert len(got) == n and got["a.txt"] == b"0" and got[f"a ({n - 1}).txt"] == b"%d" % (n - 1)
    assert len(tries) < 2 * n


def test_max_files(tmp_path):
    data = _raw(*[(f"f{i}", REG, b"", 1, i + 1) for i in range(50)])
    with pytest.raises(PackportError, match="more than 10 members"):
        extract_cpio(data, tmp_path / "capped", max_files=10)
    assert len(extract_cpio(data, tmp_path / "ok", max_files=50)) == 50
    assert inspect.signature(extract_cpio).parameters["max_files"].default == 1_000_000


def test_huge_name_size_is_refused_before_reading_the_name():
    head = bytearray(_header(1, REG, 1, MTIME, 0, b"a"))
    head[94:102] = b"7FFFFFFF"  # namesize: 2 GiB
    reads = []

    class Spy(io.BytesIO):
        def read(self, n=-1):
            reads.append(n)
            return super().read(n)

    with pytest.raises(PackportError, match="name"):
        read_cpio(Spy(bytes(head) + bytes(64)))
    assert max(reads) <= 1 << 16
    long_name = "d/" + "n" * 1000
    assert read_cpio(_raw((long_name, REG, b"ok", 1, 1)))[0].name == long_name


def test_file_and_folder_clashes(tmp_path):
    data = _raw(("a", REG, b"file a", 1, 1), ("a/b.txt", REG, b"under a file", 1, 2),
                ("d", REG, b"file d", 1, 3), ("d", DIR, b"", 2, 4),
                ("e", DIR, b"", 2, 5), ("e", REG, b"file e", 1, 6),
                ("ok.txt", REG, b"ok", 1, 7))
    skipped = []
    dest = tmp_path / "x"
    extract_cpio(data, dest, on_skip=skipped.append)
    assert _files(dest) == {"a": b"file a", "d": b"file d", "e": None, "e (1)": b"file e", "ok.txt": b"ok"}
    assert skipped == ["a/b.txt", "d"]


def test_top_level_colon_names(tmp_path):
    skipped = []
    dest = tmp_path / "x"
    # "D:rel.txt" means "rel.txt in drive D's current folder" on Windows; renamed, it's harmless
    extract_cpio(_raw(("a:b.txt", REG, b"colon", 1, 1), ("C:/drive.txt", REG, b"no", 1, 2),
                      ("D:rel.txt", REG, b"drive-relative", 1, 3)), dest,
                 on_skip=skipped.append)
    if os.name == "nt":
        assert _files(dest) == {"a_b.txt": b"colon", "D_rel.txt": b"drive-relative"}
    else:
        assert _files(dest) == {"a:b.txt": b"colon", "D:rel.txt": b"drive-relative"}
    assert skipped == ["C:/drive.txt"]


def test_hard_links_after_their_data(tmp_path):
    # GNU cpio and others put the data on the first link; newc's rule is the last one
    data = _raw(("first", REG, b"shared", 3, 9), ("second", REG, b"", 3, 9),
                ("x/third", REG, b"", 3, 9), ("empty1", REG, b"", 2, 10), ("empty2", REG, b"", 2, 10))
    written = extract_cpio(data, tmp_path / "x")
    assert _files(tmp_path / "x") == {"first": b"shared", "second": b"shared", "x": None,
                                      "x/third": b"shared", "empty1": b"", "empty2": b""}
    assert len(written) == 5  # the folder x is made for x/third, not listed by itself


def test_hard_links_wait_for_their_data(tmp_path):
    # a link is only created once its data is known, so nothing empty is left behind if the
    # data never fits
    reg = REG
    data = _raw(("l1", reg, b"", 3, 9), ("l2", reg, b"", 3, 9), ("data", reg, b"x" * 1000, 3, 9))
    with pytest.raises(PackportError, match="more than"):
        extract_cpio(data, tmp_path / "x", max_size=999)
    assert _files(tmp_path / "x") == {}
    extract_cpio(data, tmp_path / "y")
    assert _files(tmp_path / "y") == {"l1": b"x" * 1000, "l2": b"x" * 1000, "data": b"x" * 1000}


# .Z

def _codes_to_z(codes, bits: int = 16) -> bytes:
    """Pack LZW codes the way compress does, padding the group at every width change."""
    out = bytearray(b"\x1f\x9d" + bytes([bits | 0x80]))
    n_bits, free_ent, acc, group = 9, 257, 0, 0
    for i, code in enumerate(codes):
        acc |= code << (group * n_bits)
        group += 1
        if group == 8:
            out += acc.to_bytes(n_bits, "little")
            acc = group = 0
        if i and free_ent < 1 << bits:
            free_ent += 1
        if free_ent > (1 << n_bits) - 1 and n_bits < bits:
            if group:
                out += acc.to_bytes(n_bits, "little")
                acc = group = 0
            n_bits += 1
    return bytes(out + acc.to_bytes((group * n_bits + 7) // 8, "little"))


def test_lzw_table_memory_is_bounded():
    # each code is the previous string plus one byte: n codes in ~2n bytes make n*n/2 bytes of
    # output, and a table of whole strings would hold all of it at once
    n = 12_000
    z = _codes_to_z([0] + [257 + k for k in range(n)])
    expected = 1 + sum(range(2, n + 2))
    d = ZDecompressor()
    total = 0
    tracemalloc.start()
    try:
        for i in range(0, len(z), 64):
            total += len(d.decompress(z[i:i + 64]))
        total += len(d.flush())
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert total == expected  # about 72 MB
    assert peak < 32_000_000


@pytest.mark.parametrize("cache", [0, 100, 5000])
def test_lzw_strings_rebuilt_from_the_table(monkeypatch, cache):
    monkeypatch.setattr(lzw, "CACHE_BYTES", cache)
    for data in [b"", b"A", b"ab" * 5000, bytes(300_000), bytes(range(256)) * 500,
                 b"the quick brown fox jumps over the lazy dog " * 3000]:
        assert decompress(compress(data)) == data


def test_decompress_has_a_default_cap():
    assert inspect.signature(decompress).parameters["max_size"].default == 1 << 30
    assert lzw.DEFAULT_MAX_SIZE == 1 << 30
    assert len(decompress(compress(bytes(10_000_000)))) == 10_000_000


# pack(".Z", ...)

@pytest.mark.parametrize("source", [
    {"a.txt": b"hello"}, Entry("a.txt", b"hello"), [Entry("a.txt", b"hello")], [("a.txt", b"hello")],
    bytearray(b"hello"), memoryview(b"hello"), b"hello",
], ids=["mapping", "entry", "entry list", "pair list", "bytearray", "memoryview", "bytes"])
def test_pack_z_takes_what_the_other_formats_take(tmp_path, monkeypatch, source):
    monkeypatch.chdir(tmp_path)  # a mapping key must never be opened as a file
    (tmp_path / "a.txt").write_bytes(b"not this file")
    packport.pack(tmp_path / "out.Z", source)
    assert decompress((tmp_path / "out.Z").read_bytes()) == b"hello"


def test_pack_z_refuses_folders_and_several_files(tmp_path):
    for bad in [{"d": None}, {"a": b"1", "b": b"2"}, Entry("d", is_dir=True)]:
        with pytest.raises(PackportError, match="single file"):
            packport.pack(tmp_path / "out.Z", bad)


# RAR

def test_truncated_rar_raises_instead_of_returning_fewer_files(tmp_path):
    packport.write_rar(tmp_path / "two.rar", {"a.txt": b"first", "b.txt": b"second"})
    data = (tmp_path / "two.rar").read_bytes()
    after_a = data.index(b"first") + len(b"first")
    after_b = data.index(b"second") + len(b"second")
    assert [m.name for m in packport.read_rar(data)] == ["a.txt", "b.txt"]
    for cut in (after_a, after_b):
        with pytest.raises(PackportError, match="cut short"):
            packport.read_rar(data[:cut])


# Timestamps

@pytest.mark.parametrize("mtime", [-1e20, -1.0, 1e11, 1e300, float("inf"), float("-inf"), float("nan")])
def test_out_of_range_times_are_clamped(tmp_path, mtime):
    entries = [Entry("a.txt", b"x", mtime=mtime)]
    packport.write_rar(tmp_path / "t.rar", entries)
    packport.write_cpio(tmp_path / "t.cpio", entries)
    packport.write_tar_z(tmp_path / "t.tar.Z", entries)
    rar_year = packport.read_rar(tmp_path / "t.rar")[0].mtime
    cpio_time = read_cpio(tmp_path / "t.cpio")[0].mtime
    with tarfile.open(fileobj=io.BytesIO(decompress((tmp_path / "t.tar.Z").read_bytes()))) as tf:
        tar_time = tf.getmembers()[0].mtime
    big = mtime > 0  # False for NaN
    assert cpio_time == (0xFFFFFFFF if big else 0)
    assert tar_time == (8 ** 11 - 1 if big else 0)
    assert rar_year > 0


# Windows read-only attribute

@pytest.mark.skipif(os.name != "nt", reason="the Windows read-only attribute")
def test_windows_read_only_files_are_flagged(tmp_path):
    locked = tmp_path / "locked.txt"
    locked.write_bytes(b"x")
    (tmp_path / "open.txt").write_bytes(b"y")
    os.chmod(locked, stat.S_IREAD)
    try:
        packport.write_rar(tmp_path / "ro.rar", [locked, tmp_path / "open.txt"])
        packport.write_cpio(tmp_path / "ro.cpio", [locked, tmp_path / "open.txt"])
    finally:
        os.chmod(locked, stat.S_IREAD | stat.S_IWRITE)
    assert [m.mode for m in packport.read_rar(tmp_path / "ro.rar")] == [0o100444, 0o100644]
    assert [m.mode for m in read_cpio(tmp_path / "ro.cpio")] == [0o100444, 0o100644]
