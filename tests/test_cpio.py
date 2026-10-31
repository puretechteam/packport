import io
import os
import random
import stat

import pytest
from conftest import MTIME, read_tree, sparse_file

import packport
from packport import CpioWriter, PackportError, extract_cpio, read_cpio, write_cpio
from packport.cpio import _header
from packport.entries import CHUNK


def test_layout():
    out = io.BytesIO()
    with CpioWriter(out) as cpio:
        cpio.add("a.txt", b"hello", mtime=MTIME)
        cpio.add("dir", is_dir=True, mtime=MTIME)
    data = out.getvalue()
    head = data[:110]
    assert head[:6] == b"070701"
    fields = [int(head[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
    assert fields == [1, 0o100644, 0, 0, 1, MTIME, 5, 0, 0, 0, 0, 6, 0]
    assert data[110:116] == b"a.txt\0"  # 116 is already a multiple of 4: no padding
    assert data[116:121] == b"hello" and data[121:124] == bytes(3)  # data padded to 4
    second = data[124:234]
    assert int(second[14:22], 16) == 0o40755 and int(second[38:46], 16) == 2
    assert data.endswith(b"TRAILER!!!\0" + bytes(-(110 + 11) % 4))
    assert len(data) % 4 == 0


def test_round_trip(unicode_tree):
    entries = write_cpio(unicode_tree.parent / "out.cpio", packport.tree(unicode_tree))
    back = read_cpio(unicode_tree.parent / "out.cpio")
    assert [m.name for m in back] == [e.name for e in entries]
    assert {m.name: (None if m.is_dir else m.data) for m in back} == read_tree(unicode_tree)
    assert next(m for m in back if m.name == "readme.txt").mtime == MTIME


def test_modes(tmp_path):
    write_cpio(tmp_path / "m.cpio", [packport.Entry("run.sh", b"#!/bin/sh\n", mode=0o755),
                                     packport.Entry("secret", b"", mode=0o600)])
    assert [oct(m.mode) for m in read_cpio(tmp_path / "m.cpio")] == ["0o100755", "0o100600"]


def test_checksum_variant_is_read():
    out = io.BytesIO()
    with CpioWriter(out) as cpio:
        cpio.add("a", b"\x01\x02\xff")
    data = bytearray(out.getvalue())
    data[5:6] = b"2"
    data[102:110] = b"%08X" % (1 + 2 + 255)
    assert read_cpio(bytes(data))[0].data == b"\x01\x02\xff"
    data[102:110] = b"00000000"
    with pytest.raises(PackportError, match="checksum"):
        read_cpio(bytes(data))


def test_files_of_4_gib_are_refused(tmp_path):
    big = sparse_file(tmp_path / "big.bin", (1 << 32) + 1, {})
    with pytest.raises(PackportError, match="4 GiB"):
        write_cpio(tmp_path / "big.cpio", [big])
    assert not (tmp_path / "big.cpio").exists()


def test_reader_refuses_other_cpio_flavours():
    with pytest.raises(PackportError, match="old-style"):
        read_cpio(b"070707" + bytes(200))
    with pytest.raises(PackportError, match="cut short"):
        read_cpio(b"")


def _raw(*members) -> bytes:
    """A newc archive from (name, mode, data, nlink, ino) tuples, names unchecked."""
    out = b""
    for name, mode, data, nlink, ino in members:
        out += _header(ino, mode, nlink, MTIME, len(data), name.encode()) + data + bytes(-len(data) % 4)
    return out + _header(0, 0, 1, 0, 0, b"TRAILER!!!")


def test_extract_round_trip(unicode_tree, tmp_path):
    write_cpio(tmp_path / "out.cpio", packport.tree(unicode_tree))
    written = extract_cpio(tmp_path / "out.cpio", tmp_path / "x")
    assert read_tree(tmp_path / "x") == read_tree(unicode_tree)
    assert len(written) == len(read_cpio(tmp_path / "out.cpio"))
    assert os.stat(tmp_path / "x" / "readme.txt").st_mtime == MTIME


def test_extract_streams_without_reading_the_archive_whole(tmp_path):
    payload = os.urandom(3 * CHUNK + 5)
    write_cpio(tmp_path / "big.cpio", {"big.bin": payload})
    reads = []

    class Spy(io.FileIO):
        def read(self, n=-1):
            reads.append(n)
            return super().read(n)

    with Spy(tmp_path / "big.cpio") as f:
        extract_cpio(f, tmp_path / "x")
        assert not f.closed  # a file the caller opened stays open
    assert (tmp_path / "x" / "big.bin").read_bytes() == payload
    assert max(reads) <= CHUNK and -1 not in reads


def test_extract_keeps_everything_inside_the_folder(tmp_path):
    data = _raw(("../escaped.txt", stat.S_IFREG | 0o644, b"no", 1, 1),
                ("/abs.txt", stat.S_IFREG | 0o644, b"ok", 1, 2),
                ("C:/evil.txt", stat.S_IFREG | 0o644, b"no", 1, 3),
                ("link", stat.S_IFLNK | 0o777, b"../../outside", 1, 4),
                ("dev", stat.S_IFCHR | 0o644, b"", 1, 5),
                ("dir/../../up.txt", stat.S_IFREG | 0o644, b"no", 1, 6),
                ("fine/ok.txt", stat.S_IFREG | 0o644, b"yes", 1, 7))
    dest = tmp_path / "inside" / "x"
    extract_cpio(data, dest)
    assert sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*")) == ["abs.txt", "fine", "fine/ok.txt"]
    assert not (tmp_path / "inside" / "escaped.txt").exists() and not (tmp_path / "inside" / "up.txt").exists()


def test_extract_gives_hard_links_the_data():
    import tempfile
    from pathlib import Path
    data = _raw(("a", stat.S_IFREG | 0o644, b"", 2, 9), ("b", stat.S_IFREG | 0o644, b"shared", 2, 9))
    with tempfile.TemporaryDirectory() as tmp:
        extract_cpio(data, tmp)
        assert (Path(tmp) / "a").read_bytes() == (Path(tmp) / "b").read_bytes() == b"shared"


@pytest.mark.skipif(os.name != "nt", reason="Windows names")
def test_extract_makes_windows_names_safe(tmp_path):
    reg = stat.S_IFREG | 0o644
    data = _raw(("dir/a.txt:stream", reg, b"ads", 1, 1), ("CON", reg, b"con", 1, 2),
                ("nul.txt", reg, b"nul", 1, 3), ("trailing.", reg, b"dot", 1, 4),
                ("q?.txt", reg, b"q", 1, 5), ("tab\there", reg, b"tab", 1, 6))
    dest = tmp_path / "x"
    extract_cpio(data, dest)
    got = {p.relative_to(dest).as_posix(): p.read_bytes() for p in dest.rglob("*") if p.is_file()}
    assert got == {"dir/a.txt_stream": b"ads", "_CON": b"con", "_nul.txt": b"nul", "trailing_": b"dot",
                   "q_.txt": b"q", "tab_here": b"tab"}
    assert not (dest / "dir" / "a.txt").exists()  # no alternate data stream on a.txt


def test_extract_never_overwrites(tmp_path):
    reg = stat.S_IFREG | 0o644
    data = _raw(("a.txt", reg, b"first", 1, 1), ("a.txt", reg, b"second", 1, 2))
    dest = tmp_path / "x"
    dest.mkdir()
    (dest / "keep.txt").write_bytes(b"mine")
    extract_cpio(data, dest)
    extract_cpio(_raw(("keep.txt", reg, b"theirs", 1, 3)), dest)
    assert (dest / "a.txt").read_bytes() == b"first" and (dest / "a (1).txt").read_bytes() == b"second"
    assert (dest / "keep.txt").read_bytes() == b"mine" and (dest / "keep (1).txt").read_bytes() == b"theirs"


def test_extract_max_size_counts_hard_links(tmp_path):
    # one 1 KB file and 50 hard links to it: 51 KB on disk from a 7 KB archive
    reg = stat.S_IFREG | 0o644
    links = [(f"l{i}", reg, b"", 51, 9) for i in range(50)]
    data = _raw(*links, ("data", reg, b"x" * 1024, 51, 9))
    extract_cpio(data, tmp_path / "ok", max_size=60_000)
    with pytest.raises(PackportError, match="more than"):
        extract_cpio(data, tmp_path / "capped", max_size=10_000)


def test_extract_reports_skipped_members(tmp_path):
    skipped = []
    extract_cpio(_raw(("../up.txt", stat.S_IFREG | 0o644, b"no", 1, 1),
                      ("link", stat.S_IFLNK | 0o777, b"/etc", 1, 2),
                      ("ok.txt", stat.S_IFREG | 0o644, b"ok", 1, 3)), tmp_path / "x", on_skip=skipped.append)
    assert skipped == ["../up.txt", "link"]


def test_extract_damaged_archives_raise_packport_error(tmp_path):
    write_cpio(tmp_path / "s.cpio", {"a.txt": b"hello" * 100, "d/b.txt": b"world"})
    data = (tmp_path / "s.cpio").read_bytes()
    rng = random.Random(1)
    for i in range(200):
        b = bytearray(data)
        for _ in range(rng.randint(1, 6)):
            b[rng.randrange(len(b))] = rng.randrange(256)
        if rng.random() < 0.3:
            b = b[:rng.randrange(len(b))]
        try:
            extract_cpio(bytes(b), tmp_path / f"x{i}")
        except PackportError:
            pass
