import io

import pytest
from conftest import MTIME, read_tree, sparse_file

import packport
from packport import CpioWriter, PackportError, read_cpio, write_cpio


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
