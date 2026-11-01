"""Disk images name other files: a differencing disk's parent (VHD, VHDX), a VMDK's extents and
parent, a QCOW2's backing file. A name read from inside an image may only ever mean a file in the
image's own folder (its base name there, or a relative path that stays inside it): never an
absolute path, another drive, a network share or a folder above. Those are refused before
anything is opened or even looked up (a lookup of \\\\host\\share would reach out over the network)."""

import builtins
import os
import struct
from pathlib import Path

import pytest

import packport
from packport import PackportError

DATA = Path(__file__).parent / "data" / "dfvfs"
OUTSIDE_NAMES = ["{outside}", "../outside/{base}", "..\\outside\\{base}", "\\\\server\\share\\{base}",
                 "//server/share/{base}", "C:/Windows/{base}", "C:\\Windows\\{base}", "{base}:stream", "/etc/{base}"]


@pytest.fixture
def spy(monkeypatch):
    """Every path packport opens, stats or looks up."""
    seen: list[str] = []
    real_open, real_is_file, real_stat = builtins.open, Path.is_file, os.stat

    def opener(file, *a, **k):
        if isinstance(file, (str, os.PathLike)):
            seen.append(os.fspath(file))
        return real_open(file, *a, **k)

    def is_file(self):
        seen.append(os.fspath(self))
        return real_is_file(self)

    def stat(path, *a, **k):
        if isinstance(path, (str, os.PathLike)):
            seen.append(os.fspath(path))
        return real_stat(path, *a, **k)

    monkeypatch.setattr(builtins, "open", opener)
    monkeypatch.setattr(Path, "is_file", is_file)
    monkeypatch.setattr(os, "stat", stat)
    return seen


def _inside(seen: list[str], folder: Path) -> None:
    root = os.path.normcase(os.path.abspath(folder))
    for p in seen:
        full = os.path.normcase(os.path.abspath(p))
        assert full == root or full.startswith(root + os.sep), f"looked at {p}, outside {folder}"


def _layout(tmp_path, base: str, data: bytes):
    """The image's folder, and a file of the same name outside it (the bait)."""
    folder = tmp_path / "images"
    folder.mkdir()
    outside = tmp_path / "outside" / base
    outside.parent.mkdir()
    outside.write_bytes(data)
    return folder, outside


def _names(base: str, outside: Path) -> list[str]:
    return [n.format(base=base, outside=outside) for n in OUTSIDE_NAMES]


def _flat_disk() -> bytes:
    """A 1 MB raw disk with a FAT12 file system packport would read if it got there."""
    return packport.decompress((DATA / "fat12.raw.Z").read_bytes())


def _vmdk(kind: str, name: str) -> bytes:
    lines = ["# Disk DescriptorFile", "version=1", "CID=12345678", "parentCID=ffffffff",
             'createType="monolithicFlat"']
    if kind == "parent":
        lines[3] = "parentCID=87654321"
        lines.append(f'parentFileNameHint="{name}"')
        lines.append('RW 2048 FLAT "flat.img" 0')
    else:
        lines.append(f'RW 2048 {kind} "{name}" 0')
    return ("\n".join(lines) + "\n").encode()


@pytest.mark.parametrize("kind", ["FLAT", "SPARSE", "parent"])
def test_vmdk_names_outside_its_folder_are_refused(tmp_path, spy, kind):
    folder, outside = _layout(tmp_path, "secret.img", _flat_disk())
    (folder / "flat.img").write_bytes(_flat_disk())  # the parent case's own extent, inside
    for k, name in enumerate(_names("secret.img", outside)):
        desc = folder / f"d{k}.vmdk"
        desc.write_bytes(_vmdk(kind, name))
        spy.clear()
        with pytest.raises(PackportError, match="next to it|needs"):
            packport.open(desc)
        _inside(spy, folder)


def test_vmdk_extents_next_to_it_still_read(tmp_path):
    folder = tmp_path / "images"
    (folder / "sub").mkdir(parents=True)
    (folder / "flat.img").write_bytes(_flat_disk())
    (folder / "sub" / "deep.img").write_bytes(_flat_disk())
    for name in ("flat.img", "sub/deep.img", "sub\\deep.img", "./flat.img"):
        (folder / "d.vmdk").write_bytes(_vmdk("FLAT", name))
        with packport.open(folder / "d.vmdk") as a:
            assert any(m.is_file for m in a.members)


def _vhd_with_parent(path: str) -> bytes:
    """dfvfs's differencing VHD, its parent locators (and parent name) all rewritten to path."""
    data = bytearray(packport.decompress((DATA / "ntfs-differential.vhd.Z").read_bytes()))
    footer = data[-512:]
    data_offset = struct.unpack_from(">Q", footer, 16)[0]
    hdr = data_offset
    encoded16 = path.encode("utf-16-le")
    for k in range(8):
        at = hdr + 576 + 24 * k
        code, space, _length, _, offset = struct.unpack_from(">4sIIIQ", data, at)
        if code in (b"W2ru", b"W2ku"):
            raw = encoded16[:space]
            data[offset:offset + space] = raw.ljust(space, b"\0")
            struct.pack_into(">I", data, at + 8, len(raw))
    name = path.encode("utf-16-be")[:512]
    data[hdr + 64:hdr + 576] = name.ljust(512, b"\0")
    # the header's checksum: one's complement of the byte sum, with the field taken as zero
    struct.pack_into(">I", data, hdr + 36, 0)
    struct.pack_into(">I", data, hdr + 36, ~sum(data[hdr:hdr + 1024]) & 0xFFFFFFFF)
    return bytes(data)


def test_vhd_parent_outside_its_folder_is_refused(tmp_path, spy):
    parent = packport.decompress((DATA / "ntfs-parent.vhd.Z").read_bytes())
    folder, outside = _layout(tmp_path, "base.vhd", parent)
    for k, name in enumerate(_names("base.vhd", outside)):
        child = folder / f"child{k}.vhd"
        child.write_bytes(_vhd_with_parent(name))
        spy.clear()
        with pytest.raises(PackportError, match="needs its parent"):
            packport.open(child)
        _inside(spy, folder)


def test_vhd_parent_next_to_it_still_reads(tmp_path):
    folder = tmp_path / "images"
    folder.mkdir()
    (folder / "base.vhd").write_bytes(packport.decompress((DATA / "ntfs-parent.vhd.Z").read_bytes()))
    for name in ("C:\\elsewhere\\base.vhd", ".\\base.vhd", "base.vhd"):  # an absolute path's base name is looked for here
        (folder / "child.vhd").write_bytes(_vhd_with_parent(name))
        with packport.open(folder / "child.vhd") as a:
            assert any(m.is_file for m in a.members)


def _qcow2_backed_by(path: str) -> bytes:
    data = bytearray(packport.decompress((DATA / "ext2.qcow2.Z").read_bytes()))
    name = path.encode()
    struct.pack_into(">QI", data, 8, len(data), len(name))
    return bytes(data + name)


def test_qcow2_backing_file_outside_its_folder_is_refused(tmp_path, spy):
    folder, outside = _layout(tmp_path, "base.qcow2", packport.decompress((DATA / "ext2.qcow2.Z").read_bytes()))
    for k, name in enumerate(_names("base.qcow2", outside)):
        img = folder / f"img{k}.qcow2"
        img.write_bytes(_qcow2_backed_by(name))
        spy.clear()
        with pytest.raises(PackportError, match="needs its parent"):
            packport.open(img)
        _inside(spy, folder)
