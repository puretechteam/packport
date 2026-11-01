"""Disc images. ISO 9660: libarchive's test images (data/libarchive, most of them .Z-compressed as
libarchive ships them), checked against 7-Zip where packport reads a disc the way 7-Zip does,
and against libarchive where 7-Zip doesn't read what the disc holds (Rock Ridge names, folders
moved to rr_moved, zisofs), plus hostile images. El Torito boot images and UDF 1.02 to 2.50
(data/made: from libarchive's ISO writer and Windows' IMAPI2, see make_fixtures.py), checked
against 7-Zip."""

import hashlib
import json
import random
import struct
from pathlib import Path

import pytest

import packport
from packport import PackportError

DATA = Path(__file__).parent / "data" / "libarchive"
MADE = Path(__file__).parent / "data" / "made"
EXPECTED = json.loads((DATA / "expected-iso.json").read_text(encoding="utf-8"))
MADE_DISCS = {k: v for k, v in json.loads((MADE / "expected.json").read_text(encoding="utf-8")).items()
              if k.endswith(".iso.Z")}


def _image(path: Path) -> bytes:
    data = path.read_bytes()
    return packport.decompress(data) if path.suffix == ".Z" else data


def _hashes(data: bytes) -> dict:
    with packport.open(data) as a:
        return {m.name: hashlib.sha256(s.read()).hexdigest() for m, s in a.files()}


@pytest.mark.parametrize("name", sorted(k for k, v in EXPECTED.items() if v["oracle"]))
def test_same_files_as_the_oracle(name):
    assert _hashes(_image(DATA / name)) == EXPECTED[name]["files"]


@pytest.mark.parametrize("name", sorted(k for k, v in EXPECTED.items() if not v["oracle"]))
def test_hostile_images_raise_only_packport_error(name):
    # loops of continuation areas and relocated folders, a symbolic link cut short, a zisofs header
    # claiming impossible blocks: libarchive and 7-Zip fail or disagree on each
    try:
        _hashes(_image(DATA / name))
    except PackportError:
        pass


def test_rock_ridge_names_are_kept_whole():
    # 7-Zip cuts these three names to one and so writes a single file; Rock Ridge has them whole
    names = {n for n in EXPECTED["test_read_format_iso_rockridge_ce.iso.Z"]["files"] if n.startswith("a")}
    assert len(names) == 3 and min(map(len, names)) > 150


def test_relocated_folders_go_back_where_they_belong():
    files = EXPECTED["test_read_format_iso_rockridge_rr_moved.iso.Z"]["files"]
    assert "dir1/dir2/dir3/dir4/dir5/dir6/dir7/dir8/dir9/dir10/deep" in files
    assert not any(n.startswith("rr_moved") for n in files)


def test_zisofs_files_are_unpacked():
    # the same 12,345,684-byte file as in the uncompressed image next to it
    zisofs = EXPECTED["test_read_format_iso_zisofs.iso.Z"]["files"]["file"]
    assert zisofs == EXPECTED["test_read_format_iso_rockridge_rr_moved.iso.Z"]["files"]["file"]


@pytest.mark.parametrize("name", sorted(MADE_DISCS))
def test_boot_images_and_udf_as_7zip_reads_them(name):
    assert _hashes(_image(MADE / name)) == MADE_DISCS[name]


def test_udf_2_50_keeps_its_folders_in_a_metadata_partition():
    from packport.archive import Source
    from packport.udf import UdfArchive
    a = UdfArchive(Source(_image(MADE / "udf250.iso.Z")))
    assert [m[0] for m in a.maps] == ["physical", "metadata"]


def test_a_bridge_disc_is_read_through_udf():
    with packport.open(_image(MADE / "iso_joliet_udf.iso.Z")) as a:
        assert a.fmt == "udf"
        assert "日本語.txt" in {m.name for m in a.members}


def test_a_damaged_udf_side_falls_back_to_iso_9660():
    data = bytearray(_image(MADE / "iso_joliet_udf.iso.Z"))
    assert packport.open(bytes(data)).fmt == "udf"
    for at in range(0, len(data), 2048):  # the file set descriptor (tag 256) is gone
        if data[at:at + 2] == bytes([0, 1]) and sum(data[at:at + 4]) + sum(data[at + 5:at + 16]) & 0xFF == data[at + 4]:
            data[at:at + 16] = bytes(16)
    with packport.open(bytes(data)) as a:
        assert a.fmt == "iso"
        assert "folder/random.bin" in {m.name for m in a.members}


def test_formats_are_told_apart():
    assert packport.detect(_image(DATA / "test_read_format_iso_joliet.iso.Z")) == "iso"
    assert packport.detect(_image(MADE / "udf201.iso.Z")) == "udf"


def test_a_file_split_over_extents_is_joined():
    with packport.open(_image(DATA / "test_read_format_iso_multi_extent.iso.Z")) as a:
        (item,) = [m for m in a.members if m.is_file]
        assert item.size == 262280 and len(a.read(item)) == 262280


@pytest.mark.parametrize("name", ["test_read_format_iso_joliet_rockridge.iso.Z", "test_read_format_iso_zisofs.iso.Z",
                                  "test_read_format_iso_rockridge_ce.iso.Z", "test_read_format_iso_2.iso.Z"])
def test_damaged_images_raise_only_packport_error(name):
    rng = random.Random(name)
    data = _image(DATA / name)
    # damage where it matters: the volume descriptors and the folders after them
    hot = list(range(16 * 2048, min(len(data), 40 * 2048)))
    bad = []
    for _ in range(60):
        b = bytearray(data)
        for _ in range(rng.randint(1, 12)):
            b[rng.choice(hot)] = rng.randrange(256)
        if rng.random() < 0.2:
            b = b[:rng.randrange(17 * 2048, len(b))]
        try:
            _hashes(bytes(b))
        except PackportError:
            pass
        except Exception as e:  # noqa: BLE001
            bad.append(f"{type(e).__name__}: {e}")
    assert bad == []


def test_a_folder_that_contains_itself_ends():
    data = bytearray(_image(DATA / "test_read_format_iso_2.iso.Z"))
    root = struct.unpack_from("<I", data, 16 * 2048 + 158)[0]
    # point every subfolder of the root back at the root
    at = root * 2048
    while data[at]:
        if data[at + 25] & 2 and data[at + 33] > 1:
            struct.pack_into("<I", data, at + 2, root)
        at += data[at]
    with packport.open(bytes(data)) as a:
        assert len(a.members) < 100


@pytest.mark.parametrize("name", ["udf102.iso.Z", "udf250.iso.Z"])
def test_damaged_udf_raises_only_packport_error(name):
    rng = random.Random(name)
    data = _image(MADE / name)
    # the volume descriptors, the anchor and the file set, folders and file entries after them
    hot = [k for k in range(len(data)) if data[k]][:200_000]
    bad = []
    for _ in range(80):
        b = bytearray(data)
        for _ in range(rng.randint(1, 6)):
            b[rng.choice(hot)] = rng.randrange(256)
        try:
            _hashes(bytes(b))
        except PackportError:
            pass
        except Exception as e:  # noqa: BLE001
            bad.append(f"{type(e).__name__}: {e}")
    assert bad == []


def test_a_hybrid_iso_is_read_as_a_disc():
    # isohybrid puts an MBR in front so the image boots from a USB stick: it's still the ISO 9660 disc
    data = bytearray(_image(DATA / "test_read_format_iso_2.iso.Z"))
    mbr = bytearray(512)
    mbr[446], mbr[446 + 4] = 0x80, 0x17
    struct.pack_into("<II", mbr, 446 + 8, 0, len(data) // 512)
    mbr[510:512] = bytes([0x55, 0xAA])
    data[:512] = mbr
    assert packport.detect(bytes(data)) == "iso"
    assert _hashes(bytes(data)) == EXPECTED["test_read_format_iso_2.iso.Z"]["files"]
