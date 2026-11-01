"""Disk images and file systems: dfvfs's test images (data/dfvfs, Apache License 2.0, kept
.Z-compressed; make_dfvfs_fixtures.py checked each against 7-Zip): FAT12, ext2, ext4, NTFS,
HFS+, APFS, MBR and GPT disks, VHD, VHDX (differencing ones over their parents), VMDK, QCOW2,
and DMGs. Also a VDI written here, NTFS's LZNT1 against Windows' own compressor, the volumes
packport refuses, and damaged images."""

import ctypes
import hashlib
import json
import os
import random
import struct
from pathlib import Path

import pytest
from conftest import SEVEN_ZIP, needs_7z, run

import packport
from packport import EncryptedError, PackportError
from packport.fs.ntfs import lznt1

DATA = Path(__file__).parent / "data" / "dfvfs"
EXPECTED = json.loads((DATA / "expected.json").read_text(encoding="utf-8"))
PARENTS = {"ntfs-differential.vhd": "ntfs-parent.vhd", "fat-differential.vhdx": "fat-parent.vhdx"}


def _unpack(name: str, folder: Path) -> Path:
    path = folder / name
    path.write_bytes(packport.decompress((DATA / (name + ".Z")).read_bytes()))
    return path


def _hashes(src) -> dict:
    with packport.open(src) as a:
        return {m.name: hashlib.sha256(s.read()).hexdigest() for m, s in a.files()}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_same_files_as_7zip(tmp_path, name):
    if name in PARENTS:  # a differencing disk reads the rest from its parent, next to it
        _unpack(PARENTS[name], tmp_path)
    assert _hashes(_unpack(name, tmp_path)) == EXPECTED[name]


def test_partitions_get_a_folder_each():
    with packport.open(packport.decompress((DATA / "mbr.raw.Z").read_bytes())) as a:
        tops = {m.name.split("/")[0] for m in a.members}
    assert tops == {"1 ext2", "2 ext4"}


def test_a_differencing_disk_without_its_parent_says_so(tmp_path):
    with pytest.raises(PackportError, match="needs its parent"):
        packport.open(_unpack("ntfs-differential.vhd", tmp_path))


@pytest.mark.parametrize("name, why", [("luks1.raw", "LUKS"), ("lvm.raw", "LVM"), ("bdetogo.raw", "BitLocker"),
                                       ("hfsplus.sparseimage", "sparse disk image")])
def test_volumes_packport_doesnt_read_are_refused_by_name(name, why):
    with pytest.raises(PackportError, match=why):
        packport.open(packport.decompress((DATA / (name + ".Z")).read_bytes()))


def test_an_encrypted_apfs_volume_is_refused():
    with pytest.raises(EncryptedError):
        packport.open(packport.decompress((DATA / "apfs_encrypted.dmg.Z").read_bytes()))


@pytest.mark.parametrize("name, fmt", [("ntfs.raw", "disk"), ("ext2.vhdx", "disk"), ("hfsplus_zlib.dmg", "disk")])
def test_formats_are_told_apart(name, fmt):
    assert packport.detect(packport.decompress((DATA / (name + ".Z")).read_bytes())) == fmt


def _vdi(disk: bytes, block: int = 1 << 20) -> bytes:
    """A dynamic VDI holding disk, blocks of zeros left out."""
    blocks = (len(disk) + block - 1) // block
    blocks_at, data_at = 512, 512 + (4 * blocks + 511) // 512 * 512
    table, body = [], bytearray()
    for k in range(blocks):
        chunk = disk[k * block:(k + 1) * block].ljust(block, b"\0")
        if any(chunk):
            table.append(len(body) // block)
            body += chunk
        else:
            table.append(0xFFFFFFFF)
    head = bytearray(512)
    head[:40] = b"<<< Oracle VM VirtualBox Disk Image >>>\n"
    struct.pack_into("<IIII", head, 0x40, 0xBEDA107F, 0x00010001, 400, 1)
    struct.pack_into("<II", head, 0x154, blocks_at, data_at)
    struct.pack_into("<I", head, 0x168, 512)  # the sector size
    struct.pack_into("<QIII", head, 0x170, len(disk), block, 0, blocks)
    struct.pack_into("<I", head, 0x184, sum(t != 0xFFFFFFFF for t in table))
    head[0x188:0x198] = os.urandom(16)
    table_bytes = struct.pack(f"<{blocks}I", *table).ljust(data_at - blocks_at, b"\0")
    return bytes(head) + table_bytes + bytes(body)


def test_a_vdi_holds_its_disk(tmp_path):
    raw = packport.decompress((DATA / "ext2.raw.Z").read_bytes())
    vdi = tmp_path / "ext2.vdi"
    vdi.write_bytes(_vdi(raw))
    assert _hashes(vdi) == EXPECTED["ext2.raw"]


@needs_7z
def test_7zip_reads_the_vdi_written_here(tmp_path):
    raw = packport.decompress((DATA / "ext2.raw.Z").read_bytes())
    vdi = tmp_path / "ext2.vdi"
    vdi.write_bytes(_vdi(raw))
    run(SEVEN_ZIP, "x", "-y", f"-o{tmp_path / 'out'}", vdi, ok=False)  # it can't make the symbolic link inside
    theirs = {p.relative_to(tmp_path / "out").as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in (tmp_path / "out").rglob("*") if p.is_file() and p.name != "a_link"}
    assert theirs == EXPECTED["ext2.raw"]


@pytest.mark.skipif(os.name != "nt", reason="Windows' own LZNT1 compressor (ntdll) is the judge")
def test_lznt1_reads_what_windows_writes():
    ntdll = ctypes.WinDLL("ntdll")
    work_size, frag = ctypes.c_ulong(), ctypes.c_ulong()
    ntdll.RtlGetCompressionWorkSpaceSize(2, ctypes.byref(work_size), ctypes.byref(frag))  # 2: LZNT1
    work = ctypes.create_string_buffer(work_size.value)
    rng = random.Random(4)
    words = [bytes(rng.choice(b"abcdefgh") for _ in range(rng.randint(1, 9))) for _ in range(400)]
    for data in (b"a" * 65536, b" ".join(rng.choice(words) for _ in range(12000))[:65536], rng.randbytes(65536),
                 bytes(range(256)) * 256):
        out = ctypes.create_string_buffer(len(data) * 2)
        size = ctypes.c_ulong()
        status = ntdll.RtlCompressBuffer(2, data, len(data), out, len(out), 4096, ctypes.byref(size), work)
        assert status == 0
        assert lznt1(out.raw[:size.value], len(data)) == data


@pytest.mark.parametrize("name", ["fat12.raw", "ext4.raw", "ntfs.raw", "hfsplus.raw", "apfs.raw", "ext2.qcow2",
                                  "ext2.vhdx", "hfsplus_zlib.dmg"])
def test_damaged_images_raise_only_packport_error(name):
    rng = random.Random(name)
    data = packport.decompress((DATA / (name + ".Z")).read_bytes())
    hot = [k for k in range(min(len(data), 2 << 20)) if data[k]]  # damage where there's something
    bad = []
    for _ in range(60):
        b = bytearray(data)
        for _ in range(rng.randint(1, 12)):
            b[rng.choice(hot)] = rng.randrange(256)
        try:
            with packport.open(bytes(b)) as a:
                for _m, s in a.files():
                    s.read()
        except PackportError:
            pass
        except Exception as e:  # noqa: BLE001
            bad.append(f"{type(e).__name__}: {e}")
    assert bad == []


@pytest.mark.parametrize("damage", ["signature", "entry"])
def test_vhdx_falls_back_to_its_second_region_table(tmp_path, damage):
    """A VHDX keeps its region table twice (at 192 and 256 KB), each with a CRC-32C: damage to
    the first copy is read past using the second, as the specification has it (7-Zip does too)."""
    data = bytearray(_unpack("ext2.vhdx", tmp_path).read_bytes())
    first = 192 << 10
    if damage == "signature":
        data[first:first + 4] = b"\0\0\0\0"
    else:
        data[first + 16 + 16] ^= 0x10  # the first entry's file offset: still "regi", wrong checksum
    assert _hashes(bytes(data)) == EXPECTED["ext2.vhdx"]
