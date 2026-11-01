"""Disk images: a raw disk or one in a virtual-disk container (vdisk.py), its partitions (MBR with
extended partitions, GPT, the Apple Partition Map) and the file systems on them (fs/).

One file system gives its files at the top; several give a folder each, named by number and
kind ("1 NTFS", "2 FAT32"); a partition whose file system packport doesn't read comes out as a
raw image ("3.img"). A bare file system image (no partition table) works the same way. Volumes
packport can't open are refused with a clear message: BitLocker, LVM, LUKS, Storage Spaces and
dynamic disks.

Written from the UEFI specification (GPT), the MBR layout every PC firmware reads, and Apple's
Inside Macintosh (the partition map).
"""

from __future__ import annotations

import stat
import struct

from .archive import Archive, Item, Source, reader
from .entries import PackportError
from .fs import Extents, Slice

EXTENDED = (0x05, 0x0F, 0x85)
REFUSED_MBR = {0x42: "a Windows dynamic disk (LDM)", 0x8E: "LVM", 0xEE: None}
GPT_REFUSED = {
    "e6d6d379-f507-44c2-a23c-238f2a3df928": "LVM",
    "ca7d7ccb-63ed-4c53-861c-1742536059cc": "LUKS (an encrypted Linux volume)",
    "e75caf8f-f680-4cee-afa3-b001e56efc2d": "Storage Spaces",
    "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3": "a Windows dynamic disk (LDM)",
}
MAX_PARTITIONS = 256


def _guid(b: bytes) -> str:
    a, b2, c = struct.unpack_from("<IHH", b, 0)
    return f"{a:08x}-{b2:04x}-{c:04x}-{b[8:10].hex()}-{b[10:16].hex()}"


def partitions(dev) -> list[tuple[int, int, str]] | None:
    """(start, size, label) of each partition in bytes, or None when the device has no partition
    table (a bare file system)."""
    for sector in (512, 4096):
        hdr = dev.read_at(sector, 92)
        if hdr[:8] == b"EFI PART":
            return _gpt(dev, sector, hdr)
    blk0 = dev.read_at(0, 512)
    if blk0[:2] == b"ER" and dev.read_at(512, 2) == b"PM":
        return _apm(dev, struct.unpack_from(">H", blk0, 2)[0] or 512)
    if dev.read_at(512, 2) == b"PM":
        return _apm(dev, 512)
    if len(blk0) == 512 and blk0[510:512] == b"\x55\xaa" and _mbr_plausible(blk0):
        return _mbr(dev, blk0)
    return None


def _mbr_plausible(blk0: bytes) -> bool:
    """A boot sector of a file system also ends in 55 AA: an MBR's entries must make sense."""
    seen = False
    for k in range(4):
        e = blk0[446 + 16 * k:462 + 16 * k]
        if e[0] not in (0, 0x80):
            return False
        if e[4]:
            start, count = struct.unpack_from("<II", e, 8)
            if not start or not count:
                return False
            seen = True
    return seen


def _mbr(dev, blk0: bytes) -> list[tuple[int, int, str]]:
    out: list[tuple[int, int, str]] = []
    for k in range(4):
        e = blk0[446 + 16 * k:462 + 16 * k]
        kind = e[4]
        start, count = struct.unpack_from("<II", e, 8)
        if not kind or not count:
            continue
        if REFUSED_MBR.get(kind):
            raise PackportError(f"This disk holds {REFUSED_MBR[kind]}, which packport doesn't read")
        if kind in EXTENDED:
            ebr = start
            seen = set()
            while ebr and ebr not in seen and len(out) < MAX_PARTITIONS:
                seen.add(ebr)
                b = dev.read_at(ebr * 512, 512)
                if len(b) < 512 or b[510:512] != b"\x55\xaa":
                    break
                first, second = b[446:462], b[462:478]
                s1, c1 = struct.unpack_from("<II", first, 8)
                if first[4] and c1:
                    out.append(((ebr + s1) * 512, c1 * 512, f"{first[4]:02x}"))
                s2 = struct.unpack_from("<I", second, 8)[0]
                ebr = start + s2 if second[4] in EXTENDED and s2 else 0
            continue
        out.append((start * 512, count * 512, f"{kind:02x}"))
    return out


def _gpt(dev, sector: int, hdr: bytes) -> list[tuple[int, int, str]]:
    first_entry, count, size = struct.unpack_from("<QII", hdr, 72)
    if not 128 <= size <= 4096 or count > 4096:
        raise PackportError("The disk image is damaged (its GPT header)")
    table = dev.read_at(first_entry * sector, count * size)
    out = []
    for k in range(count):
        e = table[k * size:(k + 1) * size]
        if len(e) < 56 or e[:16] == bytes(16):
            continue
        kind = _guid(e[:16])
        if kind in GPT_REFUSED:
            raise PackportError(f"This disk holds {GPT_REFUSED[kind]}, which packport doesn't read")
        lo, hi = struct.unpack_from("<QQ", e, 32)
        if hi >= lo:
            out.append((lo * sector, (hi - lo + 1) * sector, kind))
    return out


def _apm(dev, block: int) -> list[tuple[int, int, str]]:
    first = dev.read_at(block, 512)
    count = struct.unpack_from(">I", first, 4)[0]
    out = []
    for k in range(1, min(count, MAX_PARTITIONS) + 1):
        e = dev.read_at(k * block, 512)
        if e[:2] != b"PM":
            break
        start, n = struct.unpack_from(">II", e, 8)
        kind = e[48:80].split(b"\0", 1)[0].decode("latin-1")
        if kind in ("Apple_partition_map", "Apple_Free", "Apple_Driver43", "Apple_Driver_ATAPI", "Apple_Patches"):
            continue
        out.append((start * block, n * block, kind))
    return out


BITLOCKER_GUID = bytes.fromhex("3bd66749292ed84a8399f6a339e3d001")  # 4967D63B-2E29-4AD8-8399-F6A339E3D001


def refusal(dev) -> str | None:
    """Why packport won't read dev, when it's an encrypted or pooled volume, or None."""
    head = dev.read_at(0, 4096)
    if head[3:11] == b"-FVE-FS-" or BITLOCKER_GUID in head[:512]:
        return "This volume is encrypted with BitLocker; packport doesn't decrypt"
    if head[:6] == bytes.fromhex("4c554b53babe"):
        return "This volume is encrypted with LUKS; packport doesn't decrypt"
    if head[536:544] == b"LVM2 001" or head[512:520] == b"LABELONE":
        return "This volume is part of LVM, which packport doesn't read"
    if head[:8] == b"encrcdsa" or (dev.size >= 8 and dev.read_at(dev.size - 8, 8) == b"cdsaencr"):
        return "This DMG is encrypted; packport doesn't decrypt"
    if head[:4] == b"sprs":
        return "This is a sparse disk image (.sparseimage), which packport doesn't read"
    return None


def file_system(dev):
    """The file system on dev (a reader from fs/), or None."""
    from .fs import apfs, ext, fat, hfs, ntfs
    why = refusal(dev)
    if why:
        raise PackportError(why)
    for module, kind in ((ntfs, "Ntfs"), (fat, "Fat"), (ext, "Ext"), (hfs, "Hfs"), (apfs, "Apfs")):
        if module.probe(dev):
            return getattr(module, kind)(dev)
    return None


def _sniff(head: bytes, source) -> bool:
    from .vdisk import container
    if refusal(source):
        return True  # so the reader can say why
    if source.size > 17 * 2048 and source.read_at(16 * 2048 + 1, 5) in (b"CD001", b"BEA01"):
        return False  # a disc (a hybrid ISO has an MBR too): the ISO 9660 and UDF readers take it
    try:
        dev = container(source)
    except PackportError:
        return True  # a container that can't be opened (no parent, damage): the reader says why
    try:
        dev = dev or source
        return partitions(dev) is not None or file_system_probe(dev)
    except PackportError:
        return False


def file_system_probe(dev) -> bool:
    from .fs import apfs, ext, fat, hfs, ntfs
    return any(m.probe(dev) for m in (ntfs, fat, ext, hfs, apfs))


@reader("disk", _sniff)
class DiskArchive(Archive):
    def __init__(self, source: Source):
        from .vdisk import container
        super().__init__(source)
        why = refusal(source)
        if why:
            raise PackportError(why)
        self.dev = container(source) or source
        parts = partitions(self.dev)
        self.volumes: list = []
        if parts is None:
            fs = file_system(self.dev)
            if fs is None:
                raise PackportError("packport doesn't know the file system in this image")
            self._add(fs, "")
            return
        found = []
        for k, (start, size, label) in enumerate(parts, 1):
            part = Slice(self.dev, start, min(size, self.dev.size - start))
            found.append((k, part, file_system(part), label))
        readable = [f for f in found if f[2] is not None]
        if len(found) == 1 and readable:
            self._add(readable[0][2], "")
            return
        for k, part, fs, label in found:
            if fs is None:  # a partition packport can't read: its raw bytes
                self.members.append(Item(f"{k}.img", part.size, False, None, 0.0, stat.S_IFREG | 0o644,
                                         ref=(None, [(part.start, part.size)])))
                continue
            folder = f"{k} {fs.name}"
            self.members.append(Item(folder, 0, True, None, 0.0, stat.S_IFDIR | 0o755))
            self._add(fs, folder + "/")

    def _add(self, fs, prefix: str) -> None:
        index = len(self.volumes)
        self.volumes.append(fs)
        for m in fs.members:
            if m.is_file and m.ref is None:
                continue  # damaged entries without a type
            self.members.append(Item(prefix + m.name, m.size, m.is_dir, m.link, m.mtime, m.mode, m.encrypted,
                                     ref=(index, m)))

    def open_member(self, item: Item):
        index, inner = item.ref
        if index is None:
            return Extents(self.dev, inner, item.size, item.name)
        return self.volumes[index].open_member(inner)
