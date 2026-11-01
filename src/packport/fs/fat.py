"""FAT12, FAT16 and FAT32, with long (VFAT) names.

Written from Microsoft's FAT specification (fatgen103). The boot sector's BIOS Parameter Block
gives the sector size, sectors per cluster, the reserved sectors, the FATs and the root folder
(a fixed run of sectors on FAT12 and FAT16, a cluster chain on FAT32); the number of clusters
decides which FAT it is. A folder is 32-byte entries: an 8.3 name, attributes, the first cluster
and the size; a long name comes as entries just before it, 13 UTF-16 characters each, last part
first. Files and folders follow their cluster chains through the FAT. Names without a long name
keep Windows NT's lowercase flags; others are read in the DOS code page (cp437).
"""

from __future__ import annotations

import stat
import struct
import time

from ..archive import Item
from ..entries import PackportError
from . import Extents

MAX_DEPTH = 128
MAX_ENTRIES = 2_000_000


def _bpb(boot: bytes) -> dict | None:
    if len(boot) < 512 or boot[510:512] != b"\x55\xaa" or boot[0] not in (0xEB, 0xE9):
        return None
    bps, spc, reserved, nfats, root_entries, total16, _media, fat16 = struct.unpack_from("<HBHBHHBH", boot, 11)
    total32, fat32 = struct.unpack_from("<II", boot, 32)
    if bps not in (512, 1024, 2048, 4096) or spc == 0 or spc & (spc - 1) or reserved == 0 or nfats == 0:
        return None
    fat_size = fat16 or fat32
    total = total16 or total32
    if not fat_size or not total:
        return None
    root_sectors = (root_entries * 32 + bps - 1) // bps
    first_data = reserved + nfats * fat_size + root_sectors
    if first_data >= total:
        return None
    clusters = (total - first_data) // spc
    kind = 12 if clusters < 4085 else 16 if clusters < 65525 else 32
    root_cluster = struct.unpack_from("<I", boot, 44)[0] if kind == 32 else 0
    return {"bps": bps, "spc": spc, "reserved": reserved, "nfats": nfats, "fat_size": fat_size,
            "root_entries": root_entries, "root_sectors": root_sectors, "first_data": first_data,
            "clusters": clusters, "kind": kind, "root_cluster": root_cluster}


def probe(dev) -> bool:
    boot = dev.read_at(0, 512)
    return _bpb(boot) is not None and boot[3:11] not in (b"NTFS    ", b"EXFAT   ")


def _dos_time(date: int, tm: int) -> float:
    if not date:
        return 0.0
    try:
        return time.mktime((1980 + (date >> 9), (date >> 5) & 15, date & 31, tm >> 11, (tm >> 5) & 63, (tm & 31) * 2,
                            0, 0, -1))
    except (OverflowError, ValueError):
        return 0.0


class Fat:
    def __init__(self, dev):
        self.dev = dev
        b = _bpb(dev.read_at(0, 512))
        if b is None:
            raise PackportError("This isn't a FAT file system")
        self.b = b
        self.name = f"FAT{b['kind']}"
        self.cluster_size = b["bps"] * b["spc"]
        fat_bytes = b["fat_size"] * b["bps"]
        if fat_bytes > 1 << 30:
            raise PackportError("The FAT file system is damaged (its FAT is too big)")
        self.fat = dev.read_at(b["reserved"] * b["bps"], fat_bytes)
        self.members: list[Item] = []
        self.count = 0
        self.seen: set[int] = set()
        if b["kind"] == 32:
            root = self._read_chain(b["root_cluster"], None)
        else:
            root = dev.read_at((b["reserved"] + b["nfats"] * b["fat_size"]) * b["bps"], b["root_sectors"] * b["bps"])
        self._walk(root, "", 0)

    def _next(self, c: int) -> int:
        kind, fat = self.b["kind"], self.fat
        if kind == 12:
            at = c + c // 2
            if at + 2 > len(fat):
                return 0xFFF
            v = fat[at] | fat[at + 1] << 8
            v = v >> 4 if c & 1 else v & 0xFFF
            return v if v < 0xFF7 else -1
        if kind == 16:
            if 2 * c + 2 > len(fat):
                return -1
            v = struct.unpack_from("<H", fat, 2 * c)[0]
            return v if v < 0xFFF7 else -1
        if 4 * c + 4 > len(fat):
            return -1
        v = struct.unpack_from("<I", fat, 4 * c)[0] & 0x0FFFFFFF
        return v if v < 0x0FFFFFF7 else -1

    def _chain(self, first: int, size: int | None) -> list[tuple[int, int]]:
        """The cluster chain from first, merged into (byte offset, length) runs."""
        runs: list[tuple[int, int]] = []
        c, total, limit = first, 0, self.b["clusters"] + 2
        while 2 <= c < limit:
            at = (self.b["first_data"] + (c - 2) * self.b["spc"]) * self.b["bps"]
            if runs and runs[-1][0] + runs[-1][1] == at:
                runs[-1] = (runs[-1][0], runs[-1][1] + self.cluster_size)
            else:
                runs.append((at, self.cluster_size))
            total += self.cluster_size
            if size is not None and total >= size:
                break
            if total > (limit + 1) * self.cluster_size:
                raise PackportError("The FAT file system is damaged (a cluster chain loops)")
            c = self._next(c)
        return runs

    def _read_chain(self, first: int, size: int | None) -> bytes:
        runs = self._chain(first, size)
        total = sum(n for _, n in runs)
        if total > 1 << 28:
            raise PackportError("The FAT file system is damaged (a folder is too big)")
        return Extents(self.dev, runs, total).read()

    def _walk(self, data: bytes, prefix: str, depth: int) -> None:
        if depth > MAX_DEPTH:
            return
        long_parts: list[tuple[int, str]] = []
        for i in range(0, len(data) - 31, 32):
            e = data[i:i + 32]
            if e[0] == 0:
                break
            if e[0] == 0xE5:
                long_parts = []
                continue
            attr = e[11]
            if attr & 0x3F == 0x0F:  # a piece of a long name
                order = e[0] & 0x1F
                chars = (e[1:11] + e[14:26] + e[28:32]).decode("utf-16-le", "replace")
                long_parts.append((order, chars.split("\0", 1)[0].replace("￿", "")))
                continue
            if attr & 0x08:  # the volume label
                long_parts = []
                continue
            short = self._short_name(e)
            name = "".join(p for _, p in sorted(long_parts)) if long_parts else short
            long_parts = []
            if name in (".", ".."):
                continue
            self.count += 1
            if self.count > MAX_ENTRIES:
                raise PackportError("The FAT file system lists too many files")
            name = name.replace("/", "_") or "_"
            first = struct.unpack_from("<H", e, 26)[0] | (struct.unpack_from("<H", e, 20)[0] << 16 if self.b["kind"] == 32 else 0)
            mtime = _dos_time(*struct.unpack_from("<HH", e, 22)[::-1])  # (time, date) at 22
            path = prefix + name
            if attr & 0x10:
                self.members.append(Item(path, 0, True, None, mtime, stat.S_IFDIR | 0o755))
                if first and first not in self.seen:
                    self.seen.add(first)
                    self._walk(self._read_chain(first, None), path + "/", depth + 1)
            else:
                size = struct.unpack_from("<I", e, 28)[0]
                runs = self._chain(first, size) if first and size else []
                self.members.append(Item(path, size, False, None, mtime,
                                         stat.S_IFREG | (0o444 if attr & 1 else 0o644), ref=runs))

    @staticmethod
    def _short_name(e: bytes) -> str:
        base, ext = e[0:8].rstrip(b" "), e[8:11].rstrip(b" ")
        if base[:1] == b"\x05":
            base = b"\xe5" + base[1:]
        base_s, ext_s = base.decode("cp437"), ext.decode("cp437")
        if e[12] & 0x08:
            base_s = base_s.lower()
        if e[12] & 0x10:
            ext_s = ext_s.lower()
        return f"{base_s}.{ext_s}" if ext_s else base_s

    def open_member(self, item: Item):
        runs = item.ref
        if sum(n for _, n in runs) < item.size:
            raise PackportError(f"{item.name}: the FAT file system is damaged (its clusters end early)")
        return Extents(self.dev, runs, item.size, item.name)
