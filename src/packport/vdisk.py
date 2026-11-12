"""Virtual disk containers, each read as the plain disk it holds: VHD (fixed, dynamic,
differencing), VHDX, VMDK (monolithic sparse, stream-optimized, and descriptor files with flat or
sparse extents), QCOW2, VDI, and Apple's DMG (UDIF).

Written from Microsoft's VHD specification and MS-VHDX, VMware's Virtual Disk Format 5.0, the
QEMU qcow2 specification, VirtualBox's VDI header layout, and the UDIF format as Apple's
hdiutil writes it (the koly trailer and its block tables). Blocks a sparse image never wrote
read as zeros; a differencing image reads the rest from its parent (or backing file), which has
to sit next to it under the name it records. Encrypted images (QCOW2 with a password) are
refused.
"""

from __future__ import annotations

import builtins
import re
import struct
import threading
import zlib
from pathlib import Path

from ._accel import native
from .cpio import _DEVICES as _WINDOWS_DEVICES
from .disk import _guid
from .entries import PackportError

MAX_BLOCK = 1 << 28  # a block of a VHD, VHDX or VDI: 256 MB at most (the VHDX spec's top; VHD uses 2 MB)
MAX_CHAIN = 16


class _Device:
    """A disk: size, and read_at() built on read_block() for whole blocks of block_size (or on
    read_range(), which a format gives for blocks it can read a piece of straight from the file)."""

    size = 0
    block_size = 512
    _cached: tuple[int, bytes] | None = None

    def read_block(self, index: int) -> bytes:
        raise NotImplementedError

    def read_range(self, index: int, inner: int, n: int) -> bytes:
        """n bytes from inner in block index: by default from the whole block, the last one kept
        (a file system reads a few KB at a time; a VHDX block is 32 MB)."""
        cached = self._cached
        if cached is None or cached[0] != index:
            cached = self._cached = (index, self.read_block(index))
        return cached[1][inner:inner + n]

    def read_at(self, offset: int, n: int) -> bytes:
        if offset < 0 or offset > self.size:
            raise PackportError("The disk image is damaged (a read past its end)")
        n = min(n, self.size - offset)
        out = bytearray()
        bs = self.block_size
        while len(out) < n:
            index, inner = divmod(offset + len(out), bs)
            take = min(n - len(out), bs - inner)
            piece = self.read_range(index, inner, take)
            if len(piece) < take:
                piece = piece.ljust(take, b"\0")
            out += piece
        return bytes(out)


class _File:
    """A file a container refers to (an extent, a parent), opened by path. It is closed with the
    archive: it goes on the list of files the opened image's Source closes."""

    def __init__(self, path: Path, owner):
        self.path, self.lock = path, threading.Lock()
        self.f = builtins.open(path, "rb")
        self.owned = getattr(owner, "owned", None)
        if self.owned is not None:
            self.owned.append(self.f)
        self.f.seek(0, 2)
        self.size = self.f.tell()

    def read_at(self, offset: int, n: int) -> bytes:
        with self.lock:
            self.f.seek(offset)
            return self.f.read(n)


def _sibling(source, name: str) -> Path:
    """The file another disk image names (a parent, an extent, a backing file), which has to be in
    the image's own folder: the name's last part there, or a relative path that stays inside it.
    Absolute paths, drives, network shares, ".." and streams are never looked up."""
    base = getattr(source, "path", None)
    if base is None:
        raise PackportError("This is a differencing disk image: open it from a file, next to its parent")
    folder = base.parent
    text = name.replace("\\", "/").strip()
    parts = [q for q in text.split("/") if q not in ("", ".")]
    leaf = parts[-1].strip() if parts else ""
    wanted = Path(leaf).name if leaf else "?"
    candidates = []
    if _plain(leaf):
        candidates.append(folder / leaf)
    relative = not text.startswith("/") and ":" not in text and len(parts) > 1
    if relative and all(_plain(q) for q in parts):
        candidates.append(folder.joinpath(*parts))
    root = folder.resolve()
    for candidate in candidates:
        if candidate.is_file() and candidate.resolve().is_relative_to(root):
            return candidate
    raise PackportError(f"This disk image needs its parent, {wanted}, next to it")


def _plain(part: str) -> bool:
    """A file or folder name that means nothing more: not "..", no drive or stream, no device."""
    return (bool(part) and part not in (".", "..") and ":" not in part and "\0" not in part
            and not part.endswith((" ", ".")) and part.split(".")[0].upper() not in _DEVICES)


_DEVICES = {d.upper() for d in _WINDOWS_DEVICES}


def container(source, depth: int = 0):
    """The disk inside source when it's a virtual disk container, else None."""
    if depth > MAX_CHAIN:
        raise PackportError("The disk image is damaged (its parents loop)")
    head = source.read_at(0, 512)
    if head[:8] == b"vhdxfile":
        return Vhdx(source, depth)
    if head[:4] == b"QFI\xfb":
        return Qcow2(source, depth)
    if head[:4] == b"KDMV":
        return Vmdk(source, depth)
    if head[:21] == b"# Disk DescriptorFile" or head.startswith(b"# Disk Descriptor"):
        return Vmdk(source, depth)
    if len(head) >= 0x48 and struct.unpack_from("<I", head, 0x40)[0] == 0xBEDA107F:
        return Vdi(source, depth)
    if head[:8] == b"encrcdsa" or (source.size >= 8 and source.read_at(source.size - 8, 8) == b"cdsaencr"):
        raise PackportError("This DMG is encrypted; packport doesn't decrypt")
    if head[:4] == b"sprs":
        raise PackportError("This is a sparse disk image (.sparseimage), which packport doesn't read")
    if source.size >= 512 and source.read_at(source.size - 512, 4) == b"koly":
        return Dmg(source, depth)
    if source.size >= 512 and source.read_at(source.size - 512, 8) == b"conectix":
        return Vhd(source, depth)
    if head[:8] == b"conectix" and source.size > 1024:  # a dynamic VHD whose footer is cut off
        return Vhd(source, depth)
    return None


# ---- VHD

class Vhd(_Device):
    def __init__(self, source, depth: int = 0):
        self.src = source
        footer = source.read_at(source.size - 512, 512)
        if footer[:8] != b"conectix":
            footer = source.read_at(0, 512)
        if footer[:8] != b"conectix":
            raise PackportError("This isn't a VHD")
        data_offset, = struct.unpack_from(">Q", footer, 16)
        self.size, = struct.unpack_from(">Q", footer, 48)
        kind, = struct.unpack_from(">I", footer, 60)
        if kind == 2:
            self.fixed = True
            self.block_size = 1 << 20
            if self.size > source.size - 512:
                raise PackportError("The VHD is cut short")
            return
        if kind not in (3, 4):
            raise PackportError("The VHD is damaged (its disk type)")
        self.fixed = False
        hdr = source.read_at(data_offset, 1024)
        if hdr[:8] != b"cxsparse":
            raise PackportError("The VHD is damaged (its dynamic disk header)")
        table, = struct.unpack_from(">Q", hdr, 16)
        entries, self.block_size = struct.unpack_from(">II", hdr, 28)
        if not self.block_size or self.block_size & 511 or self.block_size > MAX_BLOCK or entries > 1 << 24:
            raise PackportError("The VHD is damaged (its block table)")
        entries = min(entries, -(-self.size // self.block_size))  # only the blocks the disk's size needs
        raw = source.read_at(table, 4 * entries)
        self.bat = struct.unpack(f">{len(raw) // 4}I", raw[:len(raw) // 4 * 4])  # missing entries: not there
        self.bitmap = ((self.block_size // 512 + 7) // 8 + 511) // 512 * 512
        self.parent = None
        if kind == 4:
            name = hdr[64:576].decode("utf-16-be", "replace").split("\0", 1)[0]
            for k in range(8):  # the parent locators: a relative or absolute path
                code, _space, length, _, offset = struct.unpack_from(">4sIIIQ", hdr, 576 + 24 * k)
                if code in (b"W2ru", b"W2ku") and length:
                    name = source.read_at(offset, length).decode("utf-16-le", "replace").split("\0", 1)[0] or name
                    break
            parent_file = _File(_sibling(source, name), source)
            self.parent = container(parent_file, depth + 1) or parent_file

    def read_at(self, offset: int, n: int) -> bytes:
        if self.fixed:
            if offset < 0 or offset > self.size:
                raise PackportError("The disk image is damaged (a read past its end)")
            return self.src.read_at(offset, min(n, self.size - offset))
        return super().read_at(offset, n)

    def read_range(self, index: int, inner: int, n: int) -> bytes:
        if self.parent is None:  # a block of this disk alone: the piece wanted, straight from the file
            sector = self.bat[index] if index < len(self.bat) else 0xFFFFFFFF
            if sector == 0xFFFFFFFF:
                return bytes(n)
            return self.src.read_at(sector * 512 + self.bitmap + inner, n).ljust(n, b"\0")
        return super().read_range(index, inner, n)

    def read_block(self, index: int) -> bytes:
        bs = self.block_size
        sector = self.bat[index] if index < len(self.bat) else 0xFFFFFFFF
        base = self.parent.read_at(index * bs, bs).ljust(bs, b"\0") if self.parent else None
        if sector == 0xFFFFFFFF:
            return base if base is not None else bytes(bs)
        at = sector * 512
        data = self.src.read_at(at + self.bitmap, bs).ljust(bs, b"\0")
        if base is None:
            return data
        bits = self.src.read_at(at, self.bitmap)
        out = bytearray(base)
        for s in range(bs // 512):  # sectors this disk wrote, over its parent's
            if bits[s >> 3] >> (7 - (s & 7)) & 1:
                out[s * 512:(s + 1) * 512] = data[s * 512:(s + 1) * 512]
        return bytes(out)


# ---- VHDX

def _crc32c_table() -> list[int]:
    table = []
    for n in range(256):
        for _ in range(8):
            n = (n >> 1) ^ 0x82F63B78 if n & 1 else n >> 1
        table.append(n)
    return table


_CRC32C = _crc32c_table()


def _crc32c(data: bytes) -> int:
    """CRC-32C (Castagnoli), which VHDX uses for its headers and region tables."""
    crc, table = 0xFFFFFFFF, _CRC32C
    for b in data:
        crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


BAT_REGION = "2dc27766-f623-4200-9d64-115e9bfd4a08"
META_REGION = "8b7ca206-4790-4b9a-b8fe-575f050f886e"
FILE_PARAMETERS = "caa16737-fa36-4d43-b3b6-33f0aa44e76b"
DISK_SIZE = "2fa54224-cd1b-4876-b211-5dbed83bf4b8"
LOGICAL_SECTOR = "8141bf1d-a96f-4709-ba47-f233a8faab5f"
PARENT_LOCATOR = "a8d35f2d-b30b-454d-abf7-d3d84834ab0c"


class Vhdx(_Device):
    def __init__(self, source, depth: int = 0):
        self.src = source
        # the region table is kept twice, each with a CRC-32C: the first copy whose checksum
        # holds, else (a writer that left it out) the first that is there at all
        tables = [source.read_at(at, 64 << 10) for at in (192 << 10, 256 << 10)]
        tables = [r for r in tables if r[:4] == b"regi"]
        tables.sort(key=lambda r: struct.unpack_from("<I", r, 4)[0] != _crc32c(r[:4] + bytes(4) + r[8:]))
        regions = {}
        for r in tables[:1]:
            count, = struct.unpack_from("<I", r, 8)
            for k in range(min(count, 2047)):
                e = r[16 + 32 * k:48 + 32 * k]
                regions[_guid(e[:16])] = struct.unpack_from("<QI", e, 16)
        if BAT_REGION not in regions or META_REGION not in regions:
            raise PackportError("The VHDX is damaged (its region table)")
        moff, mlen = regions[META_REGION]
        meta = source.read_at(moff, mlen)
        if meta[:8] != b"metadata":
            raise PackportError("The VHDX is damaged (its metadata)")
        items = {}
        count, = struct.unpack_from("<H", meta, 10)
        for k in range(min(count, 2047)):
            e = meta[32 + 32 * k:64 + 32 * k]
            off, length = struct.unpack_from("<II", e, 16)
            items[_guid(e[:16])] = meta[off:off + length]
        try:
            self.block_size, flags = struct.unpack_from("<II", items[FILE_PARAMETERS], 0)
            self.size, = struct.unpack_from("<Q", items[DISK_SIZE], 0)
            sector, = struct.unpack_from("<I", items[LOGICAL_SECTOR], 0)
        except (KeyError, struct.error):
            raise PackportError("The VHDX is damaged (its metadata)") from None
        if not 1 << 20 <= self.block_size <= MAX_BLOCK or self.block_size & (self.block_size - 1) \
                or sector not in (512, 4096):  # the spec's 1 MB to 256 MB
            raise PackportError("The VHDX is damaged (its block size)")
        self.sector = sector
        self.ratio = (1 << 23) * sector // self.block_size  # payload blocks per sector-bitmap block
        boff, blen = regions[BAT_REGION]
        raw = source.read_at(boff, blen)
        self.bat = struct.unpack(f"<{len(raw) // 8}Q", raw[:len(raw) // 8 * 8])
        self.parent = None
        if flags & 2:
            loc = items.get(PARENT_LOCATOR, b"")
            paths = {}
            if len(loc) >= 20:
                n, = struct.unpack_from("<H", loc, 18)
                for k in range(min(n, 64)):
                    ko, vo, kl, vl = struct.unpack_from("<IIHH", loc, 20 + 12 * k)
                    paths[loc[ko:ko + kl].decode("utf-16-le", "replace")] = loc[vo:vo + vl].decode("utf-16-le", "replace")
            name = paths.get("relative_path") or paths.get("absolute_win32_path") or paths.get("volume_path")
            if not name:
                raise PackportError("The differencing VHDX doesn't name its parent")
            parent_file = _File(_sibling(source, name), source)
            self.parent = container(parent_file, depth + 1) or parent_file

    def read_range(self, index: int, inner: int, n: int) -> bytes:
        k = index + index // self.ratio
        entry = self.bat[k] if k < len(self.bat) else 0
        if entry & 7 == 6:  # fully present: the piece wanted, straight from the file
            return self.src.read_at(((entry >> 20) << 20) + inner, n).ljust(n, b"\0")
        return super().read_range(index, inner, n)

    def read_block(self, index: int) -> bytes:
        bs = self.block_size
        k = index + index // self.ratio
        entry = self.bat[k] if k < len(self.bat) else 0
        state, offset = entry & 7, (entry >> 20) << 20
        if state == 6:  # fully present
            return self.src.read_at(offset, bs).ljust(bs, b"\0")
        base = self.parent.read_at(index * bs, bs).ljust(bs, b"\0") if self.parent else bytes(bs)
        if state != 7:  # not present, zero, unmapped, undefined
            return base if self.parent and state in (0, 1) else bytes(bs) if state in (2, 3) else base
        chunk = index // self.ratio
        bmp_entry = self.bat[chunk * (self.ratio + 1) + self.ratio]
        bitmap_at = ((bmp_entry >> 20) << 20) + (index % self.ratio) * (bs // self.sector // 8)
        bits = self.src.read_at(bitmap_at, bs // self.sector // 8)
        data = self.src.read_at(offset, bs).ljust(bs, b"\0")
        out = bytearray(base)
        s = self.sector
        for k2 in range(bs // s):  # sectors in this file, the rest from the parent
            if bits[k2 >> 3] >> (k2 & 7) & 1:
                out[k2 * s:(k2 + 1) * s] = data[k2 * s:(k2 + 1) * s]
        return bytes(out)


# ---- VMDK

class _SparseExtent:
    """A hosted sparse extent (KDMV): grain directory, grain tables, grains; or stream-optimized,
    with every grain deflated and the tables at the end."""

    def __init__(self, src):
        self.src = src
        hdr = src.read_at(0, 512)
        if hdr[:4] != b"KDMV":
            raise PackportError("The VMDK is damaged (a sparse extent's header)")
        (_ver, _flags, capacity, grain, desc_off, desc_size, per_table, _rgd, gd, _over, _unclean) = \
            struct.unpack_from("<IIQQQQIQQQB", hdr, 4)
        compress, = struct.unpack_from("<H", hdr, 77)
        if gd == 0xFFFFFFFFFFFFFFFF:  # stream-optimized: the real header is in the footer
            foot = src.read_at(src.size - 1024, 512)
            if foot[:4] == b"KDMV":
                (_ver, _flags, capacity, grain, desc_off, desc_size, per_table, _rgd, gd, _over, _unclean) = \
                    struct.unpack_from("<IIQQQQIQQQB", foot, 4)
                compress, = struct.unpack_from("<H", foot, 77)
        if not grain or not per_table or grain > 1 << 16:
            raise PackportError("The VMDK is damaged (its grain size)")
        self.descriptor = src.read_at(desc_off * 512, desc_size * 512) if desc_off else b""
        self.capacity, self.grain = capacity * 512, grain * 512
        self.compressed = compress == 1
        self.per_table = per_table
        tables = (capacity + grain * per_table - 1) // (grain * per_table)
        if tables > 1 << 24:
            raise PackportError("The VMDK is damaged (its grain directory)")
        self.gd = struct.unpack(f"<{tables}I", src.read_at(gd * 512, 4 * tables).ljust(4 * tables, b"\0"))
        self.tables: dict[int, tuple] = {}

    def read_grain(self, index: int) -> bytes:
        t, k = divmod(index, self.per_table)
        if t >= len(self.gd) or not self.gd[t]:
            return bytes(self.grain)
        table = self.tables.get(t)
        if table is None:
            raw = self.src.read_at(self.gd[t] * 512, 4 * self.per_table).ljust(4 * self.per_table, b"\0")
            table = self.tables[t] = struct.unpack(f"<{self.per_table}I", raw)
        sector = table[k]
        if sector <= 1:  # unallocated, or a grain of zeros
            return bytes(self.grain)
        if not self.compressed:
            return self.src.read_at(sector * 512, self.grain).ljust(self.grain, b"\0")
        mark = self.src.read_at(sector * 512, 12)
        _lba, size = struct.unpack_from("<QI", mark, 0)
        try:
            return zlib.decompressobj().decompress(self.src.read_at(sector * 512 + 12, size), self.grain).ljust(
                self.grain, b"\0")
        except zlib.error as e:
            raise PackportError(f"The VMDK is damaged ({e})") from None


class Vmdk(_Device):
    def __init__(self, source, depth: int = 0):
        self.extents: list[tuple[int, int, object]] = []  # (start, size, extent)
        head = source.read_at(0, 4)
        if head == b"KDMV":
            sparse = _SparseExtent(source)
            text = sparse.descriptor
            self.extents.append((0, sparse.capacity, sparse))
            self.size = sparse.capacity
            self.block_size = sparse.grain
        else:
            text = source.read_at(0, min(source.size, 1 << 20))
            at = 0
            for kind, sectors, ftype, fname, foffset in re.findall(
                    rb'^\s*(RW|RDONLY|NOACCESS)\s+(\d+)\s+(\w+)\s+"([^"]+)"\s*(\d*)', text, re.MULTILINE):
                size = int(sectors) * 512
                if ftype in (b"FLAT", b"VMFS"):
                    f = _File(_sibling(source, fname.decode("utf-8", "replace")), source)
                    self.extents.append((at, size, ("flat", f, int(foffset or 0) * 512)))
                elif ftype in (b"SPARSE", b"VMFSSPARSE"):
                    self.extents.append((at, size, _SparseExtent(_File(_sibling(source, fname.decode("utf-8", "replace")), source))))
                elif ftype == b"ZERO":
                    self.extents.append((at, size, None))
                else:
                    raise PackportError(f"This VMDK uses {ftype.decode()} extents, which packport doesn't read")
                at += size
            if not self.extents:
                raise PackportError("The VMDK descriptor names no extents")
            self.size = at
            self.block_size = 64 << 10
        self.parent = None
        hint = re.search(rb'parentFileNameHint\s*=\s*"([^"]+)"', text or b"")
        if hint and re.search(rb'parentCID\s*=\s*(?!ffffffff)[0-9a-fA-F]+', text):
            parent_file = _File(_sibling(source, hint.group(1).decode("utf-8", "replace")), source)
            self.parent = container(parent_file, depth + 1) or parent_file
        if self.parent is not None:
            raise PackportError("This VMDK is a snapshot (a delta disk); packport reads its base disk instead")

    def read_block(self, index: int) -> bytes:
        bs = self.block_size
        start = index * bs
        out = bytearray()
        while len(out) < bs and start + len(out) < self.size:
            pos = start + len(out)
            for e_start, e_size, extent in self.extents:
                if e_start <= pos < e_start + e_size:
                    break
            else:
                break
            inner = pos - e_start
            take = min(bs - len(out), e_size - inner)
            if extent is None:
                out += bytes(take)
            elif isinstance(extent, tuple):
                out += extent[1].read_at(extent[2] + inner, take).ljust(take, b"\0")
            else:
                g, off = divmod(inner, extent.grain)
                piece = extent.read_grain(g)[off:off + take]
                out += piece
        return bytes(out).ljust(bs, b"\0")


# ---- QCOW2

class Qcow2(_Device):
    def __init__(self, source, depth: int = 0):
        self.src = source
        h = source.read_at(0, 112)
        version, back_off, back_len, bits = struct.unpack_from(">IQII", h, 4)
        self.size, crypt, l1_size, l1_off = struct.unpack_from(">QIIQ", h, 24)
        if version not in (2, 3) or not 9 <= bits <= 21:
            raise PackportError("The QCOW2 image is damaged (its header)")
        if crypt:
            raise PackportError("This QCOW2 image is encrypted; packport doesn't decrypt")
        self.zstd = False
        if version == 3:
            incompat, = struct.unpack_from(">Q", h, 72)
            hlen, = struct.unpack_from(">I", h, 100)
            if incompat & 0x10:
                raise PackportError("This QCOW2 image uses extended L2 entries, which packport doesn't read")
            if incompat & 0x04:
                raise PackportError("This QCOW2 image keeps its data in an external file, which packport doesn't read")
            if incompat & ~0x1F & 0xFFFFFFFFFFFFFFFF:
                raise PackportError("This QCOW2 image uses features packport doesn't read")
            self.zstd = hlen > 104 and h[104] == 1
        self.bits = bits
        self.block_size = 1 << bits
        if l1_size > 1 << 26:
            raise PackportError("The QCOW2 image is damaged (its L1 table)")
        l1_size = min(l1_size, -(-self.size // (self.block_size * (self.block_size // 8))))  # what the size needs
        raw = source.read_at(l1_off, 8 * l1_size)
        self.l1 = struct.unpack(f">{len(raw) // 8}Q", raw[:len(raw) // 8 * 8])  # missing entries: not there
        self.l2_cache: dict[int, tuple] = {}
        self.backing = None
        if back_off and back_len:
            name = source.read_at(back_off, back_len).decode("utf-8", "replace")
            back_file = _File(_sibling(source, name), source)
            self.backing = container(back_file, depth + 1) or back_file

    def read_block(self, index: int) -> bytes:
        cs = self.block_size
        per = cs // 8
        t, k = divmod(index, per)
        l2_off = (self.l1[t] if t < len(self.l1) else 0) & 0x00FFFFFFFFFFFE00
        entry = 0
        if l2_off:
            table = self.l2_cache.get(l2_off)
            if table is None:
                if len(self.l2_cache) > 256:
                    self.l2_cache.clear()
                table = self.l2_cache[l2_off] = struct.unpack(f">{per}Q", self.src.read_at(l2_off, cs).ljust(cs, b"\0"))
            entry = table[k]
        if entry & (1 << 62):  # compressed
            x = 62 - (self.bits - 8)
            offset = entry & ((1 << x) - 1)
            sectors = ((entry >> x) & ((1 << (self.bits - 8)) - 1)) + 1
            raw = self.src.read_at(offset, sectors * 512 - (offset & 511))
            try:
                if self.zstd:
                    import io

                    from .arformat import zstd_reader
                    return zstd_reader(io.BytesIO(raw)).read(cs).ljust(cs, b"\0")
                return zlib.decompressobj(-12).decompress(raw, cs).ljust(cs, b"\0")
            except Exception as e:
                raise PackportError(f"The QCOW2 image is damaged ({e})") from None
        offset = entry & 0x00FFFFFFFFFFFE00
        if entry & 1:  # reads as zeros (version 3)
            return bytes(cs)
        if offset:
            return self.src.read_at(offset, cs).ljust(cs, b"\0")
        if self.backing is not None:
            return self.backing.read_at(index * cs, cs).ljust(cs, b"\0")
        return bytes(cs)


# ---- VDI

class Vdi(_Device):
    def __init__(self, source, depth: int = 0):
        self.src = source
        h = source.read_at(0, 512)
        kind, = struct.unpack_from("<I", h, 0x4C)
        self.blocks_at, self.data_at = struct.unpack_from("<II", h, 0x154)
        self.size, = struct.unpack_from("<Q", h, 0x170)
        self.block_size, self.extra, blocks = struct.unpack_from("<III", h, 0x178)
        if kind not in (1, 2) or not self.block_size or self.block_size > MAX_BLOCK or blocks > 1 << 24:
            if kind == 4:
                raise PackportError("This is a differencing VDI; packport reads its base disk instead")
            raise PackportError("The VDI is damaged (its header)")
        blocks = min(blocks, -(-self.size // self.block_size))
        raw = source.read_at(self.blocks_at, 4 * blocks)
        self.map = struct.unpack(f"<{len(raw) // 4}I", raw[:len(raw) // 4 * 4])  # missing entries: not there

    def read_range(self, index: int, inner: int, n: int) -> bytes:
        k = self.map[index] if index < len(self.map) else 0xFFFFFFFF
        if k >= 0xFFFFFFFE:
            return bytes(n)
        return self.src.read_at(self.data_at + k * (self.block_size + self.extra) + self.extra + inner, n).ljust(n, b"\0")

    def read_block(self, index: int) -> bytes:
        bs = self.block_size
        k = self.map[index] if index < len(self.map) else 0xFFFFFFFF
        if k >= 0xFFFFFFFE:
            return bytes(bs)
        return self.src.read_at(self.data_at + k * (bs + self.extra) + self.extra, bs).ljust(bs, b"\0")


# ---- DMG (UDIF)

DMG_ZERO, DMG_RAW, DMG_IGNORE, DMG_ADC, DMG_ZLIB, DMG_BZIP2, DMG_LZFSE, DMG_LZMA = (
    0, 1, 2, 0x80000004, 0x80000005, 0x80000006, 0x80000007, 0x80000008)


def adc(data: bytes, size: int) -> bytes:
    """Apple Data Compression: runs of literals, and back references 2 or 3 bytes long."""
    out = bytearray()
    i = 0
    while i < len(data) and len(out) < size:
        b = data[i]
        if b & 0x80:
            n = (b & 0x7F) + 1
            out += data[i + 1:i + 1 + n]
            i += 1 + n
            continue
        if b & 0x40:
            if i + 3 > len(data):
                break
            length, dist = (b & 0x3F) + 4, (data[i + 1] << 8 | data[i + 2]) + 1
            i += 3
        else:
            if i + 2 > len(data):
                break
            length, dist = ((b >> 2) & 0x0F) + 3, ((b & 3) << 8 | data[i + 1]) + 1
            i += 2
        start = len(out) - dist
        if start < 0:
            raise PackportError("The DMG is damaged (ADC data)")
        for k in range(length):
            out.append(out[start + k])
    return bytes(out[:size])


if native is not None:
    adc = native.adc_decompress


class Dmg(_Device):
    """A UDIF disk image: the koly trailer, then for each partition a table of chunks of sectors,
    each zeros, stored, or packed (zlib, bzip2, ADC, LZMA)."""

    block_size = 512

    def __init__(self, source, depth: int = 0):
        import plistlib
        self.src = source
        koly = source.read_at(source.size - 512, 512)
        if koly[:4] != b"koly":
            raise PackportError("This isn't a DMG")
        self.data_at, = struct.unpack_from(">Q", koly, 24)
        xml_at, xml_len = struct.unpack_from(">QQ", koly, 216)
        try:
            plist = plistlib.loads(source.read_at(xml_at, min(xml_len, 64 << 20)))
            blocks = plist["resource-fork"]["blkx"]
        except Exception:
            raise PackportError("The DMG is damaged (its partition list)") from None
        self.chunks: list[tuple[int, int, int, int, int]] = []  # (first sector, sectors, type, offset, length)
        for b in blocks:
            mish = b.get("Data", b"")
            if mish[:4] != b"mish":
                continue
            first, = struct.unpack_from(">Q", mish, 8)
            count, = struct.unpack_from(">I", mish, 0xC8)
            for k in range(min(count, 1 << 20)):
                e = mish[0xCC + 40 * k:0xCC + 40 * (k + 1)]
                if len(e) < 40:
                    break
                kind, _comment, sector, sectors, offset, length = struct.unpack(">IIQQQQ", e)
                if kind in (0x7FFFFFFE, 0xFFFFFFFF) or not sectors:
                    continue
                self.chunks.append((first + sector, sectors, kind, offset, length))
        self.chunks.sort()
        self.starts = [c[0] for c in self.chunks]
        self.size = max((c[0] + c[1] for c in self.chunks), default=0) * 512
        self.cache: tuple[int, bytes] | None = None

    def read_at(self, offset: int, n: int) -> bytes:
        """A run of the disk, a chunk at a time (not a sector at a time)."""
        import bisect
        if offset < 0 or offset > self.size:
            raise PackportError("The disk image is damaged (a read past its end)")
        n = min(n, self.size - offset)
        out = bytearray()
        while len(out) < n:
            at = offset + len(out)
            sector = at // 512
            k = bisect.bisect_right(self.starts, sector) - 1
            if k < 0 or sector >= self.chunks[k][0] + self.chunks[k][1]:  # a gap between chunks: zeros
                nxt = self.starts[k + 1] * 512 if k + 1 < len(self.starts) else self.size
                out += bytes(min(n - len(out), max(nxt - at, 512 - at % 512)))
                continue
            first, sectors, kind, offset_in, _length = self.chunks[k]
            inner = at - first * 512
            take = min(n - len(out), sectors * 512 - inner)
            if kind in (DMG_ZERO, DMG_IGNORE):
                out += bytes(take)
            elif kind == DMG_RAW:
                out += self.src.read_at(self.data_at + offset_in + inner, take).ljust(take, b"\0")
            else:
                out += self._chunk(k)[inner:inner + take]
        return bytes(out)

    def read_block(self, index: int) -> bytes:
        return self.read_at(index * 512, 512)

    def _chunk(self, k: int) -> bytes:
        """Chunk k unpacked (the last one is kept)."""
        if self.cache is not None and self.cache[0] == k:
            return self.cache[1]
        _first, sectors, kind, offset, length = self.chunks[k]
        if sectors > 1 << 16:
            raise PackportError("The DMG is damaged (a chunk is too big)")
        raw = self.src.read_at(self.data_at + offset, length)
        want = sectors * 512
        try:
            if kind == DMG_ZLIB:
                data = zlib.decompressobj().decompress(raw, want)
            elif kind == DMG_BZIP2:
                import bz2
                data = bz2.BZ2Decompressor().decompress(raw, want)
            elif kind == DMG_ADC:
                data = adc(raw, want)
            elif kind == DMG_LZMA:
                import lzma
                data = lzma.LZMADecompressor().decompress(raw, want)
            elif kind == DMG_LZFSE:
                raise PackportError("This DMG is compressed with LZFSE, which packport doesn't read yet")
            else:
                raise PackportError(f"This DMG uses a chunk type packport doesn't know ({kind:#x})")
        except PackportError:
            raise
        except Exception as e:
            raise PackportError(f"The DMG is damaged ({e})") from None
        self.cache = (k, data.ljust(want, b"\0"))
        return self.cache[1]
