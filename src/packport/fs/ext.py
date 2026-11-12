"""ext2, ext3 and ext4.

Written from the ext4 disk layout documentation on kernel.org. The superblock (at byte 1024)
gives the block size, the blocks and inodes per group and the features; the group descriptors
that follow it say where each group's inode table is (32 bytes each, or more on 64-bit file
systems). An inode has the mode, size, times and where the data is: an extent tree (ext4) or
the classic map of 12 direct blocks and single, double and triple indirect ones (ext2, ext3);
gaps and uninitialized extents read as zeros, and small files can keep their data in the inode
itself (inline data). Folders are entries of inode number, length, name and type; hashed
(htree) folders are read the same way, block by block. Encrypted folders are refused.
"""

from __future__ import annotations

import io
import stat
import struct

from ..archive import EncryptedError, Item
from ..entries import PackportError
from . import Extents

MAGIC = 0xEF53
INCOMPAT_EXTENTS, INCOMPAT_64BIT, INCOMPAT_META_BG = 0x40, 0x80, 0x10
FLAG_EXTENTS, FLAG_INLINE, FLAG_ENCRYPT = 0x80000, 0x10000000, 0x800
ROOT = 2
MAX_DEPTH = 256
MAX_ENTRIES = 2_000_000
MAX_EXTENTS = 1 << 20
MAX_NODES = 1 << 16  # extent-tree index blocks read for one file


def probe(dev) -> bool:
    sb = dev.read_at(1024, 1024)
    return len(sb) >= 1024 and struct.unpack_from("<H", sb, 56)[0] == MAGIC


class Ext:
    def __init__(self, dev):
        self.dev = dev
        sb = dev.read_at(1024, 1024)
        if len(sb) < 1024 or struct.unpack_from("<H", sb, 56)[0] != MAGIC:
            raise PackportError("This isn't an ext file system")
        log = struct.unpack_from("<I", sb, 24)[0]
        if log > 6:
            raise PackportError("The ext file system is damaged (its block size)")
        self.bs = 1024 << log
        self.first_data = struct.unpack_from("<I", sb, 20)[0]
        self.blocks_per_group, _, self.inodes_per_group = struct.unpack_from("<III", sb, 32)
        rev = struct.unpack_from("<I", sb, 76)[0]
        self.inode_size = struct.unpack_from("<H", sb, 88)[0] if rev >= 1 else 128
        incompat = struct.unpack_from("<I", sb, 96)[0]
        if not self.inodes_per_group or not self.blocks_per_group or not 128 <= self.inode_size <= self.bs:
            raise PackportError("The ext file system is damaged (its superblock)")
        self.desc_size = (struct.unpack_from("<H", sb, 254)[0] or 64) if incompat & INCOMPAT_64BIT else 32
        if self.desc_size < 32:
            raise PackportError("The ext file system is damaged (its group descriptors)")
        self.name = "ext4" if incompat & (INCOMPAT_EXTENTS | INCOMPAT_64BIT) else \
            "ext3" if struct.unpack_from("<I", sb, 92)[0] & 0x4 else "ext2"
        inodes = struct.unpack_from("<I", sb, 0)[0]
        self.groups = (inodes + self.inodes_per_group - 1) // self.inodes_per_group
        if self.groups > 1 << 24:
            raise PackportError("The ext file system is damaged (too many groups)")
        self.meta_bg = bool(incompat & INCOMPAT_META_BG)
        if not self.meta_bg:
            self.descs = dev.read_at((self.first_data + 1) * self.bs, self.groups * self.desc_size)
        self.members: list[Item] = []
        self.count = 0
        self.seen: set[int] = set()
        self._walk(ROOT, "", 0)

    def _desc(self, group: int) -> bytes:
        if not self.meta_bg:
            d = self.descs[group * self.desc_size:(group + 1) * self.desc_size]
        else:  # each meta group keeps its descriptors in its own first block
            per = self.bs // self.desc_size
            first = group // per * per
            block = first * self.blocks_per_group + self.first_data + (1 if self._has_super(first) else 0)
            d = self.dev.read_at(block * self.bs + (group % per) * self.desc_size, self.desc_size)
        if len(d) < 32:
            raise PackportError("The ext file system is damaged (a group descriptor)")
        return d

    @staticmethod
    def _has_super(group: int) -> bool:
        if group <= 1:
            return True
        for base in (3, 5, 7):
            n = base
            while n < group:
                n *= base
            if n == group:
                return True
        return False

    def _inode(self, number: int) -> bytes:
        if not 1 <= number <= self.groups * self.inodes_per_group:
            raise PackportError("The ext file system is damaged (an inode number)")
        group, index = divmod(number - 1, self.inodes_per_group)
        d = self._desc(group)
        table = struct.unpack_from("<I", d, 8)[0]
        if self.desc_size >= 64:
            table |= struct.unpack_from("<I", d, 0x28)[0] << 32
        raw = self.dev.read_at(table * self.bs + index * self.inode_size, self.inode_size)
        if len(raw) < 128:
            raise PackportError("The ext file system is cut short")
        return raw

    @staticmethod
    def _size(ino: bytes) -> int:
        return struct.unpack_from("<I", ino, 4)[0] | struct.unpack_from("<I", ino, 108)[0] << 32

    def _extents(self, ino: bytes, size: int) -> list[tuple[int | None, int]]:
        """The inode's data as (byte offset or None for zeros, length) runs, size bytes in all."""
        flags = struct.unpack_from("<I", ino, 32)[0]
        nblocks = (size + self.bs - 1) // self.bs
        if nblocks > 1 << 40:
            raise PackportError("The ext file system is damaged (a file size)")
        mapped: list[tuple[int, int, int | None]] = []  # (logical block, count, physical block)
        if flags & FLAG_EXTENTS:
            self._tree(ino[40:100], mapped, 0, set())
        else:
            self._blockmap(ino, nblocks, mapped)
        mapped.sort(key=lambda m: m[0])
        runs: list[tuple[int | None, int]] = []
        pos = 0  # logical block reached
        for logical, count, phys in mapped:
            if logical >= nblocks:
                break
            if logical < pos:
                continue  # overlapping extents: damage; the first one wins
            if logical > pos:
                runs.append((None, (logical - pos) * self.bs))
            count = min(count, nblocks - logical)
            runs.append((None if phys is None else phys * self.bs, count * self.bs))
            pos = logical + count
        if pos < nblocks:
            runs.append((None, (nblocks - pos) * self.bs))
        return runs

    def _tree(self, node: bytes, out: list, depth: int, seen: set) -> None:
        """The extents under node into out. seen: the index blocks visited, each once (thousands of
        entries all pointing at one block would otherwise read it billions of times)."""
        if depth > 8:
            raise PackportError("The ext file system is damaged (an extent tree is too deep)")
        magic, entries, _max, level = struct.unpack_from("<HHHH", node, 0)
        if magic != 0xF30A:
            raise PackportError("The ext file system is damaged (an extent header)")
        for k in range(entries):
            e = node[12 + 12 * k:24 + 12 * k]
            if len(e) < 12:
                raise PackportError("The ext file system is damaged (an extent)")
            if level == 0:
                logical, length, hi, lo = struct.unpack("<IHHI", e)
                init = length <= 32768
                if not init:
                    length -= 32768
                out.append((logical, length, (hi << 32 | lo) if init else None))
                if len(out) > MAX_EXTENTS:
                    raise PackportError("The ext file system is damaged (too many extents)")
            else:
                _logical, lo, hi = struct.unpack_from("<IIH", e)
                block = hi << 32 | lo
                if block in seen or len(seen) >= MAX_NODES:
                    raise PackportError("The ext file system is damaged (an extent tree points back into itself)")
                seen.add(block)
                self._tree(self.dev.read_at(block * self.bs, self.bs), out, depth + 1, seen)

    def _blockmap(self, ino: bytes, nblocks: int, out: list) -> None:
        ptrs = struct.unpack_from("<15I", ino, 40)
        per = self.bs // 4
        logical = 0

        def walk(block: int, level: int) -> None:
            nonlocal logical
            if logical >= nblocks:
                return
            if level == 0:
                if block:
                    if out and out[-1][0] + out[-1][1] == logical and out[-1][2] + out[-1][1] == block:
                        out[-1] = (out[-1][0], out[-1][1] + 1, out[-1][2])
                    else:
                        out.append((logical, 1, block))
                logical += 1
                return
            if not block:
                logical += per ** level
                return
            table = struct.unpack(f"<{per}I", self.dev.read_at(block * self.bs, self.bs).ljust(self.bs, b"\0"))
            for b in table:
                walk(b, level - 1)
                if logical >= nblocks:
                    return

        for b in ptrs[:12]:
            walk(b, 0)
        for level, b in zip((1, 2, 3), ptrs[12:]):
            walk(b, level)

    def _data(self, ino: bytes, limit: int = 1 << 28) -> bytes:
        size = self._size(ino)
        if size > limit:
            raise PackportError("The ext file system is damaged (a folder is too big)")
        if struct.unpack_from("<I", ino, 32)[0] & FLAG_INLINE:
            return self._inline(ino, size)
        return Extents(self.dev, self._extents(ino, size), size).read()

    @staticmethod
    def _inline(ino: bytes, size: int) -> bytes:
        data = ino[40:100]
        if size > 60:  # the rest sits in the inode's "system.data" extended attribute
            extra = struct.unpack_from("<H", ino, 128)[0] if len(ino) > 130 else 0
            at = 128 + extra
            if ino[at:at + 4] == b"\x00\x00\x02\xea":
                e = at + 4
                while e + 16 <= len(ino) and ino[e:e + 4] != bytes(4):
                    nlen = ino[e]
                    voff, _vblock, vsize = struct.unpack_from("<HII", ino, e + 2)
                    if ino[e + 16:e + 16 + nlen] == b"data":
                        data += ino[at + 4 + voff:at + 4 + voff + vsize]
                        break
                    e += (16 + nlen + 3) & ~3
        return data[:size]

    def _walk(self, number: int, prefix: str, depth: int) -> None:
        if depth > MAX_DEPTH or number in self.seen:
            return
        self.seen.add(number)
        ino = self._inode(number)
        if struct.unpack_from("<I", ino, 32)[0] & FLAG_ENCRYPT:
            raise EncryptedError("This ext file system has encrypted folders; packport doesn't decrypt")
        data = self._data(ino)
        i = 0
        while i + 8 <= len(data):
            child, rec_len, name_len, _kind = struct.unpack_from("<IHBB", data, i)
            if rec_len < 8 or i + rec_len > len(data):
                if rec_len == 0:  # an empty block's padding
                    i = (i // self.bs + 1) * self.bs
                    continue
                raise PackportError("The ext file system is damaged (a folder entry)")
            raw = data[i + 8:i + 8 + name_len]
            i += rec_len
            if not child or not raw or raw in (b".", b".."):
                continue
            self.count += 1
            if self.count > MAX_ENTRIES:
                raise PackportError("The ext file system lists too many files")
            path = prefix + raw.decode("utf-8", "replace").replace("/", "_")
            cino = self._inode(child)
            mode = struct.unpack_from("<H", cino, 0)[0]
            mtime = float(struct.unpack_from("<I", cino, 16)[0])
            if stat.S_ISDIR(mode):
                self.members.append(Item(path, 0, True, None, mtime, mode))
                self._walk(child, path + "/", depth + 1)
            elif stat.S_ISREG(mode):
                self.members.append(Item(path, self._size(cino), False, None, mtime, mode, ref=cino))
            elif stat.S_ISLNK(mode):
                size = self._size(cino)
                target = cino[40:40 + size] if size < 60 else self._data(cino, 1 << 16)
                self.members.append(Item(path, 0, False, target.decode("utf-8", "replace") or "?", mtime, mode))
            elif stat.S_IFMT(mode):
                self.members.append(Item(path, 0, False, None, mtime, mode))  # devices, FIFOs, sockets

    def open_member(self, item: Item):
        ino = item.ref
        if struct.unpack_from("<I", ino, 32)[0] & FLAG_INLINE:
            return io.BytesIO(self._inline(ino, item.size))
        return Extents(self.dev, self._extents(ino, item.size), item.size, item.name)
