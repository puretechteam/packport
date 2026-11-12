"""squashfs 4.0 file system images (.sqfs, .squashfs, .snap, Linux live media).

Written from the squashfs 4.0 on-disk format as the Linux kernel documents it. A 96-byte
superblock gives the block size, the compressor and where each table starts. Inodes, folder
listings, the fragment table and the uid/gid table are kept in metadata blocks (up to 8 KB, each
with a 2-byte header: its size, and whether it's stored uncompressed); an inode reference is
(the block's offset in the inode table) << 16 | (the offset inside it). A folder listing is runs
of entries sharing one inode block: names, types and inode offsets. A file is data blocks (each
compressed on its own, stored as is, or a hole of zeros) and maybe a tail packed with others
into a fragment block.

Compressors: gzip (zlib), xz, lzma, LZ4 (its block format, in Python) and, when the module is
installed, zstd. LZO images are refused with a clear message. Hard links come out as files of their own; symbolic links,
devices, FIFOs and sockets are listed but not unpacked.
"""

from __future__ import annotations

import io
import lzma
import stat
import struct
import zlib
from collections.abc import Iterator

from ._accel import native
from .archive import DAMAGED, Archive, Item, Source, Stream, reader
from .entries import PackportError
from .parallel import ordered

MAGIC = b"hsqs"
META = 8192
COMPRESSORS = {1: "gzip", 2: "lzma", 3: "LZO", 4: "xz", 5: "LZ4", 6: "Zstandard"}
DIR, FILE, SYMLINK, XDIR, XFILE, XSYMLINK = 1, 2, 3, 8, 9, 10
MAX_DEPTH = 256
MAX_ENTRIES = 2_000_000


def _sniff(head: bytes, _source) -> bool:
    return head[:4] == MAGIC and len(head) >= 96 and struct.unpack_from("<H", head, 28)[0] == 4


@reader("squashfs", _sniff)
class SquashfsArchive(Archive):
    def __init__(self, source: Source):
        super().__init__(source)
        sb = source.read_at(0, 96)
        if len(sb) < 96 or sb[:4] != MAGIC:
            raise PackportError("This isn't a squashfs image")
        (self.inodes, _mtime, self.block_size, self.fragments, comp, block_log, self.flags, id_count, major,
         minor) = struct.unpack_from("<IIIIHHHHHH", sb, 4)
        (root, _used, id_table, _xattr, self.inode_table, self.dir_table, frag_table,
         _export) = struct.unpack_from("<8Q", sb, 32)
        if (major, minor) != (4, 0):
            raise PackportError(f"This is squashfs {major}.{minor}; packport reads squashfs 4.0")
        if self.block_size != 1 << block_log or not 4096 <= self.block_size <= 1 << 20:
            raise PackportError("The squashfs image is damaged (its block size)")
        if comp not in COMPRESSORS:
            raise PackportError("The squashfs image is damaged (an unknown compressor)")
        self.comp = comp
        if comp == 3:
            raise PackportError(f"This squashfs image is compressed with {COMPRESSORS[comp]}, which packport "
                                "doesn't read")
        self.meta_cache: dict[int, tuple[bytes, int]] = {}
        self.frag_cache: tuple[int, bytes] | None = None
        self.frag_table = self._table(frag_table, self.fragments, 16) if self.fragments else b""
        self._table(id_table, id_count, 4)
        self.count = 0
        self.seen: set[int] = set()
        info = self._inode(root)
        if info["type"] not in (DIR, XDIR):
            raise PackportError("The squashfs image is damaged (its root isn't a folder)")
        self._walk(info, "", 0)

    # -- metadata

    def _decompress(self, data: bytes, limit: int) -> bytes:
        try:
            if self.comp == 1:
                return zlib.decompressobj().decompress(data, limit)
            if self.comp == 4:
                return lzma.LZMADecompressor(lzma.FORMAT_XZ).decompress(data, limit)
            if self.comp == 2:
                return lzma.LZMADecompressor(lzma.FORMAT_ALONE).decompress(data, limit)
            if self.comp == 5:
                return lz4_block(data, limit)
            from .arformat import zstd_reader
            return zstd_reader(io.BytesIO(data)).read(limit)
        except (*DAMAGED, OSError) as e:  # bz2 and zstd report bad data as OSError too
            raise PackportError(f"The squashfs image is damaged ({e})") from None

    def _meta_block(self, at: int) -> tuple[bytes, int]:
        """The metadata block at at: (its data, where the next one starts)."""
        hit = self.meta_cache.get(at)
        if hit is not None:
            return hit
        head = self.source.read_at(at, 2)
        if len(head) < 2:
            raise PackportError("The squashfs image is cut short")
        h = struct.unpack("<H", head)[0]
        size, stored = h & 0x7FFF, bool(h & 0x8000)
        if size == 0 or size > META:
            raise PackportError("The squashfs image is damaged (a metadata block)")
        raw = self.source.read_at(at + 2, size)
        data = raw if stored else self._decompress(raw, META)
        if len(self.meta_cache) > 4096:
            self.meta_cache.clear()
        self.meta_cache[at] = (data, at + 2 + size)
        return self.meta_cache[at]

    def _meta(self, table: int, block: int, offset: int, length: int) -> bytes:
        """length bytes of a metadata stream, from the block at table + block, offset in."""
        # an inode starts within one metadata block (8 KB), and its fields are read from after its header,
        # which may run into the next block (an offset of 8192 and more is right): far past that is damage
        if offset >= META + 256:
            raise PackportError("The squashfs image is damaged (a metadata offset)")
        out = bytearray()
        at = table + block
        hops = 0
        while len(out) < length:
            data, nxt = self._meta_block(at)
            if offset >= len(data):  # what's wanted starts in a later block
                offset -= len(data)
                at = nxt
                hops += 1
                if hops > 1 << 16:
                    raise PackportError("The squashfs image is damaged (a metadata offset)")
                continue
            out += data[offset:offset + length - len(out)]
            offset, at = 0, nxt
        return bytes(out)

    def _table(self, start: int, count: int, size: int) -> bytes:
        """A table kept in metadata blocks, found through a list of their addresses at start."""
        total = count * size
        if total > 1 << 28:
            raise PackportError("The squashfs image is damaged (a table is too big)")
        nblocks = (total + META - 1) // META
        ptrs = self.source.read_at(start, 8 * nblocks)
        if len(ptrs) < 8 * nblocks:
            raise PackportError("The squashfs image is cut short")
        out = bytearray()
        for (p,) in struct.iter_unpack("<Q", ptrs):
            out += self._meta_block(p)[0]
        if len(out) < total:
            raise PackportError("The squashfs image is damaged (a table is short)")
        return bytes(out[:total])

    # -- inodes and folders

    def _inode(self, ref: int) -> dict:
        block, offset = ref >> 16, ref & 0xFFFF
        head = self._meta(self.inode_table, block, offset, 16)
        kind, perms, _uid, _gid, mtime, number = struct.unpack("<HHHHII", head)
        info = {"type": kind, "mode": perms & 0o7777, "mtime": float(mtime), "number": number}

        def more(n: int) -> bytes:
            return self._meta(self.inode_table, block, offset + 16, n)

        if kind == DIR:
            start, _links, size, boff, _parent = struct.unpack("<IIHHI", more(16))
            info.update(start=start, size=size, offset=boff)
        elif kind == XDIR:
            _links, size, start, _parent, _count, boff, _xattr = struct.unpack("<IIIIHHI", more(24))
            info.update(start=start, size=size, offset=boff)
        elif kind in (FILE, XFILE):
            if kind == FILE:
                start, frag, foff, size = struct.unpack("<IIII", more(16))
                head_len = 16
            else:
                start, size, _sparse, _links, frag, foff, _xattr = struct.unpack("<QQQIIII", more(40))
                head_len = 40
            if size > 1 << 50:
                raise PackportError("The squashfs image is damaged (a file size)")
            n = size // self.block_size if frag != 0xFFFFFFFF else -(-size // self.block_size)
            if n > 1 << 24:
                raise PackportError("The squashfs image is damaged (a file size)")
            sizes = struct.unpack(f"<{n}I", self._meta(self.inode_table, block, offset + 16 + head_len, 4 * n)) \
                if n else ()
            info.update(start=start, size=size, frag=frag, foff=foff, blocks=sizes)
        elif kind in (SYMLINK, XSYMLINK):
            _links, n = struct.unpack("<II", more(8))
            if n > 1 << 16:
                raise PackportError("The squashfs image is damaged (a link target)")
            info["target"] = self._meta(self.inode_table, block, offset + 24, n).decode("utf-8", "replace")
        return info

    def _walk(self, info: dict, prefix: str, depth: int) -> None:
        if depth > MAX_DEPTH or info["number"] in self.seen:
            return
        self.seen.add(info["number"])
        size = info["size"] - 3
        if size <= 0:
            return
        listing = self._meta(self.dir_table, info["start"], info["offset"], size)
        i = 0
        while i + 12 <= len(listing):
            count, start, _base = struct.unpack_from("<III", listing, i)
            i += 12
            if count >= 256:
                raise PackportError("The squashfs image is damaged (a folder listing)")
            for _ in range(count + 1):
                if i + 8 > len(listing):
                    raise PackportError("The squashfs image is damaged (a folder listing)")
                off, _delta, _kind, nlen = struct.unpack_from("<HhHH", listing, i)
                name = listing[i + 8:i + 9 + nlen].decode("utf-8", "replace")
                i += 9 + nlen
                self.count += 1
                if self.count > MAX_ENTRIES:
                    raise PackportError("The squashfs image lists too many files")
                if not name or name in (".", "..") or "/" in name:
                    name = (name or "_").replace("/", "_")
                path = prefix + name
                child = self._inode(start << 16 | off)
                kind, mode = child["type"], child["mode"]
                if kind in (DIR, XDIR):
                    self.members.append(Item(path, 0, True, None, child["mtime"], stat.S_IFDIR | mode))
                    self._walk(child, path + "/", depth + 1)
                elif kind in (FILE, XFILE):
                    self.members.append(Item(path, child["size"], False, None, child["mtime"], stat.S_IFREG | mode,
                                             ref=child))
                elif kind in (SYMLINK, XSYMLINK):
                    self.members.append(Item(path, 0, False, child["target"], child["mtime"], stat.S_IFLNK | mode))
                else:  # devices, FIFOs, sockets
                    self.members.append(Item(path, 0, False, None, child["mtime"], stat.S_IFCHR | mode))

    # -- data

    def _fragment(self, index: int) -> bytes:
        if self.frag_cache is not None and self.frag_cache[0] == index:
            return self.frag_cache[1]
        if index >= self.fragments:
            raise PackportError("The squashfs image is damaged (a fragment number)")
        start, size, _ = struct.unpack_from("<QII", self.frag_table, 16 * index)
        stored = bool(size & 0x1000000)
        size &= 0xFFFFFF
        raw = self.source.read_at(start, size)
        data = raw if stored else self._decompress(raw, self.block_size)
        self.frag_cache = (index, data)
        return data

    def open_member(self, item: Item):
        return Stream(item.name, _file_data(self, item.ref, item.name), item.ref["size"], what="squashfs image")


def _file_data(fs: SquashfsArchive, info: dict, name: str) -> Iterator[bytes]:
    """A file's blocks, unpacked in order (several at once, by the pool: each block is packed on
    its own), then its fragment tail."""
    at, left = info["start"], info["size"]

    def jobs():
        nonlocal at
        rest = left
        for entry in info["blocks"]:
            if rest <= 0:
                break
            size, stored = entry & 0xFFFFFF, bool(entry & 0x1000000)
            want = min(fs.block_size, rest)
            rest -= want
            if size == 0:  # a hole
                yield lambda want=want: bytes(want)
                continue
            raw = fs.source.read_at(at, size)
            at += size
            if stored:
                yield lambda raw=raw, want=want: _whole(raw, want, name)
            else:
                yield lambda raw=raw, want=want: _whole(fs._decompress(raw, fs.block_size), want, name)

    for data in ordered(jobs()):
        left -= len(data)
        yield data
    if left and info["frag"] != 0xFFFFFFFF:
        frag = fs._fragment(info["frag"])
        piece = frag[info["foff"]:info["foff"] + left]
        if len(piece) < left:
            raise PackportError(f"{name}: the squashfs image is damaged (a fragment)")
        left -= len(piece)
        yield piece
    if left:
        raise PackportError(f"{name}: the squashfs image is damaged (its blocks end early)")


def _whole(data: bytes, want: int, name: str) -> bytes:
    if len(data) < want:
        raise PackportError(f"{name}: the squashfs image is damaged (a short block)")
    return data[:want]


def lz4_block(data: bytes, limit: int) -> bytes:
    """An LZ4 block (lz4's block format): sequences of a token (literal count and match length,
    4 bits each, 15 meaning more bytes follow), the literals, a 2-byte distance and the match.
    The last sequence has literals only."""
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        token = data[i]
        i += 1
        count = token >> 4
        if count == 15:
            while True:
                if i >= n:
                    raise PackportError("The LZ4 data is cut short")
                b = data[i]
                i += 1
                count += b
                if b != 255:
                    break
        if i + count > n or len(out) + count > limit:
            raise PackportError("The LZ4 data is damaged")
        out += data[i:i + count]
        i += count
        if i >= n:
            break
        if i + 2 > n:
            raise PackportError("The LZ4 data is cut short")
        dist = data[i] | data[i + 1] << 8
        i += 2
        length = (token & 15) + 4
        if token & 15 == 15:
            while True:
                if i >= n:
                    raise PackportError("The LZ4 data is cut short")
                b = data[i]
                i += 1
                length += b
                if b != 255:
                    break
        start = len(out) - dist
        if dist == 0 or start < 0 or len(out) + length > limit:
            raise PackportError("The LZ4 data is damaged")
        if dist >= length:
            out += out[start:start + length]
        else:
            for k in range(length):
                out.append(out[start + k])
    return bytes(out)


if native is not None:
    lz4_block = native.lz4_block_decompress
