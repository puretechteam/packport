"""Windows Imaging (WIM) files, read and written.

Written from Microsoft's WIM file format description (the Windows Imaging File Format paper)
and the files Windows, DISM and 7-Zip write. A WIM is a 208-byte header ("MSWIM"), then
resources: file data, one metadata resource per image (security descriptors, then a tree of
directory entries naming files by the SHA-1 of their data), the lookup table (each resource's
place, size, flags and SHA-1) and an XML description. Compressed resources are chunks (32 KB
unless the header says otherwise) behind a table of chunk offsets; each chunk is XPRESS
Huffman, LZX (WIM's variant) or stored when it didn't shrink. LZMS (.esd and "solid" WIMs) and
spanned sets (.swm) are refused with a clear message.

Writing gives an uncompressed WIM 1.13, the kind 7-Zip writes: each distinct file stored once.
"""

from __future__ import annotations

import hashlib
import io
import os
import struct
import tempfile
import time
from collections.abc import Iterator

from .archive import Archive, Item, Stream, Window, reader, stored
from .entries import CHUNK, Entry, Output, PackportError, Sources, collect
from .parallel import ordered

MAGIC = b"MSWIM\0\0\0"
HEADER_SIZE = 208
FLAG_SPANNED, FLAG_RP_FIX = 0x8, 0x80
FLAG_XPRESS, FLAG_LZX, FLAG_LZMS, FLAG_XPRESS2 = 0x20000, 0x40000, 0x80000, 0x200000
RES_METADATA, RES_COMPRESSED, RES_SOLID = 0x2, 0x4, 0x10
ATTR_DIRECTORY, ATTR_REPARSE = 0x10, 0x400
DENTRY_FIXED = 0x66
MAX_DEPTH = 1024
MAX_ENTRIES = 1_000_000
MAX_METADATA = 1 << 30  # bytes of an image's metadata (its folder tree) read whole
EPOCH_DIFF = 11644473600  # seconds from 1601 to 1970


def _reshdr(raw: bytes, at: int) -> tuple[int, int, int, int]:
    """(stored size, flags, offset, original size)."""
    a, offset, original = struct.unpack_from("<QQQ", raw, at)
    return a & ((1 << 56) - 1), a >> 56, offset, original


class _Wim:
    def __init__(self, source):
        self.source = source
        head = source.read_at(0, HEADER_SIZE)
        if len(head) < HEADER_SIZE or head[:8] != MAGIC:
            raise PackportError("This isn't a WIM file")
        _, self.version, self.flags, chunk = struct.unpack_from("<IIII", head, 8)
        self.chunk = chunk or 32768
        _part, parts, self.images = struct.unpack_from("<HHI", head, 40)
        if parts > 1 or self.flags & FLAG_SPANNED:
            raise PackportError("This WIM is one part of a spanned set (.swm), which packport doesn't read yet")
        if self.flags & FLAG_LZMS or self.version == 0x0E00:
            raise PackportError("This WIM uses LZMS compression (an .esd or solid WIM), which packport doesn't read")
        if self.chunk & (self.chunk - 1) or not 1 << 12 <= self.chunk <= 1 << 26:
            raise PackportError("This WIM is damaged (a strange chunk size)")
        self.lookup = _reshdr(head, 48)
        self.by_hash: dict[bytes, tuple] = {}
        self.metadata: list[tuple] = []
        size, _flags, off, _orig = self.lookup
        table = source.read_at(off, size)
        if len(table) < size:
            raise PackportError("This WIM is cut short (its lookup table)")
        for at in range(0, size - size % 50, 50):
            res = _reshdr(table, at)
            sha = table[at + 30:at + 50]
            if res[1] & RES_METADATA:
                self.metadata.append(res)
            else:
                self.by_hash[sha] = res

    def read(self, res) -> bytes:
        """A (small) resource whole: the image metadata."""
        if res[3] > MAX_METADATA:
            raise PackportError("This WIM is damaged (its image metadata is too big)")
        return b"".join(self.chunks(res))

    def chunks(self, res) -> Iterator[bytes]:
        """A resource's data, a chunk (32 KB, or the WIM's chunk size) at a time."""
        size, flags, offset, original = res
        if flags & RES_SOLID:
            raise PackportError("This WIM keeps files in solid resources (LZMS), which packport doesn't read")
        if offset < 0 or offset + size > self.source.size:
            raise PackportError("This WIM is cut short")
        if not flags & RES_COMPRESSED:
            yield from stored(Window(self.source, offset, size))
            return
        if original > 1 << 34:
            raise PackportError("This WIM is damaged (a resource over 16 GB)")
        n = -(-original // self.chunk)
        width = 8 if original > 0xFFFFFFFF else 4
        table_size = (n - 1) * width if n else 0
        if table_size > size:
            raise PackportError("This WIM is cut short (a compressed resource)")
        raw = self.source.read_at(offset, table_size)
        starts = [0] + list(struct.unpack_from(f"<{n - 1}{'Q' if width == 8 else 'I'}", raw)) if n > 1 else [0]
        body_size = size - table_size
        ends = starts[1:] + [body_size]

        def jobs():
            for k, (a, b) in enumerate(zip(starts, ends)):
                want = min(self.chunk, original - k * self.chunk)
                if not 0 <= a <= b <= body_size:
                    raise PackportError("This WIM is damaged (a chunk table that doesn't fit)")
                piece = self.source.read_at(offset + table_size + a, b - a)
                yield (lambda p=piece: p) if len(piece) == want else (lambda p=piece, w=want: self._chunk(p, w))

        yield from ordered(jobs())

    def _chunk(self, data: bytes, size: int) -> bytes:
        if self.flags & (FLAG_XPRESS | FLAG_XPRESS2):
            from .xpress import decompress
            return decompress(data, size)
        if self.flags & FLAG_LZX:
            from .lzx import LzxDecoder
            bits = max(15, (self.chunk - 1).bit_length())
            out = LzxDecoder(bits, wim=True).decompress(data, size)
            if len(out) < size:
                raise PackportError("This WIM is damaged (an LZX chunk ends early)")
            return out
        raise PackportError("This WIM is damaged (compressed data but no compression named)")


def _filetime(v: int) -> float:
    return v / 1e7 - EPOCH_DIFF if v else 0.0


def _tree(meta: bytes, prefix: str):
    """(path, attributes, hash of the unnamed stream, size of it is unknown here, mtime) for each
    entry under the root of one image's metadata."""
    if len(meta) < 8:
        raise PackportError("This WIM is damaged (an image without metadata)")
    total = struct.unpack_from("<I", meta)[0]
    root = (total + 7) & ~7 if total else 8
    if root + DENTRY_FIXED > len(meta):
        raise PackportError("This WIM is damaged (its directory tree is missing)")
    out = []
    first = struct.unpack_from("<Q", meta, root + 0x10)[0]
    todo = [(first, prefix, 0)]
    while todo:
        at, path, depth = todo.pop()
        if depth > MAX_DEPTH:
            raise PackportError("This WIM is damaged (folders nest too deep)")
        while at and at + 8 <= len(meta):
            length = struct.unpack_from("<Q", meta, at)[0]
            if length == 0:
                break
            if length < DENTRY_FIXED or at + length > len(meta):
                raise PackportError("This WIM is damaged (a directory entry runs past its tree)")
            attrs = struct.unpack_from("<I", meta, at + 8)[0]
            subdir = struct.unpack_from("<Q", meta, at + 0x10)[0]
            mtime = struct.unpack_from("<Q", meta, at + 0x38)[0]
            digest = meta[at + 0x40:at + 0x54]
            streams, _short, name_len = struct.unpack_from("<HHH", meta, at + 0x60)
            name = meta[at + DENTRY_FIXED:at + DENTRY_FIXED + name_len].decode("utf-16-le", "replace")
            nxt = at + ((length + 7) & ~7)
            for _ in range(streams):  # alternate data streams: the unnamed one may be among them
                if nxt + 0x26 > len(meta):
                    raise PackportError("This WIM is damaged (a stream entry runs past its tree)")
                slen = struct.unpack_from("<Q", meta, nxt)[0]
                sdigest = meta[nxt + 0x10:nxt + 0x24]
                snamelen = struct.unpack_from("<H", meta, nxt + 0x24)[0]
                if snamelen == 0 and digest == bytes(20):
                    digest = sdigest
                nxt += (max(slen, 0x26) + 7) & ~7
            full = f"{path}/{name}" if path else name
            if name:
                out.append((full, attrs, digest, mtime))
                if len(out) > MAX_ENTRIES:
                    raise PackportError(f"The WIM has more than {MAX_ENTRIES:,} files")
            if attrs & ATTR_DIRECTORY and subdir and not attrs & ATTR_REPARSE:
                todo.append((subdir, full, depth + 1))
            at = nxt
    return out


def _sniff(head: bytes, _source) -> bool:
    return head.startswith(MAGIC)


@reader("wim", _sniff)
class WimArchive(Archive):
    """A WIM's images: one image's files at the top, or each image in a folder of its number."""

    def __init__(self, source):
        super().__init__(source)
        self.wim = _Wim(source)
        many = len(self.wim.metadata) > 1
        seen = set()
        for k, res in enumerate(self.wim.metadata, 1):
            if repr(res) in seen:  # two images with one tree: each copy would be unpacked (up to 1 GB) again
                raise PackportError("This WIM is damaged (two images share their metadata)")
            seen.add(repr(res))
            if len(self.members) > MAX_ENTRIES:
                raise PackportError(f"The WIM has more than {MAX_ENTRIES:,} files")
            meta = self.wim.read(res)
            for path, attrs, digest, mtime in _tree(meta, str(k) if many else ""):
                is_dir = bool(attrs & ATTR_DIRECTORY)
                data = self.wim.by_hash.get(digest) if digest != bytes(20) else None
                if not is_dir and digest != bytes(20) and data is None and not attrs & ATTR_REPARSE:
                    raise PackportError(f"{path}: this WIM is damaged (its data isn't in the lookup table)")
                mode = 0o040755 if is_dir else 0o100444 if attrs & 1 else 0o100644
                link = "?" if attrs & ATTR_REPARSE else None  # symbolic links and junctions are left out
                self.members.append(Item(path, data[3] if data else 0, is_dir, link, _filetime(mtime), mode,
                                         ref=(data, digest) if data else None))

    def open_member(self, item: Item):
        if item.ref is None:
            return io.BytesIO()
        res, digest = item.ref
        return Stream(item.name, self.wim.chunks(res), res[3], _Sha1(digest), "WIM")

    def _files(self):
        uses: dict[bytes, int] = {}
        for m in self.members:
            if m.is_file and m.ref is not None:
                uses[m.ref[1]] = uses.get(m.ref[1], 0) + 1
        kept: dict = {}  # resources more than one file uses, kept after the first (spooled to disk past 16 MB)
        try:
            for m in self.members:
                if not m.is_file:
                    continue
                if m.ref is None:
                    yield m, io.BytesIO()
                    continue
                res, digest = m.ref
                if digest in kept:
                    spool = kept[digest]
                    spool.seek(0)
                    yield m, Stream(m.name, stored(spool), res[3], what="WIM")
                    continue
                stream = self.open_member(m)
                if uses[digest] > 1:
                    spool = kept[digest] = tempfile.SpooledTemporaryFile(max_size=16 << 20)
                    stream = Stream(m.name, _tee(stream, spool), res[3], what="WIM")
                yield m, stream
                stream.drain()
        finally:
            for spool in kept.values():
                spool.close()


class _Sha1:
    """A resource's SHA-1, checked once all of it has been read."""

    def __init__(self, digest: bytes):
        self.digest, self.h = digest, hashlib.sha1()

    def update(self, chunk: bytes) -> None:
        self.h.update(chunk)

    def ok(self) -> bool:
        return self.h.digest() == self.digest


def _tee(stream, spool) -> Iterator[bytes]:
    while chunk := stream.read(1 << 20):
        spool.write(chunk)
        yield chunk


# ---- writing


def _dentry(name: str, attrs: int, digest: bytes, subdir: int, mtime: int) -> bytes:
    raw_name = name.encode("utf-16-le")
    body = struct.pack("<QIiQQQQQQ20sIQHHH", 0, attrs, -1, subdir, 0, 0, mtime, mtime, mtime, digest, 0, 0, 0, 0,
                       len(raw_name))
    body += raw_name + b"\0\0"  # every name ends in a UTF-16 NUL, the root's empty one too
    body += bytes(-len(body) % 8)
    return struct.pack("<Q", len(body)) + body[8:]  # the length counts the padding, as Windows writes it


def write_wim(out, sources: Sources, name: str = "1") -> list[Entry]:
    """Write an uncompressed WIM 1.13 holding ``sources`` (as ``collect`` takes them) as one
    image. Files with the same contents are stored once. Returns the entries."""
    entries = collect(sources)
    o = Output(out)
    try:
        f = o.f
        f.write(bytes(HEADER_SIZE))
        resources: dict[bytes, list] = {}  # sha1 -> [offset, size, refcount]
        digests: dict[str, bytes] = {}
        for e in entries:
            if e.is_dir:
                continue
            h = hashlib.sha1()
            with e.open() as src:
                while True:
                    b = src.read(CHUNK)
                    if not b:
                        break
                    h.update(b)
            sha = h.digest()
            if e.size() == 0:
                digests[e.name] = bytes(20)
                continue
            digests[e.name] = sha
            if sha in resources:
                resources[sha][2] += 1
                continue
            offset = f.tell()
            with e.open() as src:
                while True:
                    b = src.read(CHUNK)
                    if not b:
                        break
                    f.write(b)
            resources[sha] = [offset, f.tell() - offset, 1]
        # the directory tree: the root, then each folder's children, each list ending in 8 zero bytes
        folders = {""} | {e.name for e in entries if e.is_dir}
        for e in entries:
            parts = e.name.split("/")
            folders |= {"/".join(parts[:k]) for k in range(1, len(parts))}
        children: dict[str, list[str]] = {f: [] for f in folders}
        for path in sorted(folders - {""}) + [e.name for e in entries if not e.is_dir]:
            children[path.rsplit("/", 1)[0] if "/" in path else ""].append(path)
        times = {e.name: int((e.mtime + EPOCH_DIFF) * 1e7) for e in entries}
        now = int((time.time() + EPOCH_DIFF) * 1e7)
        security = struct.pack("<II", 8, 0)
        meta = bytearray(security + _dentry("", ATTR_DIRECTORY, bytes(20), 0, now) + bytes(8))
        place = {"": len(security)}
        lists: dict[str, int] = {}
        order = [""]
        for folder in order:
            lists[folder] = len(meta)
            for path in sorted(children[folder], key=lambda n: n.rsplit("/", 1)[-1].lower()):
                is_dir = path in folders
                place[path] = len(meta)
                meta += _dentry(path.rsplit("/", 1)[-1], ATTR_DIRECTORY if is_dir else 0x20,
                                bytes(20) if is_dir else digests.get(path, bytes(20)), 0, times.get(path, now))
                if is_dir:
                    order.append(path)
            meta += bytes(8)
        for folder in folders:
            struct.pack_into("<Q", meta, place[folder] + 0x10, lists[folder])
        meta_offset = f.tell()
        f.write(meta)
        meta_sha = hashlib.sha1(meta).digest()
        table = bytearray()
        for sha, (offset, size, refs) in resources.items():
            table += struct.pack("<QQQHI", size, offset, size, 1, refs) + sha
        table += struct.pack("<QQQHI", len(meta) | RES_METADATA << 56, meta_offset, len(meta), 1, 1) + meta_sha
        table_offset = f.tell()
        f.write(table)
        files = sum(1 for e in entries if not e.is_dir)
        dirs = len(folders) - 1
        total = sum(e.size() for e in entries if not e.is_dir)
        stamp = f"<HIGHPART>0x{now >> 32:08X}</HIGHPART><LOWPART>0x{now & 0xFFFFFFFF:08X}</LOWPART>"
        xml_offset = f.tell()
        body = (f"<WIM><TOTALBYTES>{xml_offset}</TOTALBYTES><IMAGE INDEX=\"1\"><NAME>{name}</NAME>"
                f"<DIRCOUNT>{dirs}</DIRCOUNT><FILECOUNT>{files}</FILECOUNT><TOTALBYTES>{total}</TOTALBYTES>"
                f"<CREATIONTIME>{stamp}</CREATIONTIME><LASTMODIFICATIONTIME>{stamp}</LASTMODIFICATIONTIME>"
                "</IMAGE></WIM>")
        xml = b"\xff\xfe" + body.encode("utf-16-le")
        f.write(xml)
        head = bytearray(HEADER_SIZE)
        struct.pack_into("<8sIIII", head, 0, MAGIC, HEADER_SIZE, 0x10D00, FLAG_RP_FIX, 0)
        head[24:40] = os.urandom(16)
        struct.pack_into("<HHI", head, 40, 1, 1, 1)
        struct.pack_into("<QQQ", head, 48, len(table) | RES_METADATA << 56, table_offset, len(table))
        struct.pack_into("<QQQ", head, 72, len(xml) | RES_METADATA << 56, xml_offset, len(xml))
        struct.pack_into("<I", head, 120, 0)
        f.seek(0)
        f.write(head)
        f.seek(0, 2)
    except BaseException:
        o.close(failed=True)
        raise
    o.close()
    return entries

