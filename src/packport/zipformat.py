"""ZIP, for the archives Python's zipfile can't open: members packed with Deflate64, bzip2, LZMA,
xz, Zstandard or PPMd (var. I), ZIP64, self-extracting archives and archives with data in front,
and damaged archives whose central directory is gone or unreadable (then the local headers are
read in order, as 7-Zip does), and PKZIP 1's Shrink and Implode (pkzip1.py).

Written from PKWARE's APPNOTE.TXT. The central directory is found from the end-of-central-
directory record (and its ZIP64 versions); when data was put in front of the archive after it
was made (a self-extractor, say), every offset is out by the same amount, found from where the
directory really starts. Names are UTF-8 when the archive says so or when they are valid UTF-8,
otherwise in the DOS code page (cp437), as zipfile reads them. Encrypted members (ZipCrypto,
WinZip AES, PKWARE strong encryption) raise EncryptedError when read; an encrypted file list
can't be read at all. Every member's CRC-32 and size are checked as it's read.
"""

from __future__ import annotations

import bz2
import itertools
import lzma
import stat
import struct
import zlib
from collections.abc import Iterator

from . import entries
from .archive import Archive, Crc32, EncryptedError, Item, Stream, Window, reader
from .entries import PackportError
from .rar import from_dos_time

LOCAL, CENTRAL, END, END64, LOCATOR64, DESCRIPTOR = (b"PK\x03\x04", b"PK\x01\x02", b"PK\x05\x06", b"PK\x06\x06",
                                                     b"PK\x06\x07", b"PK\x07\x08")
END_SEARCH = 22 + 0xFFFF  # the end record and the longest archive comment
METHODS = {0: "stored", 1: "Shrink", 6: "Implode", 8: "Deflate", 9: "Deflate64", 12: "bzip2", 14: "LZMA",
           93: "Zstandard", 95: "xz", 98: "PPMd"}
NAMED = {2: "Reduce", 3: "Reduce", 4: "Reduce", 5: "Reduce", 10: "PKWARE DCL Implode",
         16: "IBM z/OS bzip2", 18: "IBM TERSE", 19: "IBM LZ77", 96: "JPEG", 97: "WavPack"}
HOST_UNIX = 3
NTFS_EPOCH = 11644473600  # seconds from 1601 to 1970


def _sniff(head: bytes, source) -> bool:
    if head.startswith((LOCAL, DESCRIPTOR + LOCAL)) or head == END + bytes(18):
        return True
    try:
        return _directory(source) is not None  # a self-extractor, or data in front of the archive
    except PackportError:
        return False


def _directory(source) -> tuple[int, int, int] | None:
    """(where the central directory starts, how many entries, the shift to add to every offset),
    or None when no end record leads to one."""
    start = max(0, source.size - END_SEARCH)
    tail = source.read_at(start, source.size - start)
    at = len(tail)
    while True:
        at = tail.rfind(END, 0, at)
        if at < 0:
            return None
        if at + 22 > len(tail):
            continue
        (disk, _cd_disk, _here, count, size, offset, _clen) = struct.unpack_from("<HHHHIIH", tail, at + 4)
        end_at = start + at
        if disk not in (0, 0xFFFF):
            raise PackportError("This ZIP archive is split across several disks; packport reads it only "
                                "when the pieces are joined into one file")
        if end_at >= 20 and source.read_at(end_at - 20, 4) == LOCATOR64:
            at64 = struct.unpack("<Q", source.read_at(end_at - 12, 8))[0]
            found = _zip64_end(source, at64, end_at)
            if found:
                return found
        elif count == 0 and size == 0:
            return end_at, 0, 0
        for shift in (0, end_at - size - offset):
            if 0 <= offset + shift < source.size and source.read_at(offset + shift, 4) == CENTRAL:
                return offset + shift, count, shift


def _zip64_end(source, at64: int, end_at: int) -> tuple[int, int, int] | None:
    for guess in (at64, end_at - 20 - 56):  # where it says, or where it is when data was added in front
        if 0 <= guess and source.read_at(guess, 4) == END64:
            count, size, offset = struct.unpack("<QQQ", source.read_at(guess + 32, 24))
            for shift in (0, guess - size - offset):
                if 0 <= offset + shift < source.size and source.read_at(offset + shift, 4) == CENTRAL:
                    return offset + shift, count, shift
    return None


def _name(raw: bytes, utf8: bool) -> str:
    if utf8:
        return raw.decode("utf-8", "replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp437")


def _extras(data: bytes) -> dict[int, bytes]:
    out, i = {}, 0
    while i + 4 <= len(data):
        tag, size = struct.unpack_from("<HH", data, i)
        out.setdefault(tag, data[i + 4:i + 4 + size])
        i += 4 + size
    return out


def _zip64(extra: bytes, usize: int, csize: int, offset: int) -> tuple[int, int, int]:
    """The real sizes and offset from the ZIP64 extra field, which holds those set to 0xFFFFFFFF."""
    values, i = [], 0
    for v in (usize, csize, offset):
        if v == 0xFFFFFFFF:
            if i + 8 > len(extra):
                raise PackportError("The ZIP archive is damaged (a ZIP64 field is missing)")
            v = struct.unpack_from("<Q", extra, i)[0]
            i += 8
        values.append(v)
    return values[0], values[1], values[2]


def _mtime(extras: dict[int, bytes], dos: int) -> float:
    ut = extras.get(0x5455)
    if ut and len(ut) >= 5 and ut[0] & 1:
        return float(struct.unpack_from("<i", ut, 1)[0])
    ntfs = extras.get(0x000A)
    if ntfs and len(ntfs) >= 32 and struct.unpack_from("<HH", ntfs, 4) == (1, 24):
        return struct.unpack_from("<Q", ntfs, 8)[0] / 1e7 - NTFS_EPOCH
    return from_dos_time(dos)


@reader("zip", _sniff)
class ZipArchive(Archive):
    def __init__(self, source):
        super().__init__(source)
        found = _directory(source)
        try:
            entries = self._central(*found) if found else None
        except PackportError as e:
            if isinstance(e, EncryptedError):
                raise
            entries = None
        if entries is None:
            entries = self._scan()
        else:
            _no_overlap(entries)
        self.members = entries
        for item in self.members:
            if item.link == "":
                item.link = self._link(item)

    # -- the central directory

    def _central(self, at: int, count: int, shift: int) -> list[Item]:
        items = []
        size = self.source.size
        for _ in range(count):
            head = self.source.read_at(at, 46)
            if len(head) < 46 or head[:4] != CENTRAL:
                raise PackportError("The ZIP archive is damaged (its central directory)")
            (made, _need, flags, method, dos_time, dos_date, crc, csize, usize, nlen, xlen, clen, _disk, _iattr,
             eattr, offset) = struct.unpack_from("<HHHHHHIIIHHHHHII", head, 4)
            rest = self.source.read_at(at + 46, nlen + xlen)
            at += 46 + nlen + xlen + clen
            if flags & 0x2000:
                raise EncryptedError("This ZIP archive's file list is encrypted; packport doesn't decrypt")
            raw, extras = rest[:nlen], _extras(rest[nlen:])
            usize, csize, offset = _zip64(extras.get(1, b""), usize, csize, offset)
            if offset + shift + 30 > size:
                raise PackportError("The ZIP archive is damaged (a member starts past its end)")
            items.append(self._item(raw, extras, made >> 8, flags, method, dos_date << 16 | dos_time, crc, csize,
                                    usize, eattr, offset + shift))
        return items

    def _item(self, raw, extras, host, flags, method, dos, crc, csize, usize, eattr, local) -> Item:
        name = _name(raw, bool(flags & 0x800))
        up = extras.get(0x7075)
        if up and len(up) > 5 and up[0] == 1 and struct.unpack_from("<I", up, 1)[0] == zlib.crc32(raw):
            name = up[5:].decode("utf-8", "replace")
        if host != HOST_UNIX:
            name = name.replace("\\", "/")
        mode = eattr >> 16 if host == HOST_UNIX else 0
        is_dir = name.endswith("/") or stat.S_ISDIR(mode) or (host != HOST_UNIX and bool(eattr & 0x10))
        if mode and not stat.S_IFMT(mode):  # permissions with no file type: a plain file or folder
            mode |= stat.S_IFDIR if is_dir else stat.S_IFREG
        aes = extras.get(0x9901)
        if method == 99 and aes and len(aes) >= 7:
            method = struct.unpack_from("<H", aes, 5)[0]
        item = Item(name.rstrip("/") if is_dir else name, usize, is_dir, None, _mtime(extras, dos), mode,
                    bool(flags & 1) or method == 99)
        if stat.S_ISLNK(mode):
            item.link = ""  # the target is the member's data, read once the list is done
        item.ref = (local, method, flags, crc, csize)
        return item

    def _link(self, item: Item) -> str:
        try:
            if item.encrypted:
                return "?"
            return self.open_member(item).read(4096).decode("utf-8", "replace") or "?"
        except PackportError:
            return "?"

    # -- no usable central directory: the local headers, in order

    def _scan(self) -> list[Item]:
        items, at, size = [], 0, self.source.size
        while at + 30 <= size:
            head = self.source.read_at(at, 30)
            if head[:4] != LOCAL:
                nxt = self._find(LOCAL, at + 1)
                if nxt < 0:
                    break
                at = nxt
                continue
            _need, flags, method, dos_time, dos_date, crc, csize, usize, nlen, xlen = struct.unpack_from(
                "<HHHHHIIIHH", head, 4)
            rest = self.source.read_at(at + 30, nlen + xlen)
            raw, extras = rest[:nlen], _extras(rest[nlen:])
            if 1 in extras:
                usize, csize, _ = _zip64(extras[1], usize, csize, 0)
            data = at + 30 + nlen + xlen
            if flags & 8 and not csize:  # sizes come after the data
                found = self._measure(data, method)
                if found is None:
                    break
                csize, crc, usize = found
            items.append(self._item(raw, extras, 0, flags, method, dos_date << 16 | dos_time, crc, csize, usize, 0,
                                    at))
            at = data + csize
        if not items:
            raise PackportError("This ZIP archive is damaged: no members could be found in it")
        return items

    def _find(self, sig: bytes, at: int) -> int:
        while at < self.source.size:
            block = self.source.read_at(at, entries.CHUNK + 3)
            k = block.find(sig)
            if k >= 0:
                return at + k
            if len(block) <= 3:
                return -1
            at += entries.CHUNK
        return -1

    def _measure(self, at: int, method: int) -> tuple[int, int, int] | None:
        """(packed size, CRC, size) of a member whose sizes follow its data: a Deflate stream is
        unpacked to find its end (a piece at a time, never held whole); otherwise the data
        descriptor that matches the distance."""
        if method == 8:
            d = zlib.decompressobj(-15)
            pos, usize = at, 0
            while not d.eof:
                block = d.unconsumed_tail
                if not block:
                    block = self.source.read_at(pos, entries.CHUNK)
                    if not block:
                        return None
                    pos += len(block)
                try:
                    usize += len(d.decompress(block, entries.CHUNK))
                except zlib.error:
                    return None
            csize = pos - len(d.unused_data) - at
            # the CRC to check against is the one stored after the data, never one worked out
            # from the data itself (which would pass whatever the damage)
            tail = self.source.read_at(at + csize, 24)
            if tail[:4] == DESCRIPTOR:
                tail = tail[4:]
            for width, fmt in ((4, "<III"), (8, "<IQQ")):
                if len(tail) >= 4 + 2 * width:
                    crc, packed, size = struct.unpack_from(fmt, tail)
                    if packed == csize and size == usize:
                        return csize, crc, usize
            return None
        # one pass over what follows, a block at a time: each false signature is checked in the
        # block it was found in, not by reading a new block from it
        pos, size = at, self.source.size
        while pos < size:
            block = self.source.read_at(pos, entries.CHUNK + 15)
            k = block.find(DESCRIPTOR)
            while 0 <= k < entries.CHUNK:
                crc, csize, usize = struct.unpack_from("<III", block[k + 4:k + 16].ljust(12, b"\0"))
                if csize == pos + k - at:
                    return csize, crc, usize
                k = block.find(DESCRIPTOR, k + 1)
            if len(block) <= entries.CHUNK:
                return None
            pos += entries.CHUNK
        return None

    # -- data

    def open_member(self, item: Item):
        if item.encrypted:
            raise EncryptedError(f"{item.name} is encrypted; packport doesn't decrypt")
        local, method, flags, crc, csize = item.ref
        head = self.source.read_at(local, 30)
        if head[:4] != LOCAL:
            raise PackportError(f"{item.name}: the ZIP archive is damaged (its local header is missing)")
        nlen, xlen = struct.unpack_from("<HH", head, 26)
        raw = Window(self.source, local + 30 + nlen + xlen, csize)
        if method not in METHODS:
            what = NAMED.get(method, f"method {method}")
            raise PackportError(f"{item.name} is compressed with {what}, which packport doesn't read")
        return Stream(item.name, _chunks(raw, method, flags, item.size, item.name), item.size, Crc32(crc),
                      "ZIP archive")


def _no_overlap(items: list[Item]) -> None:
    """Refuse members whose data overlaps another's: the trick of a "non-recursive" ZIP bomb
    (thousands of entries that all point at one highly compressed stream)."""
    spans = sorted((item.ref[0], item.ref[4]) for item in items)
    for (start, csize), (nxt, _) in itertools.pairwise(spans):
        if nxt < start + 30 + csize:
            raise PackportError("The ZIP archive's members overlap each other (it's damaged, or a ZIP bomb "
                                "made to fill the disk)")


def _chunks(raw: Window, method: int, flags: int, size: int, name: str) -> Iterator[bytes]:
    """The member's data, unpacked a piece at a time (each piece at most CHUNK bytes)."""
    if method == 0:
        while chunk := raw.read(entries.CHUNK):
            yield chunk
    elif method == 8:
        d = zlib.decompressobj(-15)
        while not d.eof:
            data = d.unconsumed_tail or raw.read(entries.CHUNK)
            if not data:
                break
            yield d.decompress(data, entries.CHUNK)
    elif method in (12, 14, 95):
        if method == 12:
            d = bz2.BZ2Decompressor()
        elif method == 95:
            d = lzma.LZMADecompressor(lzma.FORMAT_XZ)
        else:
            d = _lzma(raw, flags, size, name)
        while not d.eof:
            data = raw.read(entries.CHUNK) if d.needs_input else b""
            if not data and d.needs_input:
                break
            yield d.decompress(data, entries.CHUNK)
    elif method == 93:
        from .arformat import zstd_reader
        stream = zstd_reader(raw)
        while chunk := stream.read(entries.CHUNK):
            yield chunk
    elif method == 9:
        from .deflate64 import decompress_iter
        yield from decompress_iter(raw, size)
    elif method == 98:
        from .ppmd8 import decode_zip_iter
        yield from decode_zip_iter(raw, size, name)
    elif method == 1:
        from .pkzip1 import unshrink_iter
        yield from unshrink_iter(raw, size)
    elif method == 6:
        from .pkzip1 import explode_iter
        yield from explode_iter(raw, size, flags)


def _lzma(raw: Window, flags: int, size: int, name: str):
    """ZIP's LZMA: a version (2 bytes), the properties' length (2) and the properties (5), then
    LZMA data, read through liblzma's .lzma format with the size known unless an end mark is."""
    head = raw.read(4)
    if len(head) < 4:
        raise PackportError(f"{name}: the ZIP archive is damaged (LZMA header)")
    plen = struct.unpack_from("<H", head, 2)[0]
    props = raw.read(plen)
    if plen != 5 or len(props) != 5:
        raise PackportError(f"{name}: the ZIP archive is damaged (LZMA properties)")
    d = lzma.LZMADecompressor(lzma.FORMAT_ALONE)
    known = 0xFFFFFFFFFFFFFFFF if flags & 2 else size
    d.decompress(props + struct.pack("<Q", known), 0)
    return d
