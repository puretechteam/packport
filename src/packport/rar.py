"""RAR 4.x archives (the RAR 2.9 format), stored entries only.

Written from RARLAB's published format description (``technote.txt``), not from unrar's source,
whose licence forbids using it to make a compressor. Every entry uses method 0x30 ("store"), so
no compression algorithm is involved. Stored RAR 4 is what every RAR reader opens, including old
comic book apps that predate RAR 5, and comic pages (JPEG, PNG) don't compress further anyway.

Layout written::

    marker block      52 61 72 21 1A 07 00          "Rar!\\x1a\\x07\\x00"
    main header       type 0x73, 6 reserved bytes
    file header       type 0x74, then the file's bytes (repeated per entry)
    end of archive    type 0x7B

Every block starts with HEAD_CRC (the low 16 bits of the CRC32 of the rest of the header),
HEAD_TYPE, HEAD_FLAGS and HEAD_SIZE.
"""

from __future__ import annotations

import os
import struct
import time
import zlib
from collections import Counter

from .entries import (
    Entry,
    Member,
    Output,
    PackportError,
    Sources,
    clamp_time,
    collect,
    copy,
)

MARK = b"Rar!\x1a\x07\x00"
RAR5_MARK = b"Rar!\x1a\x07\x01\x00"

HEAD_MAIN, HEAD_FILE, HEAD_END = 0x73, 0x74, 0x7B

MHD_ENCRYPTED_HEADERS = 0x0080
FHD_SPLIT = 0x0003           # continued from / in another volume
FHD_PASSWORD = 0x0004
FHD_DIRECTORY = 0x00E0       # the "dictionary size" bits all set
FHD_LARGE = 0x0100           # HIGH_PACK_SIZE and HIGH_UNP_SIZE follow ATTR
FHD_UNICODE = 0x0200         # FILE_NAME holds a plain name, a zero byte and the encoded Unicode name
SKIP_IF_UNKNOWN = 0x4000
LONG_BLOCK = 0x8000          # a 32-bit ADD_SIZE (here PACK_SIZE) follows; data comes after the header

METHOD_STORE = 0x30
HOST_WIN32 = 2
ATTR_READONLY, ATTR_DIRECTORY, ATTR_ARCHIVE = 0x01, 0x10, 0x20

DOS_TIME_TOP = 4354819200  # 2108-01-01 UTC: anything later is stored as the last DOS time

_FILE = struct.Struct("<IIBIIBBHI")  # PACK_SIZE UNP_SIZE HOST_OS FILE_CRC FTIME UNP_VER METHOD NAME_SIZE ATTR


def _block(htype: int, flags: int, body: bytes) -> bytes:
    size = 7 + len(body)
    if size > 0xFFFF:
        raise PackportError("RAR header too large (the file name is too long)")
    rest = struct.pack("<BHH", htype, flags, size) + body
    return struct.pack("<H", zlib.crc32(rest) & 0xFFFF) + rest


def dos_time(t: float) -> int:
    """MS-DOS date and time (local time, 2-second steps, years 1980-2107). Times outside that
    range are clamped to its ends."""
    try:
        lt = time.localtime(clamp_time(t, DOS_TIME_TOP))
    except (OverflowError, OSError):  # before 1970 in local time, on some platforms
        return 1 << 21 | 1 << 16
    if lt.tm_year < 1980:
        return 1 << 21 | 1 << 16  # 1980-01-01 00:00
    if lt.tm_year > 2107:
        return 127 << 25 | 12 << 21 | 31 << 16 | 23 << 11 | 59 << 5 | 29
    return ((lt.tm_year - 1980) << 25 | lt.tm_mon << 21 | lt.tm_mday << 16
            | lt.tm_hour << 11 | lt.tm_min << 5 | lt.tm_sec // 2)


def from_dos_time(d: int) -> float:
    try:
        return time.mktime(((d >> 25) + 1980, (d >> 21) & 0xF, (d >> 16) & 0x1F,
                            (d >> 11) & 0x1F, (d >> 5) & 0x3F, (d & 0x1F) * 2, 0, 0, -1))
    except (OverflowError, ValueError, OSError):  # a damaged or impossible date
        return 0.0


def encode_name(name: str) -> tuple[bytes, bool]:
    """The FILE_NAME field and whether FHD_UNICODE is needed.

    ASCII names are stored as they are. Other names get an ASCII stand-in, a zero byte, then the
    UTF-16 name in RAR's compact encoding: one "high byte" shared by the name, then groups of a
    flag byte (2 bits per character, first character in the top bits) followed by the characters:
    0 = one byte, high byte 0; 1 = one byte, high byte = the shared one; 2 = two bytes, low first.
    """
    win = name.replace("/", "\\")
    if win.isascii():
        return win.encode("ascii"), False
    plain = "".join(c if c.isascii() else "_" for c in win).encode("ascii")
    raw = win.encode("utf-16-le")
    units = struct.unpack(f"<{len(raw) // 2}H", raw)
    highs = Counter(u >> 8 for u in units if u > 0xFF)
    high = highs.most_common(1)[0][0] if highs else 0
    enc = bytearray([high])
    for i in range(0, len(units), 4):
        flags, payload = 0, bytearray()
        for k, u in enumerate(units[i:i + 4]):
            if u <= 0xFF:
                mode = 0
                payload.append(u)
            elif u >> 8 == high:
                mode = 1
                payload.append(u & 0xFF)
            else:
                mode = 2
                payload += struct.pack("<H", u)
            flags |= mode << (6 - 2 * k)
        enc.append(flags)
        enc += payload
    return plain + b"\0" + bytes(enc), True


def decode_name(field: bytes, unicode: bool) -> str:
    """Inverse of encode_name, also understanding mode 3 (runs copied from the plain name, with or
    without a correction added), which other RAR writers use."""
    if unicode and b"\0" in field:
        plain, enc = field.split(b"\0", 1)
        return _decode_unicode(plain, enc)
    try:
        return field.decode("utf-8")
    except UnicodeDecodeError:
        return field.decode("cp437")  # the DOS code page older archivers used


def _decode_unicode(plain: bytes, enc: bytes) -> str:
    if not enc:
        return plain.decode("cp437")
    try:
        high = enc[0]
        pos, units, flags, bits = 1, [], 0, 0
        while pos < len(enc):
            if bits == 0:
                flags, bits = enc[pos], 8
                pos += 1
                if pos >= len(enc):
                    break
            bits -= 2
            mode = (flags >> bits) & 3
            if mode == 0:
                units.append(enc[pos])
                pos += 1
            elif mode == 1:
                units.append(high << 8 | enc[pos])
                pos += 1
            elif mode == 2:
                units.append(enc[pos] | enc[pos + 1] << 8)
                pos += 2
            else:
                length = enc[pos]
                pos += 1
                if length & 0x80:
                    correction = enc[pos]
                    pos += 1
                    for _ in range((length & 0x7F) + 2):
                        units.append(high << 8 | (plain[len(units)] + correction) & 0xFF)
                else:
                    for _ in range(length + 2):
                        units.append(plain[len(units)])
    except IndexError:
        raise PackportError("Damaged RAR file name") from None
    return struct.pack(f"<{len(units)}H", *units).decode("utf-16-le", "replace")


class RarWriter:
    """Write a stored RAR 4 archive entry by entry::

        with RarWriter("pages.cbr") as rar:
            rar.add("001.jpg", jpeg_bytes)
            rar.add("extras/cover.png", Path("cover.png"))
            rar.add("empty folder", is_dir=True)

    ``out`` is a path or a writable binary file. File data is streamed, so entries can be larger
    than memory. On a seekable output each file is read once; otherwise twice (the CRC of the data
    is needed before the data).
    """

    def __init__(self, out):
        self._out = Output(out)
        self._f = self._out.f
        self._names: set[str] = set()
        self._closed = False
        self._f.write(MARK + _block(HEAD_MAIN, 0, bytes(6)))

    def add(self, name: str, source=None, *, is_dir: bool = False, mtime: float | None = None,
            mode: int | None = None) -> None:
        """Add a file (``source`` = bytes or a path) or, with no source, a directory."""
        self.add_entry(Entry(name, source, is_dir, mtime, mode))

    def add_entry(self, e: Entry) -> None:
        if e.name in self._names:
            raise PackportError(f"{e.name} is in the archive twice")
        name, unicode = encode_name(e.name)
        if 7 + _FILE.size + 8 + len(name) > 0xFFFF:  # HEAD_SIZE is 16 bits
            raise PackportError(f"{e.name[:40]}...: the name is too long for a RAR header")
        self._names.add(e.name)
        attr = ATTR_DIRECTORY if e.is_dir else ATTR_ARCHIVE
        if not e.mode & 0o200:
            attr |= ATTR_READONLY
        ftime = dos_time(e.mtime)
        if e.is_dir:
            self._f.write(self._header(name, unicode, attr, ftime, 0, 0, True))
            return
        f = self._f
        with e.open() as src:
            size = len(e.source) if isinstance(e.source, bytes) else os.fstat(src.fileno()).st_size
            if isinstance(e.source, bytes):
                f.write(self._header(name, unicode, attr, ftime, size, zlib.crc32(e.source), False))
                f.write(e.source)
            elif f.seekable():
                start = f.tell()
                f.write(self._header(name, unicode, attr, ftime, size, 0, False))
                crc = copy(src, f, size, e.name)
                end = f.tell()
                f.seek(start)
                f.write(self._header(name, unicode, attr, ftime, size, crc, False))
                f.seek(end)
            else:
                crc = copy(src, _Discard(), size, e.name)
                src.seek(0)
                f.write(self._header(name, unicode, attr, ftime, size, crc, False))
                if copy(src, f, size, e.name) != crc:
                    raise PackportError(f"{e.name} changed while it was being archived")

    @staticmethod
    def _header(name: bytes, unicode: bool, attr: int, ftime: int, size: int, crc: int, is_dir: bool) -> bytes:
        flags = LONG_BLOCK
        if is_dir:
            flags |= FHD_DIRECTORY
        if unicode:
            flags |= FHD_UNICODE
        large = size > 0xFFFFFFFF
        # 2.0 can extract plain stored files; large sizes and Unicode names arrived in RAR 2.9/3.0
        version = 29 if large or unicode else 20
        body = _FILE.pack(size & 0xFFFFFFFF, size & 0xFFFFFFFF, HOST_WIN32, crc, ftime, version,
                          METHOD_STORE, len(name), attr)
        if large:
            flags |= FHD_LARGE
            body += struct.pack("<II", size >> 32, size >> 32)
        return _block(HEAD_FILE, flags, body + name)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._f.write(_block(HEAD_END, SKIP_IF_UNKNOWN, b""))
            self._out.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *_):
        if exc_type is None:
            self.close()
        else:
            self._closed = True
            self._out.close(failed=True)


class _Discard:
    def write(self, b):
        pass


def write_rar(out, sources: Sources) -> list[Entry]:
    """Write a stored RAR 4 archive (``.rar`` or ``.cbr``). ``sources`` is a path, a list of
    paths, ``Entry`` objects, ``(name, bytes | path)`` pairs, or a ``{name: bytes | path | None}``
    mapping; see ``packport.collect``. Returns the entries written."""
    entries = collect(sources)
    with RarWriter(out) as rar:
        for e in entries:
            rar.add_entry(e)
    return entries


def read_rar(data: bytes | str | os.PathLike) -> list[Member]:
    """Read a RAR 4 archive whose entries are stored (as written by packport, or by WinRAR with
    "Store"). Compressed, encrypted and multi-volume archives raise ``PackportError``, and so
    does one that ends without its end-of-archive block (it was cut short).

    Names come back exactly as stored, so they can be absolute or contain ``..``: never join them
    onto a folder without checking them."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        with open(data, "rb") as f:
            data = f.read()
    data = bytes(data)
    if data.startswith(RAR5_MARK):
        raise PackportError("This is a RAR 5 archive; packport reads RAR 4")
    if not data.startswith(MARK):
        raise PackportError("Not a RAR archive")
    out: list[Member] = []
    pos = len(MARK)
    while pos < len(data):
        if pos + 7 > len(data):
            raise PackportError("RAR archive is cut short")
        crc, htype, flags, hsize = struct.unpack_from("<HBHH", data, pos)
        if hsize < 7 or pos + hsize > len(data):
            raise PackportError("Damaged RAR block header")
        if htype in (HEAD_MAIN, HEAD_FILE, HEAD_END) and zlib.crc32(data[pos + 2:pos + hsize]) & 0xFFFF != crc:
            raise PackportError("RAR header checksum doesn't match (the archive is damaged)")
        add = 0
        if flags & LONG_BLOCK:
            if hsize < 11:
                raise PackportError("Damaged RAR block header")
            add = struct.unpack_from("<I", data, pos + 7)[0]
        if htype == HEAD_END:
            return out
        if htype == HEAD_MAIN and flags & MHD_ENCRYPTED_HEADERS:
            raise PackportError("This RAR archive is encrypted")
        if htype == HEAD_FILE:
            add = _read_file(data, pos, flags, hsize, out)
        pos += hsize + add
    raise PackportError("RAR archive is cut short (no end-of-archive block)")


def _read_file(data: bytes, pos: int, flags: int, hsize: int, out: list[Member]) -> int:
    body = data[pos + 7:pos + hsize]
    if len(body) < _FILE.size:
        raise PackportError("Damaged RAR file header")
    pack, unp, host, fcrc, ftime, _ver, method, nsize, attr = _FILE.unpack_from(body)
    off = _FILE.size
    if flags & FHD_LARGE:
        if len(body) < off + 8:
            raise PackportError("Damaged RAR file header")
        hi_pack, hi_unp = struct.unpack_from("<II", body, off)
        pack, unp = pack | hi_pack << 32, unp | hi_unp << 32
        off += 8
    if off + nsize > len(body):
        raise PackportError("Damaged RAR file header")
    name = decode_name(body[off:off + nsize], bool(flags & FHD_UNICODE))
    if host in (0, 1, 2):  # DOS, OS/2, Windows use backslashes
        name = name.replace("\\", "/")
    if flags & FHD_PASSWORD:
        raise PackportError(f"{name} is encrypted")
    if flags & FHD_SPLIT:
        raise PackportError(f"{name} is split across volumes")
    is_dir = flags & FHD_DIRECTORY == FHD_DIRECTORY
    start = pos + hsize
    if start + pack > len(data):
        raise PackportError(f"{name}: the archive is cut short")
    if is_dir:
        out.append(Member(name, b"", True, from_dos_time(ftime), 0o40755))
        return pack
    if method != METHOD_STORE:
        raise PackportError(f"{name} is compressed; packport only reads stored RAR entries")
    if unp != pack:
        raise PackportError(f"Damaged RAR file header for {name}")
    payload = data[start:start + pack]
    if zlib.crc32(payload) != fcrc:
        raise PackportError(f"{name}: data checksum doesn't match (the archive is damaged)")
    if host in (0, 1, 2):
        mode = 0o100444 if attr & ATTR_READONLY else 0o100644
    else:
        mode = attr
    out.append(Member(name, payload, False, from_dos_time(ftime), mode))
    return pack
