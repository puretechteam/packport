"""LHA / LZH archives (.lzh, .lha), and self-extracting ones.

Every member is a header and its data, one after another; a 0 byte ends the archive. Headers
come in four levels: 0 and 1 (a DOS date, the name in the base header, level 1 adding extended
headers), 2 (a Unix time, everything in extended headers) and 3 (2 with 32-bit sizes). An
extended header is a size, a type and data: the name (1), the folder (2, its parts split by
0xFF), UTF-16 names (0x44, 0x45), DOS attributes (0x40), Windows times (0x41), 64-bit sizes
(0x42), Unix permissions (0x50) and time (0x54).

Methods: -lh0- and -lz4- store, -lhd- is a folder, and -lh4- to -lh7- are LZ77 over a 4 to 64 KB
window with static Huffman codes in blocks, as in Haruhiko Okumura's public-domain ar002: each
block gives its symbol count, a code for the code lengths, the literal-and-length code, and the
distance code. Matches reaching before the start read spaces, as LHa's window starts filled
with them. Every file's CRC-16 is checked. Names are UTF-8 when they're valid UTF-8, otherwise
Shift_JIS (most LZH archives come from Japan), otherwise the DOS code page.

Written from the LHa header documentation and libarchive's reader (BSD).
"""

from __future__ import annotations

import io
import stat
import struct
from collections.abc import Iterator

from . import entries
from ._accel import native, pump
from .archive import Archive, Item, Source, Stream, Window, reader, stored
from .bits import huffman
from .entries import PackportError
from .rar import from_dos_time

WINDOW_BITS = {b"lh4": 12, b"lh5": 13, b"lh6": 15, b"lh7": 16}
STORED = (b"lh0", b"lz4")
NT, NC = 19, 510  # code-length symbols; literals and lengths (256 + 254)
NTFS_EPOCH = 11644473600
SFX_SEARCH = 1 << 16

_CRC = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (_c >> 1) ^ 0xA001 if _c & 1 else _c >> 1
    _CRC.append(_c)
del _n, _c


def crc16(data: bytes, crc: int = 0) -> int:
    table = _CRC
    for b in data:
        crc = (crc >> 8) ^ table[(crc ^ b) & 0xFF]
    return crc


if native is not None:
    crc16 = native.crc16


class Crc16:
    """A member's CRC-16, checked once all of its data has been read."""

    def __init__(self, expected: int):
        self.expected, self.value = expected, 0

    def update(self, chunk: bytes) -> None:
        self.value = crc16(chunk, self.value)

    def ok(self) -> bool:
        return self.value == self.expected


def _header_at(h: bytes, i: int) -> bool:
    """Whether a member header starts at h[i] (its method at i + 2 and a level of 0 to 3)."""
    if i + 22 > len(h) or h[i + 2] != 0x2D or h[i + 6] != 0x2D or h[i + 3] != 0x6C:
        return False
    method = h[i + 3:i + 6]
    if method[1:2] == b"h":
        return method[2:3] in b"01234567d" and h[i + 20] <= 3
    return method in (b"lzs", b"lz4", b"lz5") and h[i + 20] == 0


def _start(h: bytes) -> int:
    if _header_at(h, 0):
        return 0
    if h[:2] == b"MZ":
        return next((i for i in range(len(h) - 22) if _header_at(h, i)), -1)
    return -1


def _sniff(head: bytes, _source) -> bool:
    return _start(head) >= 0


def _name(raw: bytes) -> str:
    for codec in ("utf-8", "cp932"):
        try:
            return raw.decode(codec)
        except UnicodeDecodeError:
            pass
    return raw.decode("cp437")


@reader("lzh", _sniff)
class LzhArchive(Archive):
    def __init__(self, source: Source):
        super().__init__(source)
        at = _start(source.read_at(0, SFX_SEARCH))
        if at < 0:
            raise PackportError("This isn't an LZH archive")
        while at < source.size:
            first = source.read_at(at, 1)
            if not first or first == b"\0":
                break
            item, at = self._member(at)
            if item is not None:
                self.members.append(item)

    def _member(self, at: int) -> tuple[Item | None, int]:
        src = self.source
        h = src.read_at(at, 28)
        if len(h) < 22 or not _header_at(h, 0):
            raise PackportError("The LZH archive is damaged (a member header)")
        method, level = h[3:6], h[20]
        packed, size = struct.unpack_from("<II", h, 7)
        info = {"name": b"", "folder": b"", "mode": 0, "attr": h[19] if level < 2 else 0, "uname": None,
                "ufolder": None}
        if level == 0:
            hsize = h[0] + 2
            raw = src.read_at(at, hsize)
            nlen = raw[21]
            info["name"] = raw[22:22 + nlen].replace(b"\\", b"/")
            crc = struct.unpack_from("<H", raw, 22 + nlen)[0] if len(raw) >= 24 + nlen else None
            mtime = from_dos_time(struct.unpack_from("<I", h, 15)[0])
            ext = raw[24 + nlen:]
            if ext[:1] == b"U" and len(ext) >= 12:  # LHa for UNIX
                mtime, info["mode"] = float(struct.unpack_from("<I", ext, 2)[0]), struct.unpack_from("<H", ext, 6)[0]
            data = at + hsize
        elif level == 1:
            hsize = h[0] + 2
            raw = src.read_at(at, hsize)
            nlen = raw[21]
            if 27 + nlen > hsize:
                raise PackportError("The LZH archive is damaged (a member header)")
            info["name"] = raw[22:22 + nlen].replace(b"\\", b"/")
            crc = struct.unpack_from("<H", raw, 22 + nlen)[0]
            mtime = from_dos_time(struct.unpack_from("<I", h, 15)[0])
            ext_size, mtime = self._extended(at + hsize - 2, 2, info, mtime)
            packed -= ext_size - 2
            data = at + hsize - 2 + ext_size
        elif level == 2:
            hsize = struct.unpack_from("<H", h, 0)[0]
            crc = struct.unpack_from("<H", h, 21)[0]
            mtime = float(struct.unpack_from("<I", h, 15)[0])
            _, mtime = self._extended(at + 24, 2, info, mtime)
            data = at + hsize
        else:
            if struct.unpack_from("<H", h, 0)[0] != 4:
                raise PackportError("The LZH archive is damaged (a level 3 header)")
            hsize = struct.unpack_from("<I", h, 24)[0]
            crc = struct.unpack_from("<H", h, 21)[0]
            mtime = float(struct.unpack_from("<I", h, 15)[0])
            _, mtime = self._extended(at + 28, 4, info, mtime)
            data = at + hsize
        packed, size = info.get("packed", packed), info.get("size", size)
        if packed < 0 or data + packed > src.size:
            raise PackportError("The LZH archive is damaged (a member reaches past its end)")
        folder = info["ufolder"] if info["ufolder"] is not None else _name(info["folder"])
        name = info["uname"] if info["uname"] is not None else _name(info["name"])
        path = (folder + name).replace("\\", "/") if level == 0 else folder + name
        mode = info["mode"]
        is_dir = method == b"lhd" or stat.S_ISDIR(mode)
        link = None
        if stat.S_ISLNK(mode) and "|" in path:
            path, link = path.split("|", 1)
        if not mode:
            mode = (stat.S_IFDIR | 0o755) if is_dir else (stat.S_IFREG | (0o444 if info["attr"] & 1 else 0o644))
        elif not stat.S_IFMT(mode):
            mode |= stat.S_IFDIR if is_dir else stat.S_IFREG
        path = path.rstrip("/")
        if not path:
            return None, data + packed
        item = Item(path, 0 if is_dir or link else size, is_dir, link, mtime, mode,
                    ref=(method, data, packed, size, crc))
        return item, data + packed

    def _extended(self, at: int, sf: int, info: dict, mtime: float) -> tuple[int, float]:
        """Read the extended headers from at (each starts with its size, sf bytes); returns their
        total size, the size field that ends them included, and the time they give."""
        src, total = self.source, 0
        fmt = "<H" if sf == 2 else "<I"
        while True:
            raw = src.read_at(at, sf)
            if len(raw) < sf:
                raise PackportError("The LZH archive is damaged (its extended headers are cut short)")
            n = struct.unpack(fmt, raw)[0]
            total += sf if n == 0 else n
            if n == 0:
                return total, mtime
            if n <= sf or total > 1 << 20:
                raise PackportError("The LZH archive is damaged (an extended header)")
            block = src.read_at(at, n)
            kind, body = block[sf], block[sf + 1:]
            if kind == 0x01:
                info["name"] = body
            elif kind == 0x02:
                info["folder"] = body.replace(b"\xff", b"/").rstrip(b"/") + b"/" if body else b""
            elif kind == 0x44 and len(body) % 2 == 0:
                info["uname"] = body.decode("utf-16-le", "replace")
            elif kind == 0x45 and len(body) % 2 == 0:
                text = body.decode("utf-16-le", "replace").replace("￿", "/")
                info["ufolder"] = text.rstrip("/") + "/" if text else ""
            elif kind == 0x40 and len(body) == 2:
                info["attr"] = body[0]
            elif kind == 0x41 and len(body) == 24:
                mtime = struct.unpack_from("<Q", body, 8)[0] / 1e7 - NTFS_EPOCH
            elif kind == 0x42 and len(body) == 16:
                info["packed"], info["size"] = struct.unpack("<QQ", body)
            elif kind == 0x50 and len(body) == 2:
                info["mode"] = struct.unpack("<H", body)[0]
            elif kind == 0x54 and len(body) == 4:
                mtime = float(struct.unpack("<I", body)[0])
            at += n

    def open_member(self, item: Item):
        method, data, packed, size, crc = item.ref
        if data + packed > self.source.size:
            raise PackportError(f"{item.name}: the LZH archive is cut short")
        raw = Window(self.source, data, packed)
        if method in STORED:
            chunks = stored(raw, size)
        elif method in WINDOW_BITS:
            chunks = decode_iter(raw, size, WINDOW_BITS[method])
        else:
            raise PackportError(f"{item.name} is compressed with -{method.decode()}-, which packport doesn't read")
        return Stream(item.name, chunks, size, Crc16(crc) if crc is not None else None)


class _Bits:
    """Bits most significant first, from bytes or a readable (read a piece at a time); past the
    end of the data, zeros (an overrun is damage)."""

    def __init__(self, data):
        if isinstance(data, (bytes, bytearray)):
            self.data, self.src = data, None
        else:
            self.data, self.src = b"", data
        self.at, self.acc, self.n, self.past = 0, 0, 0, 0

    def _more(self) -> int:
        """The next byte, refilling from the source; 0 past the end."""
        if self.src is not None:
            self.data, self.at = self.src.read(entries.CHUNK), 0
            if self.data:
                self.at = 1
                return self.data[0]
            self.src = None
        self.past += 1
        return 0

    def peek(self, k: int) -> int:
        while self.n < k:
            at = self.at
            if at < len(self.data):
                b = self.data[at]
                self.at = at + 1
            else:
                b = self._more()
            self.acc = (self.acc << 8 | b) & ((1 << 64) - 1)
            self.n += 8
        return (self.acc >> (self.n - k)) & ((1 << k) - 1)

    def drop(self, k: int) -> None:
        self.n -= k
        if self.past - self.n // 8 > 2:
            raise PackportError("The archive is damaged (a member's data runs short)")

    def get(self, k: int) -> int:
        if k == 0:
            return 0
        v = self.peek(k)
        self.drop(k)
        return v


class _Code:
    """A Huffman code to decode with: a lookup table, or one symbol that takes no bits."""

    def __init__(self, lengths=None, only: int | None = None):
        self.only = only
        if only is None:
            self.bits = max(lengths)
            self.table = huffman(lengths, self.bits)

    def read(self, bits: _Bits) -> int:
        if self.only is not None:
            return self.only
        e = self.table[bits.peek(self.bits)]
        if e < 0:
            raise PackportError("The archive is damaged (a bad Huffman code)")
        bits.drop(e & 15)
        return e >> 4


def _lengths_code(bits: _Bits, nbits: int, count: int, special: bool) -> _Code:
    n = bits.get(nbits)
    if n == 0:
        c = bits.get(nbits)
        if c >= count:
            raise PackportError("The archive is damaged (a Huffman table)")
        return _Code(only=c)
    if n > count:
        raise PackportError("The archive is damaged (a Huffman table)")
    lengths = [0] * count
    i = 0
    while i < n:
        c = bits.get(3)
        if c == 7:
            while bits.get(1):
                c += 1
                if c > 16:
                    raise PackportError("The archive is damaged (a Huffman code length)")
        lengths[i] = c
        i += 1
        if special and i == 3:
            zeros = bits.get(2)
            if i + zeros > n:
                raise PackportError("The archive is damaged (a Huffman table)")
            i += zeros
    if not any(lengths):
        raise PackportError("The archive is damaged (an empty Huffman table)")
    return _Code(lengths)


def _literal_code(bits: _Bits, pt: _Code) -> _Code:
    n = bits.get(9)
    if n == 0:
        c = bits.get(9)
        if c >= NC:
            raise PackportError("The archive is damaged (a Huffman table)")
        return _Code(only=c)
    if n > NC:
        raise PackportError("The archive is damaged (a Huffman table)")
    lengths = [0] * NC
    i = 0
    while i < n:
        c = pt.read(bits)
        if c > 2:
            lengths[i] = c - 2
            i += 1
        elif c == 0:
            i += 1
        else:
            i += bits.get(4) + 3 if c == 1 else bits.get(9) + 20
            if i > n:
                raise PackportError("The archive is damaged (a Huffman table)")
    if not any(lengths):
        raise PackportError("The archive is damaged (an empty Huffman table)")
    return _Code(lengths)


def decode(data: bytes, size: int, window_bits: int) -> bytes:
    """-lh4- to -lh7- data: size bytes."""
    return b"".join(decode_iter(data, size, window_bits))


def decode_iter(data, size: int, window_bits: int) -> Iterator[bytes]:
    """-lh4- to -lh7- data (bytes or a readable): size bytes, a piece at a time. The window
    starts out full of spaces, as ar002's does."""
    if native is not None:
        src = io.BytesIO(data) if isinstance(data, (bytes, bytearray)) else data
        yield from pump(native.LzhDecoder(window_bits, size), src, size)
        return
    bits = _Bits(data)
    pbits = 5 if window_bits >= 15 else 4
    window = 1 << window_bits
    out = bytearray(b" " * window)
    given = window  # bytes of out already handed out (or the starting spaces)
    total = 0       # bytes handed out
    piece = entries.CHUNK
    while total + len(out) - given < size:
        count = bits.get(16)
        if count == 0:
            raise PackportError("The archive is damaged (an empty LZH block)")
        pt = _lengths_code(bits, 5, NT, True)
        lt = _literal_code(bits, pt)
        dt = _lengths_code(bits, pbits, window_bits + 1, False)
        for _ in range(count):
            c = lt.read(bits)
            if c < 256:
                out.append(c)
            else:
                length = c - 253
                p = dt.read(bits)
                if p > 1:
                    p = (1 << (p - 1)) + bits.get(p - 1)
                start = len(out) - p - 1
                if start < 0:
                    raise PackportError("The archive is damaged (a match before the start of the window)")
                if start + length <= len(out):
                    out += out[start:start + length]
                else:
                    for k in range(length):
                        out.append(out[start + k])
            if len(out) - given >= piece:
                chunk = bytes(out[given:given + size - total])
                total += len(chunk)
                yield chunk
                del out[:len(out) - window]
                given = len(out)
            if total + len(out) - given >= size:
                break
    if len(out) > given and total < size:
        yield bytes(out[given:given + size - total])
