"""ARJ archives (.arj), and self-extracting ones.

Written from ARJ's technical notes. An archive is a main header, then a header and data per
member, then an empty header. Each header is 0x60 0xEA, the size of its basic part, the basic
part (fixed fields, then the name and comment, each ending in a 0 byte), its CRC-32, and
extended headers (a size, the data and its CRC-32; size 0 ends them).

Methods: 0 stores; 1 to 3 are the static Huffman LZ77 of LHA's -lh7- (lzh.py) over a 26 KB
window; 4 ("fastest") codes a literal as a 0 bit and 8 bits, and a match as its length in
groups of 0 to 7 bits (each group announced by a 1 bit) and its distance in groups of 9 to 13
bits. Every file's CRC-32 is checked. Garbled (password-scrambled) members raise
EncryptedError when read; members that continue in another volume are refused.
"""

from __future__ import annotations

import io
import stat
import struct
import zlib
from collections.abc import Iterator

from . import entries
from ._accel import native, pump
from .archive import (
    Archive,
    Crc32,
    EncryptedError,
    Item,
    Source,
    Stream,
    Window,
    reader,
    stored,
)
from .entries import PackportError
from .lzh import _Bits, decode_iter
from .rar import from_dos_time

MAGIC = b"\x60\xea"
GARBLED, VOLUME, EXTFILE, PATHSYM = 0x01, 0x04, 0x08, 0x10
DIRECTORY = 3
HOST_UNIX = 2
SFX_SEARCH = 1 << 16


def _header_ok(h: bytes, i: int) -> bool:
    """Whether a valid header (its CRC checks out) starts at h[i]."""
    if h[i:i + 2] != MAGIC or i + 4 > len(h):
        return False
    size = struct.unpack_from("<H", h, i + 2)[0]
    if not 30 <= size <= 2600 or i + 8 + size > len(h):
        return False
    return zlib.crc32(h[i + 4:i + 4 + size]) == struct.unpack_from("<I", h, i + 4 + size)[0]


def _start(h: bytes) -> int:
    if _header_ok(h, 0):
        return 0
    if h[:2] == b"MZ":
        at = h.find(MAGIC)
        while at >= 0:
            if _header_ok(h, at):
                return at
            at = h.find(MAGIC, at + 1)
    return -1


def _sniff(head: bytes, _source) -> bool:
    return _start(head) >= 0


def _name(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp437")


@reader("arj", _sniff)
class ArjArchive(Archive):
    def __init__(self, source: Source):
        super().__init__(source)
        at = _start(source.read_at(0, SFX_SEARCH))
        if at < 0:
            raise PackportError("This isn't an ARJ archive")
        basic, at = self._header(at)  # the main header
        if basic is None:
            raise PackportError("The ARJ archive is damaged (no main header)")
        while True:
            basic, data = self._header(at)
            if basic is None:
                break
            item, at = self._member(basic, data)
            if item is not None:
                self.members.append(item)

    def _header(self, at: int) -> tuple[bytes | None, int]:
        """(basic header, where what follows its extended headers starts); None at the end."""
        src = self.source
        h = src.read_at(at, 4)
        if len(h) < 4 or h[:2] != MAGIC:
            raise PackportError("The ARJ archive is damaged (a header is missing)")
        size = struct.unpack_from("<H", h, 2)[0]
        if size == 0:
            return None, at + 4
        if size > 2600:
            raise PackportError("The ARJ archive is damaged (a header is too big)")
        basic = src.read_at(at + 4, size)
        crc = src.read_at(at + 4 + size, 4)
        if len(basic) < size or len(crc) < 4 or zlib.crc32(basic) != struct.unpack("<I", crc)[0]:
            raise PackportError("The ARJ archive is damaged (a header's checksum doesn't match)")
        at += 8 + size
        while True:
            n = src.read_at(at, 2)
            if len(n) < 2:
                raise PackportError("The ARJ archive is cut short")
            n = struct.unpack("<H", n)[0]
            at += 2
            if n == 0:
                return basic, at
            at += n + 4

    def _member(self, basic: bytes, data: int) -> tuple[Item | None, int]:
        first = basic[0]
        if first < 30 or first > len(basic):
            raise PackportError("The ARJ archive is damaged (a member header)")
        _ver, _min, host, flags, method, kind = struct.unpack_from("<BBBBBB", basic, 1)
        dos, packed, size, crc = struct.unpack_from("<IIII", basic, 8)
        mode = struct.unpack_from("<H", basic, 26)[0]
        raw = basic[first:].split(b"\0", 1)[0]
        name = _name(raw)
        if not flags & PATHSYM or host != HOST_UNIX:
            name = name.replace("\\", "/")
        end = data + packed
        if end > self.source.size:
            raise PackportError(f"{name}: the ARJ archive is cut short")
        if kind not in (0, 1, DIRECTORY):
            return None, end  # comment, volume and chapter labels
        is_dir = kind == DIRECTORY
        # the kind of member comes from ARJ's own field: Unix ARJ's mode bits above the
        # permissions don't follow st_mode (a plain file can read as a FIFO)
        if host == HOST_UNIX:
            perms = mode & 0o7777
        else:
            perms = 0o755 if is_dir else (0o444 if mode & 1 else 0o644)
        mode = (stat.S_IFDIR if is_dir else stat.S_IFREG) | perms
        link = None
        name = name.rstrip("/")
        if not name:
            return None, end
        item = Item(name, 0 if is_dir else size, is_dir, link, from_dos_time(dos), mode, bool(flags & GARBLED),
                    ref=(method, flags, data, packed, size, crc))
        return item, end

    def open_member(self, item: Item):
        method, flags, data, packed, size, crc = item.ref
        if flags & GARBLED:
            raise EncryptedError(f"{item.name} is encrypted; packport doesn't decrypt")
        if flags & (VOLUME | EXTFILE):
            raise PackportError(f"{item.name} is split across ARJ volumes, which packport doesn't join")
        if data + packed > self.source.size:
            raise PackportError(f"{item.name}: the ARJ archive is cut short")
        raw = Window(self.source, data, packed)
        if method == 0:
            chunks = stored(raw, size)
        elif method in (1, 2, 3):
            chunks = decode_iter(raw, size, 16)
        elif method == 4:
            chunks = fastest_iter(raw, size)
        else:
            raise PackportError(f"{item.name} is compressed with ARJ method {method}, which packport doesn't read")
        return Stream(item.name, chunks, size, Crc32(crc))


def _groups(bits: _Bits, width: int, top: int) -> int:
    """A number in growing bit groups: a 1 bit per step past the first group (up to top bits),
    a 0 bit to stop early, then the group's bits."""
    plus = 0
    while width < top:
        if not bits.get(1):
            break
        plus += 1 << width
        width += 1
    return plus + bits.get(width)


def fastest(data: bytes, size: int) -> bytes:
    """ARJ method 4."""
    return b"".join(fastest_iter(data, size))


def fastest_iter(data, size: int) -> Iterator[bytes]:
    """ARJ method 4 (data: bytes or a readable), a piece at a time."""
    if native is not None:
        src = io.BytesIO(data) if isinstance(data, (bytes, bytearray)) else data
        yield from pump(native.LzhDecoder(16, size, True), src, size)
        return
    bits = _Bits(data)
    window = 1 << 15  # more than the longest distance (15,871)
    out = bytearray()
    given = total = 0
    piece = entries.CHUNK
    while total + len(out) - given < size:
        c = _groups(bits, 0, 7)
        if c == 0:
            out.append(bits.get(8))
        else:
            length = c + 2
            start = len(out) - _groups(bits, 9, 13) - 1
            if start < 0:
                raise PackportError("The archive is damaged (a match before the start of the data)")
            if start + length <= len(out):
                out += out[start:start + length]
            else:
                for k in range(length):
                    out.append(out[start + k])
        if len(out) - given >= piece:
            chunk = bytes(out[given:given + size - total])
            total += len(chunk)
            yield chunk
            del out[:max(0, len(out) - window)]
            given = len(out)
    if len(out) > given and total < size:
        yield bytes(out[given:given + size - total])
