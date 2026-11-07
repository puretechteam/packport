"""Microsoft Cabinet files (.cab, "MSCF"), single and in sets spanning several cabinets.

Written from Microsoft's Cabinet specification ([MS-CAB]). A cabinet has a header (the size,
where the file list starts, how many folders and files, flags for a previous and a next
cabinet in the set and for reserved areas), a folder list (where each folder's data blocks
start, how many there are, the compression), a file list (size, offset into its folder's
unpacked data, folder number, DOS date and time, attributes, name) and the data blocks
(a checksum, packed and unpacked sizes, the data). A folder is one compressed stream: stored,
MSZIP (a deflate block per data block, each using the previous 32 KB as its dictionary) or LZX
(one stream of 32 KB frames, Intel E8 call translation when its header asks). Quantum is
refused with a clear message. A folder can continue into the next cabinet of a set, and its
last data block there can be split between the two.
"""

from __future__ import annotations

import os
import struct
import time
import zlib
from collections.abc import Iterator
from pathlib import Path

from ._accel import native
from .archive import Archive, Chunks, Item, Source, Stream, reader, stored
from .entries import CHUNK, PackportError
from .parallel import streamed

MAGIC = b"MSCF"
PREV, NEXT, RESERVE = 0x0001, 0x0002, 0x0004
NONE, MSZIP, QUANTUM, LZX = 0, 1, 2, 3
CONTINUED_FROM_PREV, CONTINUED_TO_NEXT, PREV_AND_NEXT = 0xFFFD, 0xFFFE, 0xFFFF
ATTR_READONLY, ATTR_UTF8 = 0x01, 0x80


def _cstring(src, pos: int, limit: int = 1024) -> tuple[bytes, int]:
    raw = src.read_at(pos, limit)
    end = raw.find(b"\0")
    if end < 0:
        raise PackportError("This cabinet is damaged (a name runs on)")
    return raw[:end], pos + end + 1


def checksum(data: bytes, seed: int = 0) -> int:
    """The cabinet checksum: 32-bit words XORed, the 1-3 bytes left over taken high byte first."""
    n = len(data) // 4 * 4
    words = struct.unpack(f"<{n // 4}I", data[:n])
    c = seed
    for w in words:
        c ^= w
    rest = data[n:]
    ul = 0
    if len(rest) == 3:
        ul = rest[0] << 16 | rest[1] << 8 | rest[2]
    elif len(rest) == 2:
        ul = rest[0] << 8 | rest[1]
    elif len(rest) == 1:
        ul = rest[0]
    return c ^ ul


if native is not None:
    checksum = native.cab_checksum


class _Cabinet:
    """One cabinet's header, folders and files."""

    def __init__(self, src: Source):
        head = src.read_at(0, 36)
        if len(head) < 36 or head[:4] != MAGIC:
            raise PackportError("This isn't a cabinet file")
        (_r1, self.size, _r2, files_at, _r3, _minor, _major, n_folders, n_files, flags, _set_id,
         self.index) = struct.unpack_from("<IIIIIBBHHHHH", head, 4)
        pos = 36
        res_header = res_folder = res_data = 0
        if flags & RESERVE:
            res_header, res_folder, res_data = struct.unpack("<HBB", src.read_at(pos, 4))
            pos += 4 + res_header
        self.res_data = res_data
        self.prev = self.next = None
        if flags & PREV:
            name, pos = _cstring(src, pos)
            _, pos = _cstring(src, pos)
            self.prev = name.decode("cp437")
        if flags & NEXT:
            name, pos = _cstring(src, pos)
            _, pos = _cstring(src, pos)
            self.next = name.decode("cp437")
        self.folders = []
        for _ in range(n_folders):
            raw = src.read_at(pos, 8)
            if len(raw) < 8:
                raise PackportError("This cabinet is cut short")
            start, blocks, kind = struct.unpack("<IHH", raw)
            self.folders.append((start, blocks, kind))
            pos += 8 + res_folder
        self.files = []
        pos = files_at
        for _ in range(n_files):
            raw = src.read_at(pos, 16)
            if len(raw) < 16:
                raise PackportError("This cabinet is cut short")
            size, offset, folder, date, tm, attrs = struct.unpack("<IIHHHH", raw)
            name, pos = _cstring(src, pos + 16)
            self.files.append((name, size, offset, folder, date, tm, attrs))
        self.src = src

    def blocks(self, folder: int):
        """(packed data, unpacked size) of each of a folder's data blocks, in order."""
        start, count, _ = self.folders[folder]
        pos = start
        buf, at = b"", 0  # the blocks are read a CHUNK at a time, not three reads each
        for _ in range(count):
            need = 8 + self.res_data + 0xFFFF
            if len(buf) - at < need:
                buf, at = buf[at:] + self.src.read_at(pos + len(buf) - at, max(CHUNK, need)), 0
            head = buf[at:at + 8]
            if len(head) < 8:
                raise PackportError("This cabinet is cut short")
            csum, packed, unpacked = struct.unpack("<IHH", head)
            reserve = buf[at + 8:at + 8 + self.res_data]
            data = buf[at + 8 + self.res_data:at + 8 + self.res_data + packed]
            if len(data) < packed:
                raise PackportError("This cabinet is cut short")
            at += 8 + self.res_data + packed
            if csum and checksum(head[4:8], checksum(reserve + data)) != csum:
                raise PackportError("This cabinet is damaged (a data block's checksum doesn't match)")
            yield data, unpacked
            pos += 8 + self.res_data + packed


def _dos_time(date: int, tm: int) -> float:
    try:
        return time.mktime((1980 + (date >> 9), (date >> 5) & 15, date & 31, tm >> 11, (tm >> 5) & 63,
                            (tm & 31) * 2, 0, 0, -1))
    except (OverflowError, ValueError):
        return 0.0


def _name(raw: bytes) -> str:
    """A name stored without the UTF-8 flag: UTF-8 if it reads as UTF-8, else the code page
    Windows programs (makecab, 7-Zip, Explorer) read it in, the system's ANSI one."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    import locale
    encoding = locale.getencoding() if hasattr(locale, "getencoding") else locale.getpreferredencoding(False)
    try:
        return raw.decode(encoding if os.name == "nt" else "cp437")
    except (UnicodeDecodeError, LookupError):
        return raw.decode("cp437")


def _sniff(head: bytes, _source) -> bool:
    return head.startswith(MAGIC) and len(head) >= 36


def _set_paths(path: Path | None, first: _Cabinet) -> list[Path]:
    """The cabinets that follow, named in each one's header, looked for next to it."""
    out = []
    cab = first
    seen = set()
    while cab.next and path is not None:
        nxt = path.with_name(Path(cab.next.replace("\\", "/")).name)
        if not nxt.is_file() or nxt in seen or len(out) > 10_000:
            raise PackportError(f"The cabinet set goes on in {cab.next}, which isn't here")
        seen.add(nxt)
        out.append(nxt)
        cab = _Cabinet(Source(nxt))
        cab.src.close()
    return out


@reader("cab", _sniff)
class CabArchive(Archive):
    """A cabinet, or a set of them read from its first (or any) cabinet."""

    def __init__(self, source: Source):
        cab = _Cabinet(source)
        if cab.prev and source.path is not None:
            first = self._first(source.path, cab)
            if first != source.path:
                source.close()
                source = Source(first)
                cab = _Cabinet(source)
        super().__init__(source)
        self.cabs = [cab] + [_Cabinet(Source(p)) for p in _set_paths(source.path, cab)]
        # the set's folders as streams: a cabinet's first folder carries on the previous cabinet's
        # last one when files of that one go on into this cabinet
        self.streams: list[list[tuple[_Cabinet, int]]] = []
        where: dict[tuple[int, int], int] = {}
        for k, c in enumerate(self.cabs):
            for f in range(len(c.folders)):
                if f == 0 and k > 0 and self.streams and self._continues(self.cabs[k - 1]):
                    self.streams[-1].append((c, f))
                else:
                    self.streams.append([(c, f)])
                where[(k, f)] = len(self.streams) - 1
        seen = set()
        for k, c in enumerate(self.cabs):
            last = len(c.folders) - 1
            for name, size, offset, folder, date, tm, attrs in c.files:
                if folder in (CONTINUED_FROM_PREV, PREV_AND_NEXT):
                    key = (k, 0)
                elif folder == CONTINUED_TO_NEXT:
                    key = (k, last)
                else:
                    key = (k, folder)
                if key not in where:
                    raise PackportError("This cabinet is damaged (a file in a folder that isn't there)")
                stream = where[key]
                text = name.decode("utf-8", "replace") if attrs & ATTR_UTF8 else _name(name)
                text = text.replace("\\", "/")
                if (text, stream, offset) in seen:  # a file split across cabinets is listed in each
                    continue
                seen.add((text, stream, offset))
                mode = 0o100444 if attrs & ATTR_READONLY else 0o100644
                self.members.append(Item(text, size, False, None, _dos_time(date, tm), mode, ref=(stream, offset)))

    @staticmethod
    def _continues(c: _Cabinet) -> bool:
        return any(f[3] in (CONTINUED_TO_NEXT, PREV_AND_NEXT) for f in c.files)

    @staticmethod
    def _first(path: Path, cab: _Cabinet) -> Path:
        seen = set()
        while cab.prev:
            prev = path.with_name(Path(cab.prev.replace("\\", "/")).name)
            if not prev.is_file() or prev in seen:
                return path
            seen.add(prev)
            path = prev
            src = Source(prev)
            cab = _Cabinet(src)
            src.close()
        return path

    def _stream(self, k: int) -> Iterator[bytes]:
        """A folder's unpacked data (across cabinets), a data block at a time."""
        parts = self.streams[k]
        kind = parts[0][0].folders[parts[0][1]][2]
        method = kind & 0x0F
        if method == QUANTUM:
            raise PackportError("This cabinet uses Quantum compression, which packport doesn't read")
        if method not in (NONE, MSZIP, LZX):
            raise PackportError(f"This cabinet is damaged (compression type {method})")
        dec = None
        if method == LZX:
            from .lzx import LzxDecoder
            bits = (kind >> 8) & 0x1F
            try:
                dec = LzxDecoder(bits)
            except PackportError:
                raise PackportError(f"This cabinet is damaged (an LZX window of 2^{bits})") from None
        window = b""
        carry = b""
        out, held = [], 0  # 32 KB blocks handed on a CHUNK at a time: fewer, bigger writes
        for c, f in parts:
            for data, unpacked in c.blocks(f):
                if unpacked == 0:  # split: the rest comes at the start of the next cabinet
                    carry += data
                    continue
                data, carry = carry + data, b""
                if method == NONE:
                    piece = data[:unpacked]
                elif method == MSZIP:
                    if data[:2] != b"CK":
                        raise PackportError("This cabinet is damaged (an MSZIP block without its CK)")
                    try:
                        d = zlib.decompressobj(-15, zdict=window) if window else zlib.decompressobj(-15)
                        piece = d.decompress(data[2:], unpacked)
                    except zlib.error as e:
                        raise PackportError(f"This cabinet is damaged ({e})") from None
                    window = piece[-32768:] if len(piece) >= 32768 else (window + piece)[-32768:]
                else:
                    piece = dec.decompress(data, unpacked)
                if len(piece) != unpacked:
                    raise PackportError("This cabinet is damaged or cut short (a data block unpacks to the wrong size)")
                out.append(piece)
                held += len(piece)
                if held >= CHUNK:
                    yield b"".join(out)
                    out, held = [], 0
        if out:
            yield b"".join(out)

    def _member(self, m: Item, folder: Chunks) -> Stream:
        return Stream(m.name, stored(folder, m.size), m.size, what="cabinet")

    def _files(self):
        by_stream: dict[int, list[Item]] = {}
        for m in self.members:
            by_stream.setdefault(m.ref[0], []).append(m)
        for k in sorted(by_stream):
            folder, pos = Chunks(streamed(self._stream(k))), 0  # decoded in a thread while written
            for m in sorted(by_stream[k], key=lambda m: m.ref[1]):
                offset = m.ref[1]
                if offset < pos:  # it overlaps the one before: read the folder again for it
                    yield m, self.open_member(m)
                    continue
                if folder.skip(offset - pos) < offset - pos:
                    raise PackportError(f"{m.name}: the cabinet is damaged (the file reaches past its folder)")
                stream = self._member(m, folder)
                yield m, stream
                stream.drain()
                pos = offset + m.size

    def open_member(self, item: Item):
        folder = Chunks(self._stream(item.ref[0]))
        if folder.skip(item.ref[1]) < item.ref[1]:
            raise PackportError(f"{item.name}: the cabinet is damaged (the file reaches past its folder)")
        return self._member(item, folder)

    def close(self) -> None:
        for c in self.cabs[1:]:
            c.src.close()
        super().close()

