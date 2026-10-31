"""Unix ``compress`` (``.Z``): LZW with 9- to 16-bit codes, in "block mode".

The stream is a 3-byte header (``1F 9D``, then the maximum code width with 0x80 set for block
mode) followed by LZW codes packed least significant bit first. Codes start 9 bits wide and grow
by one bit whenever the next new dictionary entry wouldn't fit, up to 16 bits. Code 256 (CLEAR)
empties the dictionary when compression stops paying off.

One quirk every decoder relies on: the original ``compress`` writes codes in groups of eight (one
group of ``n`` bits is exactly ``n`` bytes), and when the code width changes or after a CLEAR, it
writes out the whole current group, unused bits and all. So readers skip to the next group
boundary at those points. This writer pads the same way, which is what lets ``gzip -d``,
``uncompress``, 7-Zip and libarchive read its output.
"""

from __future__ import annotations

import os
import tarfile
from array import array

from .entries import CHUNK, Entry, Output, PackportError, Sources, clamp_time, collect

MAGIC = b"\x1f\x9d"
BLOCK_MODE = 0x80
CLEAR = 256
FIRST = 257          # first free code in block mode
CHECK_GAP = 10000    # how often (in input bytes) a full dictionary checks whether to start over
DEFAULT_MAX_SIZE = 1 << 30  # what decompress() returns at most unless told otherwise: 1 GiB
CACHE_BYTES = 1 << 24       # decoded strings the decoder keeps whole; the rest are rebuilt
TAR_TIME_TOP = 8 ** 11 - 1  # the largest time a plain tar header holds (the year 2242)


class ZCompressor:
    """Incremental compressor, used like ``zlib.compressobj``: feed ``compress(chunk)`` and finish
    with ``flush()``. Each returns the bytes of output that are ready."""

    def __init__(self, bits: int = 16):
        if not 10 <= bits <= 16:
            raise PackportError("compress code width must be 10 to 16 bits")
        self.maxbits = bits
        self.maxmaxcode = 1 << bits
        self.n_bits = 9
        self.maxcode = (1 << 9) - 1
        self.free_ent = FIRST
        self.table: dict[int, int] = {}
        self.ent = -1
        self.acc = 0       # bits of the group being filled
        self.group = 0     # codes in that group (a full group of 8 codes is exactly n_bits bytes)
        self.in_count = 0
        self.out_count = 0
        self.checkpoint = CHECK_GAP
        self.ratio = 0
        self.clears = 0    # how many times the dictionary was restarted
        self.pending = bytearray(MAGIC + bytes([bits | BLOCK_MODE]))
        self.finished = False

    def compress(self, data: bytes) -> bytes:
        if self.finished:
            raise PackportError("compress() after flush()")
        out = self.pending
        table, ent, free_ent, maxmaxcode = self.table, self.ent, self.free_ent, self.maxmaxcode
        n_bits, maxcode, acc, group = self.n_bits, self.maxcode, self.acc, self.group
        base = self.in_count + 1  # i below counts the input bytes read so far, c included
        it = iter(data)
        if ent < 0:
            for c in it:
                ent = c
                base += 1
                break
        for i, c in enumerate(it, base):
            key = ent << 8 | c
            code = table.get(key)
            if code is not None:
                ent = code
                continue
            # output(ent)
            acc |= ent << (group * n_bits)
            group += 1
            if group == 8:
                out += acc.to_bytes(n_bits, "little")
                acc = group = 0
            if free_ent > maxcode:
                if group:
                    out += acc.to_bytes(n_bits, "little")
                    acc = group = 0
                n_bits += 1
                maxcode = maxmaxcode if n_bits == self.maxbits else (1 << n_bits) - 1
            if free_ent < maxmaxcode:
                table[key] = free_ent
                free_ent += 1
            elif i >= self.checkpoint:
                self.checkpoint = i + CHECK_GAP
                # the ratio exactly as compress computes it (coarser past 8 MB), so the output
                # matches compress and libarchive byte for byte
                done = self.out_count + len(out) + group * n_bits // 8
                if i <= 0x7FFFFF:
                    ratio = (i << 8) // done
                else:
                    ratio = i // (done >> 8) if done >> 8 else 0x7FFFFFFF
                if ratio > self.ratio:
                    self.ratio = ratio
                else:
                    # compression is getting worse: send CLEAR and start a fresh dictionary
                    self.ratio = 0
                    self.clears += 1
                    acc |= CLEAR << (group * n_bits)
                    group += 1
                    out += acc.to_bytes(n_bits, "little")
                    acc = group = 0
                    n_bits, maxcode = 9, (1 << 9) - 1
                    table.clear()
                    free_ent = FIRST
            ent = c
        self.in_count += len(data)
        self.table, self.ent, self.free_ent = table, ent, free_ent
        self.n_bits, self.maxcode, self.acc, self.group = n_bits, maxcode, acc, group
        return self._take()

    def flush(self) -> bytes:
        if not self.finished:
            self.finished = True
            if self.ent >= 0:
                self.acc |= self.ent << (self.group * self.n_bits)
                self.group += 1
            self.pending += self.acc.to_bytes((self.group * self.n_bits + 7) // 8, "little")
        return self._take()

    def _take(self) -> bytes:
        out = bytes(self.pending)
        self.out_count += len(out)
        self.pending = bytearray()
        return out


def compress(data: bytes, bits: int = 16) -> bytes:
    """``data`` as a complete ``.Z`` stream."""
    c = ZCompressor(bits)
    return c.compress(data) + c.flush()


class ZDecompressor:
    """Incremental decompressor: ``decompress(chunk)`` returns what's ready, ``flush()`` the rest.
    Damaged input raises ``PackportError``. ``max_size`` caps the total output (no cap by default,
    since the caller sees the output a piece at a time).

    The dictionary is kept as (prefix code, byte) pairs, like the original, so it never holds more
    than 65,536 entries whatever the input. Whole strings are also kept, for speed, until they add
    up to ``CACHE_BYTES``; longer ones are rebuilt from the pairs. A hostile stream whose strings
    grow by a byte per code (n*n/2 bytes from 2n) can't make the dictionary itself large."""

    def __init__(self, max_size: int | None = None):
        self.max_size = max_size
        self.buf = bytearray()
        self.header = False
        self.total = 0
        self.finished = False

    def _start(self, flags: int):
        self.maxbits = flags & 0x1F
        self.block_mode = bool(flags & BLOCK_MODE)
        if flags & 0x60 or not 9 <= self.maxbits <= 16:
            raise PackportError(f"Unsupported .Z settings (byte 3 is 0x{flags:02X})")
        self.maxmaxcode = 1 << self.maxbits
        self.first = FIRST if self.block_mode else 256
        self._reset()
        self.header = True

    def _reset(self):
        self.n_bits = 9
        self.maxcode = (1 << 9) - 1
        self.free_ent = self.first
        self.strings: list[bytes | None] = []  # each code's whole string, None once they don't fit
        self.prefix = array("H")                # for the codes after that: the code each extends
        self.suffix = bytearray()               # ... and the byte it adds
        self.kept = 0                           # output since the reset: the strings are no bigger
        self.prev: bytes | None = None
        self.prev_code = 0

    def decompress(self, data: bytes) -> bytes:
        if self.finished:
            raise PackportError("decompress() after flush()")
        self.buf += data
        if not self.header:
            if len(self.buf) < 3:
                return b""
            if self.buf[:2] != MAGIC:
                raise PackportError("Not a .Z (Unix compress) file")
            self._start(self.buf[2])
            del self.buf[:3]
        return self._run(final=False)

    def flush(self) -> bytes:
        if self.finished:
            return b""
        self.finished = True
        if not self.header:
            if self.buf:
                raise PackportError("Not a .Z (Unix compress) file")
            raise PackportError(".Z file is empty")
        return self._run(final=True)

    def _run(self, final: bool) -> bytes:
        out = []
        buf, pos = self.buf, 0
        size = 0
        while True:
            n_bits = self.n_bits
            if len(buf) - pos < n_bits and not (final and pos < len(buf)):
                break
            group = buf[pos:pos + n_bits]
            pos += len(group)
            size += self._group(group, out)
            if self.max_size is not None and self.total + size > self.max_size:
                raise PackportError(f".Z data decompresses to more than {self.max_size} bytes")
        del buf[:pos]
        self.total += size
        return b"".join(out)

    def _group(self, group: bytes, out: list) -> int:
        """Decode one group of codes; stops early (dropping the group's padding) at a width
        change or a CLEAR, like the original reader."""
        if self.kept >= CACHE_BYTES and self.prev is not None:
            return self._group_pairs(group, out)
        n_bits = self.n_bits
        acc = int.from_bytes(group, "little")
        mask = (1 << n_bits) - 1
        strings, first, prev, code = self.strings, self.first, self.prev, self.prev_code
        free_ent, maxcode, maxmaxcode = self.free_ent, self.maxcode, self.maxmaxcode
        size = 0
        for _ in range(len(group) * 8 // n_bits):
            code = acc & mask
            acc >>= n_bits
            if prev is None:
                if code > 255:
                    raise PackportError("Damaged .Z data (bad first code)")
                prev = bytes((code,))
                out.append(prev)
                size += 1
                continue
            if code == CLEAR and self.block_mode:
                self._reset()
                return size
            if code < 256:
                entry = bytes((code,))
            elif code < free_ent:
                entry = strings[code - first]
            elif code == free_ent:
                entry = prev + prev[:1]
            else:
                raise PackportError("Damaged .Z data (code out of range)")
            out.append(entry)
            size += len(entry)
            if free_ent < maxmaxcode:
                strings.append(prev + entry[:1])
                free_ent += 1
            prev = entry
            if free_ent > maxcode and n_bits < self.maxbits:
                n_bits += 1
                self.n_bits, self.maxcode = n_bits, (1 << n_bits) - 1
                break
        self.prev, self.prev_code, self.free_ent = prev, code, free_ent
        self.kept += size
        return size

    def _group_pairs(self, group: bytes, out: list) -> int:
        """_group once the whole strings fill CACHE_BYTES: new codes are kept as pairs only."""
        n_bits = self.n_bits
        acc = int.from_bytes(group, "little")
        mask = (1 << n_bits) - 1
        strings, prefix, suffix = self.strings, self.prefix, self.suffix
        first, prev, prev_code = self.first, self.prev, self.prev_code
        free_ent, maxcode, maxmaxcode = self.free_ent, self.maxcode, self.maxmaxcode
        size = 0
        for _ in range(len(group) * 8 // n_bits):
            code = acc & mask
            acc >>= n_bits
            if code == CLEAR and self.block_mode:
                self._reset()
                return size
            if code < 256:
                entry = bytes((code,))
            elif code < free_ent:
                entry = strings[code - first]
                if entry is None:
                    entry = self._rebuild(code)
            elif code == free_ent:
                entry = prev + prev[:1]
            else:
                raise PackportError("Damaged .Z data (code out of range)")
            out.append(entry)
            size += len(entry)
            if free_ent < maxmaxcode:
                strings.append(None)
                prefix.append(prev_code)
                suffix.append(entry[0])
                free_ent += 1
            prev, prev_code = entry, code
            if free_ent > maxcode and n_bits < self.maxbits:
                n_bits += 1
                self.n_bits, self.maxcode = n_bits, (1 << n_bits) - 1
                break
        self.prev, self.prev_code, self.free_ent = prev, prev_code, free_ent
        self.kept += size
        return size

    def _rebuild(self, code: int) -> bytes:
        """The string for ``code``, walking back through the pairs to one that's kept whole.
        Each step goes to a lower code, so the walk always ends."""
        first, strings, prefix, suffix = self.first, self.strings, self.prefix, self.suffix
        split = first + len(strings) - len(prefix)  # the first code that isn't kept whole
        tail = bytearray()
        while code >= split:
            tail.append(suffix[code - split])
            code = prefix[code - split]
        tail.reverse()
        return (bytes((code,)) if code < first else strings[code - first]) + tail


def decompress(data: bytes, max_size: int | None = DEFAULT_MAX_SIZE) -> bytes:
    """Decode a complete ``.Z`` stream, in memory. Output past ``max_size`` (1 GiB unless given;
    None for no cap) raises ``PackportError``. For bigger files, stream with ``ZDecompressor``."""
    d = ZDecompressor(max_size)
    return d.decompress(data) + d.flush()


class ZWriter:
    """A writable binary file whose contents land in ``out`` as ``.Z`` (e.g. for ``tarfile``)."""

    def __init__(self, out, bits: int = 16):
        self._out = Output(out)
        self._c = ZCompressor(bits)
        self._closed = False

    def write(self, data) -> int:
        self._out.f.write(self._c.compress(bytes(data)))
        return len(data)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._out.f.write(self._c.flush())
            self._out.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *_):
        if exc_type is None:
            self.close()
        else:
            self._closed = True
            self._out.close(failed=True)


def write_z(out, source: bytes | str | os.PathLike) -> None:
    """Compress one file (a path, or bytes) to ``.Z``. Data is streamed."""
    if isinstance(source, (bytes, bytearray, memoryview)):
        with ZWriter(out) as z:
            z.write(source)
        return
    if os.path.isdir(source):
        raise PackportError(".Z holds a single file; for a folder write a .tar.Z")
    with open(source, "rb") as src, ZWriter(out) as z:
        while chunk := src.read(CHUNK):
            z.write(chunk)


def write_tar_z(out, sources: Sources) -> list[Entry]:
    """A tar archive (POSIX pax format, UTF-8 names) compressed to ``.Z`` (``.tar.Z``, ``.taZ``)."""
    entries = collect(sources)
    with ZWriter(out) as z, tarfile.open(fileobj=z, mode="w|", format=tarfile.PAX_FORMAT) as tf:
        for e in entries:
            info = tarfile.TarInfo(e.name)
            info.mtime = clamp_time(e.mtime, TAR_TIME_TOP)
            info.mode = e.mode
            if e.is_dir:
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
                continue
            with e.open() as src:
                info.size = len(e.source) if isinstance(e.source, bytes) else os.fstat(src.fileno()).st_size
                tf.addfile(info, src)
    return entries
