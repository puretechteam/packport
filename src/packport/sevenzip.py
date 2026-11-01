"""7z archives, written from Igor Pavlov's public-domain 7zFormat.txt and LZMA SDK.

A 32-byte signature header ("7z\\xBC\\xAF\\x27\\x1C", version, and where the header is) points at
the header at the end, which may itself be packed (an "encoded header"). The header has the
packed streams (where they are, how big), the folders (each a small graph of coders: their
method ids, properties, how their inputs and outputs are bound, the sizes they unpack to), the
sub-streams (how a folder's output divides into files, with CRCs) and the files (names,
empty files and folders, times, attributes). Numbers are a variable-length encoding whose
first byte's leading 1 bits count the bytes that follow.

Coders: Copy, LZMA, LZMA2, BCJ (x86, ARM, ARM Thumb, ARM64, PowerPC, SPARC, IA-64), Delta,
BCJ2, BZip2, Deflate, Deflate64 and PPMd. Chains of LZMA with branch filters run in Python's
lzma module; the rest in Python. AES-encrypted folders (and headers) raise EncryptedError.
"""

from __future__ import annotations

import bz2
import io
import lzma
import struct
import zlib
from collections.abc import Iterator

from . import entries, filters
from ._accel import native, pump
from .archive import (
    Archive,
    Chunks,
    Crc32,
    EncryptedError,
    Item,
    Stream,
    Window,
    reader,
    stored,
)
from .entries import PackportError
from .parallel import ordered, streamed

SIGNATURE = b"7z\xbc\xaf\x27\x1c"
MAX_ITEMS = 1_000_000
AHEAD = 16 << 20  # folders this small are decoded ahead in threads
THREADED = 4 << 20  # folders bigger than this are decoded in a thread while their files are written
MAX_HEADER = 256 << 20  # bytes an encoded header may unpack to (it's decoded in memory)
ID = {b"\x00": "copy", b"\x03": "delta", b"\x04": "x86", b"\x05": "powerpc", b"\x06": "ia64", b"\x07": "arm",
      b"\x08": "armthumb", b"\x09": "sparc", b"\x0a": "arm64", b"\x0b": "riscv", b"\x21": "lzma2",
      b"\x03\x01\x01": "lzma", b"\x03\x03\x01\x03": "x86", b"\x03\x03\x01\x1b": "bcj2", b"\x03\x03\x02\x05": "powerpc",
      b"\x03\x03\x04\x01": "ia64", b"\x03\x03\x05\x01": "arm", b"\x03\x03\x07\x01": "armthumb",
      b"\x03\x03\x08\x05": "sparc", b"\x03\x04\x01": "ppmd", b"\x04\x01\x08": "deflate", b"\x04\x01\x09": "deflate64",
      b"\x04\x02\x02": "bzip2", b"\x04\xf7\x11\x01": "zstd", b"\x06\xf1\x07\x01": "aes"}
LZMA_FILTERS = {"x86": lzma.FILTER_X86, "powerpc": lzma.FILTER_POWERPC, "ia64": lzma.FILTER_IA64,
                "arm": lzma.FILTER_ARM, "armthumb": lzma.FILTER_ARMTHUMB, "sparc": lzma.FILTER_SPARC}


class _In:
    def __init__(self, data: bytes, pos: int = 0):
        self.d, self.pos = data, pos

    def byte(self) -> int:
        if self.pos >= len(self.d):
            raise PackportError("The 7z archive is damaged (its header is cut short)")
        b = self.d[self.pos]
        self.pos += 1
        return b

    def bytes(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.d):
            raise PackportError("The 7z archive is damaged (its header is cut short)")
        b = self.d[self.pos:self.pos + n]
        self.pos += n
        return b

    def number(self) -> int:
        first = self.byte()
        mask, value = 0x80, 0
        for k in range(8):
            if not first & mask:
                return value | ((first & (mask - 1)) << (8 * k))
            value |= self.byte() << (8 * k)
            mask >>= 1
        return value

    def count(self) -> int:
        n = self.number()
        if n > MAX_ITEMS:
            raise PackportError("The 7z archive is damaged (a count too big)")
        return n

    def bits(self, n: int) -> list[bool]:
        out, b, mask = [], 0, 0
        for _ in range(n):
            if not mask:
                b, mask = self.byte(), 0x80
            out.append(bool(b & mask))
            mask >>= 1
        return out

    def defined(self, n: int) -> list[bool]:
        """A vector of n flags: all set (a 1 byte), or the bits that follow."""
        return [True] * n if self.byte() else self.bits(n)


class _Folder:
    def __init__(self):
        self.coders: list[tuple[str, int, int, bytes]] = []  # (method, in streams, out streams, properties)
        self.binds: list[tuple[int, int]] = []               # (in index, out index)
        self.packed: list[int] = []                          # in indices fed by packed streams
        self.sizes: list[int] = []                           # each out stream's unpacked size
        self.crc: int | None = None

    def main_out(self) -> int:
        bound = {o for _, o in self.binds}
        total = sum(c[2] for c in self.coders)
        for o in range(total):
            if o not in bound:
                return o
        raise PackportError("The 7z archive is damaged (a folder without an output)")

    @property
    def size(self) -> int:
        return self.sizes[self.main_out()]


def _read_folder(h: _In) -> _Folder:
    f = _Folder()
    total_in = total_out = 0
    for _ in range(h.count()):
        flags = h.byte()
        method = h.bytes(flags & 0x0F)
        n_in = n_out = 1
        if flags & 0x10:
            n_in, n_out = h.count(), h.count()
        props = h.bytes(h.count()) if flags & 0x20 else b""
        if flags & 0x80:
            raise PackportError("The 7z archive uses alternative coder methods packport doesn't read")
        name = ID.get(method)
        if name is None:
            raise PackportError(f"The 7z archive uses a compression method packport doesn't read ({method.hex()})")
        f.coders.append((name, n_in, n_out, props))
        total_in += n_in
        total_out += n_out
    for _ in range(total_out - 1):
        f.binds.append((h.number(), h.number()))
    n_packed = total_in - len(f.binds)
    if n_packed == 1:
        bound_in = {i for i, _ in f.binds}
        f.packed = [next(i for i in range(total_in) if i not in bound_in)]
    else:
        f.packed = [h.number() for _ in range(n_packed)]
    return f


def _streams(h: _In, pack_base: int):
    """(pack positions and sizes, folders, sub-stream sizes and CRCs) from a StreamsInfo."""
    packs, folders, sub_sizes, sub_crcs = [], [], None, None
    while True:
        prop = h.byte()
        if prop == 0x00:
            break
        if prop == 0x06:  # PackInfo
            pos = pack_base + h.number()
            n = h.count()
            sizes = []
            while True:
                p = h.byte()
                if p == 0x00:
                    break
                if p == 0x09:
                    sizes = [h.number() for _ in range(n)]
                elif p == 0x0A:
                    defined = h.defined(n)
                    for d in defined:
                        if d:
                            h.bytes(4)
                else:
                    raise PackportError("The 7z archive is damaged (pack info)")
            for s in sizes:
                packs.append((pos, s))
                pos += s
        elif prop == 0x07:  # UnPackInfo
            if h.byte() != 0x0B:
                raise PackportError("The 7z archive is damaged (folder info)")
            n = h.count()
            if h.byte():
                raise PackportError("The 7z archive keeps its folders elsewhere, which packport doesn't read")
            folders = [_read_folder(h) for _ in range(n)]
            if h.byte() != 0x0C:
                raise PackportError("The 7z archive is damaged (folder sizes)")
            for f in folders:
                f.sizes = [h.number() for _ in range(sum(c[2] for c in f.coders))]
            while True:
                p = h.byte()
                if p == 0x00:
                    break
                if p == 0x0A:
                    defined = h.defined(n)
                    for f, d in zip(folders, defined):
                        if d:
                            f.crc = struct.unpack("<I", h.bytes(4))[0]
                else:
                    raise PackportError("The 7z archive is damaged (folder info)")
        elif prop == 0x08:  # SubStreamsInfo
            counts = [1] * len(folders)
            p = h.byte()
            if p == 0x0D:
                counts = [h.count() for _ in folders]
                p = h.byte()
            sub_sizes = []
            if p == 0x09:
                for f, c in zip(folders, counts):
                    if c == 0:
                        continue
                    part = [h.number() for _ in range(c - 1)]
                    sub_sizes.append(part + [f.size - sum(part)])
                p = h.byte()
            else:
                sub_sizes = [[f.size] if c == 1 else [0] * c for f, c in zip(folders, counts) if c]
            unknown = sum(c for f, c in zip(folders, counts) if not (c == 1 and f.crc is not None))
            sub_crcs = []
            if p == 0x0A:
                defined = h.defined(unknown)
                values = [struct.unpack("<I", h.bytes(4))[0] if d else None for d in defined]
                p = h.byte()
            else:
                values = [None] * unknown
            it = iter(values)
            for f, c in zip(folders, counts):
                if c == 1 and f.crc is not None:
                    sub_crcs.append([f.crc])
                elif c:
                    sub_crcs.append([next(it, None) for _ in range(c)])
            if p != 0x00:
                raise PackportError("The 7z archive is damaged (sub-stream info)")
            for f, c in zip(folders, counts):
                f.substreams = c
        else:
            raise PackportError("The 7z archive is damaged (streams info)")
    for f in folders:
        if not hasattr(f, "substreams"):
            f.substreams = 1
    if sub_sizes is None:
        sub_sizes = [[f.size] for f in folders]
        sub_crcs = [[f.crc] for f in folders]
    return packs, folders, sub_sizes, sub_crcs


def _decode(f: _Folder, packed: list) -> Iterator[bytes]:
    """A folder's output, a piece at a time, decoding its coder graph; packed holds a readable
    for each of its packed streams. The folder's size and CRC are checked at the end. A big
    folder is decoded in a thread of its own while what it gave is written; the streams that
    feed a coder of several inputs (BCJ2) are decoded side by side."""
    if f.size > THREADED:
        return streamed(_decode_here(f, packed))
    return _decode_here(f, packed)


def _decode_here(f: _Folder, packed: list) -> Iterator[bytes]:
    ins, outs = [], []  # global in/out index -> (coder, local)
    for k, c in enumerate(f.coders):
        ins += [(k, j) for j in range(c[1])]
        outs += [(k, j) for j in range(c[2])]
    if any(c[0] == "aes" for c in f.coders):
        raise EncryptedError("This 7z archive is encrypted; packport doesn't decrypt")
    taken: set[int] = set()

    def out_stream(o: int, depth: int = 0) -> Iterator[bytes]:
        if o in taken or depth > 64:
            raise PackportError("The 7z archive is damaged (its coders loop)")
        taken.add(o)
        k = outs[o][0]
        name, n_in, _n_out, props = f.coders[k]
        first_in = sum(c[1] for c in f.coders[:k])
        inputs = []
        for j in range(n_in):
            i = first_in + j
            if i in f.packed:
                inputs.append(Chunks(stored(packed[f.packed.index(i)])))
            else:
                bound = [ob for ib, ob in f.binds if ib == i]
                if not bound:
                    raise PackportError("The 7z archive is damaged (a coder input bound to nothing)")
                feed = out_stream(bound[0], depth + 1)
                inputs.append(Chunks(streamed(feed) if n_in > 1 and f.size > THREADED else feed))
        return _coder(name, props, inputs, f.sizes[o])

    got, crc = 0, 0
    for chunk in out_stream(f.main_out()):
        chunk = chunk[:f.size - got]
        if not chunk:
            break
        got += len(chunk)
        if f.crc is not None:
            crc = zlib.crc32(chunk, crc)
        yield chunk
    if got < f.size:
        raise PackportError("The 7z archive is damaged or cut short (a folder unpacks short)")
    if f.crc is not None and crc != f.crc:
        raise PackportError("The 7z archive is damaged (a folder's CRC doesn't match)")


def _lzma_filter(name: str, props: bytes) -> dict:
    if name == "lzma":
        if len(props) < 5:
            raise PackportError("The 7z archive is damaged (LZMA properties)")
        b, dict_size = props[0], struct.unpack_from("<I", props, 1)[0]
        lc, rest = b % 9, b // 9
        return {"id": lzma.FILTER_LZMA1, "lc": lc, "lp": rest % 5, "pb": rest // 5, "dict_size": max(dict_size, 4096)}
    if name == "lzma2":
        b = props[0] if props else 0
        dict_size = 0xFFFFFFFF if b == 40 else (2 | (b & 1)) << (b // 2 + 11)
        return {"id": lzma.FILTER_LZMA2, "dict_size": min(dict_size, 1 << 30)}
    if name == "delta":
        return {"id": lzma.FILTER_DELTA, "dist": (props[0] if props else 0) + 1}
    flt = {"id": LZMA_FILTERS[name]}
    if len(props) >= 4:
        flt["start_offset"] = struct.unpack_from("<I", props)[0]
    return flt


def _decompressor(d, inp: Chunks, size: int) -> Iterator[bytes]:
    """An lzma/bz2-style decompressor (needs_input, eof) run over inp, size bytes out at most."""
    left = size
    while left > 0 and not d.eof:
        data = inp.read(entries.CHUNK) if d.needs_input else b""
        if d.needs_input and not data:
            break
        out = d.decompress(data, max_length=min(left, entries.CHUNK))
        if out:
            left -= len(out)
            yield out


def _in_c(name: str, props: bytes, inp: Chunks, size: int) -> Iterator[bytes]:
    """A branch filter or Delta undone by liblzma, as data comes: its input is handed over as
    LZMA2's uncompressed chunks (up to 64 KB each), so the filter's state carries across them and
    it lets its last bytes go at the end mark."""
    d = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[_lzma_filter(name, props),
                                                         {"id": lzma.FILTER_LZMA2, "dict_size": 1 << 20}])
    left, first = size, True
    while left > 0:
        data = inp.exactly(1 << 16)
        if not data:
            break
        packet = bytes([1 if first else 2]) + (len(data) - 1).to_bytes(2, "big") + data
        first = False
        out = d.decompress(packet)
        if out:
            out = out[:left]
            left -= len(out)
            yield out
    if left > 0 and not d.eof:
        out = d.decompress(b"\x00")
        if out:
            yield out[:left]


def _aligned(fn, unit: int, start: int, inp: Chunks, size: int) -> Iterator[bytes]:
    """A branch filter whose instructions are unit bytes and fixed in place (ARM64), run a
    piece at a time: each piece ends on an instruction, so the result is the whole buffer's."""
    carry, at, left = b"", 0, size
    while left > 0:
        data = inp.read(entries.CHUNK)
        if not data:
            break
        buf = carry + data
        whole = len(buf) - len(buf) % unit
        out = fn(buf[:whole], start + at)
        carry = buf[whole:]
        at += whole
        out = out[:left]
        left -= len(out)
        yield out
    if carry and left > 0:
        yield fn(carry, start + at)[:left]


def _coder(name: str, props: bytes, inputs: list, size: int) -> Iterator[bytes]:
    inp = inputs[0] if inputs else Chunks(iter(()))
    if name == "copy":
        yield from stored(inp, size)
    elif name in ("lzma", "lzma2"):
        yield from _decompressor(lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[_lzma_filter(name, props)]),
                                 inp, size)
    elif name == "bzip2":
        left = size
        while left > 0:
            d = bz2.BZ2Decompressor()  # one per concatenated stream
            for out in _decompressor(d, inp, left):
                left -= len(out)
                yield out
            if not d.eof or left <= 0:
                break
            rest = d.unused_data or inp.read(entries.CHUNK)
            if not rest:
                break
            inp = Chunks(_chain(rest, inp))
    elif name == "deflate":
        d = zlib.decompressobj(-15)
        left = size
        while left > 0 and not d.eof:
            data = d.unconsumed_tail or inp.read(entries.CHUNK)
            if not data:
                break
            out = d.decompress(data, min(left, entries.CHUNK))
            if out:
                left -= len(out)
                yield out
    elif name == "zstd":
        from .arformat import zstd_reader
        yield from stored(zstd_reader(inp), size)
    elif name == "deflate64":
        from .deflate64 import decompress_iter
        yield from decompress_iter(inp, size)
    elif name == "ppmd":
        yield from _ppmd(props, inp, size)
    elif name in LZMA_FILTERS or name == "delta":
        yield from _in_c(name, props, inp, size)
    elif name == "arm64":
        start = struct.unpack_from("<I", props)[0] if len(props) >= 4 else 0
        yield from _aligned(filters.arm64, 4, start, inp, size)
    elif name == "riscv":
        start = struct.unpack_from("<I", props)[0] if len(props) >= 4 else 0
        yield from filters.riscv_iter(_chunks_of(inp), start, size)
    elif name == "bcj2":
        yield from _bcj2(inputs, size)
    else:
        raise PackportError(f"The 7z archive uses {name}, which packport doesn't read")


def _chain(first: bytes, inp: Chunks) -> Iterator[bytes]:
    if first:
        yield first
    while data := inp.read(entries.CHUNK):
        yield data


def _chunks_of(inp: Chunks) -> Iterator[bytes]:
    while data := inp.read(entries.CHUNK):
        yield data


def _ppmd(props: bytes, inp: Chunks, size: int) -> Iterator[bytes]:
    if len(props) < 5:
        raise PackportError("The 7z archive is damaged (PPMd properties)")
    from .ppmd import Ppmd7, Range7z
    order, mem = props[0], struct.unpack_from("<I", props, 1)[0]
    if not 2 <= order <= 64:
        raise PackportError("The 7z archive is damaged (a PPMd order)")
    if native is not None:
        yield from pump(native.Ppmd7Decoder(order, mem), inp, size)
        return
    model = Ppmd7(mem)
    model.init(order)
    rc = Range7z(b"", 0, lambda: inp.read(entries.CHUNK))
    decode = model.decode_symbol
    piece = entries.CHUNK
    left = size
    while left > 0:
        out = bytearray()
        want = min(piece, left)
        while len(out) < want:
            c = decode(rc)
            if c < 0:
                if c == -1:
                    break
                raise PackportError("The 7z archive is damaged (bad PPMd data)")
            out.append(c)
        if not out:
            break
        left -= len(out)
        yield bytes(out)
        if len(out) < want:
            break


def _bcj2(inputs: list, size: int) -> Iterator[bytes]:
    """BCJ2: x86 code with its call and jump targets split out into two streams of absolute
    addresses, and a range-coded stream of which E8/E9/Jcc bytes were converted (LZMA SDK's Bcj2).
    Read and written a piece at a time."""
    if len(inputs) != 4:
        raise PackportError("The 7z archive is damaged (BCJ2 needs four inputs)")
    if native is not None:
        dec = native.Bcj2Decoder(size)
        while not dec.eof:
            if out := dec.read(entries.CHUNK):
                yield out
                continue
            if dec.needs < 0:
                return  # nothing more: the folder comes up short
            dec.feed(dec.needs, inputs[dec.needs].read(entries.CHUNK))
        return
    main_in, call, jump, rc_in = inputs
    probs = [1 << 10] * 258
    rc, rp = b"", 0

    def rc_byte() -> int:
        nonlocal rc, rp
        if rp >= len(rc):
            rc, rp = rc_in.read(entries.CHUNK), 0
            if not rc:
                return 0
        b = rc[rp]
        rp += 1
        return b

    code = 0
    rng = 0xFFFFFFFF
    for _ in range(5):
        code = (code << 8 | rc_byte()) & 0xFFFFFFFF
    out = bytearray()
    done = 0  # bytes already handed out
    main, ip = b"", 0
    prev = 0
    piece = entries.CHUNK
    while done + len(out) < size:
        if ip >= len(main):
            main, ip = main_in.read(entries.CHUNK), 0
            if not main:
                break
        # copy plain bytes up to the next E8, E9 or Jcc
        n = len(main)
        start = ip
        while ip < n:
            b = main[ip]
            if (b & 0xFE) == 0xE8 or (prev == 0x0F and (b & 0xF0) == 0x80):
                break
            prev = b
            ip += 1
        out += main[start:ip]
        if len(out) >= piece:
            yield bytes(out)
            done += len(out)
            out = bytearray()
        if ip >= n:
            continue
        if done + len(out) >= size:
            break
        b = main[ip]
        ip += 1
        out.append(b)
        if done + len(out) >= size:
            break
        k = prev if b == 0xE8 else 256 if b == 0xE9 else 257
        p = probs[k]
        bound = (rng >> 11) * p
        if code < bound:
            rng = bound
            probs[k] = p + ((2048 - p) >> 5)
            prev = b
        else:
            rng -= bound
            code -= bound
            probs[k] = p - (p >> 5)
            src = (call if b == 0xE8 else jump).exactly(4)
            if len(src) < 4:
                raise PackportError("The 7z archive is damaged (BCJ2 runs out of addresses)")
            dest = (int.from_bytes(src, "big") - (done + len(out) + 4)) & 0xFFFFFFFF
            out += dest.to_bytes(4, "little")
            prev = (dest >> 24) & 0xFF
        if rng < 1 << 24:
            rng = (rng << 8) & 0xFFFFFFFF
            code = (code << 8 | rc_byte()) & 0xFFFFFFFF
    if out:
        yield bytes(out[:size - done])


def _names(raw: bytes, n: int) -> list[str]:
    text = raw.decode("utf-16-le", "replace")
    names = text.split("\0")
    if len(names) < n:
        raise PackportError("The 7z archive is damaged (too few names)")
    return names[:n]


def _sniff(head: bytes, _source) -> bool:
    return head.startswith(SIGNATURE)


@reader("7z", _sniff)
class SevenZipArchive(Archive):
    def __init__(self, source):
        super().__init__(source)
        self.folders, self.packs = [], []
        head = source.read_at(0, 32)
        if len(head) < 32 or head[:6] != SIGNATURE:
            raise PackportError("This isn't a 7z archive")
        start_crc, offset, size, next_crc = struct.unpack_from("<IQQI", head, 8)
        if zlib.crc32(head[12:32]) != start_crc:
            raise PackportError("The 7z archive is damaged (its start header's CRC doesn't match)")
        if size == 0:
            return  # an empty archive
        raw = source.read_at(32 + offset, size)
        if len(raw) < size:
            raise PackportError("The 7z archive is cut short (its header is missing)")
        if zlib.crc32(raw) != next_crc:
            raise PackportError("The 7z archive is damaged (its header's CRC doesn't match)")
        h = _In(raw)
        kind = h.byte()
        for _ in range(4):  # an encoded (packed) header, possibly more than once
            if kind != 0x17:
                break
            packs, folders, _, _ = _streams(h, 32)
            if not folders:
                raise PackportError("The 7z archive is damaged (an empty encoded header)")
            data = self._folder_data(folders[0], packs, 0)
            h = _In(data)
            kind = h.byte()
        if kind != 0x01:
            raise PackportError("The 7z archive is damaged (no header)")
        self._header(h)

    def _packed(self, folder: _Folder, packs, first_pack: int) -> list:
        out = []
        for k in range(len(folder.packed)):
            if first_pack + k >= len(packs):
                raise PackportError("The 7z archive is damaged (a folder without its packed data)")
            pos, size = packs[first_pack + k]
            if pos < 0 or pos + size > self.source.size:
                raise PackportError("The 7z archive is cut short")
            out.append(Window(self.source, pos, size))
        return out

    def _folder_data(self, folder: _Folder, packs, first_pack: int) -> bytes:
        """A small folder's output (an encoded header), whole."""
        if folder.size > MAX_HEADER:
            raise PackportError("The 7z archive is damaged (its header is too big)")
        return b"".join(_decode(folder, self._packed(folder, packs, first_pack)))

    def _header(self, h: _In) -> None:
        packs, folders, sub_sizes, sub_crcs = [], [], [], []
        prop = h.byte()
        if prop == 0x02:  # archive properties: skipped
            while h.byte():
                h.bytes(h.count())
            prop = h.byte()
        if prop == 0x03:
            raise PackportError("The 7z archive keeps more streams elsewhere, which packport doesn't read")
        if prop == 0x04:
            packs, folders, sub_sizes, sub_crcs = _streams(h, 32)
            prop = h.byte()
        self.folders, self.packs = folders, packs
        names, empty, empty_file, mtimes, attrs = [], [], [], [], []
        n = 0
        if prop == 0x05:
            n = h.count()
            empty, empty_file, anti = [False] * n, [], []
            while True:
                p = h.byte()
                if p == 0x00:
                    break
                size = h.number()
                body = _In(h.bytes(size))
                if p == 0x0E:
                    empty = body.bits(n)
                elif p == 0x0F:
                    empty_file = body.bits(sum(empty))
                elif p == 0x10:
                    anti = body.bits(sum(empty))
                elif p == 0x11:
                    if body.byte():
                        raise PackportError("The 7z archive keeps its names elsewhere, which packport doesn't read")
                    names = _names(body.d[body.pos:], n)
                elif p == 0x14:
                    defined = body.defined(n)
                    if body.byte():
                        raise PackportError("The 7z archive keeps its times elsewhere")
                    mtimes = [struct.unpack("<Q", body.bytes(8))[0] if d else 0 for d in defined]
                elif p == 0x15:
                    defined = body.defined(n)
                    if body.byte():
                        raise PackportError("The 7z archive keeps its attributes elsewhere")
                    attrs = [struct.unpack("<I", body.bytes(4))[0] if d else 0 for d in defined]
            del anti
        elif prop != 0x00:
            raise PackportError("The 7z archive is damaged (its header)")
        if not names:
            names = [f"file{k}" for k in range(n)]
        # files with data take the folders' sub-streams in order: (folder, size, CRC) each
        with_streams = [j for j, f in enumerate(folders) if f.substreams]
        crcs = sub_crcs or [[None] * len(sizes) for sizes in sub_sizes]
        flat = [(j, size, crc) for j, sizes, folder_crcs in zip(with_streams, sub_sizes, crcs)
                for size, crc in zip(sizes, folder_crcs)]
        offsets: dict[int, int] = {}
        si = 0
        empty_k = 0
        for k in range(n):
            name = names[k].replace("\\", "/")
            attr = attrs[k] if k < len(attrs) else 0
            mtime = mtimes[k] / 1e7 - 11644473600 if k < len(mtimes) and mtimes[k] else 0.0
            mode = attr >> 16 if attr & 0x8000 else 0
            if empty[k] if k < len(empty) else False:
                is_file = empty_k < len(empty_file) and empty_file[empty_k]
                empty_k += 1
                is_dir = not is_file and not (mode and (mode & 0o170000) == 0o100000)
                if attr & 0x10:
                    is_dir = True
                self.members.append(Item(name, 0, is_dir, None, mtime, mode or (0o040755 if is_dir else 0o100644),
                                         ref=None))
                continue
            if si >= len(flat):
                raise PackportError("The 7z archive is damaged (more files than streams)")
            j, size, crc = flat[si]
            si += 1
            at = offsets.get(j, 0)
            offsets[j] = at + size
            link = None
            item = Item(name, size, False, link, mtime, mode or 0o100644,
                        any(c[0] == "aes" for c in folders[j].coders), ref=(j, at, crc))
            if mode and (mode & 0o170000) == 0o120000:
                item.link = "?"  # a symbolic link: its data is the target, left out like other links
            self.members.append(item)

    def _folder(self, j: int) -> Iterator[bytes]:
        first = sum(len(f.packed) for f in self.folders[:j])
        return _decode(self.folders[j], self._packed(self.folders[j], self.packs, first))

    def _ahead(self):
        """The folders' data, a folder at a time in order: small ones (16 MB or less, packed and
        unpacked) decoded ahead by the pool, the rest streamed. (j, Chunks) for each folder."""
        def jobs():
            first = 0
            for j, f in enumerate(self.folders):
                packs = self.packs[first:first + len(f.packed)]
                first += len(f.packed)
                if f.size <= AHEAD and sum(size for _, size in packs) <= AHEAD and len(packs) == len(f.packed):
                    raw = [io.BytesIO(self.source.read_at(pos, size)) for pos, size in packs]
                    yield lambda f=f, raw=raw, j=j: (j, b"".join(_decode(f, raw)))
                else:
                    yield lambda j=j: (j, None)
        for j, data in ordered(jobs()):
            yield j, Chunks(iter([data])) if data is not None else Chunks(self._folder(j))

    def _files(self):
        folders = self._ahead() if len(self.folders) > 1 else None
        folder = reader = None
        for item in self.members:
            if item.ref is None:
                if item.is_file:
                    yield item, io.BytesIO()
                continue
            j, at, crc = item.ref
            if j != folder:
                if folders is not None:
                    while True:  # folders come in order; one without files is passed over
                        k, reader = next(folders)
                        if k == j:
                            break
                else:
                    reader = Chunks(self._folder(j))
                folder, pos = j, 0
            if at != pos:
                raise PackportError(f"{item.name}: the 7z archive is damaged (its streams are out of order)")
            stream = Stream(item.name, stored(reader, item.size), item.size, Crc32(crc) if crc is not None else None)
            if item.is_file:
                yield item, stream
            stream.drain()  # a link's data (its target) is passed over
            pos = at + item.size

    def open_member(self, item: Item):
        if item.ref is None:
            return io.BytesIO()
        j, at, crc = item.ref
        reader = Chunks(self._folder(j))
        skip = at
        while skip > 0:
            data = reader.read(min(skip, entries.CHUNK))
            if not data:
                raise PackportError(f"{item.name}: the 7z archive is damaged (its data runs short)")
            skip -= len(data)
        return Stream(item.name, stored(reader, item.size), item.size, Crc32(crc) if crc is not None else None)
