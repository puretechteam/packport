"""RAR 2.9 and 3.x compression ("unpack version 29"), as RAR 3 and 4 archives store files.

One bit stream per file, most significant bit first. It starts with Huffman tables (unless a
solid archive's file carries them over): a flag for PPMd, a flag to keep the previous lengths,
a 20-symbol code for the code lengths, then the lengths of the 299 literal/length, 60
distance, 17 low-distance and 28 repeat-length symbols, each added (mod 16) to its previous
length. Symbols: 0-255 literals; 256 ends a block (a new file, new tables or both); 257 brings
a filter program; 258 repeats the last match; 259-262 reuse one of the last four distances;
263-270 are length-2 matches at short distances; 271 on are matches with a length and a
distance slot (the low four bits of long distances coded on their own, and repeatable).

Filters are small programs for RAR's virtual machine. RAR only ever writes six of them, which
are told apart by their size and CRC and run here as what they do: x86 E8 and E8/E9 call
addresses, Itanium branches, Delta, RGB images and audio. Any other program is refused. PPMd
blocks (variant H, with RAR's range coder) are decoded by ppmd.py.

Written from the format's behaviour as libarchive (BSD) documents it in code; packport contains
no code from unRAR.
"""

from __future__ import annotations

import zlib
from collections.abc import Iterator

from ._accel import native, pump
from .bits import huffman
from .entries import PackportError

NC, DC, LDC, RC, BC = 299, 60, 17, 28, 20
LOW_DIST_REP = 16
MAX_FILTERS = 1024
VM_MEMSIZE = 0x40000
FLUSH = 4 << 20
READ = 4 << 20     # packed data read at a time
MARGIN = 1 << 18   # kept ahead of the read position: more than any one symbol, table or filter program

LDECODE = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224]
LBITS = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5]
SDDECODE = [0, 4, 8, 16, 32, 64, 128, 192]
SDBITS = [2, 2, 3, 4, 5, 6, 6, 6]
DDECODE, DBITS = [], []
_dist = 0
for _bits, _count in enumerate([4] + [2] * 15 + [14, 0, 12]):
    for _ in range(_count):
        DDECODE.append(_dist)
        DBITS.append(_bits)
        _dist += 1 << _bits
del _dist, _bits, _count

# RAR's six standard filter programs: (code size, CRC32) -> name
STANDARD = {(53, 0xAD576887): "e8", (57, 0x3CD7E57E): "e8e9", (120, 0x3769893F): "itanium",
            (29, 0x0E06077D): "delta", (149, 0x1C2C5DC8): "rgb", (216, 0xBC85E701): "audio"}


def _bits_at(d: bytes, pos: int, n: int) -> int:
    i = pos >> 3
    v = int.from_bytes(d[i:i + 8], "big")
    return (v >> (64 - n - (pos & 7))) & ((1 << n) - 1)


class _Code:
    """A byte string read as bits, for filter programs' parameters (RarVM::ReadData)."""

    def __init__(self, data: bytes):
        self.d, self.pos = bytes(data) + bytes(8), 0

    def bits(self, n: int) -> int:
        v = _bits_at(self.d, self.pos, n)
        self.pos += n
        return v

    def number(self) -> int:
        v = _bits_at(self.d, self.pos, 16)
        top = v & 0xC000
        if top == 0:
            self.pos += 6
            return (v >> 10) & 0xF
        if top == 0x4000:
            if v & 0x3C00 == 0:
                self.pos += 14
                return 0xFFFFFF00 | ((v >> 2) & 0xFF)
            self.pos += 10
            return (v >> 6) & 0xFF
        if top == 0x8000:
            self.pos += 2
            return self.bits(16)
        self.pos += 2
        return self.bits(16) << 16 | self.bits(16)


class Unpack29:
    """RAR 2.9 decompression with the state a solid archive carries from file to file."""

    def __init__(self, dictionary: int = 4 << 20):
        self.dictionary = dictionary
        self.native = native.Rar29Decoder(dictionary) if native is not None else None
        self.hist = bytearray()
        self.base = 0
        self.written = 0
        self.old = [0, 0, 0, 0]
        self.last_length = 0
        self.old_table = [0] * (NC + DC + LDC + RC)
        self.tables = None
        self.prev_low, self.low_reps = 0, 0
        self.filters: list[dict] = []          # filter programs seen ({"kind", "length"})
        self.pending: list[dict] = []          # blocks to filter: start, length, kind, registers
        self.last_filter = 0
        self.ppm = None
        self.ppm_esc = 2
        self.block_ppm = False

    def unpack(self, packed, size: int) -> Iterator[bytes]:
        """Decode one file's packed data (a readable, read a few MB at a time) into chunks of
        output, size bytes in all."""
        if self.native is not None:
            self.native.begin_file(size)
            yield from pump(self.native, packed, size)
            return
        self.src, self.more = packed, True
        self.d, self.end, self.pos = b"", 0, 0
        self._refill()
        self.file_start = self.base + len(self.hist)
        self.written = self.file_start
        self.size = size
        parts: list[bytes] = []
        if self.block_ppm:
            self.ppm.next_file(self)
        elif self.tables is None:
            self._tables()
        while self.base + len(self.hist) - self.file_start < size:
            if self.pos > self.end + 64:
                raise PackportError("The archive is damaged or cut short (compressed data ended early)")
            done = self._ppm_run() if self.block_ppm else self._lz_run()
            self._flush(parts.append)
            yield from parts
            parts.clear()
            if done:
                break
            self._refill()
        self._flush(parts.append, final=True)
        yield from parts

    def _refill(self) -> None:
        """Keep READ bytes of packed data ahead of pos, dropping what's been read. Decoding stops
        at lim (MARGIN bytes before the data runs out) to come back here; at the real end, the data
        is padded with zeros and lim is where running past it means it was cut short."""
        if self.more and (self.end - self.pos) >> 3 < READ // 2:
            drop = self.pos >> 3
            parts = [self.d[drop:self.end >> 3]]
            have = len(parts[0])
            while have < READ:  # a read may give less than asked for: only nothing means the end
                new = self.src.read(READ - have)
                if not new:
                    self.more = False
                    break
                parts.append(new)
                have += len(new)
            self.d = b"".join(parts)
            self.end = len(self.d) * 8
            self.pos -= drop * 8
            if self.ppm is not None:
                self.ppm.at -= drop
            if not self.more:
                self.d += bytes(64)
        self.lim = self.end - 8 * MARGIN if self.more else self.end + 32

    # -- tables

    def _align(self) -> None:
        self.pos = (self.pos + 7) & ~7

    def _tables(self) -> None:
        self._align()
        d = self.d
        flags = _bits_at(d, self.pos, 16)
        if flags & 0x8000:
            self.block_ppm = True
            from .ppmd import RarPpmd
            if self.ppm is None:
                self.ppm = RarPpmd()
            self.pos, self.ppm_esc = self.ppm.init(self, self.ppm_esc)
            return
        self.block_ppm = False
        self.prev_low = self.low_reps = 0
        if not flags & 0x4000:
            self.old_table = [0] * len(self.old_table)
        self.pos += 2
        lengths = []
        while len(lengths) < BC:
            n = _bits_at(d, self.pos, 4)
            self.pos += 4
            if n == 15:
                zeros = _bits_at(d, self.pos, 4)
                self.pos += 4
                if zeros == 0:
                    lengths.append(15)
                else:
                    lengths += [0] * min(zeros + 2, BC - len(lengths))
            else:
                lengths.append(n)
        bd = huffman(lengths)
        size = NC + DC + LDC + RC
        table: list[int] = []
        while len(table) < size:
            e = bd[_bits_at(d, self.pos, 15)]
            if e < 0:
                raise PackportError("The archive is damaged (a bad code in the Huffman tables)")
            self.pos += e & 15
            n = e >> 4
            if n < 16:
                table.append((n + self.old_table[len(table)]) & 15)
            elif n < 18:
                k = _bits_at(d, self.pos, 3) + 3 if n == 16 else _bits_at(d, self.pos, 7) + 11
                self.pos += 3 if n == 16 else 7
                if not table:
                    raise PackportError("The archive is damaged (a Huffman table repeats nothing)")
                table += [table[-1]] * min(k, size - len(table))
            else:
                k = _bits_at(d, self.pos, 3) + 3 if n == 18 else _bits_at(d, self.pos, 7) + 11
                self.pos += 3 if n == 18 else 7
                table += [0] * min(k, size - len(table))
        self.old_table = table
        self.tables = (huffman(table[:NC]), huffman(table[NC:NC + DC]), huffman(table[NC + DC:NC + DC + LDC]),
                       huffman(table[NC + DC + LDC:]))

    # -- LZ

    def _lz_run(self) -> bool:
        """Decode LZ symbols until the file is out (or a block switches to PPMd or ends the file).
        Returns True at the end of the file's data."""
        d = self.d
        pos = self.pos
        ld, dd, ldd, rd = self.tables
        hist, old = self.hist, self.old
        last_length = self.last_length
        target = self.file_start + self.size - self.base
        from_bytes = int.from_bytes
        stop = len(hist) + 1_000_000  # come back now and then so output can go out
        lim = self.lim
        s = v = 0
        while len(hist) < target and len(hist) < stop:
            if s < 32:  # the window: the 64 bits from pos's byte, s of them still to come
                if pos > lim:
                    if self.more:
                        break  # back for more packed data
                    raise PackportError("The archive is damaged or cut short (compressed data ended early)")
                i = pos >> 3
                v = from_bytes(d[i:i + 8], "big")
                s = 64 - (pos & 7)
            e = ld[(v >> (s - 15)) & 0x7FFF]
            if e < 0:
                raise PackportError("The archive is damaged (a bad Huffman code)")
            n = e & 15
            pos += n
            s -= n
            slot = e >> 4
            if slot < 256:
                hist.append(slot)
                continue
            if slot >= 271:
                slot -= 271
                length = LDECODE[slot] + 3
                b = LBITS[slot]
                if b:
                    length += (v >> (s - b)) & ((1 << b) - 1)
                    pos += b
                    s -= b
                if s < 32:
                    i = pos >> 3
                    v = from_bytes(d[i:i + 8], "big")
                    s = 64 - (pos & 7)
                e = dd[(v >> (s - 15)) & 0x7FFF]
                if e < 0:
                    raise PackportError("The archive is damaged (a bad Huffman code)")
                pos += e & 15
                s -= e & 15
                dn = e >> 4
                dist = DDECODE[dn] + 1
                b = DBITS[dn]
                if b:
                    if dn > 9:
                        if b > 4:
                            dist += _bits_at(d, pos, b - 4) << 4
                            pos += b - 4
                        if self.low_reps > 0:
                            self.low_reps -= 1
                            dist += self.prev_low
                        else:
                            e = ldd[_bits_at(d, pos, 15)]
                            if e < 0:
                                raise PackportError("The archive is damaged (a bad Huffman code)")
                            pos += e & 15
                            low = e >> 4
                            if low == 16:
                                self.low_reps = LOW_DIST_REP - 1
                                dist += self.prev_low
                            else:
                                dist += low
                                self.prev_low = low
                    else:
                        dist += (v >> (s - b)) & ((1 << b) - 1)
                        pos += b
                if dist >= 0x2000:
                    length += 1
                    if dist >= 0x40000:
                        length += 1
                old[3], old[2], old[1], old[0] = old[2], old[1], old[0], dist
                last_length = length
                s = 0
            elif slot == 256:
                self.pos, self.last_length = pos, last_length
                flags = _bits_at(d, pos, 2)
                if flags & 2:  # new tables
                    self.pos += 1
                    self._tables()
                    if self.block_ppm:
                        return False
                    d, pos = self.d, self.pos
                    ld, dd, ldd, rd = self.tables
                    s = 0
                    continue
                self.pos += 2  # a new file
                if flags & 1:
                    self.tables = None  # the next file starts with new tables
                return True
            elif slot == 257:
                self.pos, self.last_length = pos, last_length
                self._vm_code_lz()
                pos = self.pos
                s = 0
                continue
            elif slot == 258:
                if not last_length:
                    continue
                length, dist = last_length, old[0]
            elif slot < 263:
                k = slot - 259
                dist = old[k]
                for j in range(k, 0, -1):
                    old[j] = old[j - 1]
                old[0] = dist
                e = rd[(v >> (s - 15)) & 0x7FFF]
                if e < 0:
                    raise PackportError("The archive is damaged (a bad Huffman code)")
                pos += e & 15
                s -= e & 15
                ln = e >> 4
                length = LDECODE[ln] + 2
                b = LBITS[ln]
                if b:
                    length += _bits_at(d, pos, b)
                    pos += b
                    s = 0
                last_length = length
            else:
                slot -= 263
                dist = SDDECODE[slot] + 1
                b = SDBITS[slot]
                dist += (v >> (s - b)) & ((1 << b) - 1)
                pos += b
                s -= b
                old[3], old[2], old[1], old[0] = old[2], old[1], old[0], dist
                last_length = length = 2
            have = len(hist)
            if dist <= 0 or dist > have or dist > self.dictionary:
                raise PackportError("The archive is damaged (a match reaches back before the data)")
            start = have - dist
            if dist >= length:
                hist += hist[start:start + length]
            else:
                chunk = hist[start:]
                hist += (chunk * (length // dist + 1))[:length]
        self.pos, self.last_length = pos, last_length
        return False

    def release(self) -> None:
        """Let go of the window and the PPMd model (up to 256 MB), which point at each other."""
        self.native = None
        if self.ppm is not None:
            self.ppm.model = self.ppm.rc = self.ppm.unpacker = None
            self.ppm = None
        self.hist = bytearray()
        self.d = b""

    def copy(self, length: int, dist: int) -> None:
        """A match, for the PPMd decoder's escapes."""
        hist = self.hist
        have = len(hist)
        if dist <= 0 or dist > have:
            raise PackportError("The archive is damaged (a match reaches back before the data)")
        start = have - dist
        if dist >= length:
            hist += hist[start:start + length]
        else:
            hist += (hist[start:] * (length // dist + 1))[:length]

    def _ppm_run(self) -> bool:
        return self.ppm.run(self)

    # -- filters

    def _vm_code_lz(self) -> None:
        d = self.d
        first = _bits_at(d, self.pos, 8)
        self.pos += 8
        length = (first & 7) + 1
        if length == 7:
            length = _bits_at(d, self.pos, 8) + 7
            self.pos += 8
        elif length == 8:
            length = _bits_at(d, self.pos, 16)
            self.pos += 16
        code = bytes(_bits_at(d, self.pos + 8 * k, 8) for k in range(length))
        self.pos += 8 * length
        self.add_filter(first, code)

    def add_filter(self, first: int, code: bytes) -> None:
        """A filter (RAR's AddVMCode): which program, where its block starts and how long it is,
        its registers; a new program's code is identified as one of RAR's six."""
        inp = _Code(code)
        if first & 0x80:
            index = inp.number()
            if index == 0:
                self.filters, self.pending = [], []
            else:
                index -= 1
        else:
            index = self.last_filter
        if index > len(self.filters) or index > MAX_FILTERS:
            raise PackportError("The archive is damaged (a filter that isn't there)")
        self.last_filter = index
        new = index == len(self.filters)
        if new:
            self.filters.append({"kind": None, "length": 0})
        filt = self.filters[index]
        start = inp.number()
        if first & 0x40:
            start += 258
        if start >= self.dictionary:  # unRAR wraps it inside the window: past it, it's damage
            raise PackportError("The archive is damaged (a filter that starts past the dictionary window)")
        if first & 0x20:
            filt["length"] = inp.number()
        length = filt["length"]
        if length > VM_MEMSIZE:  # the block has to fit in RAR's VM memory to be filtered
            raise PackportError("The archive is damaged (a filter longer than RAR's VM memory)")
        regs = [0] * 7
        regs[4] = length
        if first & 0x10:
            mask = inp.bits(7)
            for k in range(7):
                if mask & (1 << k):
                    regs[k] = inp.number()
        if new:
            size = inp.number()
            if size == 0 or size >= 0x10000 or inp.pos // 8 + size > len(code):
                raise PackportError("The archive is damaged (a broken filter program)")
            prog = bytes(inp.bits(8) for _ in range(size))
            filt["kind"] = STANDARD.get((size, zlib.crc32(prog)))
            if filt["kind"] is None:
                raise PackportError("This RAR archive uses a filter program packport doesn't run "
                                    "(only RAR's own six standard filters are supported)")
        if len(self.pending) >= MAX_FILTERS:
            raise PackportError("The archive is damaged (too many filters)")
        self.pending.append({"start": self.base + len(self.hist) + start, "length": length, "kind": filt["kind"],
                             "regs": regs})

    def _flush(self, out, final: bool = False) -> None:
        top = self.base + len(self.hist)
        stop = self.file_start + self.size
        while True:
            self.pending = [f for f in self.pending if f["start"] >= self.written]  # others overlap written data
            nxt = min(self.pending, key=lambda f: f["start"]) if self.pending else None
            limit = min(top, stop) if nxt is None else min(top, stop, nxt["start"])
            if limit > self.written:
                out(self.hist[self.written - self.base:limit - self.base])
                self.written = limit
            if nxt is None or nxt["start"] > self.written or top < nxt["start"] + nxt["length"]:
                break
            i = self.pending.index(nxt)
            f = self.pending.pop(i)
            data = bytes(self.hist[f["start"] - self.base:f["start"] + f["length"] - self.base])
            data = run_filter(f["kind"], data, f["regs"], f["start"] - self.file_start)
            # more filters on the same block, one after the other
            while i < len(self.pending) and self.pending[i]["start"] == f["start"] and \
                    self.pending[i]["length"] == len(data):
                g = self.pending.pop(i)
                data = run_filter(g["kind"], data, g["regs"], g["start"] - self.file_start)
            room = stop - self.written
            out(data[:room])
            self.written = f["start"] + f["length"]
        if final and self.written < min(top, stop):
            out(self.hist[self.written - self.base:min(top, stop) - self.base])
            self.written = min(top, stop)
        drop = self.written - self.base - self.dictionary
        if drop > FLUSH:
            del self.hist[:drop]
            self.base += drop


def run_filter(kind: str, data: bytes, regs: list[int], offset: int) -> bytes:
    """One of RAR's standard filters undone. regs are the program's registers R0-R6 (R4 the
    block's length); offset is where the block starts in the file."""
    n = len(data)
    if n > VM_MEMSIZE:
        raise PackportError("The archive is damaged (a filter block over 256 KB)")
    if kind in ("e8", "e8e9"):
        out = bytearray(data)
        size = 0x1000000
        second = 0xE9 if kind == "e8e9" else 0xE8
        pos = 0
        while pos < n - 4:
            b = out[pos]
            pos += 1
            if b == 0xE8 or b == second:
                at = (pos + offset) & 0xFFFFFFFF
                addr = int.from_bytes(out[pos:pos + 4], "little")
                if addr & 0x80000000:
                    if (addr + at) & 0x80000000 == 0:
                        out[pos:pos + 4] = ((addr + size) & 0xFFFFFFFF).to_bytes(4, "little")
                elif (addr - size) & 0x80000000:
                    out[pos:pos + 4] = ((addr - at) & 0xFFFFFFFF).to_bytes(4, "little")
                pos += 4
        return bytes(out)
    if kind == "itanium":
        out = bytearray(data) + bytes(4)
        masks = (4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0)
        file_offset = offset >> 4
        pos = 0
        while pos < n - 21:
            b = (out[pos] & 0x1F) - 0x10
            if b >= 0:
                mask = masks[b]
                for k in range(3):
                    if mask & (1 << k):
                        start = k * 41 + 5
                        if _ia_get(out, pos, start + 37, 4) == 5:
                            target = _ia_get(out, pos, start + 13, 20)
                            _ia_set(out, pos, (target - file_offset) & 0xFFFFF, start + 13, 20)
            pos += 16
            file_offset += 1
        return bytes(out[:n])
    if kind == "delta":
        channels = regs[0]
        if channels == 0 or channels > 1024:
            raise PackportError("The archive is damaged (a Delta filter with no channels)")
        out = bytearray(n)
        src = 0
        for c in range(channels):
            prev = 0
            for at in range(c, n, channels):
                prev = (prev - data[src]) & 0xFF
                out[at] = prev
                src += 1
        return bytes(out)
    if kind == "rgb":
        width, pos_r = regs[0] - 3, regs[1]
        if n < 3 or width > n or pos_r > 2 or width < 0:
            raise PackportError("The archive is damaged (a broken RGB filter)")
        out = bytearray(n)
        src = 0
        for c in range(3):
            prev = 0
            for i in range(c, n, 3):
                if i >= width + 3:
                    up, up_left = out[i - width], out[i - width - 3]
                    predicted = prev + up - up_left
                    pa, pb, pc = abs(predicted - prev), abs(predicted - up), abs(predicted - up_left)
                    if pa <= pb and pa <= pc:
                        predicted = prev
                    elif pb <= pc:
                        predicted = up
                    else:
                        predicted = up_left
                else:
                    predicted = prev
                prev = (predicted - data[src]) & 0xFF
                out[i] = prev
                src += 1
        for i in range(pos_r, n - 2, 3):
            g = out[i + 1]
            out[i] = (out[i] + g) & 0xFF
            out[i + 2] = (out[i + 2] + g) & 0xFF
        return bytes(out)
    if kind == "audio":
        channels = regs[0]
        if channels == 0 or channels > 128:
            raise PackportError("The archive is damaged (an audio filter with no channels)")
        out = bytearray(n)
        src = 0
        for c in range(channels):
            prev = prev_delta = 0
            d1 = d2 = d3 = 0
            k1 = k2 = k3 = 0
            dif = [0] * 7
            for count, i in enumerate(range(c, n, channels)):
                d3 = d2
                d2 = prev_delta - d1
                d1 = prev_delta
                predicted = (8 * prev + k1 * d1 + k2 * d2 + k3 * d3) >> 3 & 0xFF
                cur = data[src]
                src += 1
                predicted = (predicted - cur) & 0xFF
                out[i] = predicted
                delta = (predicted - prev) & 0xFF
                prev_delta = delta - 256 if delta > 127 else delta
                prev = predicted
                dv = (cur - 256 if cur > 127 else cur) * 8
                dif[0] += abs(dv)
                dif[1] += abs(dv - d1)
                dif[2] += abs(dv + d1)
                dif[3] += abs(dv - d2)
                dif[4] += abs(dv + d2)
                dif[5] += abs(dv - d3)
                dif[6] += abs(dv + d3)
                if count & 0x1F == 0:
                    best, which = dif[0], 0
                    dif[0] = 0
                    for j in range(1, 7):
                        if dif[j] < best:
                            best, which = dif[j], j
                        dif[j] = 0
                    if which == 1 and k1 >= -16:
                        k1 -= 1
                    elif which == 2 and k1 < 16:
                        k1 += 1
                    elif which == 3 and k2 >= -16:
                        k2 -= 1
                    elif which == 4 and k2 < 16:
                        k2 += 1
                    elif which == 5 and k3 >= -16:
                        k3 -= 1
                    elif which == 6 and k3 < 16:
                        k3 += 1
        return bytes(out)
    raise PackportError(f"This RAR archive uses a filter packport doesn't know ({kind})")


def _ia_get(data, base: int, bit: int, count: int) -> int:
    at = base + bit // 8
    v = int.from_bytes(data[at:at + 4], "little") >> (bit & 7)
    return v & ((1 << count) - 1)


def _ia_set(data, base: int, value: int, bit: int, count: int) -> None:
    at = base + bit // 8
    shift = bit & 7
    mask = ~(((1 << count) - 1) << shift) & 0xFFFFFFFF
    v = int.from_bytes(data[at:at + 4], "little")
    v = (v & mask) | ((value << shift) & 0xFFFFFFFF)
    data[at:at + 4] = v.to_bytes(4, "little")
