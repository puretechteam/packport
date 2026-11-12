"""LZX, as used in Microsoft's cabinets, WIM, CHM and LIT files: the decompressor.

Written from Microsoft's description of LZX (the Cabinet format's LZX and the LZX DELTA
specification): verbatim, aligned-offset and uncompressed blocks; a 20-symbol pre-tree that
codes the main and length trees' bit lengths as deltas against the previous block; three
repeated-match offsets; 32 KB frames re-aligned to 16 bits; optional Intel E8 call translation.
CHM and LIT reset the decoder every few frames ("reset interval"); the caller decodes each
reset span with ``LzxDecoder.reset()`` in between.
"""

from __future__ import annotations

import struct

from ._accel import native
from .entries import PackportError

FRAME = 32768
MIN_MATCH = 2
NUM_CHARS = 256
PRETREE_SIZE = 20
LENGTH_SIZE = 249  # NUM_SECONDARY_LENGTHS + 1 ... codes 0..248
ALIGNED_SIZE = 8

EXTRA_BITS = []
POSITION_BASE = []
_b = 0
for _i in range(51):
    _e = 0 if _i < 4 else min(17, (_i - 2) >> 1)
    EXTRA_BITS.append(_e)
    POSITION_BASE.append(_b)
    _b += 1 << _e
del _b, _i, _e

POSITION_SLOTS = {15: 30, 16: 32, 17: 34, 18: 36, 19: 38, 20: 42, 21: 50}


class _Bits:
    """LZX bit input: 16-bit little-endian words, bits taken from the most significant end."""

    __slots__ = ("buf", "data", "left", "pos")

    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos
        self.buf = 0
        self.left = 0

    def ensure(self, n: int):
        while self.left < n:
            if self.pos + 1 < len(self.data):
                word = self.data[self.pos] | (self.data[self.pos + 1] << 8)
            elif self.pos < len(self.data):
                word = self.data[self.pos]
            else:
                word = 0
            self.pos += 2
            self.buf |= word << (16 - self.left)  # bits wait at the top of a 32-bit window
            self.left += 16

    def peek(self, n: int) -> int:
        self.ensure(n)
        return (self.buf >> (32 - n)) & ((1 << n) - 1) if n else 0

    def drop(self, n: int):
        self.buf = (self.buf << n) & 0xFFFFFFFF
        self.left -= n

    def read(self, n: int) -> int:
        if n == 0:
            return 0
        if n > 16:
            hi = self.read(n - 16)
            return (hi << 16) | self.read(16)
        v = self.peek(n)
        self.drop(n)
        return v

    def align(self):
        # drop the bits left in the current 16-bit word
        if self.left % 16:
            self.drop(self.left % 16)

    def raw_bytes(self, n: int) -> bytes:
        """Read n bytes straight from the input (after an alignment), the way uncompressed blocks do."""
        # whole 16-bit words still in the bit buffer go back to the input
        back = self.left // 16 * 2
        self.pos -= back
        self.buf = 0
        self.left = 0
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out


class _Tree:
    """A canonical Huffman decoding table from code lengths."""

    __slots__ = ("bits", "flat", "lengths", "long", "max_len")

    def __init__(self, lengths: list[int], bits: int):
        # more codes than the lengths leave room for: damage, which would decode as quiet garbage
        if sum(1 << (16 - ln) for ln in lengths if ln) > 1 << 16:
            raise PackportError("Damaged LZX data: an over-full Huffman code")
        self.lengths = lengths
        self.bits = bits
        self.max_len = max(lengths) if lengths else 0
        # every 'bits'-bit prefix as one int, symbol << 5 | length (-1: none); longer codes go to
        # a dict keyed by (length, code). Codes are given in (length, symbol) order.
        size = 1 << bits
        flat = [-1] * size
        long_codes = {}
        code = prev = 0
        for ln, sym in sorted((ln, sym) for sym, ln in enumerate(lengths) if ln):
            code <<= ln - prev
            prev = ln
            if ln <= bits:
                first = code << (bits - ln)
                if first < size:
                    span = min(1 << (bits - ln), size - first)
                    flat[first:first + span] = [sym << 5 | ln] * span
            else:
                long_codes[(ln, code)] = sym
            code += 1
        self.flat = flat
        self.long = long_codes

    def decode(self, bits: _Bits) -> int:
        n = self.bits
        e = self.flat[bits.peek(n)] if self.max_len else -1
        if e >= 0:
            bits.drop(e & 31)
            return e >> 5
        for length in range(n + 1, self.max_len + 1):
            sym = self.long.get((length, bits.peek(length)))
            if sym is not None:
                bits.drop(length)
                return sym
        raise PackportError("Damaged LZX data: bad Huffman code")


class LzxDecoder:
    """wim=True reads WIM's variant: no E8 header (calls are always translated, as if for a
    12,000,000-byte file) and block sizes as a "32 KB" bit or 16 bits (24 past a 64 KB window)."""

    def __init__(self, window_bits: int, wim: bool = False):
        if window_bits not in POSITION_SLOTS:
            raise PackportError(f"Unsupported LZX window size 2^{window_bits}")
        self.window_size = 1 << window_bits
        self.window_bits = window_bits
        self.wim = wim
        self.slots = POSITION_SLOTS[window_bits]
        self.main_size = NUM_CHARS + self.slots * 8
        self.hist = bytearray(self.window_size)  # the window (the last window_size bytes decoded), then new output
        self.carry = 0  # bytes at hist's end decoded past the last call's output (a match ran over a frame)
        self.reset()

    def reset(self):
        self.r = [1, 1, 1]
        self.main_lengths = [0] * self.main_size
        self.length_lengths = [0] * LENGTH_SIZE
        self.header_read = False
        self.e8_size = 0
        self.frames = 0
        self.block_left = 0
        self.block_type = 0
        self.intel_started = False
        self._uncompressed_odd = False
        self.trees = (None, None, None)
        self.position = 0  # output since the reset, for E8 translation

    def _read_lengths(self, bits: _Bits, lengths: list[int], first: int, last: int):
        pre = _Tree([bits.read(4) for _ in range(PRETREE_SIZE)], 6)
        i = first
        while i < last:
            code = pre.decode(bits)
            if code == 17:
                n = 4 + bits.read(4)
                for _ in range(n):
                    if i < last:
                        lengths[i] = 0
                        i += 1
            elif code == 18:
                n = 20 + bits.read(5)
                for _ in range(n):
                    if i < last:
                        lengths[i] = 0
                        i += 1
            elif code == 19:
                n = 4 + bits.read(1)
                code = pre.decode(bits)
                v = (lengths[i] - code) % 17 if i < last else 0
                for _ in range(n):
                    if i < last:
                        lengths[i] = v
                        i += 1
            else:
                lengths[i] = (lengths[i] - code) % 17
                i += 1

    def decompress(self, data: bytes, out_len: int) -> bytes:
        """Decode ``out_len`` bytes of compressed data (fewer when the data runs out first: past its
        end the decoder would only read zero bits). A reset span can come in pieces that end on
        frames, as a cabinet's data blocks do: the decoder carries on from one call to the next."""
        bits = _Bits(data)
        end = len(data) + 4  # the bit buffer reads up to two words ahead
        padded = data + bytes(32)  # the symbol loop reads words without bounds checks; past the end they are 0
        # the window followed by this span's output: matches are slices of it
        hist = self.hist
        base = len(hist) - self.carry
        if not self.header_read and self.wim:
            self.e8_size = 12_000_000
            self.header_read = True
        if not self.header_read:
            if bits.read(1):
                hi = bits.read(16)
                lo = bits.read(16)
                self.e8_size = (hi << 16) | lo
            else:
                self.e8_size = 0
            self.header_read = True
        main_tree, length_tree, aligned_tree = self.trees
        while len(hist) - base < out_len and bits.pos <= end:
            frame_size = min(FRAME, out_len - (len(hist) - base))
            frame_start = len(hist)
            while len(hist) - frame_start < frame_size and bits.pos <= end:
                if self.block_left == 0:
                    if self.block_type == 3 and self._uncompressed_odd:
                        bits.pos += 1  # an odd-sized uncompressed block is padded to 16 bits
                        self._uncompressed_odd = False
                    self.block_type = bits.read(3)
                    if self.wim:
                        if bits.read(1):
                            self.block_left = FRAME
                        else:
                            self.block_left = bits.read(16)
                            if self.window_bits >= 16:
                                self.block_left = self.block_left << 8 | bits.read(8)
                    else:
                        hi = bits.read(8)
                        mid = bits.read(8)
                        lo = bits.read(8)
                        self.block_left = (hi << 16) | (mid << 8) | lo
                    if self.block_type == 2:
                        aligned_tree = _Tree([bits.read(3) for _ in range(ALIGNED_SIZE)], 7)
                    if self.block_type in (1, 2):
                        self._read_lengths(bits, self.main_lengths, 0, NUM_CHARS)
                        self._read_lengths(bits, self.main_lengths, NUM_CHARS, self.main_size)
                        main_tree = _Tree(self.main_lengths, 12)
                        self._read_lengths(bits, self.length_lengths, 0, LENGTH_SIZE)
                        length_tree = _Tree(self.length_lengths, 12)
                    elif self.block_type == 3:
                        # 1 to 16 bits of padding (never 0) bring the input to a 16-bit boundary
                        bits.ensure(16)
                        if bits.left > 16:
                            bits.pos -= 2
                        bits.buf = 0
                        bits.left = 0
                        hdr = bits.raw_bytes(12)
                        self.r = list(struct.unpack("<III", hdr))
                        self._uncompressed_odd = bool(self.block_left & 1)
                    else:
                        raise PackportError(f"Damaged LZX data: block type {self.block_type}")
                take = min(self.block_left, frame_size - (len(hist) - frame_start))
                if self.block_type == 3:
                    raw = bits.raw_bytes(take)
                    if len(raw) < take:
                        bits.pos = end + 1
                    hist += raw
                    self.block_left -= take
                    continue
                produced = self._symbols(bits, padded, end, hist, take, main_tree, length_tree,
                                         aligned_tree if self.block_type == 2 else None)
                self.block_left -= produced
                if produced > take:
                    # a match ran past the frame end: carry the surplus over
                    self.block_left = max(0, self.block_left)
            # each frame ends on a 16-bit boundary in the input
            if self.block_type != 3:
                bits.align()
            self.frames += 1
        self.trees = (main_tree, length_tree, aligned_tree)
        out = hist[base:base + out_len]
        self.carry = len(hist) - base - len(out)
        if self.e8_size:
            out = self._undo_e8(out, self.position)
        self.position += len(out)
        if len(hist) > 2 * self.window_size:
            del hist[:len(hist) - self.window_size - self.carry]
        return bytes(out)

    def _symbols(self, bits: _Bits, data: bytes, end: int, hist: bytearray, take: int,
                 main_tree: _Tree, length_tree: _Tree, aligned_tree: _Tree | None) -> int:
        """Decode literals and matches into hist until take bytes are made (a match may run past).
        The bit reader is kept in locals and refilled exactly when _Bits would refill it, so the
        input is consumed the same way; Huffman codes come from the trees' flat tables."""
        buf, left, pos = bits.buf, bits.left, bits.pos
        main_flat, length_flat = main_tree.flat, length_tree.flat
        aligned_flat = aligned_tree.flat if aligned_tree is not None else None
        r0, r1, r2 = self.r
        wsize = self.window_size
        append = hist.append
        produced = 0
        while produced < take and pos <= end:
            if left < 12:
                buf |= (data[pos] | data[pos + 1] << 8) << (16 - left)
                pos += 2
                left += 16
            e = main_flat[buf >> 20]
            if e >= 0:
                n = e & 31
                buf = (buf << n) & 0xFFFFFFFF
                left -= n
                sym = e >> 5
            else:  # a code longer than the table, or a bad one
                bits.buf, bits.left, bits.pos = buf, left, pos
                sym = main_tree.decode(bits)
                buf, left, pos = bits.buf, bits.left, bits.pos
            if sym < NUM_CHARS:
                append(sym)
                produced += 1
                continue
            sym -= NUM_CHARS
            length = sym & 7
            if length == 7:
                if left < 12:
                    buf |= (data[pos] | data[pos + 1] << 8) << (16 - left)
                    pos += 2
                    left += 16
                e = length_flat[buf >> 20]
                if e >= 0:
                    n = e & 31
                    buf = (buf << n) & 0xFFFFFFFF
                    left -= n
                    length += e >> 5
                else:
                    bits.buf, bits.left, bits.pos = buf, left, pos
                    length += length_tree.decode(bits)
                    buf, left, pos = bits.buf, bits.left, bits.pos
            length += MIN_MATCH
            slot = sym >> 3
            if slot > 2:
                extra = EXTRA_BITS[slot]
                aligned = aligned_flat is not None and extra >= 3
                n = extra - 3 if aligned else extra  # verbatim bits
                value = 0
                if n > 16:  # 17 bits: one, then sixteen
                    if left < 1:
                        buf |= (data[pos] | data[pos + 1] << 8) << (16 - left)
                        pos += 2
                        left += 16
                    value = buf >> 31
                    buf = (buf << 1) & 0xFFFFFFFF
                    left -= 1
                    n = 16
                if n:
                    if left < n:
                        buf |= (data[pos] | data[pos + 1] << 8) << (16 - left)
                        pos += 2
                        left += 16
                    value = value << n | buf >> (32 - n)
                    buf = (buf << n) & 0xFFFFFFFF
                    left -= n
                if aligned:
                    if left < 7:
                        buf |= (data[pos] | data[pos + 1] << 8) << (16 - left)
                        pos += 2
                        left += 16
                    e = aligned_flat[buf >> 25]
                    if e >= 0:
                        n = e & 31
                        buf = (buf << n) & 0xFFFFFFFF
                        left -= n
                        a = e >> 5
                    else:
                        bits.buf, bits.left, bits.pos = buf, left, pos
                        a = aligned_tree.decode(bits)
                        buf, left, pos = bits.buf, bits.left, bits.pos
                    offset = POSITION_BASE[slot] + (value << 3) + a - 2
                else:
                    offset = POSITION_BASE[slot] + value - 2
                r2, r1, r0 = r1, r0, offset
            elif slot == 0:
                offset = r0
            elif slot == 1:
                offset = r1
                r1, r0 = r0, offset
            else:
                offset = r2
                r2, r0 = r0, offset
            # the window is a ring of wsize bytes: an offset of 0 or past it wraps around
            dist = offset if 0 < offset <= wsize else (offset - 1) % wsize + 1
            src = len(hist) - dist
            if dist >= length:
                hist += hist[src:src + length]
            else:  # the match overlaps what it writes: the last dist bytes repeat
                hist += (hist[src:] * (length // dist + 1))[:length]
            produced += length
        bits.buf, bits.left, bits.pos = buf, left, pos
        self.r = [r0, r1, r2]
        return produced

    def _undo_e8(self, data: bytearray, offset: int = 0) -> bytearray:
        """Undo E8 call translation on data, which starts offset bytes into the reset span (on a
        frame). Only the first 32768 frames are translated."""
        size = self.e8_size
        n = len(data)
        for start in range(0, n, FRAME):
            if (offset + start) // FRAME >= 32768:
                break
            end = min(n, start + FRAME)
            if end - start <= 10:
                continue
            i = start
            limit = end - 10
            while i < limit:
                if data[i] == 0xE8:
                    cur = offset + i
                    abs_off = struct.unpack("<i", data[i + 1:i + 5])[0]
                    if -cur <= abs_off < size:
                        rel = abs_off - cur if abs_off >= 0 else abs_off + size
                        data[i + 1:i + 5] = struct.pack("<i", rel)
                    i += 5
                else:
                    i += 1
        return data


if native is not None:
    LzxDecoder = native.LzxDecoder


