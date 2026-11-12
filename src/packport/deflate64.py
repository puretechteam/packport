"""Deflate64 ("enhanced deflate", ZIP method 9 and 7z's Deflate64): Deflate with a 64 KB window,
length code 285 meaning 3 + 16 more bits, and distance codes 30 and 31 (14 extra bits each).

Written from PKWARE's APPNOTE and RFC 1951. Bits are read least significant first; Huffman
codes are packed most significant bit first, so the lookup tables are indexed by the code's
bits reversed.
"""

from __future__ import annotations

from collections.abc import Iterator

from . import entries
from ._accel import native, pump
from .entries import PackportError

LENGTH_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163,
               195, 227, 3]
LENGTH_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 16]
DIST_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073,
             4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153]
DIST_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14]
ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]


def _table(lengths: list[int]) -> tuple[list[int], int]:
    """A lookup table indexed by the next `bits` bits (least significant first)."""
    bits = max(lengths) if any(lengths) else 1
    counts = [0] * 16
    for n in lengths:
        counts[n] += 1
    counts[0] = 0
    code, first = 0, [0] * 17
    for n in range(1, 16):
        code = (code + counts[n - 1]) << 1
        first[n] = code
    table = [-1] * (1 << bits)
    for sym, n in enumerate(lengths):
        if not n:
            continue
        c = first[n]
        first[n] += 1
        if c >= 1 << n:
            raise PackportError("The data is damaged (an over-full Deflate64 code)")
        rev = int(f"{c:0{n}b}"[::-1], 2)
        for fill in range(rev, 1 << bits, 1 << n):
            table[fill] = sym << 4 | n
    return table, bits


_FIXED = None


def _fixed():
    global _FIXED
    if _FIXED is None:
        _FIXED = (_table([8] * 144 + [9] * 112 + [7] * 24 + [8] * 8), _table([5] * 32))
    return _FIXED


WINDOW = 1 << 16
READ = 1 << 20      # packed data read at a time
MARGIN = 1 << 17    # kept ahead of the read position: more than a stored block and its header


def decompress_iter(inp, size: int) -> Iterator[bytes]:
    """size bytes of output (or what the stream holds, if less), in pieces of about
    entries.CHUNK, reading inp (a readable) a piece at a time."""
    if native is not None:
        yield from pump(native.Deflate64Decoder(), inp, size)
        return
    piece = entries.CHUNK
    d, end, pos, more = b"", 0, 0, True
    out = bytearray()   # the last WINDOW bytes handed out, then what's new
    given = 0           # bytes of out already handed out
    total = 0           # bytes handed out before out's start

    def refill() -> int:
        """Top up the packed data; returns where (in bits) to stop and come back."""
        nonlocal d, end, pos, more
        if more and (end - pos) >> 3 < MARGIN:
            parts = [d[pos >> 3:end >> 3]]
            have = len(parts[0])
            while have < READ:  # a read may give less than asked for: only nothing means the end
                new = inp.read(READ - have)
                if not new:
                    more = False
                    break
                parts.append(new)
                have += len(new)
            d = b"".join(parts)
            pos &= 7
            end = len(d) * 8
            if not more:
                d += bytes(8)
        return end - 8 * MARGIN if more else end + 64

    def bits(n: int) -> int:
        nonlocal pos
        i = pos >> 3
        v = int.from_bytes(d[i:i + 4], "little") >> (pos & 7)
        pos += n
        return v & ((1 << n) - 1)

    while total + len(out) < size:
        lim = refill()
        if pos > end:
            raise PackportError("The data is damaged or cut short (Deflate64 data ended early)")
        final = bits(1)
        kind = bits(2)
        if kind == 0:
            pos = (pos + 7) & ~7
            i = pos >> 3
            n, nn = int.from_bytes(d[i:i + 2], "little"), int.from_bytes(d[i + 2:i + 4], "little")
            if n ^ nn != 0xFFFF:
                raise PackportError("The data is damaged (a stored Deflate64 block's length)")
            out += d[i + 4:i + 4 + n]
            pos += (4 + n) * 8
        else:
            if kind == 1:
                (lit, lbits), (dist, dbits) = _fixed()
            elif kind == 2:
                hlit, hdist, hclen = bits(5) + 257, bits(5) + 1, bits(4) + 4
                cl = [0] * 19
                for k in range(hclen):
                    cl[ORDER[k]] = bits(3)
                ctab, cbits = _table(cl)
                lengths: list[int] = []
                while len(lengths) < hlit + hdist:
                    e = ctab[_peek(d, pos, cbits)]
                    if e < 0:
                        raise PackportError("The data is damaged (a bad Deflate64 code)")
                    pos += e & 15
                    sym = e >> 4
                    if sym < 16:
                        lengths.append(sym)
                    elif sym == 16:
                        if not lengths:
                            raise PackportError("The data is damaged (a Deflate64 code repeats nothing)")
                        lengths += [lengths[-1]] * (3 + bits(2))
                    elif sym == 17:
                        lengths += [0] * (3 + bits(3))
                    else:
                        lengths += [0] * (11 + bits(7))
                if len(lengths) > hlit + hdist:
                    raise PackportError("The data is damaged (Deflate64 code lengths overflow)")
                (lit, lbits), (dist, dbits) = _table(lengths[:hlit]), _table(lengths[hlit:])
            else:
                raise PackportError("The data is damaged (Deflate64 block type 3)")
            flush_at = given + piece
            while True:
                if pos > lim or len(out) > flush_at:
                    if len(out) - given >= piece:  # hand out what's new, keep the window
                        yield bytes(out[given:size - total])
                        given = len(out)
                        if given > WINDOW:
                            drop = given - WINDOW
                            del out[:drop]
                            total += drop
                            given = WINDOW
                    if total + len(out) >= size:
                        break
                    flush_at = given + piece
                    if pos > lim:
                        if more:
                            lim = refill()
                        else:
                            raise PackportError("The data is damaged or cut short (Deflate64 data ended early)")
                i = pos >> 3
                v = int.from_bytes(d[i:i + 8], "little") >> (pos & 7)
                e = lit[v & ((1 << lbits) - 1)]
                if e < 0:
                    raise PackportError("The data is damaged (a bad Deflate64 code)")
                n = e & 15
                pos += n
                v >>= n
                sym = e >> 4
                if sym < 256:
                    out.append(sym)
                    continue
                if sym == 256:
                    break
                sym -= 257
                if sym > 28:
                    raise PackportError("The data is damaged (a Deflate64 length code)")
                extra = LENGTH_EXTRA[sym]
                length = LENGTH_BASE[sym] + (v & ((1 << extra) - 1))
                pos += extra
                if extra > 13:  # code 285's 16 bits: read the distance afresh
                    i = pos >> 3
                    v = int.from_bytes(d[i:i + 8], "little") >> (pos & 7)
                else:
                    v >>= extra
                e = dist[v & ((1 << dbits) - 1)]
                if e < 0:
                    raise PackportError("The data is damaged (a bad Deflate64 code)")
                pos += e & 15
                v >>= e & 15
                ds = e >> 4
                if ds > 31:
                    raise PackportError("The data is damaged (a Deflate64 distance code)")
                extra = DIST_EXTRA[ds]
                distance = DIST_BASE[ds] + (int.from_bytes(d[pos >> 3:(pos >> 3) + 4], "little") >> (pos & 7)
                                            & ((1 << extra) - 1))
                pos += extra
                if distance > len(out):
                    raise PackportError("The data is damaged (a Deflate64 match reaches before the start)")
                start = len(out) - distance
                if distance >= length:
                    out += out[start:start + length]
                else:
                    out += (out[start:] * (length // distance + 1))[:length]
        if len(out) - given >= piece:
            yield bytes(out[given:size - total])
            given = len(out)
            if given > WINDOW:
                drop = given - WINDOW
                del out[:drop]
                total += drop
                given = WINDOW
        if final:
            break
    if len(out) > given:
        yield bytes(out[given:size - total])


def _peek(d: bytes, pos: int, n: int) -> int:
    i = pos >> 3
    return (int.from_bytes(d[i:i + 4], "little") >> (pos & 7)) & ((1 << n) - 1)
