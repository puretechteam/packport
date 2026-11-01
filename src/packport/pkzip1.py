"""The ZIP methods of PKZIP 1.x (1989-1993): Shrink (method 1) and Implode (method 6).

Written from PKWARE's APPNOTE.TXT. Both read their bits least significant first.

Shrink is LZW with codes of 9 to 13 bits. Code 256 is followed by a subcode: 1 makes codes one
bit wider, 2 frees every code that no other code builds on ("partial clearing"). A new string
takes the lowest free code above 256, so codes freed by a clear are used again first.

Implode is LZ77 over a 4 KB or 8 KB window (flag bit 1) with Shannon-Fano codes: two trees
(lengths and distances), or three when literals are coded too (flag bit 2). Each tree comes first
as run-length coded bit lengths. A 1 bit means a literal, a 0 bit a match: the distance's low 6
(4 KB) or 7 (8 KB) bits as they are, its high bits from the distance tree, then the length (from
the length tree, plus a byte when it says 63), plus 2, or 3 with a literal tree. Matches reaching
before the start of the data read zeros.
"""

from __future__ import annotations

from collections.abc import Iterator

from . import entries
from .entries import PackportError

MAX_CODE_BITS = 13


class _Bits:
    """Bits least significant first, from a byte string, or a readable read a piece at a time."""

    def __init__(self, data, at: int = 0):
        if isinstance(data, (bytes, bytearray)):
            self.data, self.src = data, None
        else:
            self.data, self.src = b"", data
        self.at, self.buf, self.n = at, 0, 0

    def _refill(self) -> bool:
        if self.src is None:
            return False
        self.data, self.at = self.src.read(entries.CHUNK), 0
        if not self.data:
            self.src = None
            return False
        return True

    def get(self, k: int) -> int:
        while self.n < k:
            if self.at >= len(self.data) and not self._refill():
                raise PackportError("The archive is damaged (a member's data runs short)")
            self.buf |= self.data[self.at] << self.n
            self.at += 1
            self.n += 8
        v = self.buf & ((1 << k) - 1)
        self.buf >>= k
        self.n -= k
        return v

    def left(self) -> int:
        """Bits left (at least this many, while more is to be read)."""
        if self.at >= len(self.data) and self.n < 16:
            self._refill()
        return (len(self.data) - self.at) * 8 + self.n + (1 << 20 if self.src is not None else 0)

    def take(self, n: int) -> bytes:
        """n bytes, from a byte boundary (the Implode trees at the start)."""
        out = b""
        while len(out) < n:
            if self.at >= len(self.data) and not self._refill():
                break
            got = self.data[self.at:self.at + n - len(out)]
            self.at += len(got)
            out += got
        return out


def unshrink(data: bytes, size: int) -> bytes:
    return b"".join(unshrink_iter(data, size))


def unshrink_iter(data, size: int) -> Iterator[bytes]:
    """Shrink (bytes or a readable): size bytes, a piece at a time."""
    bits = _Bits(data)
    piece = entries.CHUNK
    total = 0
    top = 1 << MAX_CODE_BITS
    prefix = [-1] * top
    char = list(range(256)) + [0] * (top - 256)
    used = [True] * 256 + [False] * (top - 256)
    width, nxt, prev, prev_first = 9, 257, -1, 0
    out = bytearray()

    def add(p: int, c: int) -> int:
        nonlocal nxt
        while nxt < top and used[nxt]:
            nxt += 1
        if nxt >= top:
            return -1
        prefix[nxt], char[nxt], used[nxt] = p, c, True
        return nxt

    while total + len(out) < size and bits.left() >= width:
        code = bits.get(width)
        if code == 256:
            sub = bits.get(width)
            if sub == 1:
                width = min(width + 1, MAX_CODE_BITS)
            elif sub == 2:
                parent = [False] * top
                for i in range(257, top):
                    if used[i]:
                        parent[prefix[i]] = True
                for i in range(257, top):
                    if not parent[i]:
                        used[i], prefix[i] = False, -1
                nxt = 257
            else:
                raise PackportError("The archive is damaged (a Shrink control code)")
            continue
        fresh = False
        if not used[code]:  # the string being defined right now: the last one plus its first byte
            if prev < 0:
                raise PackportError("The archive is damaged (a Shrink code before its string)")
            code = add(prev, prev_first)
            fresh = True
            if code < 0:
                raise PackportError("The archive is damaged (a Shrink table overflow)")
        string = bytearray()
        c = code
        while c >= 0:
            if len(string) >= top:
                raise PackportError("The archive is damaged (a Shrink code loops)")
            string.append(char[c])
            c = prefix[c]
        string.reverse()
        if prev >= 0 and not fresh:
            add(prev, string[0])
        prev, prev_first = code, string[0]
        out += string
        if len(out) >= piece:
            chunk = bytes(out[:size - total])
            total += len(chunk)
            yield chunk
            out = bytearray()
    if out and total < size:
        yield bytes(out[:size - total])




def _tree(bits: _Bits, count: int) -> dict[tuple[int, int], int]:
    """A Shannon-Fano tree: {(length, code read first bit first): value}."""
    head = bits.take(1)
    if not head:
        raise PackportError("The archive is damaged (an Implode tree)")
    n = head[0] + 1
    raw = bits.take(n)
    lengths = []
    for b in raw:
        lengths += [(b & 0x0F) + 1] * ((b >> 4) + 1)
    if len(lengths) != count or len(raw) < n:
        raise PackportError("The archive is damaged (an Implode tree)")
    order = sorted(range(count), key=lambda v: lengths[v])  # shortest first, then by value
    codes = [0] * count
    code = step = last = 0
    for v in reversed(order):  # the longest codes are counted up from zero
        code += step
        if lengths[v] != last:
            last = lengths[v]
            step = 1 << (16 - last)
        codes[v] = code
    table = {}
    for v in range(count):
        table[(lengths[v], (codes[v] >> (16 - lengths[v])) & ((1 << lengths[v]) - 1))] = v
    return table


def _read(bits: _Bits, table: dict[tuple[int, int], int]) -> int:
    code = 0
    for length in range(1, 17):
        code = code << 1 | bits.get(1)
        v = table.get((length, code))
        if v is not None:
            return v
    raise PackportError("The archive is damaged (an Implode code)")


def explode(data: bytes, size: int, flags: int) -> bytes:
    return b"".join(explode_iter(data, size, flags))


def explode_iter(data, size: int, flags: int) -> Iterator[bytes]:
    """Implode (bytes or a readable): size bytes, a piece at a time. Matches reach back at most
    8 KB, and before the start they read zeros."""
    big_window, literals = bool(flags & 2), bool(flags & 4)
    bits = _Bits(data)
    lit_tree = _tree(bits, 256) if literals else None
    len_tree = _tree(bits, 64)
    dist_tree = _tree(bits, 64)
    low_bits = 7 if big_window else 6
    least = 3 if literals else 2
    window = 1 << 13
    out = bytearray(window)  # zeros before the start
    given = window
    total = 0
    piece = entries.CHUNK
    while total + len(out) - given < size:
        if bits.get(1):
            out.append(_read(bits, lit_tree) if lit_tree else bits.get(8))
        else:
            low = bits.get(low_bits)
            distance = (_read(bits, dist_tree) << low_bits | low) + 1
            length = _read(bits, len_tree)
            if length == 63:
                length += bits.get(8)
            length += least
            start = len(out) - distance
            for k in range(length):
                out.append(out[start + k])
        if len(out) - given >= piece:
            chunk = bytes(out[given:given + size - total])
            total += len(chunk)
            yield chunk
            del out[:len(out) - window]
            given = len(out)
    if len(out) > given and total < size:
        yield bytes(out[given:given + size - total])
