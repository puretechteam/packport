"""Test-only encoders for LZH (-lh5- to -lh7-) and ARJ (methods 1 to 4), and the archives around
them. The only samples on hand are a few hundred bytes (LZH) or stored (ARJ), so make_lzh_arj.py
writes big ones with these, and 7-Zip has to read them back.

-lh5- to -lh7- and ARJ 1-3 are the static Huffman scheme of Haruhiko Okumura's public-domain
ar002: greedy LZ77 matches, blocks of tokens, each block with its code lengths. ARJ 4 sends a
literal as a 0 bit and 8 bits, and a match as its length and distance in growing bit groups."""

import heapq
import struct
import time
import zlib

NC = 510


class _BitWriter:
    def __init__(self):
        self.out, self.acc, self.n = bytearray(), 0, 0

    def put(self, value: int, k: int) -> None:
        self.acc = self.acc << k | (value & ((1 << k) - 1))
        self.n += k
        while self.n >= 8:
            self.n -= 8
            self.out.append((self.acc >> self.n) & 0xFF)
        self.acc &= (1 << self.n) - 1

    def done(self) -> bytes:
        if self.n:
            self.out.append((self.acc << (8 - self.n)) & 0xFF)
        return bytes(self.out)


def _tokens(data: bytes, window: int, longest: int = 256, shortest: int = 3) -> list:
    """Greedy LZ77: ints are literals, (length, distance) pairs are matches."""
    head: dict[bytes, int] = {}
    prev = [-1] * len(data)
    out, i, n = [], 0, len(data)

    def insert(k: int) -> None:
        if k + 3 <= n:
            key = data[k:k + 3]
            prev[k] = head.get(key, -1)
            head[key] = k

    while i < n:
        best, dist = 0, 0
        if i + 3 <= n:
            j, tries = head.get(data[i:i + 3], -1), 0
            while j >= 0 and i - j <= window and tries < 48:
                k = 3
                top = min(longest, n - i)
                while k < top and data[j + k] == data[i + k]:
                    k += 1
                if k > best:
                    best, dist = k, i - j
                j, tries = prev[j], tries + 1
        if best >= shortest:
            out.append((best, dist))
            for k in range(i, i + best):
                insert(k)
            i += best
        else:
            out.append(data[i])
            insert(i)
            i += 1
    return out


def _lengths(freq: list[int], limit: int = 16) -> list[int]:
    used = [s for s, f in enumerate(freq) if f]
    if len(used) < 2:
        return [0] * len(freq)
    work = list(freq)
    while True:
        heap = [(work[s], s, (s,)) for s in used]
        heapq.heapify(heap)
        depth = [0] * len(freq)
        tie = len(freq)
        while len(heap) > 1:
            fa, _, a = heapq.heappop(heap)
            fb, _, b = heapq.heappop(heap)
            for s in a + b:
                depth[s] += 1
            heapq.heappush(heap, (fa + fb, tie, a + b))
            tie += 1
        if max(depth) <= limit:
            return depth
        work = [(f >> 1) | 1 if f else 0 for f in work]


def _codes(lengths: list[int]) -> list[int]:
    """Canonical codes: shortest first, then in symbol order (what the decoders assume)."""
    codes, code = [0] * len(lengths), 0
    for n in range(1, 17):
        for s, length in enumerate(lengths):
            if length == n:
                codes[s] = code
                code += 1
        code <<= 1
    return codes


def _put_lengths(bw: _BitWriter, lengths: list[int], nbits: int, special: bool) -> None:
    n = max(i for i, x in enumerate(lengths) if x) + 1
    bw.put(n, nbits)
    i = 0
    while i < n:
        length = lengths[i]
        if length <= 6:
            bw.put(length, 3)
        else:
            bw.put(7, 3)
            for _ in range(length - 7):
                bw.put(1, 1)
            bw.put(0, 1)
        i += 1
        if special and i == 3:
            k = 0
            while k < 3 and i + k < n and lengths[i + k] == 0:
                k += 1
            bw.put(k, 2)
            i += k


def _tree(bw: _BitWriter, freq: list[int], nbits: int, special: bool):
    """Writes a code (or the single symbol it holds); returns (lengths, codes)."""
    used = [s for s, f in enumerate(freq) if f]
    if len(used) == 1:
        bw.put(0, nbits)
        bw.put(used[0], nbits)
        return [0] * len(freq), [0] * len(freq)
    lengths = _lengths(freq)
    _put_lengths(bw, lengths, nbits, special)
    return lengths, _codes(lengths)


def _c_runs(c_len: list[int]) -> list[tuple[int, int, int]]:
    """The literal code's lengths as code-length symbols: (symbol, extra bits, how many)."""
    n = max(i for i, x in enumerate(c_len) if x) + 1
    out, i = [], 0
    while i < n:
        if c_len[i]:
            out.append((c_len[i] + 2, 0, 0))
            i += 1
            continue
        k = 0
        while i + k < n and c_len[i + k] == 0:
            k += 1
        k = min(k, 531)
        if k <= 2:
            out += [(0, 0, 0)] * k
        elif k <= 18:
            out.append((1, k - 3, 4))
        elif k == 19:
            out += [(0, 0, 0), (1, 15, 4)]
        else:
            out.append((2, k - 20, 9))
        i += k
    return out, n


def huffman_lz(data: bytes, window_bits: int, window: int | None = None, block: int = 8000) -> bytes:
    """-lh5- (13), -lh6- (15), -lh7- (16) or ARJ 1-3 (16, with window=26624) data."""
    np, pbits = window_bits + 1, 5 if window_bits >= 15 else 4
    tokens = _tokens(data, window or (1 << window_bits))
    bw = _BitWriter()
    for start in range(0, len(tokens), block):
        part = tokens[start:start + block]
        c_freq, p_freq = [0] * NC, [0] * np
        for t in part:
            if isinstance(t, int):
                c_freq[t] += 1
            else:
                c_freq[t[0] + 253] += 1
                p_freq[(t[1] - 1).bit_length()] += 1
        bw.put(len(part), 16)
        c_used = [s for s, f in enumerate(c_freq) if f]
        if len(c_used) == 1:
            bw.put(0, 5)
            bw.put(0, 5)
            bw.put(0, 9)
            bw.put(c_used[0], 9)
            c_len, c_code = [0] * NC, [0] * NC
        else:
            c_len = _lengths(c_freq)
            c_code = _codes(c_len)
            runs, n = _c_runs(c_len)
            t_freq = [0] * 19
            for sym, _, _ in runs:
                t_freq[sym] += 1
            t_len, t_code = _tree(bw, t_freq, 5, True)
            bw.put(n, 9)
            for sym, extra, k in runs:
                bw.put(t_code[sym], t_len[sym])
                if k:
                    bw.put(extra, k)
        if any(p_freq):
            p_len, p_code = _tree(bw, p_freq, pbits, False)
        else:
            bw.put(0, pbits)
            bw.put(0, pbits)
            p_len, p_code = [0] * np, [0] * np
        for t in part:
            if isinstance(t, int):
                bw.put(c_code[t], c_len[t])
            else:
                length, dist = t
                bw.put(c_code[length + 253], c_len[length + 253])
                p = dist - 1
                code = p.bit_length()
                bw.put(p_code[code], p_len[code])
                if code > 1:
                    bw.put(p - (1 << (code - 1)), code - 1)
    return bw.done()


def arj_fastest(data: bytes) -> bytes:
    """ARJ method 4."""
    bw = _BitWriter()
    for t in _tokens(data, 15872):
        if isinstance(t, int):
            bw.put(0, 1)
            bw.put(t, 8)
            continue
        length, dist = t
        c = length - 2
        w = (c + 1).bit_length() - 1
        for _ in range(w):
            bw.put(1, 1)
        if w < 7:
            bw.put(0, 1)
        bw.put(c - ((1 << w) - 1), w)
        pos, plus, width = dist - 1, 0, 9
        while width < 13 and pos >= plus + (1 << width):
            plus += 1 << width
            width += 1
            bw.put(1, 1)
        if width < 13:
            bw.put(0, 1)
        bw.put(pos - plus, width)
    return bw.done()


def _crc16(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def lzh_archive(files: dict[str, bytes], method: str) -> bytes:
    """A level 2 LZH archive: method "lh0" (stored) or "lh5" to "lh7"."""
    out = bytearray()
    mtime = int(time.mktime((2020, 1, 2, 3, 4, 6, 0, 0, -1)))
    for name, body in files.items():
        packed = body if method == "lh0" else huffman_lz(body, {"lh5": 13, "lh6": 15, "lh7": 16}[method])
        folder, _, base = name.rpartition("/")
        ext = b""
        for kind, value in ((1, base.encode()), (2, folder.replace("/", "\xff").encode("latin-1") + b"\xff" if folder else b"")):
            if value:
                ext += struct.pack("<HB", 3 + len(value), kind) + value
        crc_ext = struct.pack("<HBH", 5, 0, 0)  # the header CRC goes here
        body_ext = crc_ext + ext + b"\0\0"
        size = 24 + len(body_ext)
        if size & 0xFF == 0:
            body_ext += b"\0"
            size += 1
        head = bytearray(struct.pack("<H5sIIIBBHB", size, f"-{method}-".encode(), len(packed), len(body), mtime, 0x20, 2,
                                     _crc16(body), ord("U")) + body_ext)
        struct.pack_into("<H", head, 24 + 3, _crc16(bytes(head)))
        out += head + packed
    return bytes(out + b"\0")


def arj_archive(files: dict[str, bytes], method: int) -> bytes:
    """An ARJ archive: method 0 (stored), 1 to 3, or 4."""
    dos = (2020 - 1980) << 25 | 1 << 21 | 2 << 16 | 3 << 11 | 4 << 5 | 3

    def header(fixed: bytes, name: str) -> bytes:
        basic = fixed + name.encode() + b"\0" + b"\0"
        return b"\x60\xea" + struct.pack("<H", len(basic)) + basic + struct.pack("<I", zlib.crc32(basic)) + b"\0\0"

    out = bytearray(header(struct.pack("<BBBBBBBBIIIIHHBB", 30, 11, 1, 2, 0x10, 0, 2, 0, dos, dos, 0, 0, 0, 0, 0, 0),
                           "test.arj"))
    for name, body in files.items():
        if method == 0:
            packed = body
        elif method == 4:
            packed = arj_fastest(body)
        else:
            packed = huffman_lz(body, 16, 26624)
        fixed = struct.pack("<BBBBBBBBIIIIHHH", 30, 11, 1, 2, 0x10, method, 0, 0, dos, len(packed), len(body),
                            zlib.crc32(body), 0, 0o100644, 0)
        out += header(fixed, name) + packed
    return bytes(out + b"\x60\xea\0\0")
