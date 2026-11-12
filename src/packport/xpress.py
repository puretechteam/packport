"""XPRESS with Huffman coding ("LZ77+Huffman"), written from Microsoft's [MS-XCA] section 2.2:
the compression of WIM resources and NTFS's compressed files.

Output comes in blocks of 64 KB. Each block starts with 256 bytes holding the 512 code lengths
(4 bits each, low nibble first) of its Huffman code: symbols 0-255 are literals, 256-511 matches
whose low four bits are the length less 3 (15: more length follows in the byte stream) and high
four bits how many bits of offset follow. Codes are read from 16-bit little-endian words, most
significant bit first; extra length bytes are read from the byte stream where it stands.
"""

from __future__ import annotations

from ._accel import native
from .bits import huffman
from .entries import PackportError

BLOCK = 65536


def decompress(data: bytes, size: int) -> bytes:
    """size bytes of output from XPRESS Huffman data."""
    out = bytearray()
    pos = 0
    n = len(data)
    d = bytes(data) + bytes(8)
    while len(out) < size:
        if pos + 256 > n:
            raise PackportError("The data is damaged (an XPRESS block is cut short)")
        lengths = []
        for b in d[pos:pos + 256]:
            lengths.append(b & 15)
            lengths.append(b >> 4)
        table = huffman(lengths)
        pos += 256
        # the bit buffer: 32 bits, the next bit at the top; refilled 16 bits at a time
        bits = (d[pos] | d[pos + 1] << 8) << 16 | d[pos + 2] | d[pos + 3] << 8
        pos += 4
        have = 32
        block_end = min(size, len(out) + BLOCK)
        while len(out) < block_end:
            e = table[(bits >> 17) & 0x7FFF]
            if e < 0:
                raise PackportError("The data is damaged (a bad XPRESS Huffman code)")
            k = e & 15
            bits = (bits << k) & 0xFFFFFFFF
            have -= k
            if have < 16:
                bits |= (d[pos] | d[pos + 1] << 8) << (16 - have)
                pos += 2
                have += 16
            sym = e >> 4
            if sym < 256:
                out.append(sym)
                continue
            sym -= 256
            length = sym & 15
            log2 = sym >> 4
            if length == 15:
                length = d[pos]
                pos += 1
                if length == 255:
                    length = d[pos] | d[pos + 1] << 8
                    pos += 2
                    if length == 0:
                        length = int.from_bytes(d[pos:pos + 4], "little")
                        pos += 4
                    if length < 15:
                        raise PackportError("The data is damaged (an XPRESS match length)")
                    length -= 15
                length += 15
            length += 3
            # a 32-bit length can say gigabytes: only what's left of size is ever copied
            length = min(length, size - len(out))
            offset = 1 << log2
            if log2:
                offset |= bits >> (32 - log2)
                bits = (bits << log2) & 0xFFFFFFFF
                have -= log2
                if have < 16:
                    bits |= (d[pos] | d[pos + 1] << 8) << (16 - have)
                    pos += 2
                    have += 16
            if offset > len(out):
                raise PackportError("The data is damaged (an XPRESS match reaches before the start)")
            start = len(out) - offset
            if offset >= length:
                out += out[start:start + length]
            else:
                out += (out[start:] * (length // offset + 1))[:length]
            if pos > n + 4:
                raise PackportError("The data is damaged (XPRESS data ends early)")
        # the next block's table comes where the byte stream stands ([MS-XCA] 2.2.4)
    return bytes(out[:size])


if native is not None:
    decompress = native.xpress_decompress
