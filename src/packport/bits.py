"""Shared pieces of the decompressors: canonical Huffman tables built for table lookup.

A table for codes of at most ``bits`` bits has 2**bits entries, one per bit pattern a peek of
``bits`` bits can give: ``symbol << 4 | code length``, or -1 for a pattern no code starts with.
Decoders peek ``bits`` bits most significant first, look the entry up, and drop its length:
one lookup per symbol, never a loop over bits.
"""

from __future__ import annotations

from .entries import PackportError


def huffman(lengths, bits: int = 15) -> list[int]:
    """The lookup table for canonical codes of these lengths (0: symbol unused), codes assigned
    shortest first and, within a length, in symbol order (as Deflate, RAR, LZX and LZH do).
    Raises PackportError for lengths no prefix code can have."""
    counts = [0] * (bits + 1)
    for n in lengths:
        if n > bits or n < 0:
            raise PackportError("The archive is damaged (a Huffman code is too long)")
        counts[n] += 1
    counts[0] = 0
    code, first = 0, [0] * (bits + 2)
    for n in range(1, bits + 1):
        code = (code + counts[n - 1]) << 1
        first[n] = code
    if any(first[n] + counts[n] > 1 << n for n in range(1, bits + 1)):
        raise PackportError("The archive is damaged (a Huffman table is over-full)")
    table = [-1] * (1 << bits)
    for sym, n in enumerate(lengths):
        if n:
            c = first[n]
            first[n] += 1
            start, span = c << (bits - n), 1 << (bits - n)
            table[start:start + span] = [sym << 4 | n] * span
    return table
