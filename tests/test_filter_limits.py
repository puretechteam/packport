"""RAR filters can only start inside the dictionary window: unRAR wraps a filter's start
around the window, so a valid archive never puts one further ahead. A damaged one that did used
to make packport hold back all output (and keep all of it in memory) until the decoder got there,
gigabytes on. Such a filter is now refused as damage."""

import pytest

from packport import PackportError
from packport.rar3 import Unpack29
from packport.rar5 import FILTER_DELTA, Unpack5


def _bits(*fields: tuple[int, int]) -> bytes:
    """(value, width) fields, most significant bit first, zero-padded to whole bytes (plus 8 more)."""
    acc, n = 0, 0
    for value, width in fields:
        acc = acc << width | (value & ((1 << width) - 1))
        n += width
    n8 = -(-n // 8) * 8
    return (acc << (n8 - n)).to_bytes(n8 // 8, "big") + bytes(8)


def _rar5_filter(start: int, length: int) -> bytes:
    def number(v: int, count: int):
        return [(count - 1, 2)] + [((v >> (8 * k)) & 0xFF, 8) for k in range(count)]
    return _bits(*number(start, 4), *number(length, 2), (FILTER_DELTA, 3), (3, 5))


def test_rar5_filter_past_the_window_is_damage():
    dec = Unpack5(1 << 22)
    with pytest.raises(PackportError, match="window"):
        dec._filter(_rar5_filter(0x7FFFFFFF, 1000), 0)
    assert dec.filters == []


def test_rar5_filter_inside_the_window_is_kept():
    dec = Unpack5(1 << 22)
    dec._filter(_rar5_filter(1000, 1000), 0)
    assert len(dec.filters) == 1


def _rar3_filter_code(start: int, length: int) -> bytes:
    """A filter definition's parameters: index 1 (a new filter), a 32-bit start, then a length."""
    return _bits((1, 6), (3, 2), (start >> 16, 16), (start & 0xFFFF, 16), (0, 2), (length & 0xFFFF, 16))


def test_rar3_filter_past_the_window_is_damage():
    dec = Unpack29(4 << 20)
    with pytest.raises(PackportError, match="window"):
        dec.add_filter(0x80 | 0x20, _rar3_filter_code(0x7FFFFFFF, 1000))
    assert dec.pending == []


def test_ppmd_models_bigger_than_7zip_writes_are_refused():
    # 7-Zip's PPMd takes at most 2 GB of memory; a damaged header asked for up to 4 GB
    from packport.ppmd import Ppmd7
    with pytest.raises(PackportError, match="2 GB"):
        Ppmd7(3 << 30)


def test_rar3_filter_longer_than_the_vm_is_damage():
    # a filter's block has to fit in RAR's VM memory (256 KB); a damaged length of gigabytes made
    # all output wait behind it, held in memory
    dec = Unpack29(4 << 20)
    code = _bits((1, 6), (0, 2), (0, 4), (3, 2), (0x7FFF, 16), (0xFFFF, 16))  # index 1, start 0, length 2^31
    with pytest.raises(PackportError, match="VM memory"):
        dec.add_filter(0x80 | 0x20, code)
    assert dec.pending == []
