"""PPMd variant I, revision 1 (Dmitry Shkarin's PPMII as PKWARE adopted it): ZIP method 98, with
the carry-less range coder RAR's PPMd uses too.

Written from Igor Pavlov's public-domain Ppmd8 (the LZMA SDK, as libarchive carries it). Like
variant H (ppmd.py), the model lives in one block of memory laid out as the reference lays it
out, because when that memory runs out the model is cut back or started over, and a decoder has
to do that exactly where the encoder did. The layout differs from variant H: a context is
NumStats (one less than its number of symbols), Flags, SummFreq, Stats and Suffix; a free block
is a stamp, the next block and its size in units. The model's "freeze" restore method isn't
supported (the reference leaves it out too: its fixed form doesn't match old encoders).
packport-native has the same model in Rust (Ppmd8Decoder), used in its place when installed.
"""

from __future__ import annotations

import io
from collections.abc import Iterator

from . import entries
from ._accel import native, pump
from .entries import PackportError
from .ppmd import (
    BIN_SCALE,
    EXP_ESCAPE,
    INDX2UNITS,
    INIT_BIN_ESC,
    M32,
    MAX_FREQ,
    NS2BSINDX,
    NUM_INDEXES,
    PERIOD_BITS,
    UNIT_SIZE,
    UNITS2INDX,
    RangeRar,
)

EMPTY = 0xFFFFFFFF
RESTART, CUT_OFF = 0, 1
MIN_ORDER, MAX_ORDER = 2, 16
NS2INDX8 = list(range(5))
_m, _k = 5, 1
for _i in range(5, 260):
    NS2INDX8.append(_m)
    _k -= 1
    if _k == 0:
        _m += 1
        _k = _m - 4
del _i, _m, _k


def _u2i(nu: int) -> int:
    return UNITS2INDX[nu - 1]


class Ppmd8:
    """The model. Addresses are byte offsets into self.mem (0 means none)."""

    def __init__(self, size: int):
        if size < (1 << 11) or size > 0xFFFFFFFF - 12 * 3:
            raise PackportError("The archive is damaged (a PPMd memory size out of range)")
        self.size = size
        self.align = 4 - (size & 3)
        self.mem = bytearray(self.align + size + UNIT_SIZE * 2)
        self.m16 = memoryview(self.mem).cast("H")
        self.free = [0] * NUM_INDEXES
        self.stamps = [0] * NUM_INDEXES
        self.see = [[[0, 0, 0] for _ in range(32)] for _ in range(24)]  # [summ, shift, count]
        self.dummy_see = [0, PERIOD_BITS, 64]
        self.bin_summ = [[0] * 64 for _ in range(25)]
        self.init_esc = 0

    # -- memory: bytes, 16-bit fields, and 32-bit references made of two of them

    def _get32(self, a: int) -> int:
        m = self.m16
        return m[a >> 1] | m[(a >> 1) + 1] << 16

    def _set32(self, a: int, v: int) -> None:
        m = self.m16
        m[a >> 1] = v & 0xFFFF
        m[(a >> 1) + 1] = v >> 16

    def _summ(self, c: int) -> int:
        return self.m16[(c >> 1) + 1]

    def _set_summ(self, c: int, v: int) -> None:
        self.m16[(c >> 1) + 1] = v & 0xFFFF

    def _copy(self, dst: int, src: int, nu: int) -> None:
        self.mem[dst:dst + UNIT_SIZE * nu] = self.mem[src:src + UNIT_SIZE * nu]

    def _swap(self, a: int, b: int) -> None:
        mem = self.mem
        mem[a:a + 6], mem[b:b + 6] = mem[b:b + 6], mem[a:a + 6]

    # -- allocator (units of 12 bytes)

    def _insert(self, node: int, indx: int) -> None:
        self._set32(node, EMPTY)
        self._set32(node + 4, self.free[indx])
        self._set32(node + 8, INDX2UNITS[indx])
        self.free[indx] = node
        self.stamps[indx] += 1

    def _remove(self, indx: int) -> int:
        node = self.free[indx]
        self.free[indx] = self._get32(node + 4)
        self.stamps[indx] -= 1
        return node

    def _split(self, ptr: int, old: int, new: int) -> None:
        nu = INDX2UNITS[old] - INDX2UNITS[new]
        ptr += UNIT_SIZE * INDX2UNITS[new]
        i = _u2i(nu)
        if INDX2UNITS[i] != nu:
            i -= 1
            k = INDX2UNITS[i]
            self._insert(ptr + UNIT_SIZE * k, nu - k - 1)
        self._insert(ptr, i)

    def _glue(self) -> None:
        get, put = self._get32, self._set32
        self.glue_count = 1 << 13
        self.stamps = [0] * NUM_INDEXES
        if self.lo_unit != self.hi_unit:
            put(self.lo_unit, 0)
        head, prev = 0, -1  # prev: where the last kept block's "next" lives (-1: head)
        for i in range(NUM_INDEXES):
            nxt = self.free[i]
            self.free[i] = 0
            while nxt:
                node = nxt
                if get(node + 8):
                    if prev < 0:
                        head = nxt
                    else:
                        put(prev, nxt)
                    prev = node + 4
                    while True:
                        node2 = node + UNIT_SIZE * get(node + 8)
                        if get(node2) != EMPTY:
                            break
                        put(node + 8, get(node + 8) + get(node2 + 8))
                        put(node2 + 8, 0)
                nxt = get(node + 4)
        if prev < 0:
            head = 0
        else:
            put(prev, 0)
        while head:
            node = head
            head = get(node + 4)
            nu = get(node + 8)
            if nu == 0:
                continue
            while nu > 128:
                self._insert(node, NUM_INDEXES - 1)
                nu -= 128
                node += UNIT_SIZE * 128
            i = _u2i(nu)
            if INDX2UNITS[i] != nu:
                i -= 1
                k = INDX2UNITS[i]
                self._insert(node + UNIT_SIZE * k, nu - k - 1)
            self._insert(node, i)

    def _alloc_rare(self, indx: int) -> int:
        if self.glue_count == 0:
            self._glue()
            if self.free[indx]:
                return self._remove(indx)
        i = indx
        while True:
            i += 1
            if i == NUM_INDEXES:
                num = UNIT_SIZE * INDX2UNITS[indx]
                self.glue_count = (self.glue_count - 1) & M32
                if self.units_start - self.text > num:
                    self.units_start -= num
                    return self.units_start
                return 0
            if self.free[i]:
                break
        ret = self._remove(i)
        self._split(ret, i, indx)
        return ret

    def _alloc(self, indx: int) -> int:
        if self.free[indx]:
            return self._remove(indx)
        num = UNIT_SIZE * INDX2UNITS[indx]
        if num <= self.hi_unit - self.lo_unit:
            ret = self.lo_unit
            self.lo_unit += num
            return ret
        return self._alloc_rare(indx)

    def _shrink(self, old: int, old_nu: int, new_nu: int) -> int:
        i0, i1 = _u2i(old_nu), _u2i(new_nu)
        if i0 == i1:
            return old
        if self.free[i1]:
            ptr = self._remove(i1)
            self._copy(ptr, old, new_nu)
            self._insert(old, i0)
            return ptr
        self._split(old, i0, i1)
        return old

    def _free_units(self, ptr: int, nu: int) -> None:
        self._insert(ptr, _u2i(nu))

    def _special_free(self, ptr: int) -> None:
        if ptr != self.units_start:
            self._insert(ptr, 0)
        else:
            self.units_start += UNIT_SIZE

    def _move_up(self, old: int, nu: int) -> int:
        indx = _u2i(nu)
        if old > self.units_start + 16 * 1024 or old > self.free[indx]:
            return old
        ptr = self._remove(indx)
        self._copy(ptr, old, nu)
        if old != self.units_start:
            self._insert(old, indx)
        else:
            self.units_start += UNIT_SIZE * INDX2UNITS[indx]
        return ptr

    def _expand_text(self) -> None:
        get, put = self._get32, self._set32
        count = [0] * NUM_INDEXES
        if self.lo_unit != self.hi_unit:
            put(self.lo_unit, 0)
        node = self.units_start
        while get(node) == EMPTY:
            put(node, 0)
            count[_u2i(get(node + 8))] += 1
            node += UNIT_SIZE * get(node + 8)
        self.units_start = node
        for i in range(NUM_INDEXES):
            where = -1  # the free-list head, or the "next" field of the block before
            while count[i]:
                node = self.free[i] if where < 0 else get(where)
                while get(node) == 0:
                    nxt = get(node + 4)
                    if where < 0:
                        self.free[i] = nxt
                    else:
                        put(where, nxt)
                    node = nxt
                    self.stamps[i] -= 1
                    count[i] -= 1
                    if count[i] == 0:
                        break
                where = node + 4

    def _used(self) -> int:
        v = sum(self.stamps[i] * INDX2UNITS[i] for i in range(NUM_INDEXES))
        return (self.size - (self.hi_unit - self.lo_unit) - (self.units_start - self.text) - UNIT_SIZE * v) & M32

    # -- the model

    def init(self, max_order: int, restore: int) -> None:
        self.max_order, self.restore = max_order, restore
        self._restart()

    def _restart(self) -> None:
        mem, put = self.mem, self._set32
        self.free = [0] * NUM_INDEXES
        self.stamps = [0] * NUM_INDEXES
        self.text = self.align
        self.hi_unit = self.text + self.size
        self.lo_unit = self.units_start = self.hi_unit - self.size // 8 // UNIT_SIZE * 7 * UNIT_SIZE
        self.glue_count = 0
        self.order_fall = self.max_order
        self.run_length = self.init_rl = -min(self.max_order, 12) - 1
        self.prev_success = 0
        self.hi_unit -= UNIT_SIZE
        c = self.min_context = self.max_context = self.hi_unit
        put(c + 8, 0)
        mem[c], mem[c + 1] = 255, 0
        self._set_summ(c, 257)
        self.found = self.lo_unit
        self.lo_unit += UNIT_SIZE * 128
        put(c + 4, self.found)
        for i in range(256):
            s = self.found + 6 * i
            mem[s], mem[s + 1] = i, 1
            put(s + 2, 0)
        i = 0
        for m in range(25):
            while NS2INDX8[i] == m:
                i += 1
            for k in range(8):
                val = BIN_SCALE - INIT_BIN_ESC[k] // (i + 1)
                for r in range(0, 64, 8):
                    self.bin_summ[m][k + r] = val
        i = 0
        for m in range(24):
            while NS2INDX8[i + 3] == m + 3:
                i += 1
            for k in range(32):
                see = self.see[m][k]
                see[1] = PERIOD_BITS - 4
                see[0] = ((2 * i + 5) << see[1]) & 0xFFFF
                see[2] = 7

    def _refresh(self, c: int, old_nu: int, scale: int) -> None:
        mem = self.mem
        i = mem[c]
        s = self._shrink(self._get32(c + 4), old_nu, (i + 2) >> 1)
        self._set32(c + 4, s)
        flags = (mem[c + 1] & (0x10 + 0x04 * scale)) + 0x08 * (mem[s] >= 0x40)
        esc = self._summ(c) - mem[s + 1]
        f = (mem[s + 1] + scale) >> scale
        mem[s + 1] = f
        total = f
        for _ in range(i):
            s += 6
            esc -= mem[s + 1]
            f = (mem[s + 1] + scale) >> scale
            mem[s + 1] = f
            total += f
            flags |= 0x08 * (mem[s] >= 0x40)
        self._set_summ(c, total + (((esc & M32) + scale) >> scale))
        mem[c + 1] = flags & 0xFF

    def _cut_off(self, c: int, order: int) -> int:
        mem, get, put = self.mem, self._get32, self._set32
        if mem[c] == 0:
            s = c + 2
            if get(s + 2) >= self.units_start:
                put(s + 2, self._cut_off(get(s + 2), order + 1) if order < self.max_order else 0)
                if get(s + 2) or order <= 9:
                    return c
            self._special_free(c)
            return 0
        tmp = (mem[c] + 2) >> 1
        put(c + 4, self._move_up(get(c + 4), tmp))
        stats = get(c + 4)
        i = mem[c]
        s = stats + 6 * i
        while s >= stats:
            if get(s + 2) < self.units_start:
                s2 = stats + 6 * i
                i -= 1
                put(s + 2, 0)
                self._swap(s, s2)
            elif order < self.max_order:
                put(s + 2, self._cut_off(get(s + 2), order + 1))
            else:
                put(s + 2, 0)
            s -= 6
        if i != mem[c] and order:
            mem[c] = i & 0xFF
            s = stats
            if i < 0:
                self._free_units(s, tmp)
                self._special_free(c)
                return 0
            if i == 0:
                mem[c + 1] = (mem[c + 1] & 0x10) + 0x08 * (mem[s] >= 0x40)
                mem[c + 2:c + 8] = mem[s:s + 6]
                self._free_units(s, tmp)
                mem[c + 3] = (mem[c + 3] + 11) >> 3
            else:
                self._refresh(c, tmp, int(self._summ(c) > 16 * i))
        return c

    def _restore(self, c1: int) -> None:
        mem, get = self.mem, self._get32
        self.text = self.align
        c = self.max_context
        while c != c1:
            ns = (mem[c] - 1) & 0xFF
            mem[c] = ns
            if ns == 0:
                s = get(c + 4)
                mem[c + 1] = (mem[c + 1] & 0x10) + 0x08 * (mem[s] >= 0x40)
                mem[c + 2:c + 8] = mem[s:s + 6]
                self._special_free(s)
                mem[c + 3] = (mem[c + 3] + 11) >> 3
            else:
                self._refresh(c, (ns + 3) >> 1, 0)
            c = get(c + 8)
        while c != self.min_context:
            if mem[c] == 0:
                mem[c + 3] -= mem[c + 3] >> 1
            else:
                v = (self._summ(c) + 4) & 0xFFFF
                self._set_summ(c, v)
                if v > 128 + 4 * mem[c]:
                    self._refresh(c, (mem[c] + 2) >> 1, 1)
            c = get(c + 8)
        if self.restore == RESTART or self._used() < (self.size >> 1):
            self._restart()
            return
        while get(self.max_context + 8):
            self.max_context = get(self.max_context + 8)
        while True:
            self._cut_off(self.max_context, 0)
            self._expand_text()
            if self._used() <= 3 * (self.size >> 2):
                break
        self.glue_count = 0
        self.order_fall = self.max_order

    def _create_successors(self, skip: bool, s1: int, c: int) -> int:
        mem, get, put = self.mem, self._get32, self._set32
        fs = self.found
        up_branch = get(fs + 2)
        fsym = mem[fs]
        ps = [] if skip else [fs]
        while get(c + 8):
            c = get(c + 8)
            if s1:
                s, s1 = s1, 0
            elif mem[c]:
                s = get(c + 4)
                while mem[s] != fsym:
                    s += 6
                if mem[s + 1] < MAX_FREQ - 9:
                    mem[s + 1] += 1
                    self._set_summ(c, self._summ(c) + 1)
            else:
                s = c + 2
                mem[s + 1] += int(mem[get(c + 8)] == 0 and mem[s + 1] < 24)
            succ = get(s + 2)
            if succ != up_branch:
                c = succ
                if not ps:
                    return c
                break
            ps.append(s)
        up_sym = mem[up_branch]
        flags = 0x10 * (fsym >= 0x40) + 0x08 * (up_sym >= 0x40)
        if mem[c] == 0:
            up_freq = mem[c + 3]
        else:
            s = get(c + 4)
            while mem[s] != up_sym:
                s += 6
            cf = mem[s + 1] - 1
            s0 = (self._summ(c) - mem[c] - cf) & M32
            if 2 * cf <= s0:
                up_freq = 1 + int(5 * cf > s0)
            else:
                up_freq = (1 + ((cf + 2 * s0 - 3) & M32) // s0) & 0xFF
        while ps:
            if self.hi_unit != self.lo_unit:
                self.hi_unit -= UNIT_SIZE
                c1 = self.hi_unit
            elif self.free[0]:
                c1 = self._remove(0)
            else:
                c1 = self._alloc_rare(0)
                if not c1:
                    return 0
            mem[c1], mem[c1 + 1], mem[c1 + 2], mem[c1 + 3] = 0, flags, up_sym, up_freq
            put(c1 + 4, up_branch + 1)
            put(c1 + 8, c)
            put(ps.pop() + 2, c1)
            c = c1
        return c

    def _reduce_order(self, s1: int, c: int) -> int:
        mem, get, put = self.mem, self._get32, self._set32
        c1 = c
        up_branch = self.text
        fsym = mem[self.found]
        put(self.found + 2, up_branch)
        self.order_fall += 1
        s = 0
        while True:
            if s1:
                c = get(c + 8)
                s, s1 = s1, 0
            else:
                if not get(c + 8):
                    return c
                c = get(c + 8)
                if mem[c]:
                    s = get(c + 4)
                    while mem[s] != fsym:
                        s += 6
                    if mem[s + 1] < MAX_FREQ - 9:
                        mem[s + 1] += 2
                        self._set_summ(c, self._summ(c) + 2)
                else:
                    s = c + 2
                    mem[s + 1] += int(mem[s + 1] < 32)
            if get(s + 2):
                break
            put(s + 2, up_branch)
            self.order_fall += 1
        if get(s + 2) <= up_branch:
            s2 = self.found
            self.found = s
            put(s + 2, self._create_successors(False, 0, c))
            self.found = s2
        if self.order_fall == 1 and c1 == self.max_context:
            put(self.found + 2, get(s + 2))
            self.text -= 1
        return get(s + 2)

    def _update_model(self) -> None:
        mem, get, put = self.mem, self._get32, self._set32
        fs = self.found
        f_succ, ffreq, fsym = get(fs + 2), mem[fs + 1], mem[fs]
        s = 0
        minc = self.min_context
        if ffreq < MAX_FREQ // 4 and get(minc + 8):
            c = get(minc + 8)
            if mem[c] == 0:
                s = c + 2
                if mem[s + 1] < 32:
                    mem[s + 1] += 1
            else:
                s = get(c + 4)
                if mem[s] != fsym:
                    s += 6
                    while mem[s] != fsym:
                        s += 6
                    if mem[s + 1] >= mem[s - 5]:
                        self._swap(s, s - 6)
                        s -= 6
                if mem[s + 1] < MAX_FREQ - 9:
                    mem[s + 1] += 2
                    self._set_summ(c, self._summ(c) + 2)
        c = self.max_context
        if self.order_fall == 0 and f_succ:
            cs = self._create_successors(True, s, minc)
            if cs == 0:
                put(fs + 2, 0)
                self._restore(c)
            else:
                put(fs + 2, cs)
                self.max_context = cs
            return
        mem[self.text] = fsym
        self.text += 1
        successor = self.text
        if self.text >= self.units_start:
            self._restore(c)
            return
        if not f_succ:
            cs = self._reduce_order(s, minc)
            if cs == 0:
                self._restore(c)
                return
            f_succ = cs
        elif f_succ < self.units_start:
            cs = self._create_successors(False, s, minc)
            if cs == 0:
                self._restore(c)
                return
            f_succ = cs
        self.order_fall -= 1
        if self.order_fall == 0:
            successor = f_succ
            self.text -= int(self.max_context != minc)
        ns = mem[minc]
        s0 = (self._summ(minc) - ns - ffreq) & M32
        flag = 0x08 * (fsym >= 0x40)
        while c != minc:
            ns1 = mem[c]
            if ns1:
                if ns1 & 1:
                    old_nu = (ns1 + 1) >> 1
                    i = _u2i(old_nu)
                    if i != _u2i(old_nu + 1):
                        ptr = self._alloc(i + 1)
                        if not ptr:
                            self._restore(c)
                            return
                        old = get(c + 4)
                        self._copy(ptr, old, old_nu)
                        self._insert(old, i)
                        put(c + 4, ptr)
                self._set_summ(c, self._summ(c) + int(3 * ns1 + 1 < ns))
            else:
                s2 = self._alloc(0)
                if not s2:
                    self._restore(c)
                    return
                mem[s2:s2 + 6] = mem[c + 2:c + 8]
                put(c + 4, s2)
                f = mem[s2 + 1]
                mem[s2 + 1] = f << 1 if f < MAX_FREQ // 4 - 1 else MAX_FREQ - 4
                self._set_summ(c, mem[s2 + 1] + self.init_esc + int(ns > 2))
            summ = self._summ(c)
            cf = 2 * ffreq * (summ + 6)
            sf = (s0 + summ) & M32
            if cf < ((6 * sf) & M32):
                cf = 1 + int(cf > sf) + int(cf >= ((4 * sf) & M32))
                self._set_summ(c, summ + 4)
            else:
                cf = 4 + int(cf > ((9 * sf) & M32)) + int(cf > ((12 * sf) & M32)) + int(cf > ((15 * sf) & M32))
                self._set_summ(c, summ + cf)
            s2 = get(c + 4) + 6 * (ns1 + 1)
            put(s2 + 2, successor)
            mem[s2], mem[s2 + 1] = fsym, cf
            mem[c + 1] |= flag
            mem[c] = ns1 + 1
            c = get(c + 8)
        self.max_context = self.min_context = f_succ

    def _rescale(self) -> None:
        mem = self.mem
        mc = self.min_context
        stats = self._get32(mc + 4)
        s = self.found
        tmp = mem[s:s + 6]
        while s != stats:
            mem[s:s + 6] = mem[s - 6:s]
            s -= 6
        mem[s:s + 6] = tmp
        esc = self._summ(mc) - mem[s + 1]
        adder = int(self.order_fall != 0)
        mem[s + 1] = (((mem[s + 1] + 4) & 0xFF) + adder) >> 1
        total = mem[s + 1]
        for _ in range(mem[mc]):
            s += 6
            esc -= mem[s + 1]
            mem[s + 1] = (mem[s + 1] + adder) >> 1
            total += mem[s + 1]
            if mem[s + 1] > mem[s - 5]:
                s1 = s
                tmp = mem[s1:s1 + 6]
                while True:
                    mem[s1:s1 + 6] = mem[s1 - 6:s1]
                    s1 -= 6
                    if s1 == stats or tmp[1] <= mem[s1 - 5]:
                        break
                mem[s1:s1 + 6] = tmp
        if mem[s + 1] == 0:
            num_stats = mem[mc]
            i = 0
            while True:
                i += 1
                s -= 6
                if mem[s + 1]:
                    break
            esc += i
            mem[mc] = num_stats - i
            if mem[mc] == 0:
                tmp = bytearray(mem[stats:stats + 6])
                e = esc & M32
                tmp[1] = min(((2 * tmp[1] + e - 1) // e) & 0xFF, MAX_FREQ // 3)
                self._insert(stats, _u2i((num_stats + 2) >> 1))
                mem[mc + 1] = (mem[mc + 1] & 0x10) + 0x08 * (tmp[0] >= 0x40)
                self.found = mc + 2
                mem[mc + 2:mc + 8] = tmp
                return
            n0, n1 = (num_stats + 2) >> 1, (mem[mc] + 2) >> 1
            if n0 != n1:
                self._set32(mc + 4, self._shrink(stats, n0, n1))
            mem[mc + 1] &= 0xF7
            s = self._get32(mc + 4)
            flags = mem[mc + 1] | 0x08 * (mem[s] >= 0x40)
            for _ in range(mem[mc]):
                s += 6
                flags |= 0x08 * (mem[s] >= 0x40)
            mem[mc + 1] = flags
        esc &= M32
        self._set_summ(mc, total + esc - (esc >> 1))
        mem[mc + 1] |= 0x04
        self.found = self._get32(mc + 4)

    def _make_esc_freq(self, num_masked: int):
        mem = self.mem
        mc = self.min_context
        ns = mem[mc]
        if ns == 0xFF:
            return self.dummy_see, 1
        see = self.see[NS2INDX8[ns + 2] - 3][
            int(self._summ(mc) > 11 * (ns + 1))
            + 2 * int(2 * ns < mem[self._get32(mc + 8)] + num_masked)
            + mem[mc + 1]]
        r = see[0] >> see[1]
        see[0] = (see[0] - r) & 0xFFFF
        return see, r + (r == 0)

    def _next_context(self) -> None:
        c = self._get32(self.found + 2)
        if self.order_fall == 0 and c >= self.units_start:
            self.min_context = self.max_context = c
        else:
            self._update_model()
            self.min_context = self.max_context

    def _update1(self) -> None:
        mem = self.mem
        s = self.found
        mem[s + 1] += 4
        self._set_summ(self.min_context, self._summ(self.min_context) + 4)
        if mem[s + 1] > mem[s - 5]:
            self._swap(s, s - 6)
            self.found = s - 6
            if mem[s - 5] > MAX_FREQ:
                self._rescale()
        self._next_context()

    def _update1_0(self) -> None:
        mem, mc = self.mem, self.min_context
        self.prev_success = int(2 * mem[self.found + 1] >= self._summ(mc))
        self.run_length += self.prev_success
        self._set_summ(mc, self._summ(mc) + 4)
        mem[self.found + 1] += 4
        if mem[self.found + 1] > MAX_FREQ:
            self._rescale()
        self._next_context()

    def _update_bin(self) -> None:
        f = self.mem[self.found + 1]
        self.mem[self.found + 1] = f + (f < 196)
        self.prev_success = 1
        self.run_length += 1
        self._next_context()

    def _update2(self) -> None:
        mc = self.min_context
        self._set_summ(mc, self._summ(mc) + 4)
        self.mem[self.found + 1] += 4
        if self.mem[self.found + 1] > MAX_FREQ:
            self._rescale()
        self.run_length = self.init_rl
        self._update_model()
        self.min_context = self.max_context

    def decode_symbol(self, rc: RangeRar) -> int:
        """The next byte, -1 at the end mark, -2 for damaged data."""
        mem, get = self.mem, self._get32
        mc = self.min_context
        if mem[mc]:
            s = get(mc + 4)
            summ = self._summ(mc)
            count = rc.threshold(summ)
            hi = mem[s + 1]
            if count < hi:
                rc.decode(0, hi)
                self.found = s
                sym = mem[s]
                self._update1_0()
                return sym
            self.prev_success = 0
            for _ in range(mem[mc]):
                s += 6
                hi += mem[s + 1]
                if hi > count:
                    rc.decode(hi - mem[s + 1], mem[s + 1])
                    self.found = s
                    sym = mem[s]
                    self._update1()
                    return sym
            if count >= summ:
                return -2
            rc.decode(hi, summ - hi)
            mask = bytearray(b"\xff" * 256)
            stats = get(mc + 4)
            for k in range(mem[mc] + 1):
                mask[mem[stats + 6 * k]] = 0
        else:
            row = self.bin_summ[NS2INDX8[mem[mc + 3] - 1]]
            col = (NS2BSINDX[mem[get(mc + 8)]] + self.prev_success + mem[mc + 1]
                   + ((self.run_length >> 26) & 0x20))
            prob = row[col]
            if rc.bit(prob, BIN_SCALE) == 0:
                row[col] = (prob + (1 << 7) - ((prob + 32) >> 7)) & 0xFFFF
                self.found = mc + 2
                sym = mem[mc + 2]
                self._update_bin()
                return sym
            prob = (prob - ((prob + 32) >> 7)) & 0xFFFF
            row[col] = prob
            self.init_esc = EXP_ESCAPE[prob >> 10]
            mask = bytearray(b"\xff" * 256)
            mask[mem[mc + 2]] = 0
            self.prev_success = 0
        while True:
            num_masked = mem[self.min_context]
            while True:
                self.order_fall += 1
                suffix = get(self.min_context + 8)
                if not suffix:
                    return -1
                self.min_context = suffix
                if mem[suffix] != num_masked:
                    break
            mc = self.min_context
            s = get(mc + 4)
            ps = []
            hi = 0
            want = mem[mc] - num_masked
            while len(ps) != want:
                if mask[mem[s]]:
                    hi += mem[s + 1]
                    ps.append(s)
                s += 6
            see, freq_sum = self._make_esc_freq(num_masked)
            freq_sum += hi
            count = rc.threshold(freq_sum)
            if count < hi:
                acc = 0
                for s in ps:
                    acc += mem[s + 1]
                    if acc > count:
                        break
                rc.decode(acc - mem[s + 1], mem[s + 1])
                if see[1] < PERIOD_BITS:
                    see[2] -= 1
                    if see[2] == 0:
                        see[0] = (see[0] << 1) & 0xFFFF
                        see[2] = 3 << see[1]
                        see[1] += 1
                self.found = s
                sym = mem[s]
                self._update2()
                return sym
            if count >= freq_sum:
                return -2
            rc.decode(hi, freq_sum - hi)
            see[0] = (see[0] + freq_sum) & 0xFFFF
            for s in ps:
                mask[mem[s]] = 0


def decode_zip(data: bytes, size: int, name: str) -> bytes:
    """A ZIP member packed with method 98 (see decode_zip_iter), whole."""
    return b"".join(decode_zip_iter(io.BytesIO(data), size, name))


def decode_zip_iter(raw, size: int, name: str) -> Iterator[bytes]:
    """A ZIP member packed with method 98 (raw: a readable): a 2-byte header (order - 1 in the
    low 4 bits, then the memory in MB - 1 in 8 bits, then the restore method), then the
    range-coded data. size bytes, a piece at a time."""
    head = raw.read(2)
    if len(head) < 2:
        raise PackportError(f"{name}: the ZIP archive is damaged (PPMd header)")
    v = head[0] | head[1] << 8
    order, mb, restore = (v & 15) + 1, ((v >> 4) & 0xFF) + 1, v >> 12
    if order < MIN_ORDER or restore > CUT_OFF:
        raise PackportError(f"{name}: PPMd settings packport doesn't read (order {order}, restore method {restore})")
    if native is not None:
        try:
            yield from pump(native.Ppmd8Decoder(order, mb << 20, restore), raw, size)
        except PackportError as e:
            raise PackportError(f"{name}: {e}") from None
        return
    model = Ppmd8(mb << 20)
    model.init(order, restore)
    buf, at = b"", 0

    def read() -> int:
        nonlocal buf, at
        if at >= len(buf):
            buf, at = raw.read(entries.CHUNK), 0
            if not buf:
                return 0
        b = buf[at]
        at += 1
        return b

    piece = entries.CHUNK
    left = size
    try:
        rc = RangeRar(read)
        decode = model.decode_symbol
        while left > 0:
            out = bytearray()
            want = min(piece, left)
            while len(out) < want:
                c = decode(rc)
                if c < 0:
                    raise PackportError(f"{name}: the ZIP archive is damaged (bad PPMd data)")
                out.append(c)
            left -= len(out)
            yield bytes(out)
    except ZeroDivisionError:
        raise PackportError(f"{name}: the ZIP archive is damaged (bad PPMd data)") from None
