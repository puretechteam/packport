"""PPMd variant H (Dmitry Shkarin's PPMII), the model 7z's PPMd method and RAR 2.9-4.x use, with
both range decoders: 7z's and RAR's (Subbotin's carry-less coder).

Written from Igor Pavlov's public-domain Ppmd7 (LZMA SDK). The model lives in one block of
memory laid out as the reference lays it out (12-byte units: contexts of NumStats, SummFreq,
Stats and Suffix; states of Symbol, Freq and a successor), because when that memory runs out
the model starts over, and a decoder has to run out exactly where the encoder did. Memory is a
bytearray read through a 16-bit view; every field sits on an even address.
"""

from __future__ import annotations

from .entries import PackportError

UNIT_SIZE = 12
MAX_O = 64
MAX_MEMORY = 1 << 31  # 7-Zip's largest PPMd model (its mem= setting goes up to 2 GB)
MAX_FREQ = 124
INT_BITS, PERIOD_BITS = 7, 7
BIN_SCALE = 1 << (INT_BITS + PERIOD_BITS)
NUM_INDEXES = 38
INIT_BIN_ESC = (0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051)
EXP_ESCAPE = (25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2)
TOP, BOT = 1 << 24, 1 << 15
M32 = 0xFFFFFFFF

INDX2UNITS, UNITS2INDX = [], []
for _i in range(NUM_INDEXES):
    _step = 4 if _i >= 12 else (_i >> 2) + 1
    UNITS2INDX += [_i] * _step
    INDX2UNITS.append(len(UNITS2INDX))
NS2BSINDX = [0, 2] + [4] * 9 + [6] * (256 - 11)
NS2INDX = [0, 1, 2]
_m, _k = 3, 1
for _i in range(3, 256):
    NS2INDX.append(_m)
    _k -= 1
    if _k == 0:
        _m += 1
        _k = _m - 2
HB2FLAG = [0] * 0x40 + [8] * (0x100 - 0x40)
del _i, _step, _m, _k


class Ppmd7:
    """The model. Addresses are byte offsets into self.mem (0 means none)."""

    def __init__(self, size: int):
        if size < (1 << 11) or size > 0xFFFFFFFF - 12 * 3:
            raise PackportError("The archive is damaged (a PPMd memory size out of range)")
        if size > MAX_MEMORY:
            raise PackportError("This archive's PPMd model needs more than 2 GB, more than 7-Zip ever writes "
                                "(the archive is probably damaged)")
        self.size = size
        self.align = 4 - (size & 3)
        self.mem = bytearray(self.align + size + UNIT_SIZE + 8)
        self.m16 = memoryview(self.mem).cast("H")
        self.see = [[[0, 0, 0] for _ in range(16)] for _ in range(25)]  # [summ, shift, count]
        self.dummy_see = [0, PERIOD_BITS, 64]
        self.bin_summ = [[0] * 64 for _ in range(128)]
        self.init_esc = self.hi_bits_flag = 0

    # -- memory: 16-bit fields, and the 32-bit references made of two of them

    def _get32(self, a: int) -> int:
        m = self.m16
        return m[a >> 1] | m[(a >> 1) + 1] << 16

    def _set32(self, a: int, v: int) -> None:
        m = self.m16
        m[a >> 1] = v & 0xFFFF
        m[(a >> 1) + 1] = v >> 16

    # -- allocator (units of 12 bytes)

    def _insert(self, node: int, indx: int) -> None:
        self._set32(node, self.free[indx])
        self.free[indx] = node

    def _remove(self, indx: int) -> int:
        node = self.free[indx]
        self.free[indx] = self._get32(node)
        return node

    def _split(self, ptr: int, old: int, new: int) -> None:
        nu = INDX2UNITS[old] - INDX2UNITS[new]
        ptr += INDX2UNITS[new] * UNIT_SIZE
        i = UNITS2INDX[nu - 1]
        if INDX2UNITS[i] != nu:
            i -= 1
            k = INDX2UNITS[i]
            self._insert(ptr + k * UNIT_SIZE, nu - k - 1)
        self._insert(ptr, i)

    def _glue(self) -> None:
        m = self.m16
        head = self.align + self.size
        n = head
        self.glue_count = 255
        for i in range(NUM_INDEXES):
            nu = INDX2UNITS[i]
            nxt = self.free[i]
            self.free[i] = 0
            while nxt:
                node = nxt
                nxt = self._get32(node)
                self._set32(node + 4, n)          # node.Next = n
                self._set32(n + 8, node)          # n.Prev = node
                n = node
                m[node >> 1] = 0                  # Stamp
                m[(node >> 1) + 1] = nu           # NU
        m[head >> 1] = 1
        self._set32(head + 4, n)
        self._set32(n + 8, head)
        if self.lo_unit != self.hi_unit:
            m[self.lo_unit >> 1] = 1
        while n != head:
            node = n
            nu = m[(node >> 1) + 1]
            while True:
                node2 = node + nu * UNIT_SIZE
                nu += m[(node2 >> 1) + 1]
                if m[node2 >> 1] != 0 or nu >= 0x10000:
                    break
                prev, nxt = self._get32(node2 + 8), self._get32(node2 + 4)
                self._set32(prev + 4, nxt)
                self._set32(nxt + 8, prev)
                m[(node >> 1) + 1] = nu
            n = self._get32(node + 4)
        n = self._get32(head + 4)
        while n != head:
            node = n
            nxt = self._get32(node + 4)
            nu = m[(node >> 1) + 1]
            while nu > 128:
                self._insert(node, NUM_INDEXES - 1)
                nu -= 128
                node += 128 * UNIT_SIZE
            i = UNITS2INDX[nu - 1]
            if INDX2UNITS[i] != nu:
                i -= 1
                k = INDX2UNITS[i]
                self._insert(node + k * UNIT_SIZE, nu - k - 1)
            self._insert(node, i)
            n = nxt

    def _alloc_rare(self, indx: int) -> int:
        if self.glue_count == 0:
            self._glue()
            if self.free[indx]:
                return self._remove(indx)
        i = indx
        while True:
            i += 1
            if i == NUM_INDEXES:
                num = INDX2UNITS[indx] * UNIT_SIZE
                self.glue_count -= 1
                if self.units_start - self.text > num:
                    self.units_start -= num
                    return self.units_start
                return 0
            if self.free[i]:
                break
        ptr = self._remove(i)
        self._split(ptr, i, indx)
        return ptr

    def _alloc(self, indx: int) -> int:
        if self.free[indx]:
            return self._remove(indx)
        num = INDX2UNITS[indx] * UNIT_SIZE
        if num <= self.hi_unit - self.lo_unit:
            ptr = self.lo_unit
            self.lo_unit += num
            return ptr
        return self._alloc_rare(indx)

    def _copy_units(self, dst: int, src: int, nu: int) -> None:
        self.mem[dst:dst + nu * UNIT_SIZE] = self.mem[src:src + nu * UNIT_SIZE]

    def _shrink(self, old: int, old_nu: int, new_nu: int) -> int:
        i0, i1 = UNITS2INDX[old_nu - 1], UNITS2INDX[new_nu - 1]
        if i0 == i1:
            return old
        if self.free[i1]:
            ptr = self._remove(i1)
            self._copy_units(ptr, old, new_nu)
            self._insert(old, i0)
            return ptr
        self._split(old, i0, i1)
        return old

    # -- the model

    def init(self, max_order: int) -> None:
        self.max_order = max_order
        self._restart()
        self.dummy_see = [0, PERIOD_BITS, 64]

    def _restart(self) -> None:
        m = self.m16
        self.free = [0] * NUM_INDEXES
        self.text = self.align
        self.hi_unit = self.text + self.size
        self.lo_unit = self.units_start = self.hi_unit - self.size // 8 // UNIT_SIZE * 7 * UNIT_SIZE
        self.glue_count = 0
        self.order_fall = self.max_order
        self.run_length = self.init_rl = -(min(12, self.max_order)) - 1
        self.prev_success = 0
        self.hi_unit -= UNIT_SIZE
        ctx = self.hi_unit
        self.min_context = self.max_context = ctx
        self._set32(ctx + 8, 0)       # Suffix
        m[ctx >> 1] = 256             # NumStats
        m[(ctx >> 1) + 1] = 257       # SummFreq
        stats = self.lo_unit
        self.found = stats
        self.lo_unit += (256 // 2) * UNIT_SIZE
        self._set32(ctx + 4, stats)
        for i in range(256):
            s = stats + 6 * i
            m[s >> 1] = i | 1 << 8    # Symbol i, Freq 1
            m[(s >> 1) + 1] = 0
            m[(s >> 1) + 2] = 0
        for i in range(128):
            row = self.bin_summ[i]
            for k in range(8):
                val = BIN_SCALE - INIT_BIN_ESC[k] // (i + 2)
                for j in range(k, 64, 8):
                    row[j] = val
        for i in range(25):
            for k in range(16):
                s = self.see[i][k]
                s[1] = PERIOD_BITS - 4
                s[0] = (5 * i + 10) << s[1]
                s[2] = 4

    def _create_successors(self, skip: bool) -> int:
        m, mem = self.m16, self.mem
        c = self.min_context
        fs = self.found
        up_branch = self._get32(fs + 2)
        fsym = mem[fs]
        ps = []
        if not skip:
            ps.append(fs)
        while self._get32(c + 8):
            c = self._get32(c + 8)
            if m[c >> 1] != 1:
                s = self._get32(c + 4)
                while mem[s] != fsym:
                    s += 6
            else:
                s = c + 2
            succ = self._get32(s + 2)
            if succ != up_branch:
                c = succ
                if not ps:
                    return c
                break
            ps.append(s)
        up_sym = mem[up_branch]
        up_succ = up_branch + 1
        if m[c >> 1] == 1:
            up_freq = mem[c + 3]
        else:
            s = self._get32(c + 4)
            while mem[s] != up_sym:
                s += 6
            cf = mem[s + 1] - 1
            s0 = m[(c >> 1) + 1] - m[c >> 1] - cf
            if 2 * cf <= s0:
                up_freq = 1 + (1 if 5 * cf > s0 else 0)
            else:
                up_freq = 1 + (2 * cf + 3 * s0 - 1) // (2 * s0)
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
            m[c1 >> 1] = 1
            mem[c1 + 2] = up_sym
            mem[c1 + 3] = up_freq
            self._set32(c1 + 4, up_succ)
            self._set32(c1 + 8, c)
            self._set32(ps.pop() + 2, c1)
            c = c1
        return c

    def _swap(self, a: int, b: int) -> None:
        mem = self.mem
        mem[a:a + 6], mem[b:b + 6] = mem[b:b + 6], mem[a:a + 6]

    def _update_model(self) -> None:
        m, mem = self.m16, self.mem
        fs = self.found
        fsym, ffreq = mem[fs], mem[fs + 1]
        f_succ = self._get32(fs + 2)
        minc = self.min_context
        if ffreq < MAX_FREQ // 4 and self._get32(minc + 8):
            c = self._get32(minc + 8)
            if m[c >> 1] == 1:
                if mem[c + 3] < 32:
                    mem[c + 3] += 1
            else:
                s = self._get32(c + 4)
                if mem[s] != fsym:
                    s += 6
                    while mem[s] != fsym:
                        s += 6
                    if mem[s + 1] >= mem[s - 5]:
                        self._swap(s, s - 6)
                        s -= 6
                if mem[s + 1] < MAX_FREQ - 9:
                    mem[s + 1] += 2
                    m[(c >> 1) + 1] += 2
        if self.order_fall == 0:
            c = self._create_successors(True)
            self.min_context = self.max_context = c
            if c == 0:
                self._restart()
                return
            self._set32(self.found + 2, c)
            return
        mem[self.text] = fsym
        self.text += 1
        successor = self.text
        if self.text >= self.units_start:
            self._restart()
            return
        if f_succ:
            if f_succ <= successor:
                cs = self._create_successors(False)
                if cs == 0:
                    self._restart()
                    return
                f_succ = cs
            self.order_fall -= 1
            if self.order_fall == 0:
                successor = f_succ
                if self.max_context != self.min_context:
                    self.text -= 1
        else:
            self._set32(self.found + 2, successor)
            f_succ = self.min_context
        ns = m[minc >> 1]
        s0 = m[(minc >> 1) + 1] - ns - (mem[self.found + 1] - 1)
        c = self.max_context
        while c != minc:
            ns1 = m[c >> 1]
            if ns1 != 1:
                if ns1 & 1 == 0:
                    old_nu = ns1 >> 1
                    i = UNITS2INDX[old_nu - 1]
                    if i != UNITS2INDX[old_nu]:
                        ptr = self._alloc(i + 1)
                        if not ptr:
                            self._restart()
                            return
                        old = self._get32(c + 4)
                        self._copy_units(ptr, old, old_nu)
                        self._insert(old, i)
                        self._set32(c + 4, ptr)
                sf_c = m[(c >> 1) + 1]
                sf_c += (1 if 2 * ns1 < ns else 0) + 2 * ((1 if 4 * ns1 <= ns else 0) & (1 if sf_c <= 8 * ns1 else 0))
                m[(c >> 1) + 1] = sf_c & 0xFFFF
            else:
                s = self._alloc(0)
                if not s:
                    self._restart()
                    return
                mem[s:s + 6] = mem[c + 2:c + 8]
                self._set32(c + 4, s)
                freq = mem[s + 1]
                freq = freq << 1 if freq < MAX_FREQ // 4 - 1 else MAX_FREQ - 4
                mem[s + 1] = freq
                m[(c >> 1) + 1] = freq + self.init_esc + (1 if ns > 3 else 0)
            sfc = m[(c >> 1) + 1]
            cf = 2 * mem[self.found + 1] * (sfc + 6)
            sf = s0 + sfc
            if cf < 6 * sf:
                cf = 1 + (1 if cf > sf else 0) + (1 if cf >= 4 * sf else 0)
                m[(c >> 1) + 1] = (sfc + 3) & 0xFFFF
            else:
                cf = 4 + (1 if cf >= 9 * sf else 0) + (1 if cf >= 12 * sf else 0) + (1 if cf >= 15 * sf else 0)
                m[(c >> 1) + 1] = (sfc + cf) & 0xFFFF
            s = self._get32(c + 4) + 6 * ns1
            self._set32(s + 2, successor)
            mem[s] = fsym
            mem[s + 1] = cf
            m[c >> 1] = ns1 + 1
            c = self._get32(c + 8)
        self.max_context = self.min_context = f_succ

    def _rescale(self) -> None:
        m, mem = self.m16, self.mem
        minc = self.min_context
        stats = self._get32(minc + 4)
        s = self.found
        tmp = bytes(mem[s:s + 6])
        while s != stats:
            mem[s:s + 6] = mem[s - 6:s]
            s -= 6
        mem[s:s + 6] = tmp
        esc = m[(minc >> 1) + 1] - mem[s + 1]
        f = mem[s + 1] + 4
        adder = 1 if self.order_fall != 0 else 0
        f = (f + adder) >> 1
        mem[s + 1] = f
        total = f
        i = m[minc >> 1] - 1
        while True:
            s += 6
            esc -= mem[s + 1]
            f = (mem[s + 1] + adder) >> 1
            mem[s + 1] = f
            total += f
            if f > mem[s - 5]:
                s1 = s
                tmp = bytes(mem[s1:s1 + 6])
                while True:
                    mem[s1:s1 + 6] = mem[s1 - 6:s1]
                    s1 -= 6
                    if s1 == stats or tmp[1] <= mem[s1 - 5]:
                        break
                mem[s1:s1 + 6] = tmp
            i -= 1
            if i == 0:
                break
        if mem[s + 1] == 0:
            num = m[minc >> 1]
            i = 0
            while True:
                i += 1
                s -= 6
                if mem[s + 1] != 0:
                    break
            esc += i
            m[minc >> 1] = num - i
            if num - i == 1:
                tmp = bytearray(mem[stats:stats + 6])
                while True:
                    tmp[1] -= tmp[1] >> 1
                    esc >>= 1
                    if esc <= 1:
                        break
                self._insert(stats, UNITS2INDX[((num + 1) >> 1) - 1])
                self.found = minc + 2
                mem[minc + 2:minc + 8] = tmp
                return
            n0, n1 = (num + 1) >> 1, (num - i + 1) >> 1
            if n0 != n1:
                self._set32(minc + 4, self._shrink(stats, n0, n1))
        m[(minc >> 1) + 1] = (total + esc - (esc >> 1)) & 0xFFFF
        self.found = self._get32(minc + 4)

    def _make_esc_freq(self, num_masked: int):
        m = self.m16
        minc = self.min_context
        ns = m[minc >> 1]
        non_masked = ns - num_masked
        if ns != 256:
            suffix_ns = m[self._get32(minc + 8) >> 1]
            see = self.see[NS2INDX[non_masked - 1]][
                (1 if non_masked < suffix_ns - ns else 0)
                + 2 * (1 if m[(minc >> 1) + 1] < 11 * ns else 0)
                + 4 * (1 if num_masked > non_masked else 0)
                + self.hi_bits_flag]
            r = see[0] >> see[1]
            see[0] = (see[0] - r) & 0xFFFF
            return see, r + (1 if r == 0 else 0)
        return self.dummy_see, 1

    def _next_context(self) -> None:
        c = self._get32(self.found + 2)
        if self.order_fall == 0 and c > self.text:
            self.min_context = self.max_context = c
        else:
            self._update_model()

    def _update1(self) -> None:
        mem, m = self.mem, self.m16
        s = self.found
        mem[s + 1] += 4
        m[(self.min_context >> 1) + 1] += 4
        if mem[s + 1] > mem[s - 5]:
            self._swap(s, s - 6)
            s -= 6
            self.found = s
            if mem[s + 1] > MAX_FREQ:
                self._rescale()
        self._next_context()

    def _update1_0(self) -> None:
        mem, m = self.mem, self.m16
        minc = self.min_context
        self.prev_success = 1 if 2 * mem[self.found + 1] > m[(minc >> 1) + 1] else 0
        self.run_length += self.prev_success
        m[(minc >> 1) + 1] += 4
        f = mem[self.found + 1] + 4
        mem[self.found + 1] = f & 0xFF
        if f > MAX_FREQ:
            self._rescale()
        self._next_context()

    def _update_bin(self) -> None:
        mem = self.mem
        f = mem[self.found + 1]
        mem[self.found + 1] = f + (1 if f < 128 else 0)
        self.prev_success = 1
        self.run_length += 1
        self._next_context()

    def _update2(self) -> None:
        mem, m = self.mem, self.m16
        s = self.found
        f = mem[s + 1] + 4
        mem[s + 1] = f & 0xFF
        m[(self.min_context >> 1) + 1] += 4
        if f > MAX_FREQ:
            self._rescale()
        self.run_length = self.init_rl
        self._update_model()

    def decode_symbol(self, rc) -> int:
        """The next byte, -1 at the end mark, -2 for damaged data."""
        m, mem = self.m16, self.mem
        minc = self.min_context
        ns = m[minc >> 1]
        mask = None
        if ns != 1:
            s = self._get32(minc + 4)
            summ = m[(minc >> 1) + 1]
            count = rc.threshold(summ)
            hi = mem[s + 1]
            if count < hi:
                rc.decode(0, hi)
                self.found = s
                sym = mem[s]
                self._update1_0()
                return sym
            self.prev_success = 0
            for _ in range(ns - 1):
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
            self.hi_bits_flag = HB2FLAG[mem[self.found]]
            rc.decode(hi, summ - hi)
            mask = bytearray(b"\xff" * 256)
            stats = self._get32(minc + 4)
            for k in range(ns):
                mask[mem[stats + 6 * k]] = 0
        else:
            suffix = self._get32(minc + 8)
            self.hi_bits_flag = HB2FLAG[mem[self.found]]
            row = self.bin_summ[mem[minc + 3] - 1]
            col = (self.prev_success + NS2BSINDX[m[suffix >> 1] - 1] + self.hi_bits_flag
                   + 2 * HB2FLAG[mem[minc + 2]] + ((self.run_length >> 26) & 0x20))
            prob = row[col]
            if rc.bit(prob, BIN_SCALE) == 0:
                row[col] = (prob + (1 << INT_BITS) - ((prob + 32) >> 7)) & 0xFFFF
                self.found = minc + 2
                sym = mem[minc + 2]
                self._update_bin()
                return sym
            prob = (prob - ((prob + 32) >> 7)) & 0xFFFF
            row[col] = prob
            self.init_esc = EXP_ESCAPE[prob >> 10]
            mask = bytearray(b"\xff" * 256)
            mask[mem[minc + 2]] = 0
            self.prev_success = 0
        while True:
            num_masked = m[self.min_context >> 1]
            while True:
                self.order_fall += 1
                suffix = self._get32(self.min_context + 8)
                if not suffix:
                    return -1
                self.min_context = suffix
                if m[suffix >> 1] != num_masked:
                    break
            minc = self.min_context
            ns = m[minc >> 1]
            s = self._get32(minc + 4)
            ps = []
            hi = 0
            want = ns - num_masked
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


class Range7z:
    """7z's range decoder for PPMd."""

    def __init__(self, data, pos: int = 0, more=None):
        self.d, self.pos, self.more = data, pos, more  # more(): the next piece of data, or b"" at the end
        if self._byte() != 0:
            raise PackportError("The archive is damaged (a PPMd stream starts wrongly)")
        self.code = 0
        self.range = M32
        for _ in range(4):
            self.code = (self.code << 8) | self._byte()

    def _byte(self) -> int:
        p = self.pos
        if p >= len(self.d) and self.more is not None:
            nxt = self.more()
            if nxt:
                self.d, p = nxt, 0
            else:
                self.more = None
        self.pos = p + 1
        return self.d[p] if p < len(self.d) else 0

    def threshold(self, total: int) -> int:
        self.range //= total
        return self.code // self.range

    def _normalize(self) -> None:
        while self.range < TOP:
            self.code = ((self.code << 8) | self._byte()) & M32
            self.range = (self.range << 8) & M32

    def decode(self, start: int, size: int) -> None:
        self.code -= start * self.range
        self.range *= size
        self._normalize()

    def bit(self, size0: int, total: int) -> int:
        bound = (self.range // total) * size0
        if self.code < bound:
            self.range = bound
            bit = 0
        else:
            self.code -= bound
            self.range -= bound
            bit = 1
        self._normalize()
        return bit


class RangeRar:
    """RAR's carry-less range decoder (Subbotin's), over a byte reader."""

    def __init__(self, read_byte):
        self.read = read_byte
        self.low = self.code = 0
        self.range = M32
        for _ in range(4):
            self.code = (self.code << 8) | self.read()

    def threshold(self, total: int) -> int:
        self.range //= total
        return ((self.code - self.low) & M32) // self.range

    def decode(self, start: int, size: int) -> None:
        self.low = (self.low + start * self.range) & M32
        self.range = (self.range * size) & M32
        self.normalize()

    def normalize(self) -> None:
        while True:
            if (self.low ^ ((self.low + self.range) & M32)) >= TOP:
                if self.range >= BOT:
                    return
                self.range = (-self.low) & (BOT - 1)
            self.code = ((self.code << 8) | self.read()) & M32
            self.range = (self.range << 8) & M32
            self.low = (self.low << 8) & M32

    def bit(self, size0: int, total: int) -> int:
        if self.threshold(total) < size0:
            self.decode(0, size0)
            return 0
        self.decode(size0, total - size0)
        return 1


class RarPpmd:
    """PPMd blocks inside RAR 2.9 compressed data: the model (kept across blocks and, in solid
    archives, across files) and the escapes RAR codes with it."""

    def __init__(self):
        self.model = None

    def init(self, unpacker, esc: int):
        """Start a PPMd block at the unpacker's (byte-aligned) position. Returns (new position,
        escape byte). The range coder reads on from wherever the unpacker's data is, so in a
        solid archive it carries on into the next file's data (see next_file)."""
        self.unpacker = unpacker
        self.at = unpacker.pos >> 3
        order = self._byte()
        reset = order & 0x20
        mb = self._byte() if reset else 0
        if order & 0x40:
            esc = self._byte()
        if not reset and self.model is None:
            raise PackportError("The archive is damaged (PPMd data without its model)")
        self.rc = RangeRar(self._byte)
        if reset:
            order = (order & 0x1F) + 1
            if order > 16:
                order = 16 + (order - 16) * 3
            if order == 1:
                raise PackportError("The archive is damaged (a PPMd order of 1)")
            if self.model is None or self.model.size != (mb + 1) << 20:
                self.model = None  # let the old model go before the new one is made (up to 256 MB each)
                self.model = Ppmd7((mb + 1) << 20)
            self.model.init(order)
        self.esc = esc
        return self.at * 8, esc

    def next_file(self, unpacker) -> None:
        """A solid archive's next file: the coder reads its data from the start."""
        self.unpacker, self.at = unpacker, 0

    def _byte(self) -> int:
        d = self.unpacker.d
        at = self.at
        self.at = at + 1
        return d[at] if at < len(d) else 0

    def _char(self) -> int:
        c = self.model.decode_symbol(self.rc)
        if c < 0:
            raise PackportError("The archive is damaged (bad PPMd data)")
        return c

    def run(self, unpacker) -> bool:
        """Decode until the file's output is complete, the block switches back to LZ, or the
        file ends. Returns True at the end of the file's data."""
        target = unpacker.file_start + unpacker.size - unpacker.base
        hist = unpacker.hist
        stop = len(hist) + 1_000_000
        char = self._char
        esc = self.esc
        lim = unpacker.lim >> 3 if unpacker.more else None  # where to stop and come back for more packed data
        while len(hist) < target and len(hist) < stop:
            if lim is not None and self.at > lim:
                break
            c = char()
            if c == esc:
                nxt = char()
                if nxt == 0:  # new tables: back to LZ (or a new PPMd block)
                    unpacker.pos = self.at * 8
                    unpacker._tables()
                    if unpacker.block_ppm:
                        esc = self.esc
                        continue
                    return False
                if nxt == 2:  # end of the file's data
                    unpacker.pos = self.at * 8
                    return True
                if nxt == 3:  # a filter
                    first = char()
                    length = (first & 7) + 1
                    if length == 7:
                        length = char() + 7
                    elif length == 8:
                        length = char() << 8 | char()
                    code = bytes(char() for _ in range(length))
                    unpacker.add_filter(first, code)
                    continue
                if nxt == 4:  # a match: three bytes of distance, one of length
                    dist = char() << 16 | char() << 8 | char()
                    length = char()
                    unpacker.copy(length + 32, dist + 2)
                    continue
                if nxt == 5:  # a run of the last byte
                    unpacker.copy(char() + 4, 1)
                    continue
            hist.append(c)
        unpacker.pos = self.at * 8
        return False
