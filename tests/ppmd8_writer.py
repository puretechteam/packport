"""A PPMd var. I encoder over packport's model, for tests only: 7-Zip can't write the "cut off"
restore method, so the fixture that needs it is written here and 7-Zip is the one that has to
read it back (make_7z_zip.py checks that)."""

import struct
import zlib

from packport.ppmd import BIN_SCALE, BOT, EXP_ESCAPE, M32, NS2BSINDX, PERIOD_BITS, TOP
from packport.ppmd8 import NS2INDX8, Ppmd8


class _Coder:
    def __init__(self):
        self.low, self.range, self.out = 0, M32, bytearray()

    def encode(self, start: int, size: int, total: int) -> None:
        self.range //= total
        self.low = (self.low + start * self.range) & M32
        self.range = (self.range * size) & M32
        while True:
            if (self.low ^ ((self.low + self.range) & M32)) >= TOP:
                if self.range >= BOT:
                    return
                self.range = (-self.low) & (BOT - 1)
            self.out.append(self.low >> 24)
            self.range = (self.range << 8) & M32
            self.low = (self.low << 8) & M32

    def flush(self) -> bytes:
        for _ in range(4):
            self.out.append(self.low >> 24)
            self.low = (self.low << 8) & M32
        return bytes(self.out)


def _encode_symbol(p: Ppmd8, rc: _Coder, symbol: int) -> None:
    """symbol, or with -1 the end mark: an escape out of every context."""
    mem, get = p.mem, p._get32
    mc = p.min_context
    mask = bytearray(b"\xff" * 256)
    if mem[mc]:
        s = get(mc + 4)
        summ = p._summ(mc)
        if mem[s] == symbol:
            rc.encode(0, mem[s + 1], summ)
            p.found = s
            p._update1_0()
            return
        p.prev_success = 0
        low = mem[s + 1]
        for _ in range(mem[mc]):
            s += 6
            if mem[s] == symbol:
                rc.encode(low, mem[s + 1], summ)
                p.found = s
                p._update1()
                return
            low += mem[s + 1]
        rc.encode(low, summ - low, summ)
        stats = get(mc + 4)
        for k in range(mem[mc] + 1):
            mask[mem[stats + 6 * k]] = 0
    else:
        row = p.bin_summ[NS2INDX8[mem[mc + 3] - 1]]
        col = NS2BSINDX[mem[get(mc + 8)]] + p.prev_success + mem[mc + 1] + ((p.run_length >> 26) & 0x20)
        prob = row[col]
        if mem[mc + 2] == symbol:
            rc.encode(0, prob, BIN_SCALE)
            row[col] = (prob + (1 << 7) - ((prob + 32) >> 7)) & 0xFFFF
            p.found = mc + 2
            p._update_bin()
            return
        rc.encode(prob, BIN_SCALE - prob, BIN_SCALE)
        prob = (prob - ((prob + 32) >> 7)) & 0xFFFF
        row[col] = prob
        p.init_esc = EXP_ESCAPE[prob >> 10]
        mask[mem[mc + 2]] = 0
        p.prev_success = 0
    while True:
        num_masked = mem[p.min_context]
        while True:
            p.order_fall += 1
            suffix = get(p.min_context + 8)
            if not suffix:  # past order 0: only the end mark (-1) gets here
                return
            p.min_context = suffix
            if mem[suffix] != num_masked:
                break
        mc = p.min_context
        s = get(mc + 4)
        ps, hi = [], 0
        while len(ps) != mem[mc] - num_masked:
            if mask[mem[s]]:
                hi += mem[s + 1]
                ps.append(s)
            s += 6
        see, freq_sum = p._make_esc_freq(num_masked)
        freq_sum += hi
        low = 0
        for s in ps:
            if mem[s] == symbol:
                rc.encode(low, mem[s + 1], freq_sum)
                if see[1] < PERIOD_BITS:
                    see[2] -= 1
                    if see[2] == 0:
                        see[0] = (see[0] << 1) & 0xFFFF
                        see[2] = 3 << see[1]
                        see[1] += 1
                p.found = s
                p._update2()
                return
            low += mem[s + 1]
        rc.encode(hi, freq_sum - hi, freq_sum)
        see[0] = (see[0] + freq_sum) & 0xFFFF
        for s in ps:
            mask[mem[s]] = 0


def encode(data: bytes, order: int, mb: int, restore: int) -> bytes:
    """ZIP method 98 data: the 2-byte header, then data range-coded with PPMd var. I."""
    model = Ppmd8(mb << 20)
    model.init(order, restore)
    rc = _Coder()
    for b in data:
        _encode_symbol(model, rc, b)
    _encode_symbol(model, rc, -1)  # the end mark, which 7-Zip looks for
    return struct.pack("<H", (order - 1) | (mb - 1) << 4 | restore << 12) + rc.flush()


def zip_one(name: str, data: bytes, packed: bytes, method: int) -> bytes:
    """A ZIP archive of one member whose data is already packed."""
    raw = name.encode()
    crc = zlib.crc32(data)
    local = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 63, 0, method, 0, 0x21, crc, len(packed), len(data), len(raw), 0)
    central = struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 63, 63, 0, method, 0, 0x21, crc, len(packed),
                          len(data), len(raw), 0, 0, 0, 0, 0, 0)
    body = local + raw + packed
    end = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(central) + len(raw), len(body), 0)
    return body + central + raw + end
