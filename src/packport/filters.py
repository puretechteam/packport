"""Branch-call filters and Delta, undone over a whole buffer (7z and xz use them in front of a
compressor: x86 code's call addresses, ARM's BL, and so on, made relative before compressing).

Written from the xz project's public-domain filter code. Where the data underneath is LZMA,
packport hands the filter to Python's lzma module instead (in C); these are for the rest
(BZip2, Deflate, PPMd, stored) and for the filters lzma doesn't have (ARM64).
"""

from __future__ import annotations

from .entries import PackportError

_X86_ALLOWED = (True, True, True, False, True, False, False, False)
_X86_BIT = (0, 1, 2, 2, 3, 3, 3, 3)


def x86(data: bytes, start: int = 0) -> bytes:
    buf = bytearray(data)
    n = len(buf)
    if n < 5:
        return bytes(buf)
    prev_mask = 0
    prev_pos = (start - 5) & 0xFFFFFFFF
    pos = 0
    while pos <= n - 5:
        b = buf[pos]
        if b != 0xE8 and b != 0xE9:
            pos += 1
            continue
        offset = (start + pos - prev_pos) & 0xFFFFFFFF
        prev_pos = (start + pos) & 0xFFFFFFFF
        if offset > 5:
            prev_mask = 0
        else:
            for _ in range(offset):
                prev_mask = ((prev_mask & 0x77) << 1) & 0xFF
        b = buf[pos + 4]
        if (b == 0 or b == 0xFF) and _X86_ALLOWED[(prev_mask >> 1) & 7] and (prev_mask >> 1) < 0x10:
            src = b << 24 | buf[pos + 3] << 16 | buf[pos + 2] << 8 | buf[pos + 1]
            while True:
                dest = (src - (start + pos + 5)) & 0xFFFFFFFF
                if prev_mask == 0:
                    break
                i = _X86_BIT[prev_mask >> 1]
                b = (dest >> (24 - i * 8)) & 0xFF
                if not (b == 0 or b == 0xFF):
                    break
                src = dest ^ ((1 << (32 - i * 8)) - 1)
            buf[pos + 4] = (~(((dest >> 24) & 1) - 1)) & 0xFF
            buf[pos + 3] = (dest >> 16) & 0xFF
            buf[pos + 2] = (dest >> 8) & 0xFF
            buf[pos + 1] = dest & 0xFF
            pos += 5
            prev_mask = 0
        else:
            pos += 1
            prev_mask |= 1
            if b == 0 or b == 0xFF:
                prev_mask |= 0x10
    return bytes(buf)


def arm(data: bytes, start: int = 0) -> bytes:
    buf = bytearray(data)
    for i in range(0, len(buf) - 3, 4):
        if buf[i + 3] == 0xEB:
            src = (buf[i + 2] << 16 | buf[i + 1] << 8 | buf[i]) << 2
            dest = ((src - (start + i + 8)) & 0xFFFFFFFF) >> 2
            buf[i], buf[i + 1], buf[i + 2] = dest & 0xFF, (dest >> 8) & 0xFF, (dest >> 16) & 0xFF
    return bytes(buf)


def armthumb(data: bytes, start: int = 0) -> bytes:
    buf = bytearray(data)
    i = 0
    while i + 4 <= len(buf):
        if (buf[i + 1] & 0xF8) == 0xF0 and (buf[i + 3] & 0xF8) == 0xF8:
            src = ((buf[i + 1] & 7) << 19 | buf[i] << 11 | (buf[i + 3] & 7) << 8 | buf[i + 2]) << 1
            dest = ((src - (start + i + 4)) & 0xFFFFFFFF) >> 1
            buf[i + 1] = 0xF0 | ((dest >> 19) & 7)
            buf[i] = (dest >> 11) & 0xFF
            buf[i + 3] = 0xF8 | ((dest >> 8) & 7)
            buf[i + 2] = dest & 0xFF
            i += 2
        i += 2
    return bytes(buf)


def powerpc(data: bytes, start: int = 0) -> bytes:
    buf = bytearray(data)
    for i in range(0, len(buf) - 3, 4):
        if buf[i] >> 2 == 0x12 and buf[i + 3] & 3 == 1:
            src = (buf[i] & 3) << 24 | buf[i + 1] << 16 | buf[i + 2] << 8 | (buf[i + 3] & ~3 & 0xFF)
            dest = (src - (start + i)) & 0xFFFFFFFF
            buf[i] = 0x48 | ((dest >> 24) & 3)
            buf[i + 1], buf[i + 2] = (dest >> 16) & 0xFF, (dest >> 8) & 0xFF
            buf[i + 3] = (buf[i + 3] & 3) | (dest & 0xFC)
    return bytes(buf)


def sparc(data: bytes, start: int = 0) -> bytes:
    buf = bytearray(data)
    for i in range(0, len(buf) - 3, 4):
        if (buf[i] == 0x40 and (buf[i + 1] & 0xC0) == 0x00) or (buf[i] == 0x7F and (buf[i + 1] & 0xC0) == 0xC0):
            src = (buf[i] << 24 | buf[i + 1] << 16 | buf[i + 2] << 8 | buf[i + 3]) << 2 & 0xFFFFFFFF
            dest = ((src - (start + i)) & 0xFFFFFFFF) >> 2
            dest = (((0 - ((dest >> 22) & 1)) << 22) & 0x3FFFFFFF) | (dest & 0x3FFFFF) | 0x40000000
            buf[i:i + 4] = dest.to_bytes(4, "big")
    return bytes(buf)


def arm64(data: bytes, start: int = 0) -> bytes:
    buf = bytearray(data)
    for i in range(0, len(buf) - 3, 4):
        instr = int.from_bytes(buf[i:i + 4], "little")
        pc = (start + i) & 0xFFFFFFFF
        if instr >> 26 == 0x25:  # BL
            out = 0x94000000 | ((instr - (pc >> 2)) & 0x03FFFFFF)
            buf[i:i + 4] = out.to_bytes(4, "little")
        elif instr & 0x9F000000 == 0x90000000:  # ADRP
            src = ((instr >> 29) & 3) | ((instr >> 3) & 0x001FFFFC)
            if (src + 0x00020000) & 0x001C0000:
                continue
            dest = (src - (pc >> 12)) & 0xFFFFFFFF
            out = instr & 0x9000001F
            out |= (dest & 3) << 29
            out |= (dest & 0x0003FFFC) << 3
            out |= (0 - (dest & 0x00020000)) & 0x00E00000
            buf[i:i + 4] = (out & 0xFFFFFFFF).to_bytes(4, "little")
    return bytes(buf)


_IA64_MASKS = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0)


def ia64(data: bytes, start: int = 0) -> bytes:
    buf = bytearray(data)
    for i in range(0, len(buf) - 15, 16):
        mask = _IA64_MASKS[buf[i] & 0x1F]
        bit_pos = 5
        for slot in range(3):
            if (mask >> slot) & 1:
                byte_pos = bit_pos >> 3
                bit_res = bit_pos & 7
                instruction = 0
                for j in range(6):
                    instruction |= buf[i + j + byte_pos] << (8 * j)
                norm = instruction >> bit_res
                if ((norm >> 37) & 0xF) == 0x5 and ((norm >> 9) & 0x7) == 0:
                    src = (norm >> 13) & 0xFFFFF
                    src |= ((norm >> 36) & 1) << 20
                    src <<= 4
                    dest = (src - (start + i)) & 0xFFFFFFFF
                    dest >>= 4
                    norm &= ~(0x8FFFFF << 13)
                    norm |= (dest & 0x0FFFFF) << 13
                    norm |= (dest & 0x100000) << (36 - 20)
                    instruction &= (1 << bit_res) - 1
                    instruction |= norm << bit_res
                    for j in range(6):
                        buf[i + j + byte_pos] = (instruction >> (8 * j)) & 0xFF
            bit_pos += 41
    return bytes(buf)


def riscv(data: bytes, start: int = 0) -> bytes:
    buf = bytearray(data) + bytes(8)
    n = len(data)
    if n < 8:
        return bytes(data)
    _riscv(buf, n, start, 0)
    return bytes(buf[:n])


def riscv_iter(chunks, start: int, size: int):
    """RISC-V undone a piece at a time: what can't be decided yet (the last 8 bytes, which an
    instruction may reach into) waits for the next piece."""
    buf, at, left = bytearray(), 0, size  # at: the stream position of buf[0]
    i = 0
    for chunk in chunks:
        buf += chunk
        if len(buf) < 8:
            continue
        i = _riscv(buf, len(buf), start + at, i)
        out = bytes(buf[:i])[:left]
        left -= len(out)
        if out:
            yield out
        del buf[:i]
        at += i
        i = 0
        if left <= 0:
            return
    if buf and left > 0:
        yield bytes(buf)[:left]


def _riscv(buf: bytearray, n: int, start: int, i: int) -> int:
    """Convert buf (n bytes of it, from i) in place, stopping where an instruction could run past
    the end; returns that position."""
    while i <= n - 8:
        inst = buf[i]
        if inst == 0xEF:  # JAL
            b1 = buf[i + 1]
            if b1 & 0x0D:
                i += 2
                continue
            b2, b3 = buf[i + 2], buf[i + 3]
            pc = (start + i) & 0xFFFFFFFF
            addr = ((b1 & 0xF0) << 13 | b2 << 9 | b3 << 1) & 0xFFFFFFFF
            addr = (addr - pc) & 0xFFFFFFFF
            buf[i + 1] = (b1 & 0x0F) | ((addr >> 8) & 0xF0)
            buf[i + 2] = ((addr >> 16) & 0x0F) | ((addr >> 7) & 0x10) | ((addr << 4) & 0xE0)
            buf[i + 3] = ((addr >> 4) & 0x7F) | ((addr >> 13) & 0x80)
            i += 4
            continue
        if inst & 0x7F == 0x17:  # AUIPC
            inst = int.from_bytes(buf[i:i + 4], "little")
            if inst & 0xE80:
                inst2 = int.from_bytes(buf[i + 4:i + 8], "little")
                if (((inst << 8) & 0xFFFFFFFF) ^ ((inst2 - 3) & 0xFFFFFFFF)) & 0xF8003:
                    i += 6
                    continue
                addr = ((inst & 0xFFFFF000) + (inst2 >> 20)) & 0xFFFFFFFF
                inst = (0x17 | (2 << 7) | (inst2 << 12)) & 0xFFFFFFFF
                inst2 = addr
            else:
                rs1 = inst >> 27
                if ((((inst - 0x3117) & 0xFFFFFFFF) << 18) & 0xFFFFFFFF) >= (rs1 & 0x1D):
                    i += 4
                    continue
                addr = int.from_bytes(buf[i + 4:i + 8], "big")
                addr = (addr - (start + i)) & 0xFFFFFFFF
                inst2 = ((inst >> 12) | (addr << 20)) & 0xFFFFFFFF
                inst = (0x17 | (rs1 << 7) | ((addr + 0x800) & 0xFFFFF000)) & 0xFFFFFFFF
            buf[i:i + 4] = inst.to_bytes(4, "little")
            buf[i + 4:i + 8] = inst2.to_bytes(4, "little")
            i += 8
            continue
        i += 2
    return i


def delta(data: bytes, distance: int) -> bytes:
    if not 1 <= distance <= 256:
        raise PackportError("The archive is damaged (a Delta filter's distance)")
    out = bytearray(data)
    for i in range(distance, len(out)):
        out[i] = (out[i] + out[i - distance]) & 0xFF
    return bytes(out)


FILTERS = {"x86": x86, "arm": arm, "armthumb": armthumb, "powerpc": powerpc, "sparc": sparc, "arm64": arm64,
           "ia64": ia64, "riscv": riscv}
