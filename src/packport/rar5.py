"""RAR 5 archives: headers, the LZ+Huffman compression (RAR 5.0's, "version 0") and its filters.

The archive is the signature 52 61 72 21 1A 07 01 00, then blocks: a CRC32, the header size
(a vint: 7 bits a byte, low first, the top bit saying more follow), type, flags, the extra and
data sizes when the flags say so, then the header's own fields and its data. Types: 1 main,
2 file, 3 service (comments, recovery records, NTFS streams: skipped), 4 archive encryption
(refused), 5 end of archive. A file's data may run on into the next volume.

Compressed data is a run of blocks, each with a small header (flags: table present, last
block; the valid bits in its last byte; a checksum; its size) and a bit stream read most
significant bit first: Huffman tables when the flags say (a 20-symbol code for the code lengths
of the 306 literal/length, 64 distance, 16 low-distance and 44 repeat-length symbols), then
symbols. 0-255 are literals, 256 starts a filter, 257 repeats the last match, 258-261 reuse one
of the last four distances, 262 on are matches with a length and a distance slot. Filters
(Delta, x86 E8 and E8/E9 call addresses, ARM BL) are applied to ranges of the output before
it's written. Solid archives carry the window, tables and distances from file to file.

Written from RARLAB's format description; packport contains no code from unRAR.
"""

from __future__ import annotations

import hashlib
import io
import struct
import tempfile
import zlib
from collections.abc import Iterator

from ._accel import native
from .archive import Archive, EncryptedError, Item, Pieces, Stream, _crc32, stored
from .bits import huffman
from .entries import PackportError
from .parallel import ordered

SIGNATURE = b"Rar!\x1a\x07\x01\x00"
NC, DC, LDC, RC, BC = 306, 64, 16, 44, 20
MAX_FILTER = 0x400000
MAX_FILTERS = 8192
FILTER_DELTA, FILTER_E8, FILTER_E8E9, FILTER_ARM = 0, 1, 2, 3
AHEAD = 16 << 20  # files this small, in a non-solid archive, are decoded ahead in threads
FLUSH = 4 << 20  # bytes decoded before the oldest ones (beyond the dictionary) are dropped


def _bits_at(d: bytes, pos: int, n: int) -> int:
    """n (<= 57) bits from bit position pos, most significant first."""
    i = pos >> 3
    v = int.from_bytes(d[i:i + 8], "big")
    return (v >> (64 - n - (pos & 7))) & ((1 << n) - 1)


class Unpack5:
    """RAR 5 decompression, one file at a time; solid files reuse the state."""

    def __init__(self, dictionary: int):
        self.dictionary = dictionary
        self.native = native.Rar5Decoder(dictionary) if native is not None else None
        self.reset()

    def reset(self) -> None:
        if self.native is not None:
            self.native.reset()
        self.hist = bytearray()     # what's been decoded and not yet dropped
        self.base = 0               # stream position of hist[0]
        self.written = 0            # stream position up to which output went out
        self.old = [0, 0, 0, 0]
        self.last_length = 0
        self.tables = None
        self.filters: list[tuple[int, int, int, int]] = []  # (start, length, type, channels)
        self.limit = None           # stream position the current file's output may not pass

    def unpack(self, packed, size: int | None) -> Iterator[bytes]:
        """Decode one file's packed stream (a readable file object, read a block at a time) into
        chunks of output. size is the file's unpacked size, when known."""
        self.file_start = self.base + len(self.hist)
        self.written = self.file_start
        # a block decodes whole before its output is checked against the size: past the file's
        # size it stops at once, so a tiny block can't grow the history to gigabytes first
        self.limit = None if size is None else self.file_start + size
        nat = self.native
        if nat is not None:
            nat.dictionary = self.dictionary
            nat.begin_file()
            if hasattr(nat, "limit"):
                nat.limit = (1 << 64) - 1 if size is None else size
        parts: list[bytes] = []
        last = False
        while not last:
            head = packed.read(2)
            if len(head) < 2:
                raise PackportError("The archive is damaged or cut short (a compressed block is missing)")
            flags, check = head[0], head[1]
            count = ((flags >> 3) & 3) + 1
            if count == 4:
                raise PackportError("The archive is damaged (a broken block header)")
            raw = packed.read(count)
            if len(raw) < count:
                raise PackportError("The archive is cut short")
            block = int.from_bytes(raw, "little")
            if (0x5A ^ flags ^ block ^ (block >> 8) ^ (block >> 16)) & 0xFF != check:
                raise PackportError("The archive is damaged (a block header checksum doesn't match)")
            data = packed.read(block)
            if len(data) < block:
                raise PackportError("The archive is cut short")
            end = (block - 1) * 8 + (flags & 7) + 1 if block else 0
            last = bool(flags & 0x40)
            if nat is not None:
                nat.block(data, end, bool(flags & 0x80))
                del data
                if out := nat.take(False):
                    yield out
                continue
            self._block(data + bytes(16), end, bool(flags & 0x80))
            del data
            self._flush(parts.append, final=False)
            yield from parts
            parts.clear()
        if nat is not None:
            if out := nat.take(True):
                yield out
            return
        self._flush(parts.append, final=True)
        yield from parts

    def _tables(self, d: bytes, pos: int) -> int:
        lengths = []
        while len(lengths) < BC:
            n = _bits_at(d, pos, 4)
            pos += 4
            if n == 15:
                zeros = _bits_at(d, pos, 4)
                pos += 4
                if zeros == 0:
                    lengths.append(15)
                else:
                    lengths += [0] * min(zeros + 2, BC - len(lengths))
            else:
                lengths.append(n)
        bd = huffman(lengths)
        size = NC + DC + LDC + RC
        table: list[int] = []
        while len(table) < size:
            e = bd[_bits_at(d, pos, 15)]
            if e < 0:
                raise PackportError("The archive is damaged (a bad code in the Huffman tables)")
            pos += e & 15
            n = e >> 4
            if n < 16:
                table.append(n)
            elif n < 18:
                k = (_bits_at(d, pos, 3) + 3) if n == 16 else (_bits_at(d, pos, 7) + 11)
                pos += 3 if n == 16 else 7
                if not table:
                    raise PackportError("The archive is damaged (a Huffman table repeats nothing)")
                table += [table[-1]] * min(k, size - len(table))
            else:
                k = (_bits_at(d, pos, 3) + 3) if n == 18 else (_bits_at(d, pos, 7) + 11)
                pos += 3 if n == 18 else 7
                table += [0] * min(k, size - len(table))
        self.tables = (huffman(table[:NC]), huffman(table[NC:NC + DC]), huffman(table[NC + DC:NC + DC + LDC]),
                       huffman(table[NC + DC + LDC:]))
        return pos

    def _block(self, d: bytes, end: int, new_tables: bool) -> None:
        pos = 0
        if new_tables:
            pos = self._tables(d, pos)
        if self.tables is None:
            raise PackportError("The archive is damaged (compressed data without Huffman tables)")
        ld, dd, ldd, rd = self.tables
        hist, old = self.hist, self.old
        last_length = self.last_length
        dictionary = self.dictionary
        room = (1 << 62) if self.limit is None else self.limit - self.base  # how long hist may grow
        from_bytes = int.from_bytes
        s = v = 0
        while pos < end:
            if s < 32:  # the window: the 64 bits from pos's byte, s of them still to come
                i = pos >> 3
                v = from_bytes(d[i:i + 8], "big")
                s = 64 - (pos & 7)
            e = ld[(v >> (s - 15)) & 0x7FFF]
            if e < 0:
                raise PackportError("The archive is damaged (a bad Huffman code)")
            n = e & 15
            pos += n
            s -= n
            slot = e >> 4
            if slot < 256:
                hist.append(slot)
                continue
            if slot >= 262:
                slot -= 262
                if slot < 8:
                    length = 2 + slot
                else:
                    lbits = (slot >> 2) - 1
                    length = 2 + ((4 | (slot & 3)) << lbits) + ((v >> (s - lbits)) & ((1 << lbits) - 1))
                    pos += lbits
                    s -= lbits
                if s < 32:  # keep 32 bits ahead for the distance
                    i = pos >> 3
                    v = from_bytes(d[i:i + 8], "big")
                    s = 64 - (pos & 7)
                e = dd[(v >> (s - 15)) & 0x7FFF]
                if e < 0:
                    raise PackportError("The archive is damaged (a bad Huffman code)")
                pos += e & 15
                s -= e & 15
                dslot = e >> 4
                if dslot < 4:
                    dist = 1 + dslot
                else:
                    dbits = (dslot >> 1) - 1
                    dist = 1 + ((2 | (dslot & 1)) << dbits)
                    if dbits >= 4:
                        if dbits > 4:
                            dist += _bits_at(d, pos, dbits - 4) << 4
                            pos += dbits - 4
                        e = ldd[_bits_at(d, pos, 15)]
                        if e < 0:
                            raise PackportError("The archive is damaged (a bad Huffman code)")
                        pos += e & 15
                        dist += e >> 4
                    else:
                        dist += (v >> (s - dbits)) & ((1 << dbits) - 1)
                        pos += dbits
                if dist > 0x100:
                    length += 1
                    if dist > 0x2000:
                        length += 1
                        if dist > 0x40000:
                            length += 1
                old[3], old[2], old[1], old[0] = old[2], old[1], old[0], dist
                last_length = length
                s = 0
            elif slot == 256:
                self.hist, self.last_length = hist, last_length
                pos = self._filter(d, pos)
                s = 0
                continue
            elif slot == 257:
                if not last_length:
                    continue
                length, dist = last_length, old[0]
            else:
                k = slot - 258
                dist = old[k]
                for j in range(k, 0, -1):
                    old[j] = old[j - 1]
                old[0] = dist
                e = rd[(v >> (s - 15)) & 0x7FFF]
                if e < 0:
                    raise PackportError("The archive is damaged (a bad Huffman code)")
                pos += e & 15
                s -= e & 15
                lslot = e >> 4
                if lslot < 8:
                    length = 2 + lslot
                else:
                    lbits = (lslot >> 2) - 1
                    length = 2 + ((4 | (lslot & 3)) << lbits) + _bits_at(d, pos, lbits)
                    pos += lbits
                    s = 0
                last_length = length
            # copy length bytes from dist back
            have = len(hist)
            if dist <= 0 or dist > have or dist > dictionary:
                raise PackportError("The archive is damaged (a match reaches back before the data)")
            if have + length > room:
                raise PackportError("The archive is damaged (a file holds more data than its stated size)")
            start = have - dist
            if dist >= length:
                hist += hist[start:start + length]
            else:
                chunk = hist[start:]
                hist += (chunk * (length // dist + 1))[:length]
        self.hist, self.last_length = hist, last_length
        if pos > end + 8:
            raise PackportError("The archive is damaged (a block's data runs past its end)")

    def _filter(self, d: bytes, pos: int) -> int:
        def data(pos):
            count = _bits_at(d, pos, 2) + 1
            pos += 2
            value = 0
            for k in range(count):
                value += _bits_at(d, pos, 8) << (8 * k)
                pos += 8
            return value, pos
        start, pos = data(pos)
        length, pos = data(pos)
        kind = _bits_at(d, pos, 3)
        pos += 3
        channels = 0
        if kind == FILTER_DELTA:
            channels = _bits_at(d, pos, 5) + 1
            pos += 5
        if length > MAX_FILTER:
            length = 0
        if start >= self.dictionary:  # unRAR wraps it inside the window: past it, it's damage
            raise PackportError("The archive is damaged (a filter that starts past the dictionary window)")
        if len(self.filters) >= MAX_FILTERS:
            raise PackportError("The archive is damaged (too many filters)")
        if kind <= FILTER_ARM and length:
            self.filters.append((self.base + len(self.hist) + start, length, kind, channels))
        return pos

    def _flush(self, out, final: bool) -> None:
        """Write out what's decoded, filtering ranges as they complete; drop old history."""
        top = self.base + len(self.hist)
        while True:
            limit = top
            pending = None
            while self.filters:
                f = self.filters[0]
                if f[0] + f[1] <= self.written:  # a filter on output already gone (damaged)
                    self.filters.pop(0)
                    continue
                pending = f
                break
            if pending is not None:
                limit = min(limit, pending[0])
            if limit > self.written:
                out(self.hist[self.written - self.base:limit - self.base])
                self.written = limit
            if pending is None or top < pending[0] + pending[1]:
                break
            start, length, kind, channels = self.filters.pop(0)
            if start < self.written:
                continue
            block = bytearray(self.hist[start - self.base:start + length - self.base])
            out(_apply(block, kind, channels, start - self.file_start))
            self.written = start + length
        if final and self.filters and self.written < top:
            out(self.hist[self.written - self.base:top - self.base])
            self.written = top
        keep = self.dictionary
        drop = self.written - self.base - keep
        if drop > FLUSH:
            del self.hist[:drop]
            self.base += drop


def _apply(data: bytearray, kind: int, channels: int, offset: int) -> bytes:
    """A filter undone on data, which starts offset bytes into the file."""
    n = len(data)
    if kind == FILTER_DELTA:
        out = bytearray(n)
        src = 0
        for c in range(channels):
            prev = 0
            for at in range(c, n, channels):
                prev = (prev - data[src]) & 0xFF
                out[at] = prev
                src += 1
        return bytes(out)
    if kind in (FILTER_E8, FILTER_E8E9):
        size = 0x1000000
        pos = 0
        marks = (0xE8, 0xE9) if kind == FILTER_E8E9 else (0xE8, 0xE8)
        while pos + 4 < n:
            b = data[pos]
            pos += 1
            if b == marks[0] or b == marks[1]:
                at = (pos + offset) % size
                addr = int.from_bytes(data[pos:pos + 4], "little")
                if addr & 0x80000000:
                    if (addr + at) & 0x80000000 == 0:
                        data[pos:pos + 4] = ((addr + size) & 0xFFFFFFFF).to_bytes(4, "little")
                elif (addr - size) & 0x80000000:
                    data[pos:pos + 4] = ((addr - at) & 0xFFFFFFFF).to_bytes(4, "little")
                pos += 4
        return bytes(data)
    if kind == FILTER_ARM:
        for pos in range(0, n - 3, 4):
            if data[pos + 3] == 0xEB:
                v = (data[pos] | data[pos + 1] << 8 | data[pos + 2] << 16) - (offset + pos) // 4
                data[pos], data[pos + 1], data[pos + 2] = v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF
        return bytes(data)
    return bytes(data)


# ---- headers


def _vint(b: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        if pos >= len(b) or shift > 63:
            raise PackportError("The archive is damaged (a number runs past its header)")
        c = b[pos]
        pos += 1
        value |= (c & 0x7F) << shift
        shift += 7
        if not c & 0x80:
            return value, pos


class Blake2sp:
    """BLAKE2sp, fed as data comes: eight BLAKE2s leaves over interleaved 64-byte blocks, and a
    root over them. A leaf's last block is finished differently, so the last one is kept back."""

    def __init__(self):
        self.leaves = [hashlib.blake2s(digest_size=32, fanout=8, depth=2, node_offset=i, node_depth=0, inner_size=32,
                                       last_node=i == 7) for i in range(8)]
        self.buf = bytearray()
        self.turn = 0

    def update(self, chunk: bytes) -> None:
        buf = self.buf
        buf += chunk
        full = len(buf) - len(buf) % 64
        if full == len(buf) and full:
            full -= 64
        if not full:
            return
        blocks = full // 64
        view = memoryview(buf)
        for k in range(min(8, blocks)):
            leaf = self.leaves[(self.turn + k) % 8]
            leaf.update(b"".join(view[at:at + 64] for at in range(k * 64, full, 512)))
        view.release()
        self.turn = (self.turn + blocks) % 8
        del buf[:full]

    def digest(self) -> bytes:
        for at in range(0, len(self.buf), 64):
            self.leaves[self.turn].update(self.buf[at:at + 64])
            self.turn = (self.turn + 1) % 8
        root = hashlib.blake2s(digest_size=32, fanout=8, depth=2, node_offset=0, node_depth=1, inner_size=32,
                               last_node=True)
        for leaf in self.leaves:
            root.update(leaf.digest())
        return root.digest()


class _Checks:
    """A RAR 5 file's CRC-32 and BLAKE2sp hash (either may be missing), checked at its end."""

    def __init__(self, crc: int | None, digest: bytes | None):
        self.crc, self.digest = crc, digest
        self.value = 0
        self.hash = Blake2sp() if digest is not None else None

    def update(self, chunk: bytes) -> None:
        if self.crc is not None:
            self.value = _crc32(chunk, self.value)
        if self.hash is not None:
            self.hash.update(chunk)

    def ok(self) -> bool:
        return (self.crc is None or self.value == self.crc) and (self.hash is None or self.hash.digest() == self.digest)


class Rar5Archive(Archive):
    """A RAR 5 archive (and its other volumes), through ``packport.open``."""

    def __init__(self, source, volumes=None):
        super().__init__(source)
        self.volumes = [source] + list(volumes or [])
        self.solid = False
        last = None
        for v, src in enumerate(self.volumes):
            last = self._volume(src, v, last)
        if last is not None and last.ref["more"]:
            raise PackportError(f"{last.name} goes on into a volume that isn't there")

    def _volume(self, src, v: int, carry):
        pos = len(SIGNATURE)
        if src.read_at(0, 8) != SIGNATURE:
            sfx = src.read_at(0, min(src.size, 1 << 20)).find(SIGNATURE)  # a self-extracting archive
            if sfx < 0:
                raise PackportError("This isn't a RAR 5 archive")
            pos = sfx + len(SIGNATURE)
        while pos < src.size:
            head = src.read_at(pos, 4 + 3)
            if len(head) < 5:
                raise PackportError("The RAR archive is cut short")
            size, at = _vint(head + src.read_at(pos + len(head), 8), 4)
            if size > 2 << 20:
                raise PackportError("The RAR archive is damaged (a header over 2 MB)")
            block = src.read_at(pos, at + size)
            if len(block) < at + size:
                raise PackportError("The RAR archive is cut short")
            if zlib.crc32(block[4:]) != struct.unpack_from("<I", block)[0]:
                raise PackportError("The RAR archive is damaged (a header checksum doesn't match)")
            kind, p = _vint(block, at)
            flags, p = _vint(block, p)
            extra = data = 0
            if flags & 1:
                extra, p = _vint(block, p)
            if flags & 2:
                data, p = _vint(block, p)
            body_end = at + size
            data_start = pos + at + size
            if kind == 1:
                archive_flags, _ = _vint(block, p)
                self.solid = self.solid or bool(archive_flags & 4)
            elif kind == 4:
                raise EncryptedError("This RAR archive's file list is encrypted; packport doesn't decrypt")
            elif kind == 2:
                carry = self._file(block, p, body_end - extra, body_end, flags, src, data_start, data, carry)
            elif kind == 5:
                return carry
            pos = data_start + data
        raise PackportError("The RAR archive is cut short (no end-of-archive block)")

    def _file(self, block, p, extra_at, end, flags, src, data_start, data_size, carry):
        file_flags, p = _vint(block, p)
        unpacked, p = _vint(block, p)
        attributes, p = _vint(block, p)
        mtime = 0.0
        if file_flags & 2:
            mtime = float(struct.unpack_from("<I", block, p)[0])
            p += 4
        crc = None
        if file_flags & 4:
            crc = struct.unpack_from("<I", block, p)[0]
            p += 4
        info, p = _vint(block, p)
        host, p = _vint(block, p)
        nlen, p = _vint(block, p)
        name = block[p:p + nlen].decode("utf-8", "replace")
        encrypted, link, digest, copy_of = False, None, None, None
        q = extra_at
        while q < end:
            rsize, q2 = _vint(block, q)
            rtype, q3 = _vint(block, q2)
            rec = block[q3:q2 + rsize]
            if rtype == 1:
                encrypted = True
            elif rtype == 2 and rec[:1] == b"\x00":
                digest = rec[1:33]
            elif rtype == 3:
                tflags, r = _vint(rec, 0)
                if tflags & 2:
                    if tflags & 1:
                        mtime = float(struct.unpack_from("<I", rec, r)[0])
                    else:
                        mtime = struct.unpack_from("<Q", rec, r)[0] / 1e7 - 11644473600
            elif rtype == 5:
                kind, r = _vint(rec, 0)
                _, r = _vint(rec, r)
                tlen, r = _vint(rec, r)
                target = rec[r:r + tlen].decode("utf-8", "replace") or "?"
                if kind in (4, 5):  # a hard link or a file copy: the target's data, as 7-Zip extracts it
                    copy_of = target.replace("\\", "/")
                else:
                    link = target
            q = q2 + rsize
        piece = (src, data_start, data_size)
        if flags & 8 and carry is not None and carry.name == name:  # continues from the previous volume
            carry.ref["pieces"].append(piece)
            carry.ref["more"] = bool(flags & 0x10)
            if not carry.ref["more"]:  # the last part carries the whole file's CRC and hash
                carry.ref["crc"] = crc
                carry.ref["hash"] = digest
            return carry if carry.ref["more"] else None
        is_dir = bool(file_flags & 1)
        mode = (0o040755 if is_dir else 0o100644) if host == 0 else attributes
        if host != 0 and not mode & 0o170000:  # permissions with no file type: a plain file or folder
            mode |= 0o040000 if is_dir else 0o100000
        if host == 0 and attributes & 1 and not is_dir:
            mode = 0o100444
        version, method = info & 0x3F, (info >> 7) & 7
        item = Item(name, 0 if is_dir else unpacked, is_dir, link, mtime, mode, encrypted, ref={
            "pieces": [piece], "method": method, "version": version, "solid": bool(info & 0x40),
            "dictionary": 0x20000 << ((info >> 10) & 15), "crc": crc, "hash": digest, "more": bool(flags & 0x10),
            "unknown_size": bool(file_flags & 8), "copy_of": copy_of})
        self.members.append(item)
        return item if item.ref["more"] else None

    def _stream(self, item: Item, decoder, packed=None):
        r = item.ref
        if r["version"] != 0:
            raise PackportError(f"{item.name} uses RAR 7's compression, which packport doesn't read yet")
        packed = packed if packed is not None else Pieces(r["pieces"])
        size = None if r["unknown_size"] else item.size
        chunks = stored(packed) if r["method"] == 0 else decoder.unpack(packed, size)
        return Stream(item.name, chunks, size, _Checks(r["crc"], r["hash"]))

    def _decoder(self, item: Item, decoder):
        """The decoder for item: decoder carried on (a solid file), or a new one."""
        r = item.ref
        if r["method"] and (decoder is None or not r["solid"] or decoder.dictionary < r["dictionary"]):
            if decoder is not None and r["solid"]:
                decoder.dictionary = r["dictionary"]
            else:
                decoder = Unpack5(r["dictionary"])
        return decoder

    def _ahead(self) -> bool:
        """Whether every file can be decoded on its own, and is small enough to decode ahead."""
        files = [m for m in self.members if m.is_file and not m.encrypted]
        compressed = any(m.ref["method"] != 0 for m in files)  # stored data is only copied
        return compressed and len(files) > 1 and all(m.ref["copy_of"] is None and not m.ref["solid"]
                                                     and not m.ref["unknown_size"]
                                      and m.size <= AHEAD and sum(p[2] for p in m.ref["pieces"]) <= AHEAD
                                      for m in files)

    def _files_ahead(self):
        def jobs():
            for item in self.members:
                if not item.is_file:
                    continue
                if item.encrypted:
                    raise EncryptedError(f"{item.name} is encrypted; packport doesn't decrypt")
                packed = io.BytesIO(Pieces(item.ref["pieces"]).read())
                yield lambda item=item, packed=packed: (item, self._stream(item, self._decoder(item, None), packed).read())

        for item, data in ordered(jobs()):
            yield item, io.BytesIO(data)

    def _files(self):
        if self._ahead():
            yield from self._files_ahead()
            return
        decoder = None
        wanted = {m.ref["copy_of"] for m in self.members if m.ref and m.ref.get("copy_of")}
        kept: dict = {}  # the data of files that hard links and copies point at, spooled to disk past 16 MB
        try:
            for item in self.members:
                r = item.ref
                if item.is_dir or item.link is not None:
                    continue
                if r["copy_of"] is not None:
                    if r["copy_of"] in kept:
                        spool = kept[r["copy_of"]]
                        spool.seek(0)
                        yield item, Stream(item.name, stored(spool), None)
                    continue
                if item.encrypted:
                    raise EncryptedError(f"{item.name} is encrypted; packport doesn't decrypt")
                decoder = self._decoder(item, decoder)
                stream = self._stream(item, decoder)
                if item.name in wanted:
                    spool = kept[item.name] = tempfile.SpooledTemporaryFile(max_size=16 << 20)  # noqa: SIM115 - closed below
                    stream = Stream(item.name, _tee(stream, spool), None)
                if item.is_file:
                    yield item, stream
                stream.drain()  # a solid archive's next file carries on from this one's end
        finally:
            for spool in kept.values():
                spool.close()

    def open_member(self, item: Item):
        r = item.ref
        if item.encrypted:
            raise EncryptedError(f"{item.name} is encrypted; packport doesn't decrypt")
        if r["copy_of"] is None and (r["method"] == 0 or not r["solid"]):
            return self._stream(item, self._decoder(item, None))
        files = self._files()
        for m, stream in files:  # solid data has to be decoded from the start
            if m is item:
                stream.keep = files  # the decoder lives as long as the stream (closing it would let it go)
                return stream
        raise PackportError(f"{item.name} has no data")


def _tee(stream, spool) -> Iterator[bytes]:
    """stream's data, a piece at a time, also written to spool."""
    while chunk := stream.read(1 << 20):
        spool.write(chunk)
        yield chunk


def _sniff(head: bytes, source) -> bool:
    if head.startswith(SIGNATURE):
        return True
    return head[:2] == b"MZ" and SIGNATURE in source.read_at(0, min(source.size, 1 << 20))  # self-extracting


def volume_paths(path) -> list:
    """The volumes after this one in a set named NAME.partN.rar (any N's width), when it's one."""
    import re
    from pathlib import Path
    path = Path(path)
    m = re.fullmatch(r"(.*\.part)(\d+)(\.rar)", path.name, re.IGNORECASE)
    if not m:
        return []
    stem, digits, ext = m.groups()
    out, k = [], int(digits) + 1
    while True:
        nxt = path.with_name(f"{stem}{k:0{len(digits)}d}{ext}")
        if not nxt.is_file():
            return out
        out.append(nxt)
        k += 1


def first_volume(path):
    """The set's first volume (NAME.part1.rar) for any of its volumes, or path itself."""
    import re
    from pathlib import Path
    path = Path(path)
    m = re.fullmatch(r"(.*\.part)(\d+)(\.rar)", path.name, re.IGNORECASE)
    if not m:
        return path
    stem, digits, ext = m.groups()
    first = path.with_name(f"{stem}{1:0{len(digits)}d}{ext}")
    return first if first.is_file() else path


from .archive import Source, reader


@reader("rar5", _sniff, first=True)
class _Rar5(Rar5Archive):
    """Rar5Archive as packport.open finds it: other volumes are looked for next to a path."""

    def __init__(self, source):
        volumes = []
        if source.path is not None and volume_paths(source.path) is not None:
            first = first_volume(source.path)
            if first != source.path:
                source.close()
                source = Source(first)
            volumes = [Source(v) for v in volume_paths(first)]
        try:
            super().__init__(source, volumes)
        except BaseException:
            for v in volumes:
                v.close()
            raise

    def close(self) -> None:
        for v in self.volumes[1:]:
            v.close()
        super().close()
