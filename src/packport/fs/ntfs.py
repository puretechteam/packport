"""NTFS.

Written from the Linux-NTFS project's documentation of the on-disk format. The boot sector gives
the sector and cluster size and where the MFT is; the MFT's own first record ($MFT) has the
runlist of the whole table. Every MFT record (after its update sequence fixups) is attributes:
the standard information, file names (with the parent folder's record number), data (resident,
inside the record, or non-resident: a runlist of clusters, sparse runs reading as zeros), and an
attribute list when they spill into extension records. Paths are built from the file names
(Win32 or POSIX names before DOS 8.3 ones), so folder indexes needn't be read.

Data compressed with NTFS compression (LZNT1, in units of 16 clusters) and Windows' WOF
compression (the CompactOS "WofCompressedData" stream: XPRESS 4, 8 or 16 KB chunks, or LZX)
is unpacked. EFS-encrypted files are marked encrypted. Reparse points (symbolic links,
junctions) are listed as links. System files ($MFT, $LogFile, $Extend and the rest) and
alternate data streams are left out.
"""

from __future__ import annotations

import io
import stat
import struct
from collections.abc import Iterator

from .._accel import native
from ..archive import Item, Stream
from ..entries import PackportError
from . import Extents

STANDARD, ATTR_LIST, FILE_NAME, DATA, REPARSE, END = 0x10, 0x20, 0x30, 0x80, 0xC0, 0xFFFFFFFF
ROOT = 5
FIRST_USER = 16
NTFS_EPOCH = 11644473600
TAG_WOF = 0x80000017
WOF_ALGORITHMS = {0: ("xpress", 4096), 1: ("lzx", 32768), 2: ("xpress", 8192), 3: ("xpress", 16384)}
MAX_RECORDS = 4_000_000
MAX_RUNS = 1 << 20


def probe(dev) -> bool:
    return dev.read_at(3, 8) == b"NTFS    "


def _filetime(v: int) -> float:
    return v / 1e7 - NTFS_EPOCH if v else 0.0


def runlist(raw: bytes, at: int, cluster: int) -> list[tuple[int | None, int]]:
    """A runlist as (byte offset or None for a sparse run, length in bytes)."""
    runs: list[tuple[int | None, int]] = []
    lcn = 0
    while at < len(raw) and raw[at]:
        head = raw[at]
        nlen, noff = head & 15, head >> 4
        if not nlen or nlen > 8 or noff > 8 or at + 1 + nlen + noff > len(raw):
            raise PackportError("The NTFS file system is damaged (a runlist)")
        count = int.from_bytes(raw[at + 1:at + 1 + nlen], "little")
        if noff:
            lcn += int.from_bytes(raw[at + 1 + nlen:at + 1 + nlen + noff], "little", signed=True)
            if lcn < 0:
                raise PackportError("The NTFS file system is damaged (a runlist)")
            runs.append((lcn * cluster, count * cluster))
        else:
            runs.append((None, count * cluster))
        at += 1 + nlen + noff
        if len(runs) > MAX_RUNS:
            raise PackportError("The NTFS file system is damaged (too many runs)")
    return runs


def _runs(attr: dict) -> list[tuple[int | None, int]]:
    """A non-resident attribute's whole runlist, its pieces in order."""
    return [r for _, piece in sorted(attr["pieces"], key=lambda p: p[0]) for r in piece]


def _trim(runs: list[tuple[int | None, int]], size: int) -> list[tuple[int | None, int]]:
    out, total = [], 0
    for at, n in runs:
        if total >= size:
            break
        n = min(n, size - total)
        out.append((at, n))
        total += n
    if total < size:
        out.append((None, size - total))
    return out


def lznt1(data: bytes, size: int) -> bytes:
    """NTFS compression: 4 KB chunks, each a 2-byte header (its size, and whether it's packed),
    then groups of a flag byte and 8 items: a literal, or a back reference whose split between
    length and distance bits widens as the position in the chunk grows."""
    out = bytearray()
    i = 0
    while i + 2 <= len(data) and len(out) < size:
        h = data[i] | data[i + 1] << 8
        if h == 0:
            break
        n = (h & 0xFFF) + 1
        chunk = data[i + 2:i + 2 + n]
        i += 2 + n
        if not h & 0x8000:
            out += chunk
            continue
        start, j = len(out), 0
        while j < len(chunk):
            flags = chunk[j]
            j += 1
            for bit in range(8):
                if j >= len(chunk):
                    break
                if not flags >> bit & 1:
                    out.append(chunk[j])
                    j += 1
                    continue
                if j + 2 > len(chunk):
                    raise PackportError("The NTFS compressed data is damaged")
                token = chunk[j] | chunk[j + 1] << 8
                j += 2
                q, shift = len(out) - start - 1, 12  # the distance takes a bit more each time q doubles
                while q >= 16:
                    q >>= 1
                    shift -= 1
                length = (token & ((1 << shift) - 1)) + 3
                dist = (token >> shift) + 1
                src = len(out) - dist
                if src < start:
                    raise PackportError("The NTFS compressed data is damaged")
                for k in range(length):
                    out.append(out[src + k])
    return bytes(out[:size])


if native is not None:
    lznt1 = native.lznt1_decompress


class _Record:
    __slots__ = ("attr_list", "data", "encrypted", "flags", "is_dir", "names", "reparse", "times")

    def __init__(self):
        self.names: list[tuple[int, int, str]] = []  # (namespace, parent, name)
        self.data: dict[str, dict] = {}  # stream name -> attribute
        self.reparse = None
        self.attr_list = False
        self.times = 0.0
        self.is_dir = False
        self.encrypted = False


class Ntfs:
    name = "NTFS"

    def __init__(self, dev):
        self.dev = dev
        boot = dev.read_at(0, 512)
        if boot[3:11] != b"NTFS    ":
            raise PackportError("This isn't an NTFS file system")
        bps, spc = struct.unpack_from("<HB", boot, 11)
        if spc > 0x80:
            spc = 1 << (256 - spc)
        if bps not in (512, 1024, 2048, 4096) or not spc:
            raise PackportError("The NTFS file system is damaged (its boot sector)")
        self.cluster = bps * spc
        self.sector = bps
        mft_lcn = struct.unpack_from("<Q", boot, 48)[0]
        per = struct.unpack_from("<b", boot, 64)[0]
        self.record_size = self.cluster * per if per > 0 else 1 << -per
        if not 256 <= self.record_size <= 65536:
            raise PackportError("The NTFS file system is damaged (its record size)")
        first = self._fixup(dev.read_at(mft_lcn * self.cluster, self.record_size))
        mft = self._parse(first, 0)
        attr = mft.data.get("")
        if attr is None or not attr["nonresident"]:
            raise PackportError("The NTFS file system is damaged (no $MFT data)")
        self.mft_runs = _trim(_runs(attr), attr["size"])
        count = attr["size"] // self.record_size
        if count > MAX_RECORDS:
            raise PackportError("The NTFS file system has more records than packport reads")
        self.records: dict[int, _Record] = {}
        mft_stream = Extents(dev, self.mft_runs, count * self.record_size)
        extensions: list[tuple[int, int, bytes]] = []
        for k in range(count):
            raw = mft_stream.read(self.record_size)
            if raw[:4] != b"FILE":
                continue
            raw = self._fixup(raw)
            flags = struct.unpack_from("<H", raw, 22)[0]
            if not flags & 1:
                continue  # not in use
            base = struct.unpack_from("<Q", raw, 32)[0] & 0xFFFFFFFFFFFF
            if base:
                extensions.append((base, k, raw))
                continue
            rec = self._parse(raw, k)
            rec.is_dir = bool(flags & 2)
            self.records[k] = rec
        for base, k, raw in extensions:  # attributes that didn't fit in their file's record
            if base in self.records:
                self._parse(raw, k, self.records[base])
        self.members: list[Item] = []
        self._paths()

    def _fixup(self, raw: bytes) -> bytes:
        usa, n = struct.unpack_from("<HH", raw, 4)
        if raw[:4] != b"FILE" or usa + 2 * n > len(raw) or n < 1:
            raise PackportError("The NTFS file system is damaged (an MFT record)")
        b = bytearray(raw)
        usn = b[usa:usa + 2]
        for k in range(1, n):
            end = k * self.sector - 2 if k * self.sector <= len(b) else None
            if end is None:
                break
            if b[end:end + 2] != usn:
                raise PackportError("The NTFS file system is damaged (a torn MFT record)")
            b[end:end + 2] = b[usa + 2 * k:usa + 2 * k + 2]
        return bytes(b)

    def _parse(self, raw: bytes, number: int, rec: _Record | None = None) -> _Record:
        rec = rec or _Record()
        at = struct.unpack_from("<H", raw, 20)[0]
        used = min(struct.unpack_from("<I", raw, 24)[0], len(raw))
        while at + 16 <= used:
            kind, length = struct.unpack_from("<II", raw, at)
            if kind == END or length < 16 or at + length > used:
                break
            a = raw[at:at + length]
            nonresident, nlen, noff, aflags = a[8], a[9], *struct.unpack_from("<HH", a, 10)
            name = a[noff:noff + 2 * nlen].decode("utf-16-le", "replace")
            if nonresident:
                vcn = struct.unpack_from("<Q", a, 16)[0]
                roff, cunit = struct.unpack_from("<HH", a, 32)
                _alloc, size, init = struct.unpack_from("<QQQ", a, 40)
                value = None
            else:
                vlen, voff = struct.unpack_from("<IH", a, 16)
                value = a[voff:voff + vlen]
            if kind == STANDARD and value is not None and len(value) >= 32:
                rec.times = _filetime(struct.unpack_from("<Q", value, 8)[0])
                rec.encrypted = rec.encrypted or bool(struct.unpack_from("<I", value, 32)[0] & 0x4000)
            elif kind == FILE_NAME and value is not None and len(value) >= 66:
                parent = struct.unpack_from("<Q", value, 0)[0] & 0xFFFFFFFFFFFF
                n, space = value[64], value[65]
                rec.names.append((space, parent, value[66:66 + 2 * n].decode("utf-16-le", "replace")))
            elif kind == ATTR_LIST:
                rec.attr_list = True
            elif kind == REPARSE and value is not None and len(value) >= 8:
                rec.reparse = value
            elif kind == DATA:
                if aflags & 0x4000:
                    rec.encrypted = True
                if value is not None:
                    rec.data[name] = {"nonresident": False, "value": value, "size": len(value)}
                else:  # a piece of the runlist, from the cluster number (VCN) it starts at
                    cur = rec.data.get(name)
                    if cur is None or not cur["nonresident"]:
                        cur = rec.data[name] = {"nonresident": True, "pieces": [], "size": 0, "init": 0,
                                                "compressed": False, "unit": 0}
                    cur["pieces"].append((vcn, runlist(a, roff, self.cluster)))
                    if vcn == 0:  # the sizes are kept in the first piece
                        cur.update(size=size, init=init, compressed=bool(aflags & 1) and cunit > 0, unit=cunit)
            at += length
        return rec

    def _paths(self) -> None:
        """Full paths from the file names; system files and their folder left out."""
        best: dict[int, tuple[int, str]] = {}
        for k, rec in self.records.items():
            for space, parent, name in sorted(rec.names, key=lambda n: (n[0] == 2, n[0])):
                if space == 2 and any(s != 2 for s, _, _ in rec.names):
                    continue  # a DOS 8.3 name, when there is a long one
                best.setdefault(k, (parent & 0xFFFFFFFFFFFF, name))
        cache: dict[int, str | None] = {ROOT: ""}

        def path(k: int, depth: int = 0) -> str | None:
            if k in cache:
                return cache[k]
            if depth > 256 or k not in best:
                return None
            parent, name = best[k]
            if parent == k:
                return None
            up = path(parent, depth + 1)
            if up is None:
                result = None
            elif up == "" and (name.startswith("$") or k < FIRST_USER):
                result = None  # $MFT, $Extend and the other system files
            else:
                result = f"{up}/{name}" if up else name
            cache[k] = result
            return result

        for k, rec in sorted(self.records.items()):
            if k < FIRST_USER:  # the root and the system files
                continue
            p = path(k)
            if p is None:
                continue
            p = "/".join(part.replace("/", "_") or "_" for part in p.split("/"))
            if rec.reparse is not None and struct.unpack_from("<I", rec.reparse, 0)[0] != TAG_WOF:
                self.members.append(Item(p, 0, False, "?", rec.times, stat.S_IFLNK | 0o777))  # a link or junction
                continue
            if rec.is_dir:
                self.members.append(Item(p, 0, True, None, rec.times, stat.S_IFDIR | 0o755))
                continue
            attr = rec.data.get("")
            wof = rec.data.get("WofCompressedData") if rec.reparse is not None else None
            if attr is None:
                continue
            self.members.append(Item(p, attr["size"], False, None, rec.times, stat.S_IFREG | 0o644, rec.encrypted,
                                     ref=(attr, wof, rec.reparse)))

    def open_member(self, item: Item):
        attr, wof, reparse = item.ref
        if wof is not None:
            return io.BytesIO(self._wof(item, reparse, wof))
        if not attr["nonresident"]:
            return io.BytesIO(attr["value"])
        if attr["compressed"]:
            return Stream(item.name, self._lznt1(item, attr), item.size, what="file system")
        init = min(attr["init"], attr["size"])
        runs = _trim(_runs(attr), init)
        if init < attr["size"]:
            runs.append((None, attr["size"] - init))  # past the initialized size: zeros, never held in memory
        return Extents(self.dev, runs, attr["size"], item.name)

    def _stream(self, attr: dict, name: str) -> bytes:
        if not attr["nonresident"]:
            return attr["value"]
        if attr["size"] > 1 << 32:
            raise PackportError(f"{name} is too big for packport to unpack in memory")
        return Extents(self.dev, _trim(_runs(attr), attr["size"]), attr["size"], name).read()

    def _lznt1(self, item: Item, attr: dict) -> Iterator[bytes]:
        """A compressed file's data, a compression unit at a time: the runlist cut to the units the
        file's size needs (a run of 2^40 clusters in a 1 KB file is never split up), each unit all
        on disk (stored), partly (packed) or not at all (zeros)."""
        unit = self.cluster << attr["unit"]
        need = -(-item.size // unit) * unit
        left, cur, filled = item.size, [], 0

        def emit(piece):
            real = [(a, n) for a, n in piece if a is not None]
            stored = sum(n for _, n in real)
            if not real:
                data = bytes(unit)
            elif stored >= unit:
                data = Extents(self.dev, real, stored, item.name).read()
            else:
                data = lznt1(Extents(self.dev, real, stored, item.name).read(), unit).ljust(unit, b"\0")
            return data[:left]

        total = 0
        for at, n in _runs(attr):
            n = min(n, need - total)
            total += n
            while n:
                take = min(n, unit - filled)
                cur.append((at, take))
                at = None if at is None else at + take
                n -= take
                filled += take
                if filled == unit:
                    data = emit(cur)
                    left -= len(data)
                    yield data
                    cur, filled = [], 0
                    if left <= 0:
                        return
            if total >= need:
                break
        if cur and left > 0:
            yield emit(cur)

    def _wof(self, item: Item, reparse: bytes, wof: dict) -> bytes:
        """WOF: the reparse data says the algorithm; the stream holds a table of chunk ends (4
        bytes each, 8 when the file is 4 GB or more), then the chunks, each packed on its own
        unless packing didn't help."""
        from ..lzx import LzxDecoder
        from ..xpress import decompress as xpress
        if len(reparse) < 24:
            raise PackportError(f"{item.name}: the NTFS WOF data is damaged")
        provider, algorithm = struct.unpack_from("<II", reparse, 16)
        if provider != 2 or algorithm not in WOF_ALGORITHMS:
            raise PackportError(f"{item.name} is compressed in a way packport doesn't read")
        method, chunk = WOF_ALGORITHMS[algorithm]
        data = self._stream(wof, item.name)
        size = item.size
        n = (size + chunk - 1) // chunk
        width = 8 if size >= 1 << 32 else 4
        table = data[:width * (n - 1)]
        ends = [int.from_bytes(table[k:k + width], "little") for k in range(0, len(table), width)]
        base = width * (n - 1)
        starts = [0, *ends]
        ends = [*ends, len(data) - base]
        out = bytearray()
        for k in range(n):
            want = min(chunk, size - k * chunk)
            piece = data[base + starts[k]:base + ends[k]]
            if len(piece) == want:
                out += piece
            elif method == "xpress":
                out += xpress(piece, want)
            else:
                out += LzxDecoder(15, wim=True).decompress(piece, want)
        return bytes(out[:size])
