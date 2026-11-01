"""UDF disc images (DVDs, Blu-rays, Windows install discs), revisions 1.02 to 2.60.

Written from ECMA-167 and the OSTA UDF specification. The anchor at sector 256 points to the
volume descriptors: partitions (where each starts) and the logical volume (block size, partition
maps, and where the file set descriptor is). Maps are physical (type 1), sparable (blocks moved
off bad packets), or metadata (UDF 2.50: file entries and folders live in a metadata file whose
extents map its blocks onto the physical partition). Every file and folder is a File Entry (or
Extended File Entry) whose allocation descriptors (short, long, or the data inline) give its
extents; a folder's data is File Identifier Descriptors: name (OSTA compressed Unicode: 8 or 16
bits a character), flags, and the File Entry of what it names. Virtual partitions (multisession
CD-R) are refused with a clear message.

A disc with UDF and ISO 9660 (a bridge disc) is read through whichever lists more, UDF on a tie;
Windows install discs keep everything in UDF and only a README in ISO 9660.
"""

from __future__ import annotations

import calendar
import io
import stat
import struct

from .archive import Archive, Item, Source, reader
from .entries import CHUNK, PackportError

MAX_DEPTH = 64
MAX_ENTRIES = 1_000_000
MAX_DIR = 64 << 20
MAX_EXTENTS = 1 << 20


def _anchor(source: Source) -> tuple[int, bytes] | None:
    for bs in (2048, 512, 4096):
        for at in (256 * bs, source.size - bs, source.size - 257 * bs):
            if at <= 0 or at + 512 > source.size:
                continue
            d = source.read_at(at, 512)
            if _tag_ok(d, 2):
                return bs, d
    return None


def _tag_ok(d: bytes, kind: int | None = None) -> bool:
    if len(d) < 16:
        return False
    if sum(d[:4]) + sum(d[5:16]) & 0xFF != d[4]:
        return False
    return kind is None or struct.unpack_from("<H", d, 0)[0] == kind


def _sniff(head: bytes, source) -> bool:
    if source.size < 257 * 2048 and source.size < 257 * 512:
        return False
    nsr = any(source.read_at(k * 2048 + 1, 5) in (b"NSR02", b"NSR03") for k in range(16, 32)
              if (k + 1) * 2048 <= source.size)
    return nsr and _anchor(source) is not None


def _name(raw: bytes) -> str:
    if not raw:
        return ""
    kind, body = raw[0], raw[1:]
    if kind in (8, 254):
        return body.decode("latin-1")
    if kind in (16, 255):
        return body[:len(body) // 2 * 2].decode("utf-16-be", "replace")
    raise PackportError("The UDF disc is damaged (a name in an unknown encoding)")


def _time(b: bytes) -> float:
    tz, y, mo, d, h, mi, s = struct.unpack_from("<HHBBBBB", b, 0)
    try:
        t = calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0))
    except (ValueError, OverflowError):
        return 0.0
    if tz >> 12 == 1:
        off = tz & 0xFFF
        if off != 0x801:  # "no time zone"
            t -= (off - 0x1000 if off & 0x800 else off) * 60
    return float(t)


class _Extents(io.RawIOBase):
    """A file's data: (byte offset, length) extents, offset None for zeros."""

    def __init__(self, source: Source, extents: list[tuple[int | None, int]], size: int):
        self.source, self.extents, self.left, self.k, self.pos = source, extents, size, 0, 0

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1) -> bytes:
        want = self.left if n is None or n < 0 else min(n, self.left)
        if want and self.k < len(self.extents):
            at, length = self.extents[self.k]
            if at is not None and self.pos + want <= length:  # within one extent: no gathering
                chunk = self.source.read_at(at + self.pos, want)
                if len(chunk) < want:
                    raise PackportError("The disc image is cut short")
                self.pos += want
                if self.pos >= length:
                    self.k, self.pos = self.k + 1, 0
                self.left -= want
                return chunk
        out = bytearray()
        while len(out) < want and self.k < len(self.extents):
            at, length = self.extents[self.k]
            take = min(length - self.pos, want - len(out), CHUNK * 16)
            if at is None:
                out += bytes(take)
            else:
                chunk = self.source.read_at(at + self.pos, take)
                if len(chunk) < take:
                    raise PackportError("The disc image is cut short")
                out += chunk
            self.pos += take
            if self.pos >= length:
                self.k, self.pos = self.k + 1, 0
        if len(out) < want:
            raise PackportError("The UDF disc is damaged (a file's extents end early)")
        self.left -= len(out)
        return bytes(out)

    def readinto(self, b) -> int:
        data = self.read(len(b))
        b[:len(data)] = data
        return len(data)


class UdfArchive(Archive):
    fmt = "udf"

    def __init__(self, source: Source):
        super().__init__(source)
        found = _anchor(source)
        if found is None:
            raise PackportError("This isn't a UDF disc")
        self.bs, avdp = found
        length, loc = struct.unpack_from("<II", avdp, 16)
        partitions: dict[int, tuple[int, int]] = {}
        lvd = None
        for k in range(min(length // self.bs, 512)):
            d = source.read_at((loc + k) * self.bs, self.bs)
            if not _tag_ok(d):
                continue
            kind = struct.unpack_from("<H", d, 0)[0]
            if kind == 5:
                number = struct.unpack_from("<H", d, 22)[0]
                partitions[number] = struct.unpack_from("<II", d, 188)
            elif kind == 6 and lvd is None:
                lvd = d
            elif kind == 8:
                break
        if lvd is None or not partitions:
            raise PackportError("The UDF disc is damaged (no logical volume)")
        if struct.unpack_from("<I", lvd, 212)[0] != self.bs:
            raise PackportError("The UDF disc uses a block size packport doesn't read")
        self.maps: list[tuple] = []
        count = struct.unpack_from("<I", lvd, 268)[0]
        at = 440
        metadata = []
        for _ in range(min(count, 64)):
            kind, mlen = lvd[at], lvd[at + 1]
            if kind == 1:
                number = struct.unpack_from("<H", lvd, at + 4)[0]
                self.maps.append(("physical", self._partition(partitions, number)))
            elif kind == 2:
                ident = lvd[at + 5:at + 28].rstrip(b"\0")
                number = struct.unpack_from("<H", lvd, at + 38)[0]
                start = self._partition(partitions, number)
                if ident.startswith(b"*UDF Metadata Partition"):
                    file_loc = struct.unpack_from("<I", lvd, at + 40)[0]
                    metadata.append(len(self.maps))
                    self.maps.append(("metadata", start, file_loc))
                elif ident.startswith(b"*UDF Sparable Partition"):
                    self.maps.append(("sparable", start, self._sparing(lvd, at)))
                elif ident.startswith(b"*UDF Virtual Partition"):
                    raise PackportError("This UDF disc uses a virtual partition (a multisession CD-R), "
                                        "which packport doesn't read")
                else:
                    raise PackportError("The UDF disc has a partition map packport doesn't know")
            else:
                raise PackportError("The UDF disc is damaged (a partition map)")
            at += max(mlen, 6)
        for k in metadata:  # the metadata file's own extents sit in the physical partition
            _, start, file_loc = self.maps[k]
            fe = self.source.read_at((start + file_loc) * self.bs, self.bs)
            extents, _ = self._extents(fe, None, physical_start=start)
            table, logical = [], 0
            for off, n in extents:
                table.append((logical, n, off))
                logical += n
            self.maps[k] = ("metadata", start, table)
        fsd_block, fsd_part = struct.unpack_from("<IH", lvd, 252)
        fsd = self._block(fsd_block, fsd_part)
        if not _tag_ok(fsd, 256):
            raise PackportError("The UDF disc is damaged (no file set descriptor)")
        root_block, root_part = struct.unpack_from("<IH", fsd, 404)
        self.seen: set[tuple[int, int]] = set()
        self._walk(root_block, root_part, "", 0)

    @staticmethod
    def _partition(partitions: dict, number: int) -> int:
        if number not in partitions:
            raise PackportError("The UDF disc is damaged (a partition is missing)")
        return partitions[number][0]

    def _sparing(self, lvd: bytes, at: int) -> dict[int, int]:
        packet, tables = struct.unpack_from("<HB", lvd, at + 40)
        size = struct.unpack_from("<I", lvd, at + 44)[0]
        remap: dict[int, int] = {}
        for k in range(min(tables, 4)):
            loc = struct.unpack_from("<I", lvd, at + 48 + 4 * k)[0]
            t = self.source.read_at(loc * self.bs, min(size, 1 << 20))
            if len(t) < 56 or t[17:40].rstrip(b"\0") != b"*UDF Sparing Table":
                continue
            n = struct.unpack_from("<H", t, 48)[0]
            for e in range(n):
                orig, mapped = struct.unpack_from("<II", t, 56 + 8 * e)
                if orig < 0xFFFFFFF0:
                    for p in range(packet):
                        remap[orig + p] = mapped + p
            break
        return remap

    def _sector(self, block: int, part: int) -> int:
        """The physical sector of a block in a partition."""
        if part >= len(self.maps):
            raise PackportError("The UDF disc is damaged (a partition reference)")
        m = self.maps[part]
        if m[0] == "physical":
            return m[1] + block
        if m[0] == "sparable":
            return m[2].get(m[1] + block, m[1] + block)
        for logical, n, off in m[2]:
            if logical <= block * self.bs < logical + n:
                if off is None:
                    raise PackportError("The UDF disc is damaged (metadata in an unrecorded extent)")
                return (off + block * self.bs - logical) // self.bs
        raise PackportError("The UDF disc is damaged (a block outside the metadata file)")

    def _block(self, block: int, part: int) -> bytes:
        return self.source.read_at(self._sector(block, part) * self.bs, self.bs)

    def _extents(self, fe: bytes, part: int | None, physical_start: int | None = None):
        """(extents, inline data) of a File Entry, as (byte offset or None, length) pairs."""
        kind = struct.unpack_from("<H", fe, 0)[0]
        if kind == 261:
            l_ea, l_ad = struct.unpack_from("<II", fe, 168)
            base = 176
        elif kind == 266:
            l_ea, l_ad = struct.unpack_from("<II", fe, 208)
            base = 216
        else:
            raise PackportError("The UDF disc is damaged (not a file entry)")
        ad_type = struct.unpack_from("<H", fe, 34)[0] & 7
        area = fe[base + l_ea:base + l_ea + l_ad]
        if base + l_ea + l_ad > len(fe):
            raise PackportError("The UDF disc is damaged (a file entry)")
        if ad_type == 3:
            return [], area
        out: list[tuple[int | None, int]] = []
        hops = 0
        while area is not None:
            nxt, i = None, 0
            step = {0: 8, 1: 16, 2: 20}.get(ad_type)
            if step is None:
                raise PackportError("The UDF disc is damaged (an allocation descriptor type)")
            while i + step <= len(area):
                raw_len = struct.unpack_from("<I", area, i)[0]
                length, flag = raw_len & 0x3FFFFFFF, raw_len >> 30
                if length == 0:
                    break
                if ad_type == 0:
                    block, apart = struct.unpack_from("<I", area, i + 4)[0], part
                elif ad_type == 1:
                    block, apart = struct.unpack_from("<IH", area, i + 4)
                else:
                    block, apart = struct.unpack_from("<IH", area, i + 12)
                if flag == 3:
                    nxt = (block, apart)
                    break
                if flag == 0:
                    if physical_start is not None:
                        out.append(((physical_start + block) * self.bs, length))
                    else:
                        out.append((self._sector(block, apart) * self.bs, length))
                else:
                    out.append((None, length))
                if len(out) > MAX_EXTENTS:
                    raise PackportError("The UDF disc is damaged (too many extents)")
                i += step
            area = None
            if nxt is not None and hops < 4096:
                hops += 1
                if physical_start is not None:
                    d = self.source.read_at((physical_start + nxt[0]) * self.bs, self.bs)
                else:
                    d = self._block(*nxt)
                if not _tag_ok(d, 258):
                    raise PackportError("The UDF disc is damaged (an allocation extent)")
                area = d[24:24 + struct.unpack_from("<I", d, 20)[0]]
        return out, b""

    def _entry(self, block: int, part: int) -> dict:
        fe = self._block(block, part)
        if not (_tag_ok(fe, 261) or _tag_ok(fe, 266)):
            raise PackportError("The UDF disc is damaged (a file entry's tag)")
        ext = struct.unpack_from("<H", fe, 0)[0] == 266
        size = struct.unpack_from("<Q", fe, 56)[0]
        mtime = _time(fe[(92 if ext else 84):])
        perms = struct.unpack_from("<I", fe, 44)[0]
        mode = (perms & 0o7) | (perms >> 2 & 0o70) | (perms >> 4 & 0o700)
        extents, inline = self._extents(fe, part)
        return {"type": fe[27], "size": size, "mtime": mtime, "mode": mode, "extents": extents, "inline": inline}

    def _read(self, info: dict) -> bytes:
        if info["inline"]:
            return info["inline"][:info["size"]]
        if info["size"] > MAX_DIR:
            raise PackportError("The UDF disc is damaged (a folder is too big)")
        return _Extents(self.source, info["extents"], info["size"]).read()

    def _walk(self, block: int, part: int, prefix: str, depth: int) -> None:
        if depth > MAX_DEPTH or (block, part) in self.seen:
            return
        self.seen.add((block, part))
        data = self._read(self._entry(block, part))
        i = 0
        while i + 38 <= len(data):
            if not _tag_ok(data[i:i + 16], 257):
                raise PackportError("The UDF disc is damaged (a folder entry)")
            flags, nlen = data[i + 18], data[i + 19]
            fblock, fpart = struct.unpack_from("<IH", data, i + 24)
            l_iu = struct.unpack_from("<H", data, i + 36)[0]
            raw = data[i + 38 + l_iu:i + 38 + l_iu + nlen]
            i += (38 + l_iu + nlen + 3) & ~3
            if flags & 0x0C:  # deleted, or the parent
                continue
            if len(self.members) > MAX_ENTRIES:
                raise PackportError("The UDF disc lists too many files")
            name = _name(raw).replace("/", "_") or "_"
            if name in (".", ".."):
                name = "_"
            path = prefix + name
            info = self._entry(fblock, fpart)
            if flags & 0x02 or info["type"] == 4:
                self.members.append(Item(path, 0, True, None, info["mtime"], stat.S_IFDIR | (info["mode"] or 0o755)))
                self._walk(fblock, fpart, path + "/", depth + 1)
            elif info["type"] == 12:
                self.members.append(Item(path, 0, False, "?", info["mtime"], stat.S_IFLNK | 0o777))
            elif info["type"] in (0, 5):
                self.members.append(Item(path, info["size"], False, None, info["mtime"],
                                         stat.S_IFREG | (info["mode"] or 0o644), ref=info))

    def open_member(self, item: Item):
        info = item.ref
        if info["inline"]:
            return io.BytesIO(info["inline"][:item.size])
        if sum(n for _, n in info["extents"]) < item.size:
            raise PackportError(f"{item.name}: the UDF disc is damaged (its extents are too short)")
        return _Extents(self.source, info["extents"], item.size)


def _open(source: Source) -> Archive:
    """UDF, or ISO 9660 when the disc's ISO side lists more (or its UDF side is damaged)."""
    from .iso import IsoArchive
    from .iso import _sniff as iso_sniff
    try:
        udf = UdfArchive(source)
    except PackportError:
        if iso_sniff(b"", source):
            return IsoArchive(source)
        raise
    if iso_sniff(b"", source):
        try:
            iso = IsoArchive(source)
        except PackportError:
            return udf
        if len(iso.members) > len(udf.members):
            return iso
    return udf


reader("udf", _sniff, first=True)(_open)
