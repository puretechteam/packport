"""ISO 9660 disc images (.iso), with Joliet, Rock Ridge, zisofs and El Torito boot images.

Written from ECMA-119, the Joliet specification, IEEE P1281/P1282 (SUSP and Rock Ridge) and the
El Torito specification. Volume descriptors start at sector 16 (2048 bytes each): the primary
one, a Joliet one (a supplementary descriptor with UCS-2 escape sequences) and a boot record.
A directory is a run of records: extent, size, date, flags and name, then a System Use area,
where Rock Ridge keeps the POSIX name (NM), mode (PX), times (TF), symbolic links (SL), deep
folders moved to rr_moved (CL, RE) and zisofs compression (ZF), continuing elsewhere when long
(CE). Names come from Rock Ridge when the disc has it, else from Joliet, else the plain ISO
names without their ";1"; a disc with both Rock Ridge and Joliet is read through whichever tree
lists more. Folders Rock Ridge moved to rr_moved go back where they belong; one that nothing
points back to stays in rr_moved. Files bigger than 4 GB span several records (multi-extent).

El Torito boot images are listed under [BOOT]/, named the way 7-Zip names them. A disc that
also has a UDF file system is read through UDF (udf.py) when that holds more.
"""

from __future__ import annotations

import calendar
import io
import stat
import struct
import zlib
from collections.abc import Iterator

from .archive import Archive, Item, Source, Stream, reader
from .entries import CHUNK, MAX_ITEMS, PackportError

SECTOR = 2048
JOLIET = (b"%/@", b"%/C", b"%/E")
MAX_DEPTH = 64
MAX_DIR = 64 << 20
ZISOFS_MAGIC = bytes.fromhex("37e45396c9dbd607")
BOOT_MEDIA = {0: ("NoEmul", 0), 1: ("1.2M", 1228800), 2: ("1.44M", 1474560), 3: ("2.88M", 2949120),
              4: ("HardDisk", 0)}


def _sniff(head: bytes, source) -> bool:
    return source.size >= 17 * SECTOR and source.read_at(16 * SECTOR + 1, 5) == b"CD001"


def _time(rec: bytes, at: int = 18) -> float:
    y, mo, d, h, mi, s, tz = struct.unpack_from("<6Bb", rec, at)
    try:
        return float(calendar.timegm((1900 + y, mo, d, h, mi, s, 0, 0, 0)) - tz * 900)
    except (ValueError, OverflowError):
        return 0.0


def _long_time(b: bytes) -> float:
    try:
        t = calendar.timegm((int(b[0:4]), int(b[4:6]), int(b[6:8]), int(b[8:10]), int(b[10:12]), int(b[12:14]),
                             0, 0, 0))
        return float(t - struct.unpack("b", b[16:17])[0] * 900)
    except (ValueError, OverflowError, struct.error):
        return 0.0


class _Parts(io.RawIOBase):
    """A file stored in several extents, read as one."""

    def __init__(self, source: Source, parts: list[tuple[int, int]]):
        self.source, self.parts, self.k, self.pos = source, parts, 0, 0

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1) -> bytes:
        out = bytearray()
        while self.k < len(self.parts) and (n < 0 or len(out) < n):
            at, size = self.parts[self.k]
            take = size - self.pos if n < 0 else min(size - self.pos, n - len(out))
            chunk = self.source.read_at(at + self.pos, min(take, CHUNK * 16))
            if len(chunk) < min(take, CHUNK * 16):
                raise PackportError("The disc image is cut short")
            out += chunk
            self.pos += len(chunk)
            if self.pos >= size:
                self.k, self.pos = self.k + 1, 0
        return bytes(out)

    def readinto(self, b) -> int:
        data = self.read(len(b))
        b[:len(data)] = data
        return len(data)


@reader("iso", _sniff)
class IsoArchive(Archive):
    def __init__(self, source: Source):
        super().__init__(source)
        pvd = joliet = boot = None
        for k in range(16, 16 + 64):
            d = source.read_at(k * SECTOR, SECTOR)
            if len(d) < SECTOR or d[1:6] != b"CD001":
                break
            if d[0] == 255:
                break
            if d[0] == 1 and pvd is None:
                pvd = d
            elif d[0] == 2 and d[88:91] in JOLIET and joliet is None:
                joliet = d
            elif d[0] == 0 and d[7:30] == b"EL TORITO SPECIFICATION":
                boot = d
        if pvd is None and joliet is None:
            raise PackportError("The disc image is damaged (no volume descriptor)")
        self.rr_skip = None
        if pvd is not None:
            root = pvd[156:190]
            first = next(self._records(*struct.unpack_from("<I", root, 2), struct.unpack_from("<I", root, 10)[0]),
                         None)
            if first is not None:
                for sig, body in self._susp(first, 0):
                    if sig == b"SP" and body[:2] == b"\xbe\xef":
                        self.rr_skip = body[2]
                        break
        trees = []
        if self.rr_skip is not None:
            trees.append(("rr", pvd))
        if joliet is not None:
            trees.append(("joliet", joliet))
        if not trees:
            trees.append(("iso", pvd))
        best = None
        for mode, desc in trees:
            self.members = []
            self._read_tree(mode, desc)
            if best is None or len(self.members) > len(best[1]):
                best = (mode, self.members)
        self.mode, self.members = best
        if boot is not None:
            self._boot(struct.unpack_from("<I", boot, 0x47)[0])

    # -- directories

    def _read_tree(self, mode: str, desc: bytes) -> None:
        self.mode = mode
        self.seen: set[int] = set()
        self.moved: list[tuple[bytes, str, int]] = []
        root = desc[156:190]
        self._walk(struct.unpack_from("<I", root, 2)[0], struct.unpack_from("<I", root, 10)[0], "", 0)
        for rec, path, depth in self.moved:  # moved folders nothing pointed back to stay where they are
            ext = struct.unpack_from("<I", rec, 2)[0]
            if ext not in self.seen:
                self.members.append(Item(path, 0, True, None, _time(rec), stat.S_IFDIR | 0o755))
                self._walk(ext, struct.unpack_from("<I", rec, 10)[0], path + "/", depth + 1)
        if mode == "rr":
            moved = {m.name for m in self.members if m.name.lower() == "rr_moved" and m.is_dir}
            used = {m.name.split("/", 1)[0] for m in self.members if "/" in m.name}
            self.members = [m for m in self.members if not (m.name in moved and m.name not in used)]

    def _records(self, extent: int, size: int):
        if size > MAX_DIR:
            raise PackportError("The disc image is damaged (a folder is too big)")
        data = self.source.read_at(extent * SECTOR, size)
        i = 0
        while i < len(data):
            n = data[i]
            if n == 0:
                i = (i // SECTOR + 1) * SECTOR
                continue
            if n < 34 or i + n > len(data):
                return
            yield data[i:i + n]
            i += n

    def _susp(self, rec: bytes, skip: int) -> list[tuple[bytes, bytes]]:
        """The SUSP entries of a record: its System Use area, then any continuation areas."""
        nlen = rec[32]
        area = rec[33 + nlen + (1 - nlen % 2):][skip:]
        out, hops, seen = [], 0, set()
        while area is not None:
            ce, j = None, 0
            while j + 4 <= len(area):
                sig, ln = area[j:j + 2], area[j + 2]
                if ln < 4 or j + ln > len(area):
                    break
                body = area[j + 4:j + ln]
                if sig == b"CE" and len(body) >= 24:
                    ce = struct.unpack_from("<I", body, 0)[0], struct.unpack_from("<I", body, 8)[0], \
                        struct.unpack_from("<I", body, 16)[0]
                elif sig == b"ST":
                    break
                else:
                    out.append((sig, body))
                j += ln
            area = None
            if (ce is not None and ce not in seen and hops < 64 and ce[2] <= 1 << 20
                    and ce[0] * SECTOR + ce[1] + ce[2] <= self.source.size):
                seen.add(ce)
                hops += 1
                area = self.source.read_at(ce[0] * SECTOR + ce[1], ce[2])
        return out

    def _walk(self, extent: int, size: int, prefix: str, depth: int) -> None:
        if depth > MAX_DEPTH or extent in self.seen:
            return
        self.seen.add(extent)
        pending: list[tuple[int, int]] = []
        for rec in self._records(extent, size):
            if len(self.members) + len(pending) > MAX_ITEMS:
                raise PackportError(f"The disc image lists more than {MAX_ITEMS:,} files (it's damaged)")
            flags, nlen = rec[25], rec[32]
            raw = rec[33:33 + nlen]
            if raw in (b"\0", b"\1"):
                continue
            ext, length = struct.unpack_from("<I", rec, 2)[0], struct.unpack_from("<I", rec, 10)[0]
            info = self._rock(rec) if self.mode == "rr" else {}
            if info.get("relocated"):
                self.moved.append((rec, f"{prefix}{info.get('name') or self._plain_name(raw)}", depth))
                continue
            if flags & 0x80:  # this file goes on in the next record
                pending.append((ext * SECTOR, length))
                continue
            parts = [*pending, (ext * SECTOR, length)]
            pending = []
            name = info.get("name") or self._plain_name(raw)
            if not name or name in (".", "..") or "/" in name:
                name = name.replace("/", "_") if name and name not in (".", "..") else "_"
            path = f"{prefix}{name}"
            mtime = info.get("mtime") or _time(rec)
            mode = info.get("mode", 0)
            is_dir = bool(flags & 0x02) or "child" in info or stat.S_ISDIR(mode)
            if is_dir:
                if "child" in info:
                    child = next(self._records(info["child"], SECTOR), None)
                    if child is None:
                        continue
                    ext, length = info["child"], struct.unpack_from("<I", child, 10)[0]
                self.members.append(Item(path, 0, True, None, mtime, mode or (stat.S_IFDIR | 0o755)))
                self._walk(ext, length, path + "/", depth + 1)
                continue
            if "link" in info:
                self.members.append(Item(path, 0, False, info["link"], mtime, mode or (stat.S_IFLNK | 0o777)))
                continue
            if mode and not stat.S_ISREG(mode):
                continue  # devices, FIFOs, sockets
            total = sum(n for _, n in parts)
            zf = info.get("zf")
            self.members.append(Item(path, zf if zf is not None else total, False, None, mtime,
                                     mode or (stat.S_IFREG | 0o644), ref=(parts, zf)))

    def _plain_name(self, raw: bytes) -> str:
        if self.mode == "joliet":
            name = raw.decode("utf-16-be", "replace")
        else:
            name = raw.decode("latin-1")
        name = name.split(";", 1)[0]
        if self.mode != "joliet" and name.endswith("."):
            name = name[:-1]
        return name

    def _rock(self, rec: bytes) -> dict:
        info: dict = {}
        name, link_parts, part = b"", [], b""
        for sig, body in self._susp(rec, self.rr_skip or 0):
            if sig == b"NM" and body:
                if body[0] & 6:
                    continue
                name += body[1:]
            elif sig == b"PX" and len(body) >= 4:
                info["mode"] = struct.unpack_from("<I", body, 0)[0]
            elif sig == b"TF" and body:
                tf, at = body[0], 1
                size = 17 if tf & 0x80 else 7
                for bit in (1, 2):
                    if tf & bit:
                        if bit == 2 and at + size <= len(body):
                            stamp = body[at:at + size]
                            info["mtime"] = _long_time(stamp) if size == 17 else _time(stamp, 0)
                        at += size
            elif sig == b"SL" and body:
                j = 1
                while j + 2 <= len(body):
                    cf, cl = body[j], body[j + 1]
                    text = body[j + 2:j + 2 + cl]
                    if cf & 8:
                        link_parts.append(b"")
                    elif cf & 2:
                        link_parts.append(b".")
                    elif cf & 4:
                        link_parts.append(b"..")
                    else:
                        part += text
                        if not cf & 1:
                            link_parts.append(part)
                            part = b""
                    j += 2 + cl
                info["link"] = True
            elif sig == b"CL" and len(body) >= 4:
                info["child"] = struct.unpack_from("<I", body, 0)[0]
            elif sig == b"RE":
                info["relocated"] = True
            elif sig == b"ZF" and len(body) >= 8 and body[:2] == b"pz":
                info["zf"] = struct.unpack_from("<I", body, 4)[0]
        if name:
            info["name"] = name.decode("utf-8", "replace")
        if info.get("link"):
            info["link"] = "/".join(p.decode("utf-8", "replace") for p in link_parts) or "/"
            if link_parts and link_parts[0] == b"":
                info["link"] = "/" + "/".join(p.decode("utf-8", "replace") for p in link_parts[1:])
        return info

    # -- El Torito

    def _boot(self, lba: int) -> None:
        cat = self.source.read_at(lba * SECTOR, SECTOR)
        if len(cat) < 64 or cat[0] != 1 or cat[30:32] != b"\x55\xaa":
            return
        entries = [cat[32:64]]
        at = 64
        while at + 32 <= len(cat) and cat[at] in (0x90, 0x91):
            count = struct.unpack_from("<H", cat, at + 2)[0]
            entries += [cat[at + 32 * (k + 1):at + 32 * (k + 2)] for k in range(count)]
            last = cat[at] == 0x91
            at += 32 * (count + 1)
            if last:
                break
        names: dict[str, int] = {}
        for e in entries:
            if len(e) < 32 or e[0] not in (0x88, 0x00):
                continue
            media = e[1] & 0x0F
            if media not in BOOT_MEDIA:
                continue
            what, size = BOOT_MEDIA[media]
            count, rba = struct.unpack_from("<HI", e, 6)
            if media == 0:
                size = count * 512
            elif media == 4:
                size = self._hard_disk_size(rba)
            if not size or rba * SECTOR + size > self.source.size:
                size = max(0, min(size, self.source.size - rba * SECTOR))
            name = f"[BOOT]/Boot-{what}.img"
            n = names.get(name, 0)
            names[name] = n + 1
            if n:
                name = f"[BOOT]/Boot-{what}-{n}.img"
            self.members.append(Item(name, size, False, None, 0.0, stat.S_IFREG | 0o444,
                                     ref=([(rba * SECTOR, size)], None)))

    def _hard_disk_size(self, rba: int) -> int:
        mbr = self.source.read_at(rba * SECTOR, 512)
        if len(mbr) < 512 or mbr[510:512] != b"\x55\xaa":
            return 0
        start, count = struct.unpack_from("<II", mbr, 446 + 8)
        return (start + count) * 512

    # -- data

    def open_member(self, item: Item):
        parts, zf = item.ref
        stream = _Parts(self.source, parts)
        if zf is None:
            return stream
        stored = sum(n for _, n in parts)
        return Stream(item.name, _unzisofs(lambda: _Parts(self.source, parts), stored, item.size, item.name),
                      item.size, what="disc image")


def _unzisofs(open_parts, stored: int, size: int, name: str) -> Iterator[bytes]:
    """zisofs: a header (magic, size, header size / 4, log2 of the block size), a table of block
    offsets, then each block on its own as zlib data (an empty block is zeros). Unpacked a block
    at a time; open_parts() gives the stored data from its start, stored bytes of it."""
    data = open_parts()
    head = data.read(16)
    if len(head) < 16 or head[:8] != ZISOFS_MAGIC:
        raise PackportError(f"{name}: the zisofs data is damaged")
    hsize, bits = head[12] * 4, head[13]
    if not 15 <= bits <= 17 or hsize < 16:
        raise PackportError(f"{name}: the zisofs data is damaged (block size)")
    block = 1 << bits
    nblocks = (size + block - 1) // block
    if 4 * (nblocks + 1) > stored:  # a table longer than the data: the size is damaged
        raise PackportError(f"{name}: the zisofs data is cut short")
    data.read(hsize - 16)
    table = data.read(4 * (nblocks + 1))
    if len(table) < 4 * (nblocks + 1):
        raise PackportError(f"{name}: the zisofs data is cut short")
    ptrs = struct.unpack(f"<{nblocks + 1}I", table)
    pos, left = hsize + len(table), size
    for k in range(nblocks):
        want = min(block, left)
        a, b = ptrs[k], ptrs[k + 1]
        if b < a or b > stored:
            raise PackportError(f"{name}: the zisofs data is damaged")
        left -= want
        if a == b:
            yield bytes(want)
            continue
        if a < pos:  # blocks out of order: read from the start again
            data, pos = open_parts(), 0
        data.read(a - pos)
        raw = data.read(b - a)
        pos = b
        try:
            piece = zlib.decompressobj().decompress(raw, want)
        except zlib.error as e:
            raise PackportError(f"{name}: the zisofs data is damaged ({e})") from None
        if len(piece) < want:
            raise PackportError(f"{name}: the zisofs data is damaged (a block unpacks short)")
        yield piece
