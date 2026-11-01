"""APFS (Apple File System).

Written from Apple's File System Reference. A container's superblock (the newest valid one in
the checkpoint area, by its Fletcher-64 checksum) gives the block size, the container's object
map and its volumes. An object map is a B-tree from (object ID, transaction) to a block; each
volume's superblock has its own object map and the root of its file-system tree, a B-tree of
records keyed by object ID and type: inodes (mode, times, size), folder entries (name and the
inode it names), file extents (where each run of a file's data is) and extended attributes
(files macOS compressed keep "com.apple.decmpfs" there). Several volumes in one container come
out in a folder each. Encrypted volumes are refused.
"""

from __future__ import annotations

import stat
import struct

from ..archive import EncryptedError, Item
from ..entries import PackportError
from . import Extents

NX_MAGIC, APSB_MAGIC = b"NXSB", b"APSB"
TYPE_INODE, TYPE_XATTR, TYPE_EXTENT, TYPE_DREC = 3, 4, 8, 9
ROOT_DIR = 2
FS_UNENCRYPTED = 0x1
INCOMPAT_CASE_INSENSITIVE, INCOMPAT_NORMALIZATION_INSENSITIVE = 0x1, 0x8
INO_EXT_DSTREAM = 8
MAX_NODES = 1 << 22
MAX_DEPTH = 256


def probe(dev) -> bool:
    return dev.read_at(32, 4) == NX_MAGIC


def _fletcher_ok(block: bytes) -> bool:
    words = struct.unpack(f"<{(len(block) - 8) // 4}I", block[8:8 + (len(block) - 8) // 4 * 4])
    s1 = s2 = 0
    m = 0xFFFFFFFF
    for w in words:
        s1 = (s1 + w) % m
        s2 = (s2 + s1) % m
    c1 = m - ((s1 + s2) % m)
    c2 = m - ((s1 + c1) % m)
    return struct.unpack_from("<Q", block, 0)[0] == (c2 << 32 | c1)


class Apfs:
    name = "APFS"

    def __init__(self, dev):
        self.dev = dev
        sb = dev.read_at(0, 4096)
        if sb[32:36] != NX_MAGIC:
            raise PackportError("This isn't an APFS container")
        self.bs, = struct.unpack_from("<I", sb, 36)
        if self.bs < 4096 or self.bs & (self.bs - 1) or self.bs > 1 << 16:
            raise PackportError("The APFS container is damaged (its block size)")
        sb = self._latest(dev.read_at(0, self.bs))
        omap_oid, = struct.unpack_from("<Q", sb, 160)
        max_fs, = struct.unpack_from("<I", sb, 180)
        self.xid, = struct.unpack_from("<Q", sb, 16)
        container_tree = self._omap_root(omap_oid)
        volumes = []
        for k in range(min(max_fs, 100)):
            oid, = struct.unpack_from("<Q", sb, 184 + 8 * k)
            if not oid:
                continue
            at = self._lookup(container_tree, oid)
            if at is None:
                continue
            vsb = self._block(at)
            if vsb[32:36] != APSB_MAGIC:
                continue
            volumes.append(vsb)
        if not volumes:
            raise PackportError("The APFS container has no volume packport can find")
        self.members: list[Item] = []
        for vsb in volumes:
            prefix = ""
            if len(volumes) > 1:
                vname = vsb[704:960].split(b"\0", 1)[0].decode("utf-8", "replace").replace("/", "_") or "Volume"
                prefix = vname + "/"
                self.members.append(Item(vname, 0, True, None, 0.0, stat.S_IFDIR | 0o755))
            self._volume(vsb, prefix)

    def _block(self, n: int) -> bytes:
        b = self.dev.read_at(n * self.bs, self.bs)
        if len(b) < self.bs:
            raise PackportError("The APFS container is cut short")
        return b

    def _latest(self, sb: bytes) -> bytes:
        """The newest valid container superblock in the checkpoint descriptor area."""
        base, blocks = struct.unpack_from("<QI", sb, 112)[0], struct.unpack_from("<I", sb, 104)[0] & 0x7FFFFFFF
        best = sb
        for k in range(min(blocks, 4096)):
            b = self.dev.read_at((base + k) * self.bs, self.bs)
            if b[32:36] == NX_MAGIC and _fletcher_ok(b) and struct.unpack_from("<Q", b, 16)[0] >= \
                    struct.unpack_from("<Q", best, 16)[0]:
                best = b
        return best

    def _omap_root(self, omap_oid: int) -> int:
        omap = self._block(omap_oid)
        tree, = struct.unpack_from("<Q", omap, 48)
        return tree

    # -- B-trees

    def _records(self, root: int, virtual_map: int | None):
        """Every (key, value) in a B-tree, in key order. Child pointers are physical blocks in an
        object map's tree, virtual object IDs (looked up in virtual_map) in a file-system tree."""
        stack, seen = [root], set()
        while stack:
            n = stack.pop()
            if n in seen or len(seen) > MAX_NODES:
                continue
            seen.add(n)
            node = self._block(n)
            flags, level, nkeys = struct.unpack_from("<HHI", node, 32)
            toc_off, toc_len = struct.unpack_from("<HH", node, 40)
            fixed = flags & 0x4
            key_start = 56 + toc_off + toc_len
            end = self.bs - (40 if flags & 0x1 else 0)
            children = []
            for k in range(nkeys):
                if fixed:
                    ko, vo = struct.unpack_from("<HH", node, 56 + toc_off + 4 * k)
                    kl, vl = 16, 16 if level == 0 else 8
                else:
                    ko, kl, vo, vl = struct.unpack_from("<HHHH", node, 56 + toc_off + 8 * k)
                key = node[key_start + ko:key_start + ko + kl]
                val = node[end - vo:end - vo + vl]
                if level == 0:
                    yield key, val
                else:
                    child, = struct.unpack_from("<Q", val, 0)
                    if virtual_map is not None:
                        child = self._lookup(virtual_map, child)
                        if child is None:
                            continue
                    children.append(child)
            stack.extend(reversed(children))

    def _lookup(self, tree: int, oid: int) -> int | None:
        """The block an object ID maps to in an object map (the newest version)."""
        cache = self.__dict__.setdefault("_maps", {})
        table = cache.get(tree)
        if table is None:
            table = {}
            for key, val in self._records(tree, None):
                koid, kxid = struct.unpack_from("<QQ", key, 0)
                _flags, _size, paddr = struct.unpack_from("<IIQ", val, 0)
                if kxid <= self.xid and (koid not in table or table[koid][0] <= kxid):
                    table[koid] = (kxid, paddr)
            cache[tree] = table
        hit = table.get(oid)
        return hit[1] if hit else None

    # -- a volume

    def _volume(self, vsb: bytes, prefix: str) -> None:
        fs_flags, = struct.unpack_from("<Q", vsb, 264)
        if not fs_flags & FS_UNENCRYPTED:
            raise EncryptedError("This APFS volume is encrypted; packport doesn't decrypt")
        incompat, = struct.unpack_from("<Q", vsb, 56)
        hashed = bool(incompat & (INCOMPAT_CASE_INSENSITIVE | INCOMPAT_NORMALIZATION_INSENSITIVE))
        vomap, root_oid = struct.unpack_from("<QQ", vsb, 128)
        vtree = self._omap_root(vomap)
        root = self._lookup(vtree, root_oid)
        if root is None:
            raise PackportError("The APFS volume is damaged (its file-system tree is missing)")
        inodes: dict[int, tuple] = {}
        children: dict[int, list[tuple[str, int]]] = {}
        extents: dict[int, list[tuple[int, int, int]]] = {}
        decmpfs: dict[int, bytes] = {}
        for key, val in self._records(root, vtree):
            if len(key) < 8:
                continue
            word, = struct.unpack_from("<Q", key, 0)
            oid, kind = word & 0x0FFFFFFFFFFFFFFF, word >> 60
            if kind == TYPE_INODE and len(val) >= 92:
                parent, private, _ctime, mtime = struct.unpack_from("<QQQQ", val, 0)
                mode, = struct.unpack_from("<H", val, 80)
                inodes[oid] = (parent, private, mtime / 1e9, mode, self._dstream_size(val))
            elif kind == TYPE_DREC:
                if hashed:
                    nlen = struct.unpack_from("<I", key, 8)[0] & 0x3FF
                    name = key[12:12 + nlen]
                else:
                    nlen, = struct.unpack_from("<H", key, 8)
                    name = key[10:10 + nlen]
                child, = struct.unpack_from("<Q", val, 0)
                children.setdefault(oid, []).append((name.rstrip(b"\0").decode("utf-8", "replace"), child))
            elif kind == TYPE_EXTENT and len(key) >= 16 and len(val) >= 16:
                logical, = struct.unpack_from("<Q", key, 8)
                length, phys = struct.unpack_from("<QQ", val, 0)
                extents.setdefault(oid, []).append((logical, length & 0x00FFFFFFFFFFFFFF, phys))
            elif kind == TYPE_XATTR and len(key) >= 10:
                nlen, = struct.unpack_from("<H", key, 8)
                if key[10:10 + nlen].rstrip(b"\0") == b"com.apple.decmpfs" and len(val) >= 4:
                    flags, size = struct.unpack_from("<HH", val, 0)
                    if flags & 0x2:  # embedded
                        decmpfs[oid] = val[4:4 + size]
        self.extents = getattr(self, "extents", {})
        self.extents.update(extents)
        seen: set[int] = set()

        def walk(folder: int, path: str, depth: int) -> None:
            if depth > MAX_DEPTH or folder in seen:
                return
            seen.add(folder)
            for name, child in sorted(children.get(folder, [])):
                info = inodes.get(child)
                if info is None or not name:
                    continue
                _parent, private, mtime, mode, size = info
                p = path + name.replace("/", ":")
                if stat.S_ISDIR(mode):
                    if depth == 0 and name in (".fseventsd", ".Spotlight-V100", ".Trashes", "private-dir"):
                        continue
                    self.members.append(Item(p, 0, True, None, mtime, mode))
                    walk(child, p + "/", depth + 1)
                elif stat.S_ISLNK(mode):
                    self.members.append(Item(p, 0, False, "?", mtime, mode))
                elif stat.S_ISREG(mode):
                    comp = decmpfs.get(child)
                    if comp is not None and len(comp) >= 16 and comp[:4] == b"fpmc":
                        size = struct.unpack_from("<Q", comp, 8)[0]
                    self.members.append(Item(p, size, False, None, mtime, mode, ref=(private, size, comp)))

        walk(ROOT_DIR, prefix, 0)

    @staticmethod
    def _dstream_size(val: bytes) -> int:
        """The file's size, from the inode's extended field for its data stream."""
        if len(val) < 96:
            return 0
        count, _used = struct.unpack_from("<HH", val, 92)
        fields = [struct.unpack_from("<BBH", val, 96 + 4 * k) for k in range(count) if 96 + 4 * k + 4 <= len(val)]
        at = 96 + 4 * count
        for kind, _flags, size in fields:
            if kind == INO_EXT_DSTREAM and at + 8 <= len(val):
                return struct.unpack_from("<Q", val, at)[0]
            at += (size + 7) & ~7
        return 0

    def open_member(self, item: Item):
        import io
        import zlib
        private, size, comp = item.ref
        if comp is not None and comp[:4] == b"fpmc":
            kind, = struct.unpack_from("<I", comp, 4)
            if kind == 3:
                body = comp[16:]
                try:
                    return io.BytesIO(body[1:1 + size] if body[:1] == b"\xff" else zlib.decompress(body)[:size])
                except zlib.error as e:
                    raise PackportError(f"{item.name}: the compressed data is damaged ({e})") from None
            what = {7: "LZVN", 8: "LZVN", 11: "LZFSE", 12: "LZFSE", 4: "zlib in its resource fork"}.get(kind, f"type {kind}")
            raise PackportError(f"{item.name} is compressed by macOS with {what}, which packport doesn't read yet")
        runs, pos = [], 0
        for logical, length, phys in sorted(self.extents.get(private, [])):
            if logical > pos:
                runs.append((None, logical - pos))
            runs.append((phys * self.bs if phys else None, length))
            pos = logical + length
        if pos < size:
            runs.append((None, size - pos))
        return Extents(self.dev, runs, size, item.name)
