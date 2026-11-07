"""HFS+ and HFSX (Mac OS Extended), also inside a classic HFS wrapper.

Written from Apple's Technical Note TN1150. The volume header (at byte 1024) gives the block
size and the forks (extents) of the special files. The catalog file is a B-tree whose leaf
records are folders, files and threads, each keyed by its parent folder's ID and its name
(UTF-16); walking every leaf node gives the whole tree. A file's data fork lists up to 8
extents; more are in the extents overflow file, another B-tree. Hard links are files of type
"hlnk" pointing to a node in the hidden metadata folder; symbolic links keep their target as
data. Files compressed by macOS (decmpfs) are unpacked when they use zlib, inline in the
attribute or in the resource fork; LZVN and LZFSE ones are refused with a clear message.
"""

from __future__ import annotations

import stat
import struct
import zlib

from ..archive import Item
from ..entries import PackportError
from . import Extents

HFS_EPOCH = 2082844800  # seconds from 1904 to 1970
ROOT = 2
FOLDER, FILE = 1, 2
PRIVATE = "\0\0\0\0HFS+ Private Data"
HIDDEN = {PRIVATE, ".HFS+ Private Directory Data\r", ".journal", ".journal_info_block", ".Trashes",
          ".fseventsd", ".Spotlight-V100", ".DocumentRevisions-V100"}
MAX_NODES = 1 << 22
MAX_DEPTH = 256


def _volume_start(dev) -> int | None:
    sig = dev.read_at(1024, 2)
    if sig in (b"H+", b"HX"):
        return 0
    if sig == b"BD":  # an HFS wrapper around an HFS+ volume
        mdb = dev.read_at(1024, 162)
        if mdb[124:126] == b"H+":
            al_block, = struct.unpack_from(">I", mdb, 20)
            first, = struct.unpack_from(">H", mdb, 28)
            start, = struct.unpack_from(">H", mdb, 126)
            return first * 512 + start * al_block
    return None


def probe(dev) -> bool:
    return _volume_start(dev) is not None


class _Fork:
    def __init__(self, raw: bytes):
        self.size, = struct.unpack_from(">Q", raw, 0)
        self.extents = [struct.unpack_from(">II", raw, 16 + 8 * k) for k in range(8)]


class Hfs:
    def __init__(self, dev):
        start = _volume_start(dev)
        if start is None:
            raise PackportError("This isn't an HFS+ volume")
        if start:
            from . import Slice
            dev = Slice(dev, start, dev.size - start)
        self.dev = dev
        vh = dev.read_at(1024, 512)
        self.name = "HFSX" if vh[:2] == b"HX" else "HFS+"
        self.bs, = struct.unpack_from(">I", vh, 40)
        if self.bs < 512 or self.bs & (self.bs - 1):
            raise PackportError("The HFS+ volume is damaged (its block size)")
        self.overflow_fork = _Fork(vh[192:272])
        self.catalog_fork = _Fork(vh[272:352])
        self.attr_fork = _Fork(vh[352:432])
        self.overflow: dict[tuple[int, int], list[tuple[int, int]]] = {}
        if self.overflow_fork.size:
            for key, data in self._leaves(self._fork_runs(self.overflow_fork, 0, 0xFF)):
                if len(key) >= 10:
                    kind, _pad, fid, first = struct.unpack_from(">BBII", key, 0)
                    self.overflow.setdefault((kind, fid), []).append(
                        (first, [struct.unpack_from(">II", data, 8 * k) for k in range(8)]))
        self.decmpfs: dict[int, bytes] = {}
        if self.attr_fork.size:
            for key, data in self._leaves(self._fork_runs(self.attr_fork, 0, 0xFE)):
                if len(key) < 12:
                    continue
                fid, = struct.unpack_from(">I", key, 2)
                nlen, = struct.unpack_from(">H", key, 10)
                name = key[12:12 + 2 * nlen].decode("utf-16-be", "replace")
                if name == "com.apple.decmpfs" and len(data) >= 16 and struct.unpack_from(">I", data, 0)[0] == 0x10:
                    size, = struct.unpack_from(">I", data, 12)
                    self.decmpfs[fid] = data[16:16 + size]
        self.folders: dict[int, tuple[int, str, float, int]] = {}  # id -> (parent, name, mtime, mode)
        files: list[tuple[int, str, bytes]] = []
        for key, data in self._leaves(self._fork_runs(self.catalog_fork, 0, 0)):
            if len(key) < 8 or len(data) < 2:
                continue
            parent, nlen = struct.unpack_from(">IH", key, 2)
            name = key[8:8 + 2 * nlen].decode("utf-16-be", "replace")
            kind, = struct.unpack_from(">h", data, 0)
            if kind == FOLDER and len(data) >= 88:
                fid, = struct.unpack_from(">I", data, 8)
                mtime, = struct.unpack_from(">I", data, 16)
                mode, = struct.unpack_from(">H", data, 42)
                self.folders[fid] = (parent, name, float(mtime - HFS_EPOCH) if mtime else 0.0, mode)
            elif kind == FILE and len(data) >= 248:
                files.append((parent, name, data))
        self.members: list[Item] = []
        self.nodes: dict[str, bytes] = {}  # hard link targets: "iNode<n>" in the private folder
        private = next((fid for fid, (p, n, _, _) in self.folders.items() if p == ROOT and n == PRIVATE), None)
        for parent, name, data in files:
            if parent == private:
                self.nodes[name] = data
        cache: dict[int, str | None] = {ROOT: ""}

        def path(fid: int, depth: int = 0) -> str | None:
            if fid in cache:
                return cache[fid]
            if depth > MAX_DEPTH or fid not in self.folders:
                return None
            parent, name, _, _ = self.folders[fid]
            up = path(parent, depth + 1)
            result = None if up is None or (up == "" and name in HIDDEN) else (f"{up}/{name}" if up else name)
            cache[fid] = result
            return result

        for fid, (parent, name, mtime, mode) in sorted(self.folders.items()):
            if fid == ROOT:
                continue
            p = path(fid)
            if p:
                self.members.append(Item(self._clean(p), 0, True, None, mtime, stat.S_IFDIR | (mode & 0o7777 or 0o755)))
        for parent, name, data in files:
            up = path(parent)
            if up is None or (up == "" and name in HIDDEN):
                continue
            p = self._clean(f"{up}/{name}" if up else name)
            ftype, creator = data[48:52], data[52:56]
            if ftype == b"hlnk" and creator == b"hfs+":  # a hard link: the data is in the node it names
                special, = struct.unpack_from(">I", data, 44)
                target = self.nodes.get(f"iNode{special}")
                if target is None:
                    continue
                data = target
            mode, = struct.unpack_from(">H", data, 42)
            mtime, = struct.unpack_from(">I", data, 16)
            mtime = float(mtime - HFS_EPOCH) if mtime else 0.0
            fid, = struct.unpack_from(">I", data, 8)
            fork = _Fork(data[88:168])
            if stat.S_ISLNK(mode):
                target = Extents(self.dev, self._fork_runs(fork, fid, 0), min(fork.size, 4096)).read()
                self.members.append(Item(p, 0, False, target.decode("utf-8", "replace") or "?", mtime, mode))
                continue
            if mode and not stat.S_ISREG(mode):
                continue  # devices, FIFOs, sockets
            compressed = data[41] & 0x20 and fid in self.decmpfs  # UF_COMPRESSED
            size = struct.unpack_from("<Q", self.decmpfs[fid], 8)[0] if compressed else fork.size
            self.members.append(Item(p, size, False, None, mtime, stat.S_IFREG | (mode & 0o7777 or 0o644),
                                     ref=(fid, fork, _Fork(data[168:248]), bool(compressed))))

    @staticmethod
    def _clean(path: str) -> str:
        return "/".join((part.replace("/", ":") or "_") for part in path.split("/"))

    def _fork_runs(self, fork: _Fork, fid: int, kind: int) -> list[tuple[int, int]]:
        """A fork's data as (byte offset, length) runs, the overflow extents included."""
        extents = [e for e in fork.extents if e[1]]
        blocks = sum(n for _, n in extents)
        for first, more in sorted(self.overflow.get((kind, fid), [])) if fid else []:
            if first == blocks:
                extents += [e for e in more if e[1]]
                blocks = sum(n for _, n in extents)
        runs, total = [], 0
        for start, count in extents:
            n = min(count * self.bs, fork.size - total)
            if n <= 0:
                break
            runs.append((start * self.bs, n))
            total += n
        if total < fork.size:
            raise PackportError("The HFS+ volume is damaged (a fork's extents end early)")
        return runs

    def _leaves(self, runs: list[tuple[int, int]]):
        """Every leaf record (key, data) of a B-tree file, in order."""
        size = sum(n for _, n in runs)
        tree = Extents(self.dev, runs, size)
        header = tree.read(512)
        if len(header) < 512:
            raise PackportError("The HFS+ volume is damaged (a B-tree header)")
        _depth, _root, _records, first, _last, node_size = struct.unpack_from(">HIIIIH", header, 14)
        if node_size < 512 or node_size & (node_size - 1):
            raise PackportError("The HFS+ volume is damaged (a B-tree node size)")
        data = header + tree.read(size)
        node, seen = first, set()
        while node and node not in seen and len(seen) < MAX_NODES:
            seen.add(node)
            raw = data[node * node_size:(node + 1) * node_size]
            if len(raw) < node_size:
                raise PackportError("The HFS+ volume is damaged (a B-tree node is missing)")
            flink, _blink, kind, _height, count = struct.unpack_from(">IIbBH", raw, 0)
            if kind != -1:
                raise PackportError("The HFS+ volume is damaged (a B-tree leaf)")
            offsets = struct.unpack_from(f">{count + 1}H", raw, node_size - 2 * (count + 1))[::-1]
            for k in range(count):
                rec = raw[offsets[k]:offsets[k + 1]]
                if len(rec) < 2:
                    continue
                klen, = struct.unpack_from(">H", rec, 0)
                key = rec[:2 + klen]
                body = rec[(2 + klen + 1) & ~1:]
                yield key, body
            node = flink

    def open_member(self, item: Item):
        import io
        fid, fork, rsrc, compressed = item.ref
        if not compressed:
            return Extents(self.dev, self._fork_runs(fork, fid, 0), fork.size, item.name)
        return io.BytesIO(self._decompress(item, fid, rsrc))

    def _decompress(self, item: Item, fid: int, rsrc: _Fork) -> bytes:
        attr = self.decmpfs[fid]
        kind, size = struct.unpack_from("<IQ", attr, 4)
        try:
            if kind == 3:  # zlib (or stored when the first byte says so), inline in the attribute
                body = attr[16:]
                return body[1:1 + size] if body[:1] == b"\xff" else zlib.decompress(body)[:size]
            if kind == 4:  # zlib in the resource fork: a table of 64 KB blocks
                fork = Extents(self.dev, self._fork_runs(rsrc, fid, 0xFF), rsrc.size).read()
                data_at, = struct.unpack_from(">I", fork, 0)
                base = data_at + 4
                count, = struct.unpack_from("<I", fork, base)
                out = bytearray()
                for k in range(count):
                    off, n = struct.unpack_from("<II", fork, base + 4 + 8 * k)
                    block = fork[base + off:base + off + n]
                    out += block[1:] if block[:1] == b"\xff" else zlib.decompress(block)
                return bytes(out[:size])
        except (zlib.error, struct.error) as e:
            raise PackportError(f"{item.name}: the compressed data is damaged ({e})") from None
        what = {7: "LZVN", 8: "LZVN", 11: "LZFSE", 12: "LZFSE", 5: "a sparse form", 9: "raw blocks"}.get(kind, f"type {kind}")
        raise PackportError(f"{item.name} is compressed by macOS with {what}, which packport doesn't read yet")
