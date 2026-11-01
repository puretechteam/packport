"""A squashfs 4.0 writer, for tests only: the real images on hand are big (random data) or few,
so make_fixtures.py writes small ones with every compressor this one has, fragments, holes and
extended inodes, and 7-Zip has to read them back.

Data blocks first, then the inode table, the folder listings, the fragment table and the uid/gid
table, each table in 8 KB metadata blocks. Inodes are written children first, so a folder's
listing can name them, and its own inode follows its listing."""

import lzma
import struct
import zlib

GZIP, LZMA, XZ, LZ4, ZSTD = 1, 2, 4, 5, 6
META = 8192


def _compress(comp: int, data: bytes) -> bytes:
    if comp == GZIP:
        return zlib.compress(data, 9)
    if comp == XZ:
        return lzma.compress(data, lzma.FORMAT_XZ, check=lzma.CHECK_CRC32)
    if comp == LZMA:
        return lzma.compress(data, lzma.FORMAT_ALONE)
    if comp == LZ4:
        import lz4.block
        return lz4.block.compress(data, store_size=False)
    from backports import zstd
    return zstd.compress(data)


class _Meta:
    """A table of metadata blocks: (block start, offset) for every position written."""

    def __init__(self, comp: int):
        self.comp, self.raw, self.out, self.starts = comp, bytearray(), bytearray(), [0]

    def where(self) -> tuple[int, int]:
        return self.starts[len(self.raw) // META], len(self.raw) % META

    def write(self, data: bytes) -> None:
        self.raw += data
        while len(self.raw) >= META * len(self.starts):
            self._flush(len(self.starts) - 1)

    def _flush(self, k: int) -> None:
        chunk = bytes(self.raw[META * k:META * (k + 1)])
        packed = _compress(self.comp, chunk)
        if len(packed) >= len(chunk):
            self.out += struct.pack("<H", 0x8000 | len(chunk)) + chunk
        else:
            self.out += struct.pack("<H", len(packed)) + packed
        self.starts.append(len(self.out))

    def done(self) -> bytes:
        if len(self.raw) > META * (len(self.starts) - 1):
            self._flush(len(self.starts) - 1)
        return bytes(self.out)


def write(files: dict, comp: int, block_size: int = 4096, mtime: int = 1600000000) -> bytes:
    """files: {path: bytes, or None for a folder, or ("link", target)}."""
    tree: dict = {}
    for path, value in files.items():
        node, parts = tree, path.split("/")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = {} if value is None else value
    data = bytearray(bytes(96))
    if comp == LZ4:  # LZ4 needs its options: version 1, no flags
        opts = struct.pack("<II", 1, 0)
        data += struct.pack("<H", 0x8000 | len(opts)) + opts
    inodes, dirs = _Meta(comp), _Meta(comp)
    frags: list[tuple[int, int]] = []
    frag_buf = bytearray()
    numbers = [0]

    def flush_fragment() -> None:
        nonlocal frag_buf
        if frag_buf:
            packed = _compress(comp, bytes(frag_buf))
            stored = len(packed) >= len(frag_buf)
            body = bytes(frag_buf) if stored else packed
            frags.append((len(data), len(body) | (0x1000000 if stored else 0)))
            data.extend(body)
            frag_buf = bytearray()

    def add_file(body: bytes) -> tuple[int, int]:
        start, sizes, holes = len(data), [], 0
        full = len(body) // block_size
        for k in range(full):
            block = body[k * block_size:(k + 1) * block_size]
            if not any(block):
                sizes.append(0)
                holes += block_size
                continue
            packed = _compress(comp, block)
            if len(packed) >= len(block):
                sizes.append(len(block) | 0x1000000)
                data.extend(block)
            else:
                sizes.append(len(packed))
                data.extend(packed)
        tail = body[full * block_size:]
        frag, foff = 0xFFFFFFFF, 0
        if tail:
            if len(frag_buf) + len(tail) > block_size:
                flush_fragment()
            frag, foff = len(frags), len(frag_buf)
            frag_buf.extend(tail)
        numbers[0] += 1
        ref = inodes.where()
        if holes or len(body) >= 1 << 32:  # an extended file inode, with its count of hole bytes
            inodes.write(struct.pack("<HHHHII", 9, 0o644, 0, 0, mtime, numbers[0]))
            inodes.write(struct.pack("<QQQIIII", start, len(body), holes, 1, frag, foff, 0xFFFFFFFF))
        else:
            inodes.write(struct.pack("<HHHHII", 2, 0o644, 0, 0, mtime, numbers[0]))
            inodes.write(struct.pack("<IIII", start, frag, foff, len(body)))
        inodes.write(struct.pack(f"<{len(sizes)}I", *sizes))
        return ref[0] << 16 | ref[1], numbers[0]

    def add_dir(node: dict, parent: int | None) -> tuple[int, int]:
        entries = []
        for name in sorted(node):
            value = node[name]
            if isinstance(value, dict):
                ref, number = add_dir(value, None)
                kind = 1
            elif isinstance(value, tuple):
                target = value[1].encode()
                numbers[0] += 1
                number = numbers[0]
                where = inodes.where()
                inodes.write(struct.pack("<HHHHII", 3, 0o777, 0, 0, mtime, number))
                inodes.write(struct.pack("<II", 1, len(target)) + target)
                ref, kind = where[0] << 16 | where[1], 3
            else:
                ref, number = add_file(value)
                kind = 2
            entries.append((name.encode(), ref, number, kind))
        listing = bytearray()
        k = 0
        while k < len(entries):  # one header per run sharing an inode block (and at most 256)
            block, base = entries[k][1] >> 16, entries[k][2]
            j = k
            while (j < len(entries) and j - k < 256 and entries[j][1] >> 16 == block
                   and abs(entries[j][2] - base) < 32767):
                j += 1
            run = entries[k:j]
            listing += struct.pack("<III", len(run) - 1, block, base)
            for name, ref, number, kind in run:
                listing += struct.pack("<HhHH", ref & 0xFFFF, number - base, kind, len(name) - 1) + name
            k += len(run)
        dir_at = dirs.where()
        dirs.write(bytes(listing))
        numbers[0] += 1
        number = numbers[0]
        where = inodes.where()
        inodes.write(struct.pack("<HHHHII", 1, 0o755, 0, 0, mtime, number))
        inodes.write(struct.pack("<IIHHI", dir_at[0], 2, len(listing) + 3, dir_at[1], parent or number + 1))
        return where[0] << 16 | where[1], number

    root_ref, _ = add_dir(tree, None)
    flush_fragment()
    inode_table = len(data)
    data += inodes.done()
    dir_table = len(data)
    data += dirs.done()
    frag_meta = _Meta(comp)
    frag_meta.write(b"".join(struct.pack("<QII", s, n, 0) for s, n in frags))
    frag_blocks = frag_meta.done()
    frag_at = len(data)
    data += frag_blocks
    frag_table = len(data)
    data += b"".join(struct.pack("<Q", frag_at + s) for s in frag_meta.starts[:-1])
    id_meta = _Meta(comp)
    id_meta.write(struct.pack("<I", 0))
    id_at = len(data)
    data += id_meta.done()
    id_table = len(data)
    data += struct.pack("<Q", id_at)
    flags = 0x0200 | (0x0400 if comp == LZ4 else 0)  # no xattrs; compressor options
    struct.pack_into("<4sIIIIHHHHHH8Q", data, 0, b"hsqs", numbers[0], mtime, block_size, len(frags), comp,
                     block_size.bit_length() - 1, flags, 1, 4, 0, root_ref, len(data), id_table, 2 ** 64 - 1,
                     inode_table, dir_table, frag_table, 2 ** 64 - 1)
    data += bytes(-len(data) % 4096)
    return bytes(data)
