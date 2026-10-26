"""CPIO archives in the SVR4 "newc" format (magic ``070701``), as used by Linux initramfs and RPM.

Each member is a 110-byte ASCII header (the magic, then 13 fields of 8 hex digits: inode, mode,
uid, gid, link count, mtime, file size, device major/minor, rdev major/minor, name size including
its NUL, checksum), the name and a NUL padded to a multiple of 4 bytes, then the data padded to a
multiple of 4 bytes. The archive ends with a member named ``TRAILER!!!``. Names are UTF-8.

The format's sizes are 32-bit, so a member can't reach 4 GiB.
"""

from __future__ import annotations

import os
import re
import stat

from .entries import Entry, Member, Output, PackportError, Sources, collect, copy

MAGIC = b"070701"
MAGIC_CRC = b"070702"   # same layout, with a byte-sum checksum of the data
TRAILER = "TRAILER!!!"
HEADER_SIZE = 110
_HEX = re.compile(rb"[0-9A-Fa-f]{104}")


def _header(ino: int, mode: int, nlink: int, mtime: int, size: int, name: bytes) -> bytes:
    fields = (ino, mode, 0, 0, nlink, mtime, size, 0, 0, 0, 0, len(name) + 1, 0)
    head = MAGIC + b"".join(b"%08X" % f for f in fields) + name + b"\0"
    return head + bytes(-len(head) % 4)


class CpioWriter:
    """Write a newc CPIO archive entry by entry; ``out`` is a path or a writable binary file.
    File data is streamed."""

    def __init__(self, out):
        self._out = Output(out)
        self._f = self._out.f
        self._ino = 0
        self._names: set[str] = set()
        self._closed = False

    def add(self, name: str, source=None, *, is_dir: bool = False, mtime: float | None = None,
            mode: int | None = None) -> None:
        """Add a file (``source`` = bytes or a path) or, with no source, a directory."""
        self.add_entry(Entry(name, source, is_dir, mtime, mode))

    def add_entry(self, e: Entry) -> None:
        if e.name in self._names:
            raise PackportError(f"{e.name} is in the archive twice")
        name = e.name.encode("utf-8")
        mtime = min(max(int(e.mtime), 0), 0xFFFFFFFF)
        self._ino += 1
        if e.is_dir:
            self._names.add(e.name)
            self._f.write(_header(self._ino, stat.S_IFDIR | e.mode & 0o7777, 2, mtime, 0, name))
            return
        with e.open() as src:
            size = len(e.source) if isinstance(e.source, bytes) else os.fstat(src.fileno()).st_size
            if size > 0xFFFFFFFF:
                raise PackportError(f"{e.name} is {size:,} bytes; CPIO can't hold files of 4 GiB or more")
            self._names.add(e.name)
            self._f.write(_header(self._ino, stat.S_IFREG | e.mode & 0o7777, 1, mtime, size, name))
            copy(src, self._f, size, e.name)
            self._f.write(bytes(-size % 4))

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._f.write(_header(0, 0, 1, 0, 0, TRAILER.encode()))
            self._out.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *_):
        if exc_type is None:
            self.close()
        else:
            self._closed = True
            self._out.close(failed=True)


def write_cpio(out, sources: Sources) -> list[Entry]:
    """Write a newc CPIO archive. ``sources`` works as for ``write_rar``. Returns the entries."""
    entries = collect(sources)
    with CpioWriter(out) as cpio:
        for e in entries:
            cpio.add_entry(e)
    return entries


def read_cpio(data: bytes | str | os.PathLike) -> list[Member]:
    """Read a newc (``070701``) or newc-with-checksum (``070702``) CPIO archive. Symbolic links
    come back as members whose ``mode`` says so and whose data is the link target."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        with open(data, "rb") as f:
            data = f.read()
    data = bytes(data)
    out: list[Member] = []
    pos = 0
    while True:
        head = data[pos:pos + HEADER_SIZE]
        if len(head) < HEADER_SIZE:
            raise PackportError("CPIO archive is cut short (no TRAILER!!! entry)")
        magic = head[:6]
        if magic not in (MAGIC, MAGIC_CRC):
            if magic == b"070707" or head[:2] in (b"\xc7\x71", b"\x71\xc7"):  # odc, old binary
                raise PackportError("This is an old-style CPIO archive; packport reads newc")
            raise PackportError("Not a newc CPIO archive" if pos == 0 else "Damaged CPIO archive")
        if not _HEX.fullmatch(head[6:]):
            raise PackportError("Damaged CPIO header")
        f = [int(head[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
        _ino, mode, _uid, _gid, _nlink, mtime, size, *_, namesize, check = f
        if namesize < 1:
            raise PackportError("Damaged CPIO header")
        name_end = pos + HEADER_SIZE + namesize
        if name_end > len(data):
            raise PackportError("CPIO archive is cut short")
        name = data[pos + HEADER_SIZE:name_end].split(b"\0", 1)[0].decode("utf-8", "replace")
        start = name_end + (-(HEADER_SIZE + namesize) % 4)
        if name == TRAILER:
            return out
        end = start + size
        if end > len(data):
            raise PackportError(f"{name}: the archive is cut short")
        payload = data[start:end]
        if magic == MAGIC_CRC and stat.S_ISREG(mode) and sum(payload) & 0xFFFFFFFF != check:
            raise PackportError(f"{name}: data checksum doesn't match (the archive is damaged)")
        out.append(Member(name, payload, stat.S_ISDIR(mode), float(mtime), mode))
        pos = end + (-size % 4)
