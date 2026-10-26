"""CPIO archives in the SVR4 "newc" format (magic ``070701``), as used by Linux initramfs and RPM.

Each member is a 110-byte ASCII header (the magic, then 13 fields of 8 hex digits: inode, mode,
uid, gid, link count, mtime, file size, device major/minor, rdev major/minor, name size including
its NUL, checksum), the name and a NUL padded to a multiple of 4 bytes, then the data padded to a
multiple of 4 bytes. The archive ends with a member named ``TRAILER!!!``. Names are UTF-8.

The format's sizes are 32-bit, so a member can't reach 4 GiB.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import shutil
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO, NamedTuple

from .entries import CHUNK, Entry, Member, Output, PackportError, Sources, collect, copy

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


class _Header(NamedTuple):
    name: str
    mode: int
    mtime: int
    size: int
    nlink: int
    link_key: tuple[int, int, int]  # inode and device: hard links of one file share it
    checksum: int | None            # the 070702 byte sum, None for plain newc


def _headers(f: BinaryIO) -> Iterator[_Header]:
    """Each member's header, leaving ``f`` at the start of its data. The caller reads or skips
    exactly ``size`` bytes before asking for the next one. Stops at the TRAILER!!! entry."""
    first = True
    while True:
        head = f.read(HEADER_SIZE)
        if len(head) < HEADER_SIZE:
            raise PackportError("CPIO archive is cut short (no TRAILER!!! entry)")
        magic = head[:6]
        if magic not in (MAGIC, MAGIC_CRC):
            if magic == b"070707" or head[:2] in (b"\xc7\x71", b"\x71\xc7"):  # odc, old binary
                raise PackportError("This is an old-style CPIO archive; packport reads newc")
            raise PackportError("Not a newc CPIO archive" if first else "Damaged CPIO archive")
        first = False
        if not _HEX.fullmatch(head[6:]):
            raise PackportError("Damaged CPIO header")
        ino, mode, _uid, _gid, nlink, mtime, size, dev_major, dev_minor, _, _, namesize, check = (
            int(head[6 + 8 * i:14 + 8 * i], 16) for i in range(13))
        if namesize < 1:
            raise PackportError("Damaged CPIO header")
        padded = namesize + (-(HEADER_SIZE + namesize) % 4)
        raw = f.read(padded)
        if len(raw) < namesize:
            raise PackportError("CPIO archive is cut short")
        raw = raw[:namesize].split(b"\0", 1)[0]
        try:
            name = raw.decode("utf-8")
        except UnicodeDecodeError:
            name = raw.decode("cp437")
        if name == TRAILER:
            return
        yield _Header(name, mode, mtime, size, nlink, (ino, dev_major, dev_minor),
                      check if magic == MAGIC_CRC and stat.S_ISREG(mode) else None)
        f.read(-size % 4)


def _data(f: BinaryIO, h: _Header, out: BinaryIO | None = None) -> bytes:
    """Read a member's data: into ``out`` in chunks when given (returning b""), else whole."""
    left, total, parts = h.size, 0, []
    while left:
        chunk = f.read(min(CHUNK, left))
        if not chunk:
            raise PackportError(f"{h.name}: the archive is cut short")
        if h.checksum is not None:
            total += sum(chunk)
        if out is None:
            parts.append(chunk)
        else:
            out.write(chunk)
        left -= len(chunk)
    if h.checksum is not None and total & 0xFFFFFFFF != h.checksum:
        raise PackportError(f"{h.name}: data checksum doesn't match (the archive is damaged)")
    return b"".join(parts)


def _open(src) -> contextlib.AbstractContextManager[BinaryIO]:
    """Bytes, a path, or an open binary file (which is left open)."""
    if isinstance(src, (bytes, bytearray, memoryview)):
        return io.BytesIO(bytes(src))
    if hasattr(src, "read"):
        return contextlib.nullcontext(src)
    return open(src, "rb")


def read_cpio(data: bytes | str | os.PathLike | BinaryIO) -> list[Member]:
    """Read a newc (``070701``) or newc-with-checksum (``070702``) CPIO archive. Symbolic links
    come back as members whose ``mode`` says so and whose data is the link target. Hard links
    each get the file's data (newc stores it once, with the last link). CPIO doesn't record an
    encoding: names are UTF-8 when they're valid UTF-8, and otherwise read in the DOS code page
    (cp437), which is what libarchive on Windows writes by default. To unpack an archive too big
    for memory, use ``extract_cpio``."""
    out: list[Member] = []
    links: dict[tuple, list[Member]] = {}
    with _open(data) as f:
        for h in _headers(f):
            out.append(Member(h.name, _data(f, h), stat.S_ISDIR(h.mode), float(h.mtime), h.mode))
            if h.nlink > 1 and stat.S_ISREG(h.mode):
                links.setdefault(h.link_key, []).append(out[-1])
    for group in links.values():
        shared = next((m.data for m in reversed(group) if m.data), b"")
        for m in group:
            m.data = m.data or shared
    return out


def extract_cpio(archive: bytes | str | os.PathLike | BinaryIO, dest: str | os.PathLike) -> list[Path]:
    """Unpack a newc CPIO archive (bytes, a path or an open binary file) into the folder
    ``dest``, streaming file data so archives larger than memory work. Nothing lands outside
    ``dest``: leading slashes are dropped (as bsdtar does), names that would still climb out or
    name a drive are skipped, and so are symbolic links and device files. Files keep their
    modification times, and hard links each get the file's data. Returns every file and folder
    written."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    written: list[Path] = []
    waiting: dict[tuple, list[Path]] = {}  # hard links seen before the one that carries the data
    with _open(archive) as f:
        for h in _headers(f):
            rel = h.name.replace("\\", "/").lstrip("/")
            target = (dest / rel).resolve()
            if (":" in rel.split("/", 1)[0] or root not in target.parents
                    or not (stat.S_ISDIR(h.mode) or stat.S_ISREG(h.mode))):
                _data(f, h, _Discard())
                continue
            if stat.S_ISDIR(h.mode):
                _data(f, h, _Discard())
                target.mkdir(parents=True, exist_ok=True)
                written.append(target)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "wb") as out:
                _data(f, h, out)
            os.utime(target, (h.mtime, h.mtime))
            written.append(target)
            if h.nlink > 1:
                if h.size == 0:
                    waiting.setdefault(h.link_key, []).append(target)
                else:
                    for other in waiting.pop(h.link_key, []):
                        shutil.copy2(target, other)
    return written


class _Discard:
    def write(self, _chunk: bytes) -> None:
        pass
