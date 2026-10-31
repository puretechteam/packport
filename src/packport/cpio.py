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

from .entries import (
    CHUNK,
    Entry,
    Member,
    Output,
    PackportError,
    Sources,
    clamp_time,
    collect,
    copy,
)

MAGIC = b"070701"
MAGIC_CRC = b"070702"   # same layout, with a byte-sum checksum of the data
TRAILER = "TRAILER!!!"
HEADER_SIZE = 110
MAX_NAME = 1 << 16       # the longest name read or written, in bytes with its NUL (Linux allows 4096)
MAX_FILES = 1_000_000    # extract_cpio's default limit on members
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
        if len(name) >= MAX_NAME:
            raise PackportError(f"{e.name[:40]}...: the name is too long for packport's CPIO reader")
        mtime = clamp_time(e.mtime, 0xFFFFFFFF)
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
        if namesize > MAX_NAME:  # checked before reading it: a hostile size could be 4 GiB
            raise PackportError(f"Damaged CPIO header (a name of {namesize:,} bytes; "
                                f"packport reads names up to {MAX_NAME:,})")
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
    for memory, use ``extract_cpio``.

    Names come back exactly as stored, so they can be absolute or contain ``..``: never join them
    onto a folder yourself. ``extract_cpio`` makes them safe."""
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


# Names Windows keeps for devices, with or without an extension ("CON", "nul.txt", "COM¹")
_DEVICES = ({"con", "prn", "aux", "nul", "conin$", "conout$", "clock$"}
            | {f"{d}{n}" for d in ("com", "lpt") for n in "123456789¹²³"})
_WINDOWS_BAD = re.compile(r'[\x00-\x1f<>:"|?*]')


def _windows_name(part: str) -> str:
    """A name Windows can create, renamed the way 7-Zip does it: characters Windows doesn't allow
    become "_" (a ':' would otherwise write an alternate data stream), a trailing dot or space
    becomes "_", and device names get a "_" in front."""
    part = _WINDOWS_BAD.sub("_", part)
    if part[-1] in ". ":
        part = part.rstrip(". ") + "_"
    if part.split(".", 1)[0].rstrip(" ").lower() in _DEVICES:
        part = "_" + part
    return part


_DRIVE = re.compile(r"[A-Za-z]:\Z")  # "C:" as the whole first part: an absolute Windows path


def _create(target: Path, counters: dict[str, int]):
    """Open a new file at target, or at "name (1).ext", "name (2).ext"... when that name is
    taken (the same name twice in the archive, a folder, a file already there, or only the case
    differs on Windows). ``counters`` remembers how far each name got, so n copies of a name cost
    about n tries rather than n*n/2."""
    key = os.path.normcase(target)
    stem, suffix, n = target.stem, target.suffix, counters.get(key, 0)
    while True:
        path = target.with_name(f"{stem} ({n}){suffix}") if n else target
        try:
            f = open(path, "xb")  # noqa: SIM115 - the caller closes it
        except FileExistsError:
            pass
        except (IsADirectoryError, PermissionError):  # a folder, on some systems
            if not path.is_dir():
                raise
        else:
            counters[key] = n + 1
            return f
        n += 1


def _folder(path: Path) -> bool:
    """Make a folder and its parents; False when a file already has one of their names."""
    try:
        path.mkdir(parents=True, exist_ok=True)
    except (FileExistsError, NotADirectoryError):
        return False
    return True


def extract_cpio(archive: bytes | str | os.PathLike | BinaryIO, dest: str | os.PathLike, *,
                 max_size: int | None = None, max_files: int | None = MAX_FILES,
                 on_skip=None) -> list[Path]:
    """Unpack a newc CPIO archive (bytes, a path or an open binary file) into the folder
    ``dest``, streaming file data so archives larger than memory work. Nothing lands outside
    ``dest``: leading slashes are dropped (as bsdtar does), names that would still climb out or
    start with a drive (``C:``) are skipped, and so are symbolic links and device files. On
    Windows, other names are made safe the way 7-Zip does it (``a:b`` becomes ``a_b``). Existing
    files are never overwritten: a name that's taken, by a file or a folder, gets " (1)". A
    folder, or a file inside one, whose name is already taken by a file is skipped. Files keep
    their modification times, and hard links each get the file's data, whichever link carries it.

    ``max_size`` caps the bytes written (hard links count each time), so a small archive can't
    fill the disk, and ``max_files`` caps the members (a million by default; None for no limit).
    Going over either raises ``PackportError``. ``on_skip(name)`` hears about each member left
    out. Returns every file and folder written."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    written: list[Path] = []
    counters: dict[str, int] = {}
    filled: dict[tuple, tuple[Path, int]] = {}             # hard links: the file with the data
    waiting: dict[tuple, list[tuple[Path, int]]] = {}      # links seen before it, made after it
    total = members = 0

    def spend(n: int) -> None:
        nonlocal total
        total += n
        if max_size is not None and total > max_size:
            raise PackportError(f"The archive unpacks to more than {max_size:,} bytes")

    def link(target: Path, mtime: int, data: tuple[Path, int] | None) -> None:
        """A hard link, as a copy of the file holding the data (or empty if none did)."""
        spend(data[1] if data else 0)
        with _create(target, counters) as out:
            if data:
                with open(data[0], "rb") as src:
                    shutil.copyfileobj(src, out, CHUNK)
        os.utime(out.name, (mtime, mtime))
        written.append(Path(out.name))

    def skip(h: _Header) -> None:
        _data(f, h, _Discard())
        if on_skip:
            on_skip(h.name)

    with _open(archive) as f:
        for h in _headers(f):
            members += 1
            if max_files is not None and members > max_files:
                raise PackportError(f"The archive has more than {max_files:,} members")
            parts = [p for p in h.name.replace("\\", "/").split("/") if p not in ("", ".")]
            first = parts[0] if parts else ""
            if os.name == "nt":
                parts = [_windows_name(p) if p != ".." else p for p in parts]
            target = (dest.joinpath(*parts)).resolve() if parts else root
            if (not parts or ".." in parts or _DRIVE.match(first)
                    or root not in target.parents or not (stat.S_ISDIR(h.mode) or stat.S_ISREG(h.mode))):
                skip(h)
                continue
            if stat.S_ISDIR(h.mode):
                if not _folder(target):
                    skip(h)
                    continue
                _data(f, h, _Discard())
                written.append(target)
                continue
            if not _folder(target.parent):
                skip(h)
                continue
            key = h.link_key if h.nlink > 1 else None
            if key and h.size == 0:  # a link whose data comes with another member
                _data(f, h, _Discard())
                if key in filled:
                    link(target, h.mtime, filled[key])
                else:
                    waiting.setdefault(key, []).append((target, h.mtime))
                continue
            spend(h.size)
            with _create(target, counters) as out:
                _data(f, h, out)
            target = Path(out.name)
            os.utime(target, (h.mtime, h.mtime))
            written.append(target)
            if key:
                filled[key] = (target, h.size)
                for other, mtime in waiting.pop(key, []):
                    link(other, mtime, filled[key])
    for group in waiting.values():  # links to an empty file, or whose data never came
        for other, mtime in group:
            link(other, mtime, None)
    return written


class _Discard:
    def write(self, _chunk: bytes) -> None:
        pass
