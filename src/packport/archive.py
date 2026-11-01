"""Reading any archive packport knows: ``open()`` gives an ``Archive`` whose ``members`` say what's
inside and whose ``files()`` hands over each file's data in archive order (so solid and streamed
formats are decoded once), and ``extract()`` unpacks one safely into a folder.

Every format is a reader class with ``members`` and ``_files()``, registered in ``_READERS``;
``open`` tells them apart by their content, never by the file name.
"""

from __future__ import annotations

import builtins
import contextlib
import io
import lzma
import os
import stat
import struct
import threading
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from . import entries
from ._accel import native
from .entries import CHUNK, PackportError


class EncryptedError(PackportError):
    """The archive, or a member of it, is encrypted: packport doesn't decrypt."""


def _zstd_error() -> tuple:
    try:
        from compression.zstd import ZstdError  # Python 3.14
    except ImportError:
        try:
            from backports.zstd import ZstdError
        except ImportError:
            return ()
    return (ZstdError,)


# What a damaged archive can make the parsers and decompressors raise. Readers give clear messages
# for what they check; open() and files() turn anything that still slips through into PackportError.
DAMAGED = (struct.error, IndexError, KeyError, ValueError, OverflowError, EOFError, RecursionError, MemoryError,
           zlib.error, lzma.LZMAError, UnicodeError, *_zstd_error())


@dataclass
class Item:
    """One member of an archive being read. ``link`` is a symbolic link's target, ``size`` the
    unpacked size (as the archive declares it), and ``ref`` whatever its reader needs to find
    the data again."""
    name: str
    size: int = 0
    is_dir: bool = False
    link: str | None = None
    mtime: float = 0.0
    mode: int = 0
    encrypted: bool = False
    ref: object = field(default=None, repr=False, compare=False)

    @property
    def is_file(self) -> bool:
        return not self.is_dir and self.link is None and (self.mode == 0 or stat.S_ISREG(self.mode))


class Source:
    """The archive's bytes: one file, several volumes read as one, or bytes in memory. Seekable,
    and closed by its Archive only if packport opened it."""

    def __init__(self, src):
        self.lock = threading.Lock()  # read_at is a seek and a read: one thread at a time
        self.owned: list[BinaryIO] = []
        self.path = Path(src) if isinstance(src, (str, os.PathLike)) else None
        if isinstance(src, (bytes, bytearray, memoryview)):
            self.f: BinaryIO = io.BytesIO(bytes(src))
        elif isinstance(src, (list, tuple)):
            parts = [builtins.open(p, "rb") for p in src]  # noqa: SIM115 - closed by close()
            self.owned = parts
            self.f = _Joined(parts)
        elif hasattr(src, "read"):
            self.f = src
        else:
            self.f = builtins.open(src, "rb")  # noqa: SIM115 - closed by close()
            self.owned = [self.f]
        self.f.seek(0, 2)
        self.size = self.f.tell()
        self.f.seek(0)

    def read_at(self, offset: int, n: int) -> bytes:
        if offset < 0 or n < 0 or offset > self.size:
            raise PackportError("The archive is damaged (a read past its end)")
        with self.lock:
            self.f.seek(offset)
            return self.f.read(n)

    def close(self) -> None:
        for f in self.owned:
            f.close()


class _Joined(io.RawIOBase):
    """Several files read as one after another (split volumes: .001, .002, ...)."""

    def __init__(self, parts: list[BinaryIO]):
        self.parts, self.starts = parts, [0]
        for p in parts:
            p.seek(0, 2)
            self.starts.append(self.starts[-1] + p.tell())
        self.pos = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, pos: int, whence: int = 0) -> int:
        self.pos = {0: pos, 1: self.pos + pos, 2: self.starts[-1] + pos}[whence]
        return self.pos

    def tell(self) -> int:
        return self.pos

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            n = self.starts[-1] - self.pos
        out = bytearray()
        while n > 0 and self.pos < self.starts[-1]:
            k = next(i for i in range(len(self.parts)) if self.starts[i + 1] > self.pos)
            p = self.parts[k]
            p.seek(self.pos - self.starts[k])
            chunk = p.read(min(n, self.starts[k + 1] - self.pos))
            if not chunk:
                break
            out += chunk
            self.pos += len(chunk)
            n -= len(chunk)
        return bytes(out)

    def readinto(self, b) -> int:
        data = self.read(len(b))
        b[:len(data)] = data
        return len(data)


class Archive:
    """An open archive. Use it as a context manager, or call close()."""

    fmt = ""

    def __init__(self, source: Source):
        self.source = source
        self.members: list[Item] = []

    def files(self) -> Iterator[tuple[Item, BinaryIO]]:
        """(item, stream) for every regular file, in archive order. Each stream is good until
        the next one is taken."""
        for item in self.members:
            if item.is_file and item.encrypted:
                raise EncryptedError(f"{item.name} is encrypted; packport doesn't decrypt")
        try:
            yield from self._files()
        except DAMAGED as e:
            raise PackportError(f"The archive is damaged ({type(e).__name__}: {e})") from None

    def _files(self) -> Iterator[tuple[Item, BinaryIO]]:
        for item in self.members:
            if item.is_file:
                yield item, self.open_member(item)

    def open_member(self, item: Item) -> BinaryIO:
        raise NotImplementedError

    def read(self, item: Item | str) -> bytes:
        """One member's data (by Item or name)."""
        if isinstance(item, str):
            found = [m for m in self.members if m.name == item]
            if not found:
                raise PackportError(f"No member named {item!r}")
            item = found[0]
        if item.encrypted:
            raise EncryptedError(f"{item.name} is encrypted; packport doesn't decrypt")
        return self.open_member(item).read()

    def close(self) -> None:
        self.source.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class Window(io.RawIOBase):
    """A piece of the archive (offset, size) read as a file of its own."""

    def __init__(self, source: Source, offset: int, size: int):
        if offset < 0 or size < 0 or offset + size > source.size:
            raise PackportError("The archive is damaged (a member reaches past its end)")
        self.source, self.offset, self.size, self.pos = source, offset, size, 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, pos: int, whence: int = 0) -> int:
        self.pos = min(max({0: pos, 1: self.pos + pos, 2: self.size + pos}[whence], 0), self.size)
        return self.pos

    def tell(self) -> int:
        return self.pos

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0 or n > self.size - self.pos:
            n = self.size - self.pos
        data = self.source.read_at(self.offset + self.pos, n)
        self.pos += len(data)
        return data

    def readinto(self, b) -> int:
        data = self.read(len(b))
        b[:len(data)] = data
        return len(data)


class Pieces(io.RawIOBase):
    """A member's packed data spread over (source, offset, size) pieces, as across volumes,
    read as one stream."""

    def __init__(self, pieces):
        self.pieces, self.k, self.at = list(pieces), 0, 0

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1) -> bytes:
        if n is not None and n >= 0 and self.k < len(self.pieces):
            source, start, size = self.pieces[self.k]
            if self.at + n <= size:  # within one piece: no gathering
                got = source.read_at(start + self.at, n)
                self.at += len(got)
                if self.at >= size and len(got) == n:
                    self.k, self.at = self.k + 1, 0
                return got
        out = bytearray()
        while (n is None or n < 0 or len(out) < n) and self.k < len(self.pieces):
            source, start, size = self.pieces[self.k]
            want = size - self.at if n is None or n < 0 else min(n - len(out), size - self.at)
            got = source.read_at(start + self.at, want)
            out += got
            self.at += len(got)
            if len(got) < want:
                break  # the volume is cut short
            if self.at >= size:
                self.k, self.at = self.k + 1, 0
        return bytes(out)

    def readinto(self, b) -> int:
        data = self.read(len(b))
        b[:len(data)] = data
        return len(data)


def stored(raw, size: int | None = None) -> Iterator[bytes]:
    """Chunks of raw (a readable), at most entries.CHUNK each: size bytes, or all of it."""
    left = size
    while left is None or left > 0:
        chunk = raw.read(entries.CHUNK if left is None else min(entries.CHUNK, left))
        if not chunk:
            return
        if left is not None:
            left -= len(chunk)
        yield chunk


class Chunks:
    """Data that comes in chunks (a decoder's output, say), read as a file: read(n) gives at
    least one byte and at most n, or b"" at the end."""

    def __init__(self, chunks: Iterator[bytes]):
        self.chunks, self.buf, self.at = chunks, b"", 0

    def read(self, n: int) -> bytes:
        if self.at >= len(self.buf):
            self.buf, self.at = b"", 0
            for chunk in self.chunks:
                if chunk:
                    self.buf = chunk
                    break
            else:
                return b""
        if self.at == 0 and n >= len(self.buf):
            self.at = len(self.buf)
            return self.buf
        out = self.buf[self.at:self.at + n]
        self.at += len(out)
        return out

    def exactly(self, n: int) -> bytes:
        """n bytes, or fewer only at the end."""
        out = self.read(n)
        while len(out) < n:
            more = self.read(n - len(out))
            if not more:
                break
            out += more
        return out

    def skip(self, n: int) -> int:
        """Pass over n bytes; returns how many there were."""
        left = n
        while left > 0:
            data = self.read(min(left, entries.CHUNK))
            if not data:
                break
            left -= len(data)
        return n - left


_crc32 = native.crc32 if native is not None else zlib.crc32


class Crc32:
    """A member's CRC-32, checked once all of its data has been read."""

    def __init__(self, expected: int):
        self.expected, self.value = expected, 0

    def update(self, chunk: bytes) -> None:
        self.value = _crc32(chunk, self.value)

    def ok(self) -> bool:
        return self.value == self.expected


class Stream(io.RawIOBase):
    """A member's data, unpacked as it is read: chunks from an iterator (each at most a few MB),
    checked against the member's size and, when given, a checksum (``update(chunk)`` and
    ``ok()``) once it has all been read. Damage found while unpacking is a PackportError."""

    def __init__(self, name: str, chunks: Iterator[bytes], size: int | None, check=None, what: str = "archive"):
        self.name, self.chunks, self.size, self.check, self.what = name, chunks, size, check, what
        self.buf, self.at, self.got, self.done = b"", 0, 0, False

    def readable(self) -> bool:
        return True

    def _fill(self) -> bool:
        while self.at >= len(self.buf) and not self.done:
            try:
                chunk = next(self.chunks)
            except StopIteration:
                self.done = True
                if self.size is not None and self.got != self.size:
                    raise PackportError(f"{self.name}: the data is cut short (the {self.what} is damaged)") from None
                if self.check is not None and not self.check.ok():
                    raise PackportError(f"{self.name}: data checksum doesn't match (the {self.what} is damaged)") \
                        from None
                return False
            except PackportError:
                self.done = True
                raise
            except (*DAMAGED, OSError) as e:  # bz2 reports bad data as OSError
                self.done = True
                raise PackportError(f"{self.name}: the {self.what} is damaged ({type(e).__name__}: {e})") from None
            self.got += len(chunk)
            if self.size is not None and self.got > self.size:
                self.done = True
                raise PackportError(f"{self.name}: holds more than its stated size (the {self.what} is damaged)")
            if self.check is not None:
                self.check.update(chunk)
            self.buf, self.at = chunk, 0
        return self.at < len(self.buf)

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            return self.readall()
        if not self._fill():
            return b""
        if self.at == 0 and n >= len(self.buf) and type(self.buf) is bytes:  # the whole piece, as it is
            self.at = len(self.buf)
            return self.buf
        out = self.buf[self.at:self.at + n]
        self.at += len(out)
        return bytes(out)

    def readall(self) -> bytes:
        parts = []
        while self._fill():
            parts.append(self.buf[self.at:] if self.at else self.buf)
            self.at = len(self.buf)
        return b"".join(parts)

    def readinto(self, b) -> int:
        data = self.read(len(b))
        b[:len(data)] = data
        return len(data)

    def drain(self) -> None:
        """Read the rest (so a solid decoder moves on to the next member, and checks run)."""
        while self._fill():
            self.at = len(self.buf)


# ---- telling formats apart

_READERS: list[tuple[str, Callable[[bytes, Source], bool], Callable[[Source], Archive]]] = []


def reader(fmt: str, sniff: Callable[[bytes, Source], bool], first: bool = False):
    """Register an Archive class for fmt, found when sniff(first 64 KB, source) says so. Readers
    are tried in the order they register; first=True puts this one ahead of all the others."""
    def add(cls):
        cls.fmt = fmt
        if first:
            _READERS.insert(0, (fmt, sniff, cls))
        else:
            _READERS.append((fmt, sniff, cls))
        return cls
    return add


def _load_readers() -> None:
    from . import (  # noqa: F401 - each registers its readers
        arformat,
        arj,
        cab,
        cpio,
        disk,
        iso,
        lzh,
        nsis,
        rar,
        rar5,
        rpm,
        sevenzip,
        squashfs,
        udf,
        wim,
        xar,
        zipformat,
    )


def detect(src) -> str | None:
    """The format packport reads src as, or None."""
    _load_readers()
    source = Source(src)
    try:
        head = source.read_at(0, 1 << 16)
        return next((fmt for fmt, sniff, _ in _READERS if sniff(head, source)), None)
    finally:
        source.close()


def open(src, fmt: str | None = None) -> Archive:
    """Open an archive: a path, a list of volume paths (read as one, in order), bytes, or a
    seekable binary file. The format comes from the content unless ``fmt`` says."""
    _load_readers()
    if isinstance(src, (str, os.PathLike)) and fmt is None and not str(src).lower().endswith((".rar", ".r00")):
        volumes = split_volumes(Path(src))
        if volumes:
            src = volumes
    source = Source(src)
    try:
        head = source.read_at(0, 1 << 16)
        for name, sniff, cls in _READERS:
            if (fmt is None and sniff(head, source)) or name == fmt:
                return cls(source)
    except DAMAGED as e:
        source.close()
        raise PackportError(f"The archive is damaged ({type(e).__name__}: {e})") from None
    except BaseException:
        source.close()
        raise
    source.close()
    raise PackportError(f"packport doesn't read {fmt!r} archives" if fmt else
                        "packport doesn't know what kind of archive this is")


def split_volumes(path: Path) -> list[Path] | None:
    """For a .001 (or .000) file, or any one of the set: every volume in order, when there are more. The
    "aa", "ab", ... pieces Unix's split writes are joined too, when the name ends in "aa"."""
    if path.name.endswith("aa") and path.with_name(path.name[:-2] + "ab").is_file():
        stem, found = path.name[:-2], []
        for k in range(26 * 26):
            part = path.with_name(stem + chr(97 + k // 26) + chr(97 + k % 26))
            if not part.is_file():
                break
            found.append(part)
        return found
    stem, _, number = path.name.rpartition(".")
    if not (number.isdigit() and len(number) >= 3):
        return None
    width = len(number)
    found = []
    k = 0 if path.with_name(f"{stem}.{0:0{width}d}").is_file() else 1  # some splitters count from .000
    first = k
    while True:
        part = path.with_name(f"{stem}.{k:0{width}d}")
        if not part.is_file():
            break
        found.append(part)
        k += 1
    return found if len(found) > 1 or (found and int(number) == first) else None


# ---- unpacking safely

def extract(src, dest: str | os.PathLike, *, fmt: str | None = None, max_size: int | None = None,
            max_files: int | None = 1_000_000, on_skip: Callable[[str], None] | None = None,
            on_rename: Callable[[str, Path], None] | None = None) -> list[Path]:
    """Unpack any archive packport reads into ``dest``, with ``extract_cpio``'s rules: nothing
    lands outside ``dest`` (leading slashes dropped; names that climb out or start with a drive
    skipped, and so are links and devices), Windows-safe names (``a:b`` becomes ``a_b``, ``CON``
    becomes ``_CON``), existing files never overwritten (a taken name gets " (1)"), ``max_size``
    bytes and ``max_files`` members at most. ``on_skip(name)`` hears about each member left
    out, ``on_rename(name, path)`` about each that lands under another name. An encrypted file
    raises ``EncryptedError``. Returns every file and folder written."""
    from .cpio import _DRIVE, _create, _folder, _windows_name
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    written: list[Path] = []
    counters: dict[str, int] = {}
    total = 0
    with open(src, fmt) as archive:
        if max_files is not None and len(archive.members) > max_files:
            raise PackportError(f"The archive has more than {max_files:,} members")
        declared = sum(m.size for m in archive.members if m.is_file)
        if max_size is not None and declared > max_size:
            raise PackportError(f"The archive unpacks to more than {max_size:,} bytes")

        folders: dict[tuple, Path | None] = {}  # a folder's parts -> where it really is (None: outside)
        made: set[Path] = set()

        def place(item: Item) -> Path | None:
            parts = [p for p in item.name.replace("\\", "/").split("/") if p not in ("", ".")]
            first = parts[0] if parts else ""
            if os.name == "nt":
                parts = [_windows_name(p) if p != ".." else p for p in parts]
            if not parts or ".." in parts or _DRIVE.match(first):
                return None
            # the folder is resolved (through any links already there) once, not every file in it;
            # the file itself is created new, so a link with its name is never followed
            key = tuple(parts[:-1])
            if key not in folders:
                where = dest.joinpath(*key).resolve() if key else root
                folders[key] = where if where == root or root in where.parents else None
            parent = folders[key]
            return None if parent is None else parent / parts[-1]

        def folder(path: Path) -> bool:
            if path in made:
                return True
            if not _folder(path):
                return False
            made.add(path)
            return True

        def skip(item: Item) -> None:
            if on_skip:
                on_skip(item.name)

        for item in archive.members:
            if item.is_dir:
                target = place(item)
                if target is None or not folder(target):
                    skip(item)
                else:
                    written.append(target)
            elif not item.is_file:
                skip(item)  # links, devices
        for item, stream in archive.files():
            target = place(item)
            if target is None or not folder(target.parent):
                skip(item)
                continue
            with _create(target, counters) as out:
                while True:
                    chunk = stream.read(CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if max_size is not None and total > max_size:
                        raise PackportError(f"The archive unpacks to more than {max_size:,} bytes")
                    out.write(chunk)
            path = Path(out.name)
            with contextlib.suppress(OSError, ValueError, OverflowError):
                if item.mtime:
                    os.utime(path, (item.mtime, item.mtime))
            written.append(path)
            if on_rename and (path.name != item.name.replace("\\", "/").rsplit("/", 1)[-1]):
                on_rename(item.name, path)
    return written
