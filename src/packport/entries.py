"""What goes into an archive: entries with a name, a source (bytes or a file on disk) and metadata."""

from __future__ import annotations

import math
import os
import stat
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

CHUNK = 1 << 20


class PackportError(Exception):
    """Raised for anything packport can't write or read: bad names, damaged archives, limits."""


@dataclass
class Entry:
    """One archive member. ``source`` is bytes, a path to a file, or None for a directory."""
    name: str
    source: bytes | str | os.PathLike | None = None
    is_dir: bool = False
    mtime: float | None = None  # seconds since the epoch; None means now (or the file's own mtime)
    mode: int | None = None     # permission bits (0o644 / 0o755 by default)

    def __post_init__(self):
        self.name = clean_name(self.name)
        if isinstance(self.source, (bytearray, memoryview)):
            self.source = bytes(self.source)
        if self.source is None and not self.is_dir:
            self.is_dir = True
        if self.is_dir and self.source is not None and not isinstance(self.source, (str, os.PathLike)):
            raise PackportError(f"{self.name}: a directory can't have data")
        if isinstance(self.source, (str, os.PathLike)) and (self.mtime is None or self.mode is None):
            st = os.stat(self.source)
            if self.mtime is None:
                self.mtime = st.st_mtime
            if self.mode is None and os.name != "nt":
                self.mode = st.st_mode & 0o7777
            elif self.mode is None and not self.is_dir and not st.st_mode & stat.S_IWRITE:
                self.mode = 0o444  # the Windows read-only attribute
        if self.mtime is None:
            self.mtime = time.time()
        if self.mode is None:
            self.mode = 0o755 if self.is_dir else 0o644

    def size(self) -> int:
        if self.is_dir:
            return 0
        if isinstance(self.source, bytes):
            return len(self.source)
        return os.stat(self.source).st_size

    def open(self) -> BinaryIO:
        import io
        if isinstance(self.source, bytes):
            return io.BytesIO(self.source)
        return open(self.source, "rb")


Source = bytes | bytearray | memoryview | str | os.PathLike | None
Sources = (str | os.PathLike | Entry | Iterable[str | os.PathLike | Entry | tuple[str, Source]]
           | Mapping[str, Source])


def clamp_time(t: float, top: int) -> int:
    """A modification time as whole seconds in 0..top: earlier times (and NaN) become 0, later
    ones ``top``, so an odd timestamp never stops an archive from being written."""
    return 0 if math.isnan(t) else int(min(max(t, 0), top))


@dataclass
class Member:
    """One member read back from an archive."""
    name: str
    data: bytes = b""
    is_dir: bool = False
    mtime: float = 0.0
    mode: int = 0


def clean_name(name: str) -> str:
    """Archive names use '/', are relative, and never climb out of the extraction folder."""
    if not isinstance(name, str):
        raise PackportError(f"Archive names must be text, not {type(name).__name__}")
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts:
        raise PackportError(f"Empty archive name: {name!r}")
    if name.replace("\\", "/").startswith("/") or ":" in parts[0] or ".." in parts:
        raise PackportError(f"Archive names must be relative paths inside the archive: {name!r}")
    if any("\0" in p for p in parts):
        raise PackportError(f"Archive names can't contain NUL: {name!r}")
    return "/".join(parts)


def tree(folder: str | os.PathLike, prefix: str = "") -> list[Entry]:
    """Entries for everything inside ``folder`` (not the folder itself), sorted, directories
    before their contents. ``prefix`` puts them under a folder name inside the archive."""
    folder = Path(folder)
    if not folder.is_dir():
        raise PackportError(f"Not a folder: {folder}")
    out: list[Entry] = []
    seen = {_identity(folder)}

    def walk(path: Path, arc: str):
        for child in sorted(path.iterdir(), key=lambda p: p.name):
            name = f"{arc}/{child.name}" if arc else child.name
            if child.is_dir():
                st = child.stat()
                out.append(Entry(name, None, True, st.st_mtime, None if os.name == "nt" else st.st_mode & 0o7777))
                # links to folders (symlinks, Windows junctions) are stored as empty folders: they
                # can point back up the tree, and following them would archive things twice
                if not _is_link(child) and _identity(child) not in seen:
                    seen.add(_identity(child))
                    walk(child, name)
            else:
                out.append(Entry(name, child))

    if prefix:
        st = folder.stat()
        out.append(Entry(prefix, None, True, st.st_mtime))
    walk(folder, clean_name(prefix) if prefix else "")
    return out


def _is_link(path: Path) -> bool:
    """A symbolic link, or a Windows junction (which ``is_symlink()`` doesn't report)."""
    if path.is_symlink():
        return True
    tag = getattr(os.lstat(path), "st_reparse_tag", 0)
    return tag in (getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", -1), getattr(stat, "IO_REPARSE_TAG_SYMLINK", -1))


def _identity(path: Path) -> tuple[int, int]:
    st = os.stat(path)
    return st.st_dev, st.st_ino


def collect(sources: Sources) -> list[Entry]:
    """Turn what callers pass into a flat entry list.

    - a path, or a list of paths: files under their own name, folders under their own name with
      everything inside them (like ``7z a`` and ``tar``); use ``tree(folder)`` for just the contents
    - ``Entry`` objects, as they are
    - a mapping ``{archive name: bytes | path | None}``, where None makes a directory
    """
    if isinstance(sources, Mapping):
        items: Iterable = [Entry(k, v) for k, v in sources.items()]
    elif isinstance(sources, (str, os.PathLike, Entry)):
        items = [sources]
    else:
        items = sources
    out: list[Entry] = []
    for item in items:
        if isinstance(item, Entry):
            out.append(item)
        elif isinstance(item, tuple) and len(item) == 2:
            out.append(Entry(*item))
        elif isinstance(item, (str, os.PathLike)):
            path = Path(item)
            if path.is_dir():
                name = path.resolve().name
                if not name:
                    raise PackportError(f"Can't name the archive folder for {path}; use tree()")
                out.extend(tree(path, name))
            elif path.exists():
                out.append(Entry(path.name, path))
            else:
                raise PackportError(f"No such file or folder: {path}")
        else:
            raise PackportError(f"Don't know how to archive {item!r}")
    seen = set()
    for e in out:
        if e.name in seen:
            raise PackportError(f"{e.name} is in the archive twice")
        seen.add(e.name)
    return out


def copy(src: BinaryIO, dst: BinaryIO, size: int, name: str, crc: int = 0) -> int:
    """Copy exactly ``size`` bytes, returning their CRC32. A file that shrank while being read is
    an error rather than a silently short archive member."""
    import zlib
    left = size
    while left:
        chunk = src.read(min(CHUNK, left))
        if not chunk:
            raise PackportError(f"{name} got shorter while it was being archived")
        crc = zlib.crc32(chunk, crc)
        dst.write(chunk)
        left -= len(chunk)
    return crc


class Output:
    """A path or an open binary file; closes only what it opened."""

    def __init__(self, out):
        self.owned = isinstance(out, (str, os.PathLike))
        self.f: BinaryIO = open(out, "wb") if self.owned else out  # noqa: SIM115 - closed by close()

    def close(self, failed: bool = False):
        if self.owned:
            self.f.close()
            if failed:
                try:
                    os.remove(self.f.name)
                except OSError:
                    pass
