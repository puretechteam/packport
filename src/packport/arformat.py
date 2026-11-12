"""Unix ar archives (``!<arch>``), the GNU and BSD kinds, and Debian packages (.deb) built on them.

An ar member is a 60-byte header (name, mtime, uid, gid, octal mode, decimal size, then
"`\\n") and its data, padded to an even length. GNU ar ends names with "/" and keeps long ones
in a "//" table that "/123" points into; BSD ar writes "#1/N" with the N-byte name in front of
the data. The symbol tables ("/", "/SYM64/", "__.SYMDEF") are left out.

A .deb is an ar archive of debian-binary, control.tar.* and data.tar.*: packport shows it the
way ``dpkg-deb -R`` unpacks it, the data's files where they go and the control files in DEBIAN/.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import zlib

from .archive import Archive, Item, Window, reader
from .entries import PackportError

MAGIC = b"!<arch>\n"
_SYMBOLS = {"/", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED", "/SYM64"}
MAX_MEMBERS = 1_000_000


def _members(source) -> list[tuple[str, int, int, float, int]]:
    """(name, data offset, size, mtime, mode) for each member."""
    out = []
    pos = len(MAGIC)
    names = b""
    while pos < source.size:
        head = source.read_at(pos, 60)
        if len(head) < 60:
            if not head.strip(b"\n"):
                break
            raise PackportError("This ar archive is cut short")
        if head[58:60] != b"`\n":
            raise PackportError("This ar archive is damaged (a member header is broken)")
        try:
            size = int(head[48:58].strip() or b"0")
            mtime = int(head[16:28].strip() or b"0")
            mode = int(head[40:48].strip() or b"0", 8)
        except ValueError:
            raise PackportError("This ar archive is damaged (a member header is broken)") from None
        if size < 0:
            raise PackportError("This ar archive is damaged (a negative size)")
        data = pos + 60
        if data + size > source.size:
            raise PackportError("This ar archive is cut short")
        raw = head[:16].rstrip(b" ")
        if raw == b"//":  # GNU's long name table
            names = source.read_at(data, size)
            name = None
        elif raw.startswith(b"#1/"):  # BSD: the name is the first N bytes of the data
            try:
                n = int(raw[3:])
            except ValueError:
                raise PackportError("This ar archive is damaged (a broken long name)") from None
            if not 0 <= n <= size:
                raise PackportError("This ar archive is damaged (a long name past its member)")
            name = source.read_at(data, n).split(b"\0", 1)[0].decode("utf-8", "replace")
            data, size_left = data + n, size - n
            out.append((name, data, size_left, float(mtime), mode))
            pos += 60 + size + size % 2
            continue
        elif raw.startswith(b"/") and raw[1:].isdigit():  # GNU: an offset into the long name table
            at = int(raw[1:])
            end = names.find(b"/\n", at)
            if at >= len(names) or end < 0:
                raise PackportError("This ar archive is damaged (a long name that isn't there)")
            name = names[at:end].decode("utf-8", "replace")
        else:
            name = raw.decode("utf-8", "replace")
            if name not in _SYMBOLS and name.endswith("/"):
                name = name[:-1]
        if name is not None and name not in _SYMBOLS and name:
            out.append((name, data, size, float(mtime), mode))
            if len(out) > MAX_MEMBERS:
                raise PackportError(f"The archive has more than {MAX_MEMBERS:,} members")
        pos += 60 + size + size % 2
    return out


def _sniff_ar(head: bytes, _source) -> bool:
    return head.startswith(MAGIC)


def _sniff_deb(head: bytes, source) -> bool:
    if not head.startswith(MAGIC):
        return False
    try:
        names = [m[0] for m in _members(source)[:3]]
    except PackportError:
        return False
    return bool(names) and names[0] == "debian-binary" and any(n.startswith("data.tar") for n in names)


def decompressed(stream, name: str):
    """A file object reading a compressed tar member (.gz, .xz, .bz2, .lzma, .zst, or none)."""
    if name.endswith(".gz"):
        return gzip.GzipFile(fileobj=stream)
    if name.endswith(".xz"):
        return lzma.LZMAFile(stream, format=lzma.FORMAT_XZ)
    if name.endswith(".lzma"):
        return lzma.LZMAFile(stream, format=lzma.FORMAT_ALONE)
    if name.endswith(".bz2"):
        return bz2.BZ2File(stream)
    if name.endswith(".zst"):
        return zstd_reader(stream)
    return stream


def zstd_reader(stream):
    try:
        from compression import zstd  # Python 3.14
    except ImportError:
        try:
            from backports import zstd
        except ImportError:
            raise PackportError("This uses Zstandard compression: install backports.zstd (or use Python 3.14) "
                                "to read it") from None
    return zstd.ZstdFile(stream)


@reader("deb", _sniff_deb)
class DebArchive(Archive):
    """A Debian package, as ``dpkg-deb -R`` lays it out."""

    def __init__(self, source):
        super().__init__(source)
        self.tars: list[tuple[tarfile.TarFile, str]] = []
        for name, at, size, _mtime, _mode in _members(source):
            if not name.startswith(("control.tar", "data.tar")):
                continue
            prefix = "DEBIAN/" if name.startswith("control") else ""
            try:
                tar = tarfile.open(fileobj=decompressed(Window(source, at, size), name), mode="r:")
                infos = tar.getmembers()
            except (tarfile.TarError, OSError, EOFError, zlib.error, lzma.LZMAError) as e:
                raise PackportError(f"This package's {name} is damaged ({e})") from None
            self.tars.append((tar, prefix))
            for info in infos:
                inner = info.name
                while inner.startswith("./"):  # only the "./" in front: ".profile" keeps its dot
                    inner = inner[2:]
                inner = inner.lstrip("/")
                if not inner or inner == ".":
                    continue
                if prefix and inner in ("", "."):
                    continue
                self.members.append(Item(prefix + inner, info.size, info.isdir(),
                                         info.linkname if info.issym() else None, float(info.mtime),
                                         info.mode | (0o040000 if info.isdir() else 0o100000 if info.isfile() else 0),
                                         ref=(tar, info)))
            if prefix:
                self.members.insert(0, Item("DEBIAN", is_dir=True, mode=0o040755))

    def open_member(self, item: Item):
        tar, info = item.ref
        try:
            f = tar.extractfile(info)
        except (tarfile.TarError, OSError) as e:
            raise PackportError(f"{item.name}: the package is damaged ({e})") from None
        return f if f is not None else io.BytesIO()

    def _files(self):
        for item in self.members:
            if item.is_file and not (item.ref and item.ref[1].islnk()):
                yield item, self.open_member(item)

    def close(self) -> None:
        for tar, _ in self.tars:
            tar.close()
        super().close()


@reader("ar", _sniff_ar)
class ArArchive(Archive):
    def __init__(self, source):
        super().__init__(source)
        for name, at, size, mtime, mode in _members(source):
            self.members.append(Item(name, size, False, None, mtime, (mode & 0o7777) | 0o100000, ref=(at, size)))

    def open_member(self, item: Item):
        return Window(self.source, *item.ref)
