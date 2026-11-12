"""xar archives (``xar!``) and macOS installer packages (.pkg, which are xar archives).

A xar file is a 28-byte (or longer) big-endian header, a zlib-compressed XML table of contents,
then the heap. Each <file> in the TOC has a name, type (file, directory, symlink), mode, mtime
and, for files, a <data> with the offset into the heap, the stored length, the unpacked size and
an encoding: none, "application/x-gzip" (a zlib stream), bzip2, xz or lzma. Directories hold
their files as nested <file> elements.

A .pkg also shows what's inside its Payload and Scripts (a CPIO archive, gzip-compressed or in
Apple's pbzx chunks), under Payload/ and Scripts/, the way ``pkgutil --expand-full`` does.
"""

from __future__ import annotations

import base64
import bz2
import calendar
import collections
import io
import lzma
import struct
import tempfile
import time
import zlib
from xml.etree import ElementTree

from .archive import Archive, Item, Source, Window, reader
from .entries import CHUNK, MAX_ITEMS, PackportError, TooBig, spool_limit, too_big

MAGIC = b"xar!"
MAX_TOC = 64 << 20  # bytes of XML table of contents read; real ones are a few KB per file
MAX_DEPTH = 256


def _toc(source) -> tuple[ElementTree.Element, int]:
    head = source.read_at(0, 28)
    if len(head) < 28 or head[:4] != MAGIC:
        raise PackportError("This isn't a xar archive")
    size, _version, packed, unpacked, _alg = struct.unpack(">HHQQI", head[4:28])
    if size < 28 or packed > source.size or unpacked > MAX_TOC:
        raise PackportError("This xar archive is damaged (its table of contents is too big)")
    raw = source.read_at(size, packed)
    try:
        text = zlib.decompressobj().decompress(raw, MAX_TOC + 1)
    except zlib.error as e:
        raise PackportError(f"This xar archive is damaged ({e})") from None
    if len(text) > MAX_TOC:
        raise PackportError("This xar archive is damaged (its table of contents is too big)")
    if b"<!DOCTYPE" in text or b"<!ENTITY" in text:
        raise PackportError("This xar archive's table of contents declares entities; packport doesn't read those")
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as e:
        raise PackportError(f"This xar archive is damaged ({e})") from None
    toc = root.find("toc")
    if toc is None:
        raise PackportError("This xar archive is damaged (no table of contents)")
    return toc, size + packed


def _text(el, tag: str, default: str = "") -> str:
    child = el.find(tag)
    return (child.text or "").strip() if child is not None and child.text else default


def _name(el) -> str:
    child = el.find("name")
    if child is None or not child.text:
        return ""
    if child.get("enctype") == "base64":
        return base64.b64decode(child.text).decode("utf-8", "replace")
    return child.text


def _mtime(text: str) -> float:
    try:
        return float(calendar.timegm(time.strptime(text[:19], "%Y-%m-%dT%H:%M:%S")))
    except ValueError:
        return 0.0


def _decoded(raw: bytes, style: str, size: int) -> bytes:
    """A member's stored bytes, unpacked (at most size bytes)."""
    try:
        if "gzip" in style or raw[:1] == b"\x78":
            return zlib.decompressobj().decompress(raw, size)
        if "bzip2" in style:
            return bz2.BZ2Decompressor().decompress(raw, size)
        if "xz" in style or "lzma" in style:
            return lzma.LZMADecompressor().decompress(raw, size)
    except (zlib.error, OSError, lzma.LZMAError, EOFError) as e:
        raise PackportError(f"A member of this xar archive is damaged ({e})") from None
    return raw[:size]


def _sniff_xar(head: bytes, _source) -> bool:
    return head.startswith(MAGIC)


def _sniff_pkg(head: bytes, source) -> bool:
    if not head.startswith(MAGIC):
        return False
    try:
        toc, _ = _toc(source)
    except PackportError:
        return False
    names = {_name(f) for f in toc.iter("file")}
    return "Payload" in names and bool(names & {"Distribution", "PackageInfo", "Bom"})


@reader("xar", _sniff_xar)
class XarArchive(Archive):
    def __init__(self, source):
        super().__init__(source)
        toc, self.heap = _toc(source)
        todo = collections.deque((f, "", 0) for f in toc.findall("file"))
        while todo:
            el, parent, depth = todo.popleft()
            if depth > MAX_DEPTH:
                raise PackportError("This xar archive is damaged (its folders nest too deep)")
            name = _name(el).replace("/", "_")
            if not name:
                continue
            path = f"{parent}/{name}" if parent else name
            kind = _text(el, "type", "file")
            try:
                mode = int(_text(el, "mode", "0") or "0", 8)
            except ValueError:
                mode = 0
            item = Item(path, 0, kind == "directory", None, _mtime(_text(el, "mtime")),
                        (mode & 0o7777) | {"directory": 0o040000, "file": 0o100000}.get(kind, 0o120000))
            if kind == "symlink":
                item.link = _text(el, "link")
            data = el.find("data")
            if kind == "file" and data is not None:
                try:
                    offset, length, size = (int(_text(data, k, "0")) for k in ("offset", "length", "size"))
                except ValueError:
                    raise PackportError(f"{path}: this xar archive is damaged") from None
                enc = data.find("encoding")
                item.size, item.ref = size, (self.heap + offset, length, enc.get("style", "") if enc is not None else "")
            elif kind == "file":
                item.ref = (self.heap, 0, "")
            if kind in ("file", "directory", "symlink"):
                self.members.append(item)
                if len(self.members) > MAX_ITEMS:
                    raise PackportError(f"This xar archive lists more than {MAX_ITEMS:,} files (it's damaged)")
            todo.extend((c, path, depth + 1) for c in el.findall("file"))

    def open_member(self, item: Item):
        at, length, style = item.ref
        if "octet-stream" in style or not style:
            return Window(self.source, at, length)
        return io.BytesIO(_decoded(self.source.read_at(at, length), style, item.size))


def pbzx(raw, limit: int | None = None):
    """Apple's pbzx stream: 'pbzx', a chunk size, then (flags, length, xz data or plain bytes).
    The unpacked data, a piece at a time (each at most CHUNK bytes), limit bytes at most."""
    if raw.read(4) != b"pbzx":
        raise PackportError("This package's payload is damaged (not pbzx)")
    raw.read(8)
    got = 0
    while True:
        head = raw.read(16)
        if len(head) < 16:
            return
        _flags, length = struct.unpack(">QQ", head)
        chunk = raw.read(length)
        if len(chunk) < length:
            raise PackportError("This package's payload is cut short")
        if chunk[:6] != b"\xfd7zXZ\x00":
            pieces = [chunk]
        else:
            d = lzma.LZMADecompressor()

            def unpacked(d=d, chunk=chunk):
                data = chunk
                while not d.eof:
                    try:
                        out = d.decompress(data, CHUNK)
                    except lzma.LZMAError as e:
                        raise PackportError(f"This package's payload is damaged ({e})") from None
                    data = b""
                    if out:
                        yield out
                    elif d.needs_input:
                        return
            pieces = unpacked()
        for piece in pieces:
            got += len(piece)
            if limit is not None and got > limit:
                raise too_big("This package's payload", limit)
            yield piece


@reader("pkg", _sniff_pkg, first=True)  # a .pkg is a xar archive too: tried before plain xar
class PkgArchive(XarArchive):
    """A macOS installer package: its xar members, plus every Payload's and Scripts' files."""

    def __init__(self, source):
        super().__init__(source)
        self.spools = []
        try:
            self._expand()
        except BaseException:  # close() is never called on an archive that didn't open
            for s in self.spools:
                s.close()
            raise

    def _expand(self) -> None:
        from .cpio import CpioArchive
        for item in list(self.members):
            base = item.name.rsplit("/", 1)[-1]
            if base not in ("Payload", "Scripts") or not item.is_file:
                continue
            spool = tempfile.TemporaryFile()
            self.spools.append(spool)
            stream = XarArchive.open_member(self, item)
            head = stream.read(6)
            stream.seek(0)
            limit, got = spool_limit(self.source, item.ref[1]), 0
            try:
                if head[:4] == b"pbzx":
                    for piece in pbzx(stream, limit):
                        spool.write(piece)
                else:
                    import gzip
                    unpacked = gzip.GzipFile(fileobj=stream) if head[:2] == b"\x1f\x8b" else stream
                    while True:
                        chunk = unpacked.read(CHUNK)
                        if not chunk:
                            break
                        got += len(chunk)
                        if got > limit:
                            raise too_big("This package's payload", limit)
                        spool.write(chunk)
                inner = CpioArchive(Source(spool))
            except TooBig:
                raise
            except (OSError, EOFError, zlib.error, PackportError):
                continue  # not a CPIO payload: it stays as the file it is
            self.members.remove(item)
            self.members.append(Item(item.name, is_dir=True, mode=0o040755, mtime=item.mtime))
            for m in inner.members:
                name = m.name[2:] if m.name.startswith("./") else m.name.lstrip("/")
                if name and name != ".":
                    self.members.append(Item(f"{item.name}/{name}", m.size, m.is_dir, m.link, m.mtime, m.mode,
                                             ref=("cpio", inner, m)))

    def open_member(self, item: Item):
        if isinstance(item.ref, tuple) and item.ref and item.ref[0] == "cpio":
            return item.ref[1].open_member(item.ref[2])
        return super().open_member(item)

    def close(self) -> None:
        for s in self.spools:
            s.close()
        super().close()
