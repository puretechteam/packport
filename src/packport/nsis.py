"""NSIS installers (Nullsoft Scriptable Install System, 2.x and 3.x, ANSI and Unicode): the files
they install, as the installer would put them under its install folder.

Written from NSIS's own description of its format (its zlib-licensed headers). The installer
program is followed, on a 512-byte boundary, by a first header: flags, 0xDEADBEEF,
"NullsoftInst", the uncompressed size of the script header and the size of everything after.
Then either one compressed stream holding the script header and every file (solid), or the
header and each file compressed on its own, each led by a 32-bit size whose top bit says
"compressed". Compression is zlib (raw deflate), bzip2 (without its "BZh" header) or LZMA (5
bytes of properties, then the raw stream).

The script header lists blocks (pages, sections, entries, strings, ...). Entries are the
installer's instructions: SetOutPath (CreateDir with "update $OUTDIR") and File (ExtractFile:
a name and where its data starts), which packport follows to name each file. Names are
strings with codes for variables ($INSTDIR, $PLUGINSDIR, ...), shell folders and language
strings. Files land where the script puts them, $INSTDIR becoming the top; other folders keep
their variable's name ($PLUGINSDIR/...).
"""

from __future__ import annotations

import bz2
import lzma
import struct
import tempfile
import zlib
from collections.abc import Iterator

from . import entries
from .archive import Archive, Item, Stream, Window, reader, stored
from .entries import PackportError, spool_limit, too_big

SIG = struct.pack("<I", 0xDEADBEEF) + b"NullsoftInst"
EW_CREATEDIR, EW_EXTRACTFILE = 11, 20
NB_ENTRIES, NB_STRINGS = 2, 3
BLOCKS = 8
MAX_HEADER = 64 << 20
MAX_STRING = 8192  # NSIS's own NSIS_MAX_STRLEN is 1024 (8192 in its large-strings build)
VARIABLES = {**{i: f"{i}" for i in range(10)}, **{10 + i: f"R{i}" for i in range(10)},
             20: "CMDLINE", 21: "INSTDIR", 22: "OUTDIR", 23: "EXEDIR", 24: "LANGUAGE", 25: "TEMP",
             26: "PLUGINSDIR", 27: "EXEPATH", 28: "EXEFILE", 29: "HWNDPARENT", 30: "_CLICK", 31: "_OUTDIR"}
SHELL = {0x1A: "APPDATA", 0x23: "COMMONAPPDATA", 0x05: "DOCUMENTS", 0x26: "PROGRAMFILES", 0x2A: "PROGRAMFILES32",
         0x2B: "COMMONFILES", 0x24: "WINDIR", 0x25: "SYSDIR", 0x10: "DESKTOP", 0x0B: "STARTMENU", 0x02: "SMPROGRAMS",
         0x07: "SMSTARTUP", 0x1C: "LOCALAPPDATA", 0x14: "FONTS", 0x15: "TEMPLATES"}


def _find(source) -> int:
    """Where the first header is: on a 512-byte boundary after the installer program (from where
    its PE sections end, when it has them). Read a MB at a time, and remembered on the source."""
    at = getattr(source, "_nsis_at", None)
    if at is not None:
        return at
    start = _overlay(source)
    end = min(source.size, start + (64 << 20))
    pos = start
    while pos < end:
        block = source.read_at(pos, min(1 << 20, end - pos) + 20)
        k = block.find(SIG)
        while k >= 0:
            if k >= 4 and (pos + k - 4) % 512 == 0:
                source._nsis_at = pos + k - 4
                return source._nsis_at
            k = block.find(SIG, k + 1)
        pos += 1 << 20
    raise PackportError("This isn't an NSIS installer")


def _overlay(source) -> int:
    """Where an exe's data past its sections starts (512-aligned), or 0 if it isn't a PE file."""
    head = source.read_at(0, 4096)
    if len(head) < 0x40:
        return 0
    pe = struct.unpack_from("<I", head, 0x3C)[0]
    if pe + 24 > len(head) or head[pe:pe + 4] != b"PE\0\0":
        return 0
    count, opt = struct.unpack_from("<H", head, pe + 6)[0], struct.unpack_from("<H", head, pe + 20)[0]
    table = pe + 24 + opt
    end = 0
    for k in range(min(count, 96)):
        at = table + 40 * k
        if at + 40 > len(head):
            return 0
        size, ptr = struct.unpack_from("<II", head, at + 16)
        end = max(end, ptr + size)
    return end - end % 512 if end <= source.size else 0


def _sniff(head: bytes, source) -> bool:
    if head[:2] != b"MZ":
        return False
    try:
        _find(source)
    except PackportError:
        return False
    return True


def _unpack(raw, method: str, limit: int) -> Iterator[bytes]:
    """The decompressed bytes of a stream (raw: a readable), a piece at a time, limit at most."""
    try:
        if method == "stored":
            yield from stored(raw, limit)
            return
        if method == "lzma":
            head = raw.read(5)
            if len(head) < 5:
                raise PackportError("This installer is damaged (LZMA properties)")
            props, dict_size = head[0], struct.unpack_from("<I", head, 1)[0]
            lc, rest = props % 9, props // 9
            # liblzma allocates the dictionary up front: never more than the limit on what comes out
            # (it never looks further back than that), so 5 bytes can't ask for 4 GB
            dict_size = min(max(dict_size, 4096), max(limit, 4096))
            d = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[{
                "id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": lc, "lp": rest % 5, "pb": rest // 5}])
            first = b""
        elif method == "bzip2":
            d, first = bz2.BZ2Decompressor(), b"BZh9"
        else:
            d, first = zlib.decompressobj(-15), b""
        left = limit
        if method == "zlib":
            data = b""
            while left > 0 and not d.eof:
                data = d.unconsumed_tail or raw.read(entries.CHUNK)
                if not data:
                    break
                out = d.decompress(data, min(left, entries.CHUNK))
                if out:
                    left -= len(out)
                    yield out
            return
        while left > 0 and not d.eof:
            data = (first + raw.read(entries.CHUNK)) if d.needs_input else b""
            first = b""
            if d.needs_input and not data:
                break
            out = d.decompress(data, max_length=min(left, entries.CHUNK))
            if out:
                left -= len(out)
                yield out
    except (zlib.error, OSError, lzma.LZMAError, EOFError, ValueError) as e:
        raise PackportError(f"This installer is damaged ({e})") from None


class _Spool:
    """Decoded data kept in a temporary file (in memory up to 4 MB), read like a Source: limit
    bytes at most (more is a bomb, refused before it fills the disk)."""

    def __init__(self, chunks, limit: int | None = None):
        self.f = tempfile.SpooledTemporaryFile(max_size=4 << 20)
        try:
            size = 0
            for chunk in chunks:
                size += len(chunk)
                if limit is not None and size > limit:
                    raise too_big("This installer", limit)
                self.f.write(chunk)
        except BaseException:
            self.f.close()  # damaged data part-way: the temporary file goes now, not at exit
            raise
        self.size = self.f.tell()

    def read_at(self, offset: int, n: int) -> bytes:
        if offset < 0 or n < 0 or offset > self.size:
            raise PackportError("This installer is damaged (a read past its data)")
        self.f.seek(offset)
        return self.f.read(n)

    def close(self) -> None:
        self.f.close()


def _method(raw: bytes) -> str:
    if raw[:1] == b"\x5d":  # LZMA's usual properties byte (lc 3, lp 0, pb 2)
        return "lzma"
    if raw[:1] == b"\x31" and raw[1:6] == b"AY&SY":
        return "bzip2"
    return "zlib"


def _strings(data: bytes, unicode: bool):
    """A function giving the text at a string offset (in characters), its codes spelled as NSIS
    spells them: $INSTDIR, $PLUGINSDIR, $(LangString) ..."""
    seen: dict[int, str] = {}  # the same string is named by many entries ($INSTDIR, a folder)

    def text(offset: int) -> str:
        if offset in seen:
            return seen[offset]
        seen[offset] = got = _text(offset)
        return got

    def _text(offset: int) -> str:
        out = []
        if unicode:
            at = 2 * offset
            stop = min(len(data), at + 2 * MAX_STRING)
            while at + 1 < stop:
                c = data[at] | data[at + 1] << 8
                at += 2
                if c == 0:
                    break
                if c in (1, 2, 3, 4):  # language string, shell folder, variable, skip
                    if at + 1 >= len(data):
                        break
                    lo, hi = data[at], data[at + 1]
                    at += 2
                    number = (lo & 0x7F) | (hi & 0x7F) << 7  # seven bits in each byte, as in ANSI scripts
                    if c == 4:
                        out.append(chr(lo | hi << 8))
                    elif c == 3:
                        out.append("$" + VARIABLES.get(number, f"VAR{number}"))
                    elif c == 2:
                        out.append("$" + SHELL.get(lo, SHELL.get(hi, "SHELL")))
                    else:
                        out.append(f"$(LSTR_{number})")
                else:
                    out.append(chr(c))
        else:
            at = offset
            stop = min(len(data), at + MAX_STRING)
            while at < stop:
                c = data[at]
                at += 1
                if c == 0:
                    break
                code = {252: 2, 253: 3, 254: 1, 255: 4}.get(c) if c >= 252 else None
                if code is None and c in (1, 2, 3, 4):
                    code = c
                if code is not None:
                    b0, b1 = data[at:at + 2] if at + 2 <= len(data) else (0, 0)
                    at += 2
                    v = (b0 & 0x7F) | (b1 & 0x7F) << 7
                    if code == 4:
                        out.append(chr(b0))
                        at -= 1
                    elif code == 3:
                        out.append("$" + VARIABLES.get(v, f"VAR{v}"))
                    elif code == 2:
                        out.append("$" + SHELL.get(b0, SHELL.get(b1, "SHELL")))
                    else:
                        out.append(f"$(LSTR_{v})")
                else:
                    out.append(chr(c) if c < 128 else bytes([c]).decode("cp1252", "replace"))
        return "".join(out)
    return text


def _path(outdir: str, name: str) -> str:
    """Where a file goes, as a name inside the archive: $INSTDIR becomes the top."""
    full = name if name.startswith("$") and "\\" in name or name.startswith("$INSTDIR") else \
        (outdir + "\\" + name if outdir else name)
    full = full.replace("/", "\\")
    for top in ("$INSTDIR\\", "$INSTDIR"):
        if full.startswith(top):
            full = full[len(top):]
            break
    parts = [p for p in full.split("\\") if p not in ("", ".")]
    return "/".join(parts)


@reader("nsis", _sniff, first=True)
class NsisArchive(Archive):
    def __init__(self, source):
        super().__init__(source)
        self.spool, self.spools = None, []
        try:
            self._read(source)
        except BaseException:
            for spool in [self.spool, *self.spools]:
                if spool is not None:
                    spool.close()  # a damaged installer: its temporary file goes now
            raise

    def _read(self, source) -> None:
        at = _find(source)
        _flags, _sig, _name, header_size, total = struct.unpack("<II12sII", source.read_at(at, 28))
        if header_size > MAX_HEADER or total > source.size or total < 32:
            raise PackportError("This installer is damaged (its header is too big)")
        self.body_at, body_size = at + 28, total - 28
        if self.body_at + body_size > source.size:
            raise PackportError("This installer is cut short")
        start = source.read_at(self.body_at, 10)
        first = struct.unpack_from("<I", start)[0]
        # not solid: a 32-bit size (top bit: compressed), then the header compressed on its own; a
        # solid LZMA stream's properties (5D 00 00 80 ...) also read as a size with the top bit set,
        # so what follows the size decides
        packed = first & 0x7FFFFFFF
        follows = start[4:10]
        not_solid = first == header_size or (first & 0x80000000 and packed <= body_size - 4 and (
            follows[:1] == b"\x5d" or follows[:6] == b"1AY&SY" or start[:1] != b"\x5d"))
        if not_solid:  # the header, then each file on its own
            self.solid = False
            size = first & 0x7FFFFFFF
            raw = Window(source, self.body_at + 4, min(size, body_size - 4))
            if first & 0x80000000:
                method = _method(source.read_at(self.body_at + 4, 6))
                header = b"".join(_unpack(raw, method, header_size))
            else:
                header = raw.read()
            self.data_at = self.body_at + 4 + size
            self.body_end = self.body_at + body_size
            self.method = method if first & 0x80000000 else _method(source.read_at(self.data_at + 4, 6))
        else:
            self.solid = True
            self.method = _method(start)
            limit = spool_limit(source, body_size)
            self.spool = _Spool(_unpack(Window(source, self.body_at, body_size), self.method, limit + 1), limit)
            hlen = struct.unpack("<I", self.spool.read_at(0, 4).ljust(4, b"\0"))[0]
            if hlen > MAX_HEADER:
                raise PackportError("This installer is damaged (its header is too big)")
            header = self.spool.read_at(4, hlen)
            self.data_at = 4 + hlen
        if len(header) < 4 + 8 * BLOCKS:
            raise PackportError("This installer is damaged (a short script header)")
        blocks = [struct.unpack_from("<II", header, 4 + 8 * k) for k in range(BLOCKS)]
        e_off, e_num = blocks[NB_ENTRIES]
        s_off = blocks[NB_STRINGS][0]
        strings_end = min(o for o, _ in blocks if o > s_off) if any(o > s_off for o, _ in blocks) else len(header)
        sdata = header[s_off:strings_end]
        unicode = len(sdata) > 3 and sdata[1] == 0 and sdata[3] == 0  # UTF-16: every other byte is 0
        text = _strings(sdata, unicode)
        outdir = saved = ""
        seen: dict[str, int] = {}
        for k in range(e_num):
            pos = e_off + 28 * k
            if pos + 28 > len(header):
                raise PackportError("This installer is damaged (its instructions are cut short)")
            which, *parm = struct.unpack_from("<7I", header, pos)
            if which == EW_CREATEDIR and parm[1]:
                # File /r keeps the out folder in $_OUTDIR while it walks the tree; $OUTDIR is the current one
                target = text(parm[0])
                if target.startswith("$_OUTDIR"):
                    target = saved + target[len("$_OUTDIR"):]
                elif target.startswith("$OUTDIR"):
                    target = outdir + target[len("$OUTDIR"):]
                else:
                    saved = target
                outdir = target
            elif which == EW_EXTRACTFILE:
                name = text(parm[1])
                for var, value in (("$_OUTDIR", saved), ("$OUTDIR", outdir)):
                    if name.startswith(var):
                        name = value + name[len(var):]
                name = _path(outdir, name)
                if not name:
                    continue
                if name in seen and seen[name] == parm[2]:
                    continue  # the same data to the same place again (another section)
                seen[name] = parm[2]
                mtime = 0.0
                ft = parm[3] | parm[4] << 32
                if ft and ft != 0xFFFFFFFFFFFFFFFF:
                    mtime = ft / 1e7 - 11644473600
                self.members.append(Item(name, 0, False, None, mtime, 0o100644, ref=parm[2]))
        for m in self.members:
            m.size = self._size(m.ref)

    def _size(self, offset: int) -> int:
        if self.solid:
            raw = self.spool.read_at(self.data_at + offset, 4)
            if len(raw) < 4:
                raise PackportError("This installer is damaged (a file's data isn't there)")
            return struct.unpack("<I", raw)[0]
        return -1  # known once read

    def _raw(self, item: Item):
        """A non-solid file's stored bytes, and whether they're compressed."""
        at = self.data_at + item.ref
        word = self.source.read_at(at, 4) if at + 4 <= self.body_end else b""
        if len(word) < 4:
            raise PackportError(f"{item.name}: the installer is damaged (its data isn't there)")
        size = struct.unpack("<I", word)[0]
        n = size & 0x7FFFFFFF
        if at + 4 + n > self.body_end:
            raise PackportError(f"{item.name}: the installer is damaged (its data runs past the end)")
        return Window(self.source, at + 4, n), bool(size & 0x80000000)

    def open_member(self, item: Item):
        if self.solid:
            at = self.data_at + item.ref + 4
            if at + item.size > self.spool.size:
                raise PackportError(f"{item.name}: the installer is damaged (its data runs past the end)")
            return Stream(item.name, stored(Window(self.spool, at, item.size)), item.size, what="installer")
        raw, packed = self._raw(item)
        if not packed:
            item.size = raw.size
            return Stream(item.name, stored(raw), raw.size, what="installer")
        # its size isn't stored: unpack it to learn it
        limit = spool_limit(self.source, raw.size)
        spool = _Spool(_unpack(raw, self.method, limit + 1), limit)
        self.spools.append(spool)  # closed when read to the end, or with the archive
        item.size = spool.size
        return Stream(item.name, _drain_spool(spool), spool.size, what="installer")

    def _files(self):
        for m in self.members:
            stream = self.open_member(m)
            yield m, stream
            stream.drain()

    def close(self) -> None:
        for spool in [self.spool, *self.spools]:
            if spool is not None:
                spool.close()
        super().close()


def _drain_spool(spool: _Spool) -> Iterator[bytes]:
    try:
        yield from stored(Window(spool, 0, spool.size))
    finally:
        spool.close()
