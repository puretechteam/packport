"""RPM packages: the files inside, as ``rpm2cpio package.rpm | cpio -idm`` unpacks them.

An RPM is a 96-byte lead (magic ED AB EE DB), a signature header padded to 8 bytes, the main
header (both: magic 8E AD E8 01, four reserved bytes, an index count and a data size, 16-byte
index entries, then the data), and the payload: a CPIO archive (newc), compressed as the
header's PAYLOADCOMPRESSOR tag says (gzip, bzip2, xz, lzma or zstd; the payload's own magic
decides if the tag is missing). Names lose their leading "./".
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import struct
import zlib

from .archive import Archive, Item, reader
from .entries import CHUNK, PackportError

LEAD = b"\xed\xab\xee\xdb"
HEADER = b"\x8e\xad\xe8\x01"
_PAYLOAD_COMPRESSOR = 1125
MAX_INDEX = 1 << 16


def _header(source, pos: int) -> tuple[dict[int, tuple[int, bytes, int]], int]:
    """{tag: (type, data from its offset on, count)} and the position after the header."""
    head = source.read_at(pos, 16)
    if len(head) < 16 or head[:4] != HEADER:
        raise PackportError("This RPM package is damaged (a header is missing)")
    count, size = struct.unpack(">II", head[8:16])
    if count > MAX_INDEX or size > source.size:
        raise PackportError("This RPM package is damaged (a header is too big)")
    index = source.read_at(pos + 16, 16 * count)
    data = source.read_at(pos + 16 + 16 * count, size)
    if len(index) < 16 * count or len(data) < size:
        raise PackportError("This RPM package is cut short")
    tags = {}
    for i in range(count):
        tag, kind, offset, n = struct.unpack(">IIII", index[16 * i:16 * i + 16])
        if offset <= size:
            tags[tag] = (kind, data[offset:], n)
    return tags, pos + 16 + 16 * count + size


def _string(entry) -> str | None:
    if entry is None or entry[0] not in (6, 8, 9):  # STRING, STRING_ARRAY, I18NSTRING
        return None
    return entry[1].split(b"\0", 1)[0].decode("utf-8", "replace")


def _sniff(head: bytes, _source) -> bool:
    return head.startswith(LEAD)


def payload_stream(raw, compressor: str | None):
    """A file object giving the decompressed payload."""
    raw.seek(0)
    magic = raw.read(6)
    raw.seek(0)
    if magic[:2] == b"\x1f\x8b" or compressor == "gzip":
        return gzip.GzipFile(fileobj=raw)
    if magic[:3] == b"BZh" or compressor == "bzip2":
        return bz2.BZ2File(raw)
    if magic[:6] == b"\xfd7zXZ\x00" or compressor == "xz":
        return lzma.LZMAFile(raw, format=lzma.FORMAT_XZ)
    if magic[:4] == b"\x28\xb5\x2f\xfd" or compressor == "zstd":
        from .arformat import zstd_reader
        return zstd_reader(raw)
    if compressor == "lzma" or magic[:3] == b"\x5d\x00\x00":
        return lzma.LZMAFile(raw, format=lzma.FORMAT_ALONE)
    return raw


@reader("rpm", _sniff)
class RpmArchive(Archive):
    def __init__(self, source):
        super().__init__(source)
        if source.size < 96:
            raise PackportError("This RPM package is cut short")
        _, pos = _header(source, 96)
        pos += -pos % 8  # the signature is padded to 8 bytes
        tags, pos = _header(source, pos)
        compressor = _string(tags.get(_PAYLOAD_COMPRESSOR))
        from .archive import Window
        raw = Window(source, pos, source.size - pos)
        # the payload streams out once, into a temporary file, so its members can be read in any order
        import tempfile
        self.spool = tempfile.TemporaryFile()  # noqa: SIM115 - closed by close()
        try:
            stream = payload_stream(raw, compressor)
            while True:
                chunk = stream.read(CHUNK)
                if not chunk:
                    break
                self.spool.write(chunk)
        except (OSError, EOFError, zlib.error, lzma.LZMAError, ValueError) as e:
            self.spool.close()
            raise PackportError(f"This RPM package's payload is damaged ({e})") from None
        except BaseException:
            self.spool.close()
            raise
        from .archive import Source
        from .cpio import CpioArchive
        try:
            self.inner = CpioArchive(Source(self.spool))
        except BaseException:  # not CPIO inside: close() is never called on an archive that didn't open
            self.spool.close()
            raise
        for item in self.inner.members:
            name = item.name[2:] if item.name.startswith("./") else item.name.lstrip("/")
            if name:
                self.members.append(Item(name, item.size, item.is_dir, item.link, item.mtime, item.mode, ref=item))

    def open_member(self, item: Item):
        return self.inner.open_member(item.ref)

    def close(self) -> None:
        self.spool.close()
        super().close()
