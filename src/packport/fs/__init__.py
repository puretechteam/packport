"""File systems inside disk images: each module reads one (fat, ntfs, ext, hfs, apfs) from a
device, anything with ``read_at(offset, n)`` and ``size``, and lists its files as Items.

Every reader has ``probe(dev) -> bool`` and a class built from the device, with ``name`` (as the
disk reader labels its folder: "NTFS", "FAT32"...), ``members`` and ``open_member(item)``.
"""

from __future__ import annotations

import io

from ..entries import CHUNK, PackportError


class Slice:
    """A run of a device (a partition) read as a device of its own."""

    def __init__(self, dev, start: int, size: int):
        if start < 0 or size < 0 or start + size > dev.size:
            raise PackportError("The disk image is damaged (a partition reaches past its end)")
        self.dev, self.start, self.size = dev, start, size

    def read_at(self, offset: int, n: int) -> bytes:
        if offset < 0 or offset > self.size:
            raise PackportError("The disk image is damaged (a read past the end of a partition)")
        return self.dev.read_at(self.start + offset, min(n, self.size - offset))


class Extents(io.RawIOBase):
    """A file's data on a device: (byte offset, length) extents, offset None for zeros (holes)."""

    def __init__(self, dev, extents: list[tuple[int | None, int]], size: int, name: str = "a file"):
        self.dev, self.extents, self.left, self.name = dev, extents, size, name
        self.k, self.pos = 0, 0

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1) -> bytes:
        out = bytearray()
        want = self.left if n is None or n < 0 else min(n, self.left)
        while len(out) < want and self.k < len(self.extents):
            at, length = self.extents[self.k]
            take = min(length - self.pos, want - len(out), CHUNK * 16)
            if at is None:
                out += bytes(take)
            else:
                chunk = self.dev.read_at(at + self.pos, take)
                if len(chunk) < take:
                    raise PackportError(f"{self.name}: the disk image is cut short")
                out += chunk
            self.pos += take
            if self.pos >= length:
                self.k, self.pos = self.k + 1, 0
        if len(out) < want:
            raise PackportError(f"{self.name}: the file system is damaged (the data ends early)")
        self.left -= len(out)
        return bytes(out)

    def readinto(self, b) -> int:
        data = self.read(len(b))
        b[:len(data)] = data
        return len(data)
