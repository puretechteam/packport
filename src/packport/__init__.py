"""packport: write the archive formats that have no free writer, in pure Python.

    import packport
    packport.write_rar("comic.cbr", "pages/")          # stored RAR 4
    packport.write_z("data.csv.Z", "data.csv")         # Unix compress
    packport.write_cpio("initrd.cpio", ["bin", "etc"])  # newc CPIO
    packport.pack("out.rar", ["a.txt", "folder"])      # format from the extension

or from a terminal: ``packport pages/ comic.cbr``.
"""

from __future__ import annotations

__version__ = "0.2.0"

from .cpio import CpioWriter, extract_cpio, read_cpio, write_cpio
from .entries import Entry, Member, PackportError, Sources, collect, tree
from .lzw import (
    ZCompressor,
    ZDecompressor,
    ZWriter,
    compress,
    decompress,
    write_tar_z,
    write_z,
)
from .rar import RarWriter, read_rar, write_rar

FORMATS = {
    "rar": "RAR 4, stored", "cbr": "comic book RAR (RAR 4, stored)",
    "z": "Unix compress (one file)", "tar.z": "tar compressed with Unix compress", "taz": "same as .tar.Z",
    "cpio": "CPIO, newc",
}

__all__ = [
    "FORMATS",
    "CpioWriter",
    "Entry",
    "Member",
    "PackportError",
    "RarWriter",
    "Sources",
    "ZCompressor",
    "ZDecompressor",
    "ZWriter",
    "__version__",
    "collect",
    "compress",
    "decompress",
    "extract_cpio",
    "format_of",
    "pack",
    "read_cpio",
    "read_rar",
    "tree",
    "write_cpio",
    "write_rar",
    "write_tar_z",
    "write_z",
]


def format_of(path) -> str:
    """The FORMATS key for an output file name, e.g. ``"tar.z"`` for ``backup.tar.Z``."""
    name = str(path).lower()
    for fmt in sorted(FORMATS, key=len, reverse=True):
        if name.endswith("." + fmt):
            return fmt
    raise PackportError(f"packport doesn't write {name.rsplit('.', 1)[-1]!r} files "
                        f"(it writes .{', .'.join(FORMATS)})")


def pack(out, sources: Sources, fmt: str | None = None) -> None:
    """Write ``sources`` to ``out``, choosing the format from its extension unless ``fmt`` is given.
    ``.Z`` takes exactly one file; the others take anything ``collect`` accepts."""
    fmt = (fmt or format_of(out)).lower().lstrip(".")
    if fmt in ("rar", "cbr"):
        write_rar(out, sources)
    elif fmt == "cpio":
        write_cpio(out, sources)
    elif fmt in ("tar.z", "taz"):
        write_tar_z(out, sources)
    elif fmt == "z":
        if not isinstance(sources, (str, bytes)) and not hasattr(sources, "__fspath__"):
            items = list(sources)
            if len(items) != 1:
                raise PackportError(".Z holds a single file; for several files write a .tar.Z")
            sources = items[0]
        write_z(out, sources)
    else:
        raise PackportError(f"Unknown format {fmt!r}")
