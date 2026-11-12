"""packport SOURCES... OUT: archive files and folders (format from OUT's extension).
packport --list ARCHIVE, packport --extract ARCHIVE FOLDER: read any archive packport knows."""

from __future__ import annotations

import argparse
import os
import sys
import time

from . import FORMATS, PackportError, __version__, accelerated, extract, pack
from . import open as open_archive
from ._accel import mismatch

_UNITS = {"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}


def size_arg(text: str) -> int | str | None:
    """--max-size's value: bytes, or with K, M, G or T after it (1024s); "none" for no limit, "free"
    for the drive's free space less a margin (the default)."""
    t = text.strip().upper().removesuffix("B")
    if t == "NONE":
        return None
    if t == "FREE":
        return "free"
    unit = t[-1:] if t[-1:] in _UNITS and not t[-1:].isdigit() else ""
    try:
        value = float(t[:-1] if unit else t)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a size: {text!r} (say 500M, 20G or none)") from None
    if value < 0:
        raise argparse.ArgumentTypeError(f"not a size: {text!r}")
    return int(value * _UNITS[unit])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="packport",
        description=f"Write archives (formats: .{', .'.join(FORMATS)}; folders are stored under their own name, "
                    "with everything inside them), or list and extract any archive packport reads: RAR, 7z, ZIP, "
                    "CAB, ISO, UDF, WIM, NSIS, LZH, ARJ, squashfs, deb, RPM, xar and pkg, CPIO, disk images "
                    "(VHD, VHDX, VMDK, QCOW2, VDI, DMG) and the file systems on them.")
    ap.add_argument("paths", nargs="*", metavar="SOURCE... OUT", help="files and folders, then the archive to write")
    ap.add_argument("-l", "--list", metavar="ARCHIVE", help="list what's in ARCHIVE")
    ap.add_argument("-x", "--extract", nargs=2, metavar=("ARCHIVE", "FOLDER"),
                    help="unpack ARCHIVE into FOLDER (names made safe, links left out, nothing overwritten)")
    ap.add_argument("--max-size", type=size_arg, default="free", metavar="SIZE",
                    help="with --extract: write at most SIZE bytes (500M, 20G; none for no limit). By default, "
                         "what FOLDER's drive has free less 1 GB, so an archive made to fill the disk stops first")
    decoders = "with packport-native" if accelerated() else "Python decoders"
    if mismatch():
        decoders += f"; packport-native {mismatch()} is installed but doesn't match, so it isn't used"
    ap.add_argument("--version", action="version", version=f"packport {__version__} ({decoders})")
    args = ap.parse_args(argv)
    try:
        start = time.perf_counter()
        if args.list:
            with open_archive(args.list) as archive:
                for m in archive.members:
                    kind = "dir " if m.is_dir else "link" if m.link is not None else "file" if m.is_file else "other"
                    print(f"{kind} {m.size:>14,}  {m.name}{' (encrypted)' if m.encrypted else ''}")
                print(f"{len(archive.members):,} entries ({archive.fmt})")
            return 0
        if args.extract:
            src, dest = args.extract
            skipped: list[str] = []
            written = extract(src, dest, max_size=args.max_size, on_skip=skipped.append)
            print(f"{dest}: {len(written):,} files and folders in {time.perf_counter() - start:.2f}s"
                  + (f", {len(skipped):,} left out" if skipped else ""))
            return 0
        if len(args.paths) < 2:
            ap.error("give at least one file or folder and the archive to write (or --list, --extract)")
        *sources, out = args.paths
        pack(out, sources)
        print(f"{out}: {os.path.getsize(out):,} bytes in {time.perf_counter() - start:.2f}s")
        return 0
    except (PackportError, OSError) as e:
        print(f"packport: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
