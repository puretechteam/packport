"""packport SOURCES... OUT: archive files and folders (format from OUT's extension)."""

from __future__ import annotations

import argparse
import os
import sys
import time

from . import FORMATS, PackportError, __version__, pack


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="packport", description="Write archives. "
                                 f"Formats: .{', .'.join(FORMATS)}. Folders are stored under their own "
                                 "name, with everything inside them.")
    ap.add_argument("paths", nargs="+", metavar="SOURCE... OUT", help="files and folders, then the archive to write")
    ap.add_argument("--version", action="version", version=f"packport {__version__}")
    args = ap.parse_args(argv)
    if len(args.paths) < 2:
        ap.error("give at least one file or folder and the archive to write")
    *sources, out = args.paths
    try:
        start = time.perf_counter()
        pack(out, sources)
        print(f"{out}: {os.path.getsize(out):,} bytes in {time.perf_counter() - start:.2f}s")
        return 0
    except (PackportError, OSError) as e:
        print(f"packport: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
