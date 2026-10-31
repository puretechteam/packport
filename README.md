# packport

Write RAR, Unix compress (`.Z`) and CPIO archives in pure Python. No WinRAR, no dependencies.

```
pip install git+https://github.com/puretechteam/packport
```

```python
import packport

packport.write_rar("comic.cbr", "pages/")                 # stored RAR 4, opens in every RAR reader
packport.write_z("data.csv.Z", "data.csv")                # Unix compress
packport.write_cpio("initrd.cpio", ["bin", "etc"])        # CPIO, newc
packport.write_tar_z("backup.tar.Z", "project/")          # tar inside compress
packport.pack("out.rar", ["notes.txt", "photos"])         # format from the extension
```

or from a terminal:

```
packport pages/ comic.cbr
packport report.pdf notes.txt bundle.cpio
packport data.csv data.csv.Z
```

## Why packport?

Some archive formats are easy to read but have no free way to write them:

- **RAR.** Only WinRAR's own `rar` can create RAR files, and it's paid, closed-source software. The free unrar source can't be used either: its licence forbids building a RAR compressor from it. 7-Zip and libarchive read RAR but don't write it. Python has `rarfile`, which reads only.
- **Unix compress (`.Z`).** Python's standard library has gzip, bz2 and lzma, but no LZW. 7-Zip reads `.Z` but can't write it.
- **CPIO.** Python has `tarfile` and `zipfile`, but no `cpio` module. 7-Zip reads CPIO but can't write it.

packport writes all three in about 58 KB of Python source with no dependencies (a 28 KB wheel, about 160 KB once installed with its compiled bytecode; on Windows pip adds a 106 KB `packport.exe` launcher), so it installs anywhere Python 3.10+ does and bundles cleanly into a PyInstaller app.

**RAR without the compressor.** packport writes RAR 4 with every file *stored* (method 0x30). That's the format every RAR reader opens, including old comic book apps that predate RAR 5. Comic pages are JPEG or PNG, which don't compress further anyway: packport writes a 200-page, 100 MB comic in 0.09 s, about the time 7-Zip takes to store the same pages in a ZIP (0.08 s). It's limited by the disk, not by Python.

**`.Z` that matches the original byte for byte.** packport's compressor follows the original `compress`, down to when it clears its dictionary. Its output is identical, byte for byte, to libarchive's compress writer (which follows the same rules) on every input tried, up to 20 MB, and `gzip -d`, 7-Zip and libarchive all decompress it.

**Big files.** Files are streamed, never loaded whole. A 4 GiB + 4 KB file goes into a RAR with the format's 64-bit size fields, and 7-Zip and libarchive extract it identically (checked by SHA-256). Writing and checking it took 21 s.

**Where the others are ahead.**

- WinRAR compresses, and writes RAR 5, recovery records, encryption and multi-volume sets. packport does none of that: it stores.
- libarchive (`bsdtar`, Windows' `tar.exe`) writes CPIO and `.Z` too, in C. For `.Z` it's much faster: 20 MB of text took packport 4.5 s and libarchive 0.27 s, for the same bytes. If you can run a C library, libarchive is the better `.Z` writer. packport is for when you want a pure-Python dependency.

## Where it came from

packport was written for [ConvertAll](https://github.com/puretechteam/ConvertAll), a drag-and-drop file converter, when it set out to handle every archive type. Most archive formats have a free writer. RAR/CBR, `.Z` and CPIO didn't, so ConvertAll could read them but not produce them.

It's a sibling of [meshport](https://github.com/puretechteam/meshport), which replaced Blender for FBX in ConvertAll, and the same idea: a small pure-Python library for the formats nobody else writes.

The RAR writer grew out of a short stored-RAR writer in ConvertAll's test suite, which built sample `.cbr` files for its tests. packport turns it into a library and adds Unicode names, large files, folders, streaming, real timestamps and a reader.

## What it does

| Format | Write | Read |
|---|---|---|
| RAR 4 (`.rar`, `.cbr`), stored | ✓ | ✓ (stored archives only) |
| Unix compress (`.Z`), 9 to 16-bit LZW | ✓ | ✓ |
| tar + compress (`.tar.Z`, `.taZ`) | ✓ | via `decompress` + `tarfile` |
| CPIO newc (`.cpio`) | ✓ | ✓ (also the `070702` checksum variant), and streaming extraction to a folder |

**RAR 4**, written from RARLAB's published format description (`technote.txt`), never from unrar's source:

- Marker block, main archive header, a file header per entry, end-of-archive block. Every header has its CRC.
- Folders, including empty ones, as directory entries.
- Unicode names (Japanese, accented letters, emoji, ...) in RAR's Unicode name encoding, with an ASCII stand-in for very old readers. Plain ASCII names are stored as they are.
- Files over 4 GiB, with the 64-bit size fields.
- Modification times (DOS format, to 2 seconds), the CRC32 of each file, and the read-only flag (from the permissions, or from the read-only attribute on Windows).
- Names use Windows conventions (backslashes, host OS "Win32"), as WinRAR on Windows writes them.

**Unix compress**: LZW with codes growing from 9 to 16 bits, block mode with CLEAR, header `1F 9D 90`, and the original's padding at every width change and CLEAR, which decoders depend on. `ZCompressor` and `ZDecompressor` work incrementally, like `zlib.compressobj`. `decompress()` returns at most `max_size` bytes (1 GiB unless you say otherwise, `None` for no cap), so a tiny hostile file can't claim unlimited memory; `ZDecompressor` takes a `max_size` too, with no cap by default, since its output comes a piece at a time. The decoder keeps its dictionary as (prefix code, byte) pairs, like the original, so it never holds more than 65,536 entries: a 19 KB hostile stream that expands to 72 MB peaks at 18 MB of memory rather than 73 MB.

**CPIO newc** (`070701`): files, folders, permissions, modification times, the `TRAILER!!!` entry and 4-byte padding. Names are UTF-8. The format's sizes are 32-bit, so files of 4 GiB or more are refused with a clear error.

Not handled: compressed or encrypted RAR, RAR 5, symbolic links and hard links, and old-style CPIO (`070707` and binary). A link to a file is stored as the file it points to. A link to a folder, including a Windows junction, is stored as an empty folder, because links can loop back up the tree. When reading, hard-linked CPIO members each get the file's data.

`extract_cpio(archive, folder)` unpacks a CPIO archive without holding it in memory. Nothing lands outside the folder: leading slashes are dropped (as bsdtar does), names that would still climb out or start with a drive (`C:/...`) are skipped, and so are symbolic links and device files. On Windows, other names are made safe the way 7-Zip does it (`a:b` becomes `a_b`, `CON` becomes `_CON`), so nothing is written to an alternate data stream or a device. Existing files are never overwritten: a name that's taken, by a file or a folder, gets ` (1)`. A folder, or a file inside a folder, whose name is already taken by a file is skipped. Hard links each get the file's data, whichever link carries it, and are created only once that data is known. `max_size` caps the bytes written, hard-link copies included, `max_files` caps the members (a million by default, `None` for no limit), and `on_skip(name)` hears about each member left out. Names longer than 64 KiB are refused before they're read. Files keep their modification times.

`read_rar` and `read_cpio` return names exactly as they're stored, so a hostile archive can hand back `../../x`, `/etc/x` or `C:\x`. Never join those onto a folder yourself: unpack CPIO with `extract_cpio`, which makes every name safe, and check RAR names before using them as paths.

Times outside what a format can hold (before 1970, after 2106 for CPIO or 2107 for RAR, or not a number) are clamped to its nearest limit instead of failing the write.

Damaged archives, bad names and format limits raise `packport.PackportError`. That includes a cut-short archive, even one cut exactly between two files: a RAR file needs its end-of-archive block, as a CPIO file needs its `TRAILER!!!`. Errors from the file system (a missing or unreadable file) stay `OSError`. A failed write removes the half-written file.

## The API

```python
packport.write_rar(out, sources) -> list[Entry]
packport.write_cpio(out, sources) -> list[Entry]
packport.write_tar_z(out, sources) -> list[Entry]
packport.write_z(out, source)                  # one file: a path or bytes
packport.pack(out, sources, fmt=None)          # format from out's extension
packport.format_of(path) -> str                # "rar", "cbr", "z", "tar.z", "taz" or "cpio"

packport.compress(data, bits=16) -> bytes      # .Z in memory
packport.decompress(data, max_size=1 << 30) -> bytes
packport.read_rar(data_or_path) -> list[Member]    # names as stored: not safe as paths
packport.read_cpio(data_or_path) -> list[Member]   # names as stored: not safe as paths
packport.extract_cpio(data_path_or_file, folder, *, max_size=None, max_files=1_000_000,
                      on_skip=None) -> list[Path]  # streams, makes names safe
```

`out` is a path or a writable binary file. `sources` can be the following, for every format; `.Z` also takes plain bytes, and needs exactly one file:

- a path or a list of paths. Files keep their name; folders keep their name and include everything inside them, like `7z a` and `tar`.
- `packport.tree(folder)`: everything inside a folder, without the folder itself.
- `(archive name, bytes or path)` pairs, `packport.Entry` objects, or a `{archive name: bytes | path | None}` mapping, where `None` makes a folder.

To write entry by entry:

```python
with packport.RarWriter("pages.cbr") as rar:
    rar.add("001.jpg", jpeg_bytes)
    rar.add("extras/cover.png", "cover.png", mtime=1700000000)
    rar.add("empty folder", is_dir=True)
```

`CpioWriter` works the same way. `ZWriter` is a writable file that compresses into `.Z`. `Entry(name, source, is_dir=False, mtime=None, mode=None)` takes its time and permissions from the file when they aren't given. Archive names use `/`. Absolute paths, `..` and duplicate names are refused.

## How it's tested

- **Against unrar, RARLAB's own reader.** calibre bundles RARLAB's unrar library, so the tests run it through calibre (`tests/unrar_helper.py`). It extracts packport's RAR files byte for byte, Unicode names included, and reports the headers packport meant to write. It refuses a copy with one flipped data byte, which shows it really checks packport's CRCs. calibre's comic reader also opens a packport `.cbr` as a comic.
- **Against a WinRAR archive.** WinRAR's own main header is byte-identical to packport's. In a real WinRAR-made archive, all 40 header CRCs check out under packport's rules, and names and dates decode as 7-Zip shows them.
- **Against 7-Zip 24.09.** Every RAR, CPIO and `.Z` file the tests write is extracted by 7-Zip and compared byte for byte with the source. The tree has nested folders, empty folders, empty files, odd sizes and Unicode names (Japanese, Chinese, Greek, accented letters, emoji). `7z t` also checks every RAR CRC.
- **Against libarchive 3.8.9** (Windows' own `tar.exe`). The same checks for RAR, CPIO, `.Z` and `.tar.Z`, plus modification times. `tar.exe` converts names to the Windows code page and skips any that don't fit, for ZIP and tar files from other tools too, so its tests use accented Latin names.
- **Against gzip 1.13**, which decompresses `.Z`.
- **Byte-identical `.Z`.** packport's output is compared with libarchive's compress writer on every payload, including dictionary resets and inputs past 8 MB.
- **Reading other tools' archives.** CPIO and `.Z` written by libarchive, including hard links and names in the Windows code page, read back exactly.
- **Big files** (sparse, so they cost no disk space): a 3 GiB file (32-bit sizes with the top bit set) in RAR and CPIO, and a file over 4 GiB in RAR. 7-Zip and libarchive extract each one, compared by SHA-256, and unrar reads every byte and checks the CRC. These write several GB, so they run only with `PACKPORT_SLOW=1` (about a minute and a half). In the normal suite, a 300 MB file is written with Python never holding more than 20 MB.
- **Damaged files.** The readers get thousands of corrupted, truncated and random archives and must only ever raise `PackportError`.
- **Random trees.** Randomly generated folders, names and sizes go through every writer and come back unchanged, through packport's readers, 7-Zip, libarchive and unrar.
- **Python 3.10, 3.11 and 3.13**, the whole suite on each. Also a clean `pip install` from git (nothing else gets installed), and a PyInstaller one-file build using `collect_submodules("packport")`, whose archives 7-Zip accepts.

## Development

```
python -m venv .venv
.venv\Scripts\pip install -e .[dev]
.venv\Scripts\python -m pytest
```

The tests that need 7-Zip, `tar.exe` (libarchive's `bsdtar` elsewhere), gzip or calibre (for unrar) skip when those aren't installed. Run the big-file tests with `PACKPORT_SLOW=1`.

Code layout:

- `src/packport/rar.py`: RAR 4 writer and stored-RAR reader, Unicode names.
- `src/packport/lzw.py`: Unix compress (`.Z`) and `.tar.Z`.
- `src/packport/cpio.py`: CPIO newc writer, reader and extractor.
- `src/packport/entries.py`: entries, name checks, gathering files and folders.

## License

MIT, see [LICENSE](LICENSE).
