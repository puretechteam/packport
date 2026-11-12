# packport

Read the archives, installers, disc and disk images 7-Zip reads, and write RAR, Unix compress (`.Z`), CPIO and WIM, in pure Python. No 7-Zip, no WinRAR, no dependencies. Its optional compiled decoders, **packport-native**, make it as fast as 7-Zip or faster on 11 of the 18 archives benchmarked ([Speed](#speed)).

```
pip install git+https://github.com/puretechteam/packport
pip install https://github.com/puretechteam/packport/releases/download/v0.4.0/packport_native-0.4.0-cp310-abi3-win_amd64.whl
```

The second line is optional: the wheel for 64-bit Windows (each [release](https://github.com/puretechteam/packport/releases) has Linux and macOS ones too). Without it packport works the same, with its Python decoders.

```python
import packport

with packport.open("comic.cbr") as archive:               # the format comes from the content
    for item, stream in archive.files():                  # solid archives are unpacked once
        print(item.name, item.size, len(stream.read()))

packport.extract("disk.vhdx", "out/")                     # names made safe, links left out
packport.write_rar("comic.cbr", "pages/")                 # stored RAR 4, opens in every RAR reader
packport.write_z("data.csv.Z", "data.csv")                # Unix compress
packport.write_cpio("initrd.cpio", ["bin", "etc"])        # CPIO, newc
packport.write_wim("image.wim", "folder/")                # uncompressed WIM
packport.pack("out.rar", ["notes.txt", "photos"])         # format from the extension
```

or from a terminal:

```
packport --list setup.exe
packport --extract disk.vhdx out
packport --extract backup.7z out --max-size 20G   # by default: the drive's free space less 1 GB
packport pages/ comic.cbr
packport report.pdf notes.txt bundle.cpio
```

## Why packport?

[Latheport](https://github.com/puretechteam/Latheport) (called ConvertAll until 1.5) used to hand about 30 archive formats to 7-Zip: RAR and CBR, CAB, ISO and UDF discs, WIM, installers, Linux and macOS packages, old archivers, virtual disks and the file systems on them, and the ZIP and 7z files Python's own modules can't open. packport reads all of them itself, so Latheport no longer needs 7-Zip. It's pure Python on purpose: it installs anywhere Python 3.10+ does and bundles cleanly into a PyInstaller app. The price is speed on the heavier compression methods (see [Speed](#speed)).

Some formats are easy to read but have no free way to write them, and packport writes those too:

- **RAR.** Only WinRAR's own `rar` can create RAR files, and it's paid, closed-source software. The free unrar source can't be used either: its licence forbids building a RAR compressor from it. 7-Zip and libarchive read RAR but don't write it.
- **Unix compress (`.Z`)**, which 7-Zip reads but can't write, and Python's standard library doesn't have.
- **CPIO**, which Python has no module for.
- **WIM**, which only Windows' DISM and wimlib write.

packport is about 570 KB of Python source with no dependencies (about 175 KB zipped). Zstandard members need `compression.zstd` (Python 3.14) or `backports.zstd`; everything else is the standard library.

## What it reads

| Format | What's read | Checked against |
|---|---|---|
| RAR (`.rar`, `.cbr`, `.partN.rar`, `.r00`) | RAR 5 (LZ, filters, BLAKE2sp) and RAR 2.9 to 4.x (LZ, PPMd, the standard filters); solid archives, volumes from any one of them, self-extracting `.exe` | 7-Zip, on libarchive's 23 RAR test archives (41 volume files) |
| 7z | LZMA, LZMA2, PPMd, BZip2, Deflate, Deflate64, Zstandard, BCJ, BCJ2, ARM, ARM64, ARMT, PowerPC, SPARC, IA64, RISC-V, Delta | 7-Zip, on 58 libarchive and 10 7-Zip-made archives |
| ZIP | Deflate, Deflate64, bzip2, LZMA, xz, Zstandard, PPMd (variant I), Shrink, Implode; ZIP64; data in front (self-extractors); a lost central directory (read from the local headers) | 7-Zip, on 45 libarchive, 5 7-Zip-made and 4 Commons Compress archives |
| CAB | stored, MSZIP, LZX (15 to 21), cabinet sets | 7-Zip, on everything Windows' `makecab` writes |
| WIM | stored, XPRESS, LZX | 7-Zip |
| NSIS installers (`.exe`) | 2.x and 3.x, zlib, bzip2 and LZMA, solid or not, ANSI and Unicode names | 7-Zip: all 653 files of the Ghostscript 10.08 installer |
| ISO 9660 (`.iso`) | Joliet, Rock Ridge (long names, folders moved to `rr_moved` put back), zisofs, multi-extent files, El Torito boot images (`[BOOT]/Boot-1.44M.img`), hybrid discs | 7-Zip, and libarchive for Rock Ridge and zisofs |
| UDF | 1.02 to 2.60: physical, sparable and metadata partitions; bridge discs read through the side that lists more | 7-Zip, on images Windows' IMAPI2 writes |
| squashfs | 4.0: gzip, xz, lzma, LZ4, Zstandard; fragments, holes | 7-Zip and the lz4 library |
| LZH / LHA (`.lzh`, `.lha`) | header levels 0 to 3; -lh0-, -lz4-, -lh4- to -lh7-, folders; Shift_JIS and UTF-16 names | 7-Zip, on libarchive's 11 LZH test archives |
| ARJ | methods 0 to 4 | 7-Zip |
| deb, ar, RPM, xar and macOS `.pkg` | deb as `dpkg-deb -R` lays it out, RPM's CPIO payload, a `.pkg` with its Payload unpacked | 7-Zip and libarchive |
| CPIO | newc, crc, odc and old binary (both byte orders) | libarchive |
| Split files | `.001`, `.002`... (or from `.000`), and `aa`, `ab`... | |
| Disk images | raw, VHD (fixed, dynamic, differencing), VHDX, VMDK (sparse, stream-optimized, flat), QCOW2, VDI, DMG (raw, zlib, bzip2, ADC, LZMA chunks) | 7-Zip, on 18 of dfvfs's test images |
| Partition tables | MBR (with extended partitions), GPT, Apple Partition Map: a folder per partition (`1 NTFS`, `2 FAT32`), a raw `.img` for one packport can't read | 7-Zip |
| File systems | FAT12/16/32 with long names; NTFS (LZNT1 and WOF compression, sparse files); ext2, ext3, ext4; HFS+ and HFSX (zlib-compressed files, hard links); APFS | 7-Zip; LZNT1 against Windows' own compressor |

Encrypted data raises `packport.EncryptedError`: password-protected RAR, 7z and ZIP members (ZipCrypto, WinZip AES, PKWARE strong encryption), garbled ARJ members, EFS files on NTFS, encrypted APFS volumes and DMGs. BitLocker (To Go too), LUKS, LVM and sparse images are refused with a message that names them.

**Not read:** exFAT and classic (pre-HFS+) HFS, which 7-Zip doesn't read either (a disk image's exFAT or HFS partition comes out as a raw `.img`); LZFSE and LZVN compression (DMGs made as `ULFO`, and files macOS compressed that way); WIM's LZMS (`.esd`) and split `.swm` sets; CAB's Quantum; RAR 1.5 and 2.0 compression; ZIP's Reduce and DCL Implode; LZO squashfs; UDF virtual partitions (multisession CD-R); VMDK snapshots and differencing VDIs; sparse bundles. Each gives an error that says so. lzma-compressed squashfs (a squashfs-tools extension the Linux kernel never shipped) is read through liblzma but hasn't been tested on a real image.

## What it writes

| Format | Write |
|---|---|
| RAR 4 (`.rar`, `.cbr`), stored | ✓ |
| Unix compress (`.Z`), 9 to 16-bit LZW; tar + compress (`.tar.Z`, `.taZ`) | ✓ |
| CPIO newc (`.cpio`), and odc | ✓ |
| WIM 1.13, uncompressed, one image | ✓ |

**RAR 4**, written from RARLAB's published format description (`technote.txt`), never from unrar's source: every file *stored* (method 0x30), the format every RAR reader opens, including old comic book apps that predate RAR 5. Comic pages are JPEG or PNG, which don't compress further anyway: packport writes a 200-page, 100 MB comic in 0.09 s. Folders, Unicode names (in RAR's Unicode name encoding, with an ASCII stand-in), files over 4 GiB (the 64-bit size fields), modification times, CRC32s and the read-only flag. Names use Windows conventions, as WinRAR on Windows writes them.

**Unix compress**: LZW with codes growing from 9 to 16 bits, block mode with CLEAR, header `1F 9D 90`, and the original's padding at every width change and CLEAR. The output is identical, byte for byte, to libarchive's compress writer on every input tried, up to 20 MB. `ZCompressor` and `ZDecompressor` work incrementally, like `zlib.compressobj`. `decompress()` returns at most `max_size` bytes (1 GiB unless you say otherwise), and the decoder keeps its dictionary as (prefix code, byte) pairs, so a 19 KB hostile stream that expands to 72 MB peaks at 18 MB of memory.

**CPIO**: files, folders, permissions, modification times, the `TRAILER!!!` entry and the padding. Names are UTF-8. Sizes are 32-bit, so files of 4 GiB or more are refused with a clear error.

**WIM**: one image, files with the same contents stored once (SHA-1), the metadata resource and the XML data, as 7-Zip writes it; 7-Zip reads packport's WIM files back.

Writers never write links: a link to a file is stored as the file, a link to a folder (or a Windows junction) as an empty folder. Times a format can't hold are clamped to its nearest limit. A failed write removes the half-written file.

## packport-native

packport's own decoders are written in Python. packport-native has the slow ones again in Rust: LZX (CAB, WIM, CHM), RAR 2.9 to 5 (LZ, PPMd and the filters), 7z's PPMd and BCJ2, ZIP's PPMd, Deflate64, XPRESS, LZH and ARJ, NTFS's LZNT1, Apple's ADC, LZ4, and the CRC-32, CRC-16 and CAB checksums. PKZIP 1's Shrink and Implode, 7z's ARM64 and RISC-V filters and `.Z` stay in Python (rare, or fast enough). packport uses it when it's installed, and gives the same bytes either way: the tests read every test archive, and damaged copies of each, both ways and compare. `packport.accelerated()` says which is in use; `PACKPORT_PURE=1` keeps packport on its Python decoders. A packport-native of another version isn't used (its decoders may not match): packport says so in a warning when it starts, and in `packport --version`.

Independent pieces are decoded on several cores at once, in archive order: 7z folders, WIM chunks, squashfs blocks, and the files of a non-solid RAR archive (a CBR's pages). A big 7z folder or cabinet folder is decoded in a thread of its own while what it already gave is being written, and BCJ2's streams are decoded side by side. `PACKPORT_THREADS` sets how many threads (1: none); by default one less than the cores, at most 8. The Python decoders gain little from it; zlib, lzma and packport-native let go of Python's lock while they work.

Every file is unpacked a piece at a time and never held whole, so a 5 GB file in a RAR takes no more memory than a small one: about the size of its dictionary.

## The API

Reading:

```python
packport.open(src, fmt=None, *, max_size=...) -> Archive   # a path, a list of volume paths, bytes, or a binary file
packport.detect(src) -> str | None             # "rar", "rar5", "7z", "zip", "iso", "udf", "disk", ...
packport.extract(src, folder, *, fmt=None, max_size="free", max_files=1_000_000,
                 on_skip=None, on_rename=None) -> list[Path]

archive.members                                # Items: name, size, is_dir, link, mtime, mode, encrypted
archive.files()                                # (Item, stream) for each file, in archive order
archive.read(item_or_name) -> bytes
```

An `Archive` is a context manager. `files()` hands over each stream in turn, valid until the next one is taken, so solid RAR and 7z blocks are decoded once. Damaged archives raise `packport.PackportError`, never anything else (thousands of corrupted, truncated and random inputs in the tests make sure of that).

`extract` never writes outside the folder: leading slashes are dropped, names that would still climb out or start with a drive (`C:/...`) are skipped, and so are links and device files. On Windows, other names are made safe the way 7-Zip does it (`a:b` becomes `a_b`, `CON` becomes `_CON`), so nothing is written to an alternate data stream or a device. Existing files are never overwritten: a taken name gets ` (1)`. `max_size` caps the bytes written: by default what the folder's drive has free, less 1 GB (or a tenth of what's free, if less), so an archive made to fill the disk stops first; `None` means no limit. `max_files` caps the members. A file whose data turns out damaged part-way (a checksum that doesn't match) is removed, not left half-written. `on_skip(name)` and `on_rename(name, path)` hear about each member left out (also one whose name the file system refuses, such as a part longer than 255 characters on Windows) or renamed.

Some formats are unpacked into a temporary file as they open, so their members can be read in any order: an RPM's payload, a solid NSIS installer, a .pkg's Payload. That stops at `open(..., max_size=...)` bytes, or when you give none at 200 times the archive's size (at least 64 MB): a 778-byte installer that unpacks to 300 MB of zeros is refused after 64 MB, where it used to write all 300 MB first. An explicit `max_size=None` (in `open`, `extract` or `--max-size none`) means no limit at all, this one included; `extract`'s default, `"free"`, keeps it. ZIP members whose data overlaps another's (the trick of a "non-recursive" ZIP bomb) are refused.

Writing:

```python
packport.write_rar(out, sources) -> list[Entry]
packport.write_cpio(out, sources, fmt="newc") -> list[Entry]   # fmt="odc" for odc
packport.write_wim(out, sources) -> list[Entry]
packport.write_tar_z(out, sources) -> list[Entry]
packport.write_z(out, source)                  # one file: a path or bytes
packport.pack(out, sources, fmt=None)          # format from out's extension
packport.compress(data, bits=16) -> bytes      # .Z in memory
packport.decompress(data, max_size=1 << 30) -> bytes
packport.read_rar(data_or_path) -> list[Member]    # stored RAR only; names as stored
packport.read_cpio(data_or_path) -> list[Member]   # names as stored
packport.extract_cpio(data_path_or_file, folder, *, max_size="free", max_files=1_000_000, on_skip=None)
```

`out` is a path or a writable binary file. `sources` can be a path or a list of paths (folders keep their name and include everything inside them, like `7z a` and `tar`), `packport.tree(folder)` (everything inside a folder, without the folder itself), `(archive name, bytes or path)` pairs, `packport.Entry` objects, or a `{archive name: bytes | path | None}` mapping, where `None` makes a folder. `RarWriter` and `CpioWriter` write entry by entry; `ZWriter` is a writable file that compresses into `.Z`.

`read_rar` and `read_cpio` return names exactly as they're stored, so a hostile archive can hand back `../../x` or `C:\x`: unpack with `extract` or `extract_cpio`, which make every name safe.

## Speed

With packport-native, packport unpacks half of the archives below faster than 7-Zip and two more in the same time: archives of many pieces (7z folders, squashfs, a CBR's pages) are decoded on several cores at once, and there's no program to start. A single long PPMd, LZX or BCJ2 stream is still up to twice as slow as 7-Zip's C++, and so are an NSIS installer and one long LZMA2 stream, which wait on Python's liblzma. Without packport-native, the methods packport decodes in Python are far slower.

Same files, same machine, best of 3 (the Python column: one run), timed by `benchmarks/bench.py` with 7-Zip 24.09; each tool writes the files to disk:

| Archive | Unpacked | 7-Zip | packport (Python) | packport-native | against 7-Zip |
|---|---|---|---|---|---|
| squashfs, gzip | 33.6 MB | 0.25 s | 0.12 s | 0.04 s | 6.8 times as fast |
| squashfs, xz | 33.6 MB | 0.45 s | 0.20 s | 0.11 s | 4.0 times as fast |
| 7z, LZMA2 in 32 folders | 67.1 MB | 0.65 s | 0.27 s | 0.17 s | 3.9 times as fast |
| 7z, Deflate64 | 16.8 MB | 0.11 s | 4.61 s | 0.07 s | 1.6 times as fast |
| CBR (RAR, stored) | 52.1 MB | 0.10 s | 0.15 s | 0.07 s | 1.4 times as fast |
| CAB, MSZIP | 33.6 MB | 0.24 s | 0.44 s | 0.18 s | 1.3 times as fast |
| LZH, -lh5- | 4.2 MB | 0.05 s | 2.25 s | 0.04 s | 1.3 times as fast |
| ZIP, Deflate64 | 16.8 MB | 0.11 s | 4.84 s | 0.09 s | 1.2 times as fast |
| RAR 4, LZ and PPMd (libarchive's test) | 241.6 MB | 0.21 s | 1.87 s | 0.20 s | 1.1 times as fast |
| UDF 2.50 disc | 67.1 MB | 0.06 s | 0.14 s | 0.06 s | the same |
| WIM, stored | 67.1 MB | 0.10 s | 0.18 s | 0.10 s | the same |
| ZIP, bzip2 | 33.6 MB | 1.27 s | 1.73 s | 1.56 s | 1.2 times as long |
| 7z, LZMA2, one stream | 67.1 MB | 0.74 s | 0.97 s | 0.96 s | 1.3 times as long |
| 7z, PPMd | 6.3 MB | 0.71 s | 84.82 s | 0.99 s | 1.4 times as long |
| ZIP, PPMd | 6.3 MB | 0.76 s | 110.31 s | 1.15 s | 1.5 times as long |
| 7z, BCJ2 | 16.8 MB | 0.42 s | 2.13 s | 0.73 s | 1.7 times as long |
| CAB, LZX 21 | 33.6 MB | 0.09 s | 8.35 s | 0.18 s | 2.1 times as long |
| NSIS installer (Ghostscript 10.08) | 92.8 MB | 2.00 s | 5.59 s | 4.54 s | 2.3 times as long |

For `.Z`, libarchive is much faster too: 20 MB of text took packport 4.5 s to write and libarchive 0.27 s, for the same bytes.

## How it's tested

The suite has 699 tests, and any warning fails one (4 big-file ones run with `PACKPORT_SLOW=1`, one needs the Ghostscript installer, `PACKPORT_NSIS_SAMPLE`, and three check packport-native against the Python decoders when it's installed), against these oracles:

- **7-Zip 24.09.** Every archive packport reads in the tests was extracted by 7-Zip and compared byte for byte: 145 of libarchive's own test archives (RAR, CAB, 7z, ZIP, LZH; BSD license), 25 of its ISO images, 6 of Apache Commons Compress's (Shrink, Implode, ARJ; Apache License 2.0), dfvfs's disk images (Apache License 2.0), go-diskfs's squashfs image (MIT), and archives 7-Zip itself wrote with every method it has. Where packport and 7-Zip differ on purpose, the test says so and why: links left out, names in old code pages, Rock Ridge names 7-Zip cuts short, system files.
- **Formats 7-Zip doesn't write.** PPMd's "cut off" mode, big Shrink streams, LZH, ARJ, squashfs and VDI are written by test-only encoders in `tests/` (never shipped), and 7-Zip has to read each back to the original bytes. NTFS's LZNT1 decoder unpacks what Windows' own compressor (`RtlCompressBuffer`) writes; the LZ4 decoder what the lz4 library writes.
- **libarchive 3.8.9** (Windows' own `tar.exe`) for Rock Ridge, zisofs, CPIO and what packport writes.
- **unrar, RARLAB's own reader** (through calibre), for every RAR packport writes; WinRAR's main header and header CRCs match packport's.
- **gzip 1.13** decompresses packport's `.Z`; packport's compressor matches libarchive's byte for byte.
- **Damaged input.** Every reader gets corrupted, truncated and random input and must only ever raise `PackportError`. `tests/fuzz_readers.py` damages every test archive (bytes changed, cut short, header fields set to 0, 1 and their largest values) and reads each copy in a process held to 1 GB: a case fails if anything but `PackportError` comes out (a panic in packport-native included), if it runs out of memory, crashes its process, or is stuck. The suite runs 6 copies of each archive; `python tests/fuzz_readers.py 200` runs the deep pass.
- **Damaged input against 7-Zip.** 200 damaged copies of each of the 197 test archives 7-Zip reads (39,400 in all) were read by packport and by 7-Zip and compared. For every format with checksums, every file packport gave back was right. Where it and 7-Zip disagreed, packport either read on where 7-Zip gave up (4,172 cases, 3,353 of them giving back every file of the undamaged archive: a ZIP without its central directory, an ISO cut short) or refused data 7-Zip let through damaged (179). The 54 cases 7-Zip read correctly and packport refused are damaged headers packport is stricter about: a header checksum that doesn't match (RAR, LZH), a size that doesn't (CAB, ZIP), a folder too big (ISO), or VHDX region tables, which now fall back to their second copy as 7-Zip's do. The comparison found one real bug, fixed: see the changelog.
- **Memory.** `tests/test_memory.py` reads a file 4 to 16 times bigger than a limit, in every format, and checks the peak with tracemalloc (or, for the slowest Python decoders, that the first output comes before half the input has been read).
- **packport-native** against the Python decoders: every test archive and damaged copies, the same bytes or the same error both ways (`tests/test_native.py`), plus Rust unit tests (`cargo test`).
- **Hostile disk images** can't make packport look at a file outside their folder: parents, extents and backing files named by absolute paths, other drives, network shares or `..` are refused before anything is looked up (`tests/test_disk_paths.py`).
- **Big files**, sparse so they cost no disk space: 3 GiB and 4 GiB+ files in RAR and CPIO, checked by 7-Zip, libarchive and unrar (`PACKPORT_SLOW=1`).

`tests/data/make_fixtures.py` and `tests/data/make_dfvfs_fixtures.py` rebuild the test archives, checking each against 7-Zip as they go.

## Development

```
python -m venv .venv
.venv\Scripts\pip install -e .[dev]
.venv\Scripts\python -m pytest
```

packport-native needs Rust (`rustup`) and maturin (`pip install maturin`):

```
.venv\Scripts\maturin develop --release -m native/Cargo.toml
cargo clippy --release --manifest-path native/Cargo.toml -- -D warnings
cargo test --release --manifest-path native/Cargo.toml --no-default-features
```

A Rust build keeps the paths of its sources, your home folder's among them. For a wheel you'll hand out, build it with `$env:RUSTFLAGS = "--remap-path-prefix=$env:USERPROFILE=~"` first (the release's wheels are built by GitHub Actions).

`benchmarks/bench.py WORK` builds a set of archives and times 7-Zip, packport's Python decoders and packport-native on them (the table above).

The tests that need 7-Zip, `tar.exe` (libarchive's `bsdtar` elsewhere), gzip or calibre (for unrar) skip when those aren't installed.

Code layout (`src/packport/`):

- `archive.py`: `open`, `extract`, `detect`; volumes; the reader registry.
- One module per format: `rar.py` and `rar5.py` (with `rar3.py`, `ppmd.py`), `sevenzip.py`, `zipformat.py` (with `ppmd8.py`, `pkzip1.py`, `deflate64.py`), `cab.py` and `lzx.py`, `wim.py` and `xpress.py`, `nsis.py`, `iso.py`, `udf.py`, `squashfs.py`, `lzh.py`, `arj.py`, `arformat.py` (ar, deb), `rpm.py`, `xar.py`, `cpio.py`, `lzw.py` (`.Z`).
- `disk.py` (partitions), `vdisk.py` (VHD, VHDX, VMDK, QCOW2, VDI, DMG), `fs/` (FAT, NTFS, ext, HFS+, APFS).
- `entries.py`: entries, name checks, gathering files and folders for the writers.
- `_accel.py` (packport-native, when installed), `parallel.py` (decoding ahead in threads); `native/`: packport-native's Rust source, a module per decoder.

## Credits

Written from the formats' own documentation: RARLAB's technote, PKWARE's APPNOTE, 7-Zip's `7zFormat.txt`, Microsoft's specifications (MS-XCA, MS-VHDX, VHD, FAT, the cabinet format), ECMA-119 and ECMA-167, the OSTA UDF specification, IEEE P1281/P1282, the El Torito specification, the kernel.org ext4 and squashfs documentation, the Linux-NTFS documentation, QEMU's qcow2 specification, VMware's VMDK format, Apple's TN1150 and File System Reference, and the LHa and ARJ technical notes. Read as references, all under permissive licenses: libarchive's readers (BSD), Igor Pavlov's public-domain LZMA SDK (PPMd variants H and I), Haruhiko Okumura's public-domain ar002 (LZH), NSIS's zlib-licensed headers. Test data comes from libarchive (BSD), Apache Commons Compress and dfvfs (Apache License 2.0) and go-diskfs (MIT), each with its license next to it in `tests/data`.

## License

MIT, see [LICENSE](LICENSE).
