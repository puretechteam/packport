# Changelog

Newest first. Each entry is dated by when it landed.

## 2026-10-30: packport 0.2.1, safer CPIO extraction and .Z decoding

- **Fixed (security):** on Windows, `extract_cpio` could write an alternate data stream from a name like `dir/a.txt:hidden`, because it only checked the first part of a name for `:`. It now makes every part of a name safe the way 7-Zip does: characters Windows doesn't allow become `_` (so `a.txt:hidden` becomes `a.txt_hidden`), a trailing dot or space becomes `_`, and device names such as `CON` or `nul.txt` get a `_` in front.
- **Fixed (security):** a small archive could fill the disk through hard links, because each link wrote another full copy of its file. The new `max_size` caps the bytes written, counting every copy.
- **Changed:** `extract_cpio` never overwrites a file. A name that's already taken, whether written twice in the archive, already in the folder, or differing only in case on Windows, is saved as `name (1).ext`.
- **Added:** `on_skip(name)` hears about each member that's left out (names that would climb out of the folder, links, device files).
- **Fixed (security):** an archive with the same name many times made `extract_cpio` retry every earlier ` (n)` name for each copy, which grows with the square of the count. It now remembers where each name got to: 300 copies of one name took 45,150 file-open attempts before and 300 now.
- **Fixed (security):** a CPIO header could claim a name of up to 4 GiB, and packport tried to read it all. Names longer than 64 KiB are now refused before they're read, by `read_cpio` and `extract_cpio` alike. `CpioWriter` refuses to write them too.
- **Added:** `extract_cpio(..., max_files=1_000_000)` caps the number of members, so an archive of millions of empty files can't flood a folder. `None` turns it off.
- **Fixed:** a CPIO archive with a file and a folder of the same name (a file `a`, then `a/b.txt`, or a file `d`, then a folder `d`) stopped `extract_cpio` with an `OSError`. The folder, or the file inside it, is now skipped and reported to `on_skip`; a file whose name is taken by a folder is saved as `name (1)`.
- **Fixed:** top-level names with a colon were skipped even though the docs said they're renamed. Now only a name starting with a bare drive (`C:/...`) is skipped; on Windows `a:b` becomes `a_b` and `D:rel.txt` becomes `D_rel.txt`, and elsewhere they're kept as they are.
- **Fixed:** hard links whose data comes with the first link (as GNU cpio writes them) came out empty, apart from the first. Every link now gets the data, whichever one carries it, and links are only created once the data is known, so a `max_size` stop leaves no empty placeholders behind.
- **Fixed (security):** the `.Z` decoder kept each dictionary entry as a whole string, so a 19 KB hostile stream made it hold 73 MB at once (and about 2 GB at the format's limit). It now keeps (prefix code, byte) pairs, like the original `compress`, with whole strings only up to 16 MB for speed: the same stream peaks at 18 MB, and normal files decode within 3% of the old speed (text 15.5 MB/s before, 15.1 MB/s after).
- **Changed:** `decompress()` now caps its output at 1 GiB by default (`max_size=None` turns the cap off). `ZDecompressor`, which hands output back a piece at a time, still has no cap unless you give one.
- **Fixed:** `pack("out.Z", ...)` took only a path or bytes. A mapping like `{"a.txt": data}` made it open a file called `a.txt` from the current folder instead, and an `Entry`, a `(name, data)` pair, a `bytearray` or a `memoryview` raised the wrong error. It now takes everything the other formats take, and a folder or several files raise "`.Z` holds a single file".
- **Fixed:** `read_rar` returned the files before the cut when an archive was cut short exactly between two files. A RAR archive without its end-of-archive block now raises `PackportError` ("cut short"), as a CPIO archive without `TRAILER!!!` already did.
- **Fixed:** modification times a format can't hold (before 1970, far in the future, infinite or NaN) made `write_rar`, `write_cpio` and `write_tar_z` fail with `OSError`, `OverflowError` or `ValueError`. They're now clamped to the format's range; `.tar.Z` no longer stores negative times.
- **Fixed:** on Windows, files with the read-only attribute weren't flagged read-only in RAR (or given mode `0o444` in CPIO and `.tar.Z`). They are now.
- **Docs:** the README gives the real size (about 58 KB of source, a 28 KB wheel, about 160 KB installed), and says that `read_rar` and `read_cpio` return names as stored, which aren't safe to use as paths.
- **Added:** tests for all of the above: 29 new ones, each building its hostile archive in code; 28 of them failed before these fixes (the one exception, `pack` with plain bytes, guards what already worked). The suite is now 193 passed, 3 skipped (164 before).

## 2026-10-26: Tests pass on Python 3.10.11 (after the 0.2.0 tag)

- **Fixed (tests only):** the `.tar.Z` round-trip test used `tarfile`'s extraction filter, which Python 3.10.11 (the last 3.10 with a Windows installer) doesn't have. It now uses the filter only where it exists. Found by the new GitHub Actions run on Python 3.10.

## 2026-10-26: packport 0.2.0, streaming CPIO extraction

- **Added:** `extract_cpio(archive, folder)` unpacks a CPIO archive straight to disk in 1 MB pieces, so archives larger than memory work. It never writes outside the folder: leading slashes are dropped (as bsdtar does), names that would still climb out or name a drive are skipped, and so are symbolic links and device files. Files keep their modification times, and hard links each get the file's data.
- **Changed:** `read_cpio` reads the archive as it goes instead of loading the whole file first, and both accept an open binary file as well as bytes or a path.
- **Added:** tests for extraction: round trips, streaming, hostile names, links, hard links and damaged archives.
- **Added:** GitHub Actions run the tests (Python 3.10 and 3.13 on Windows, with 7-Zip) and `ruff check` on every push and pull request, plus `CONTRIBUTING.md` and `SECURITY.md`. `ruff` is in the `dev` extra.

## 2026-10-26: packport 0.1.0, first release

- **Writes RAR 4** (`.rar`, `.cbr`) with stored entries, written from RARLAB's published format description:
  - folders, including empty ones;
  - Unicode names in RAR's Unicode name encoding;
  - files over 4 GiB, with the 64-bit size fields;
  - modification times, CRC32s and the read-only flag;
  - streaming, so files larger than memory work.
- **Writes Unix compress** (`.Z`): 9 to 16-bit LZW in block mode. The output matches libarchive's compress writer byte for byte, and gzip, 7-Zip and libarchive read it. Also `.tar.Z`.
- **Writes CPIO newc** (`.cpio`): files, folders, permissions and modification times.
- **Reads** stored RAR 4, `.Z` and CPIO newc, for round trips without other tools. Damaged archives raise `PackportError`; `.Z` output can be capped with `max_size`.
- **Command line:** `packport SOURCES... OUT`, with the format taken from OUT's extension.
- **Tested** byte for byte against RARLAB's own unrar (bundled with calibre), 7-Zip, libarchive (Windows' `tar.exe`) and gzip. The tests use Unicode names, empty folders and files, sparse files of 3 GiB and over 4 GiB, corrupted archives and random trees. They pass on Python 3.10, 3.11 and 3.13 and in a PyInstaller build.
