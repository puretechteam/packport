# Changelog

Newest first. Each entry is dated by when it landed.

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
