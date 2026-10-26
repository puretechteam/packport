# Changelog

Newest first. Each entry is dated by when it landed.

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
- **Tested** against 7-Zip, libarchive (Windows' `tar.exe`) and gzip, byte for byte, with Unicode names, empty folders and files, a sparse file over 4 GiB, corrupted archives and random trees.
