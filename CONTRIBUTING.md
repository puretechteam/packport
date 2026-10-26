# Contributing

Thanks for helping. Bug reports, new formats and fixes are all welcome.

## Reporting a bug

Open an issue with the archive that fails, if you can share it, the tool that refuses packport's output (and its version), and the error it gives.

Security problems go through [SECURITY.md](SECURITY.md) instead, not a public issue.

## Making a change

```
python -m venv .venv
.venv\Scripts\pip install -e .[dev]
.venv\Scripts\python -m pytest
.venv\Scripts\ruff check .
```

Tests that need 7-Zip, `tar.exe` (bsdtar), gzip or calibre (for RARLAB's unrar) skip when those aren't installed. The multi-gigabyte tests run only with `PACKPORT_SLOW=1`. GitHub Actions runs the tests (Python 3.10 and 3.13, with 7-Zip) and `ruff check` on every pull request.

- **Write from published format descriptions.** For RAR that means RARLAB's `technote.txt`, never unrar's source, whose license forbids using it to build a RAR writer.
- **No dependencies.** packport is pure Python with nothing to install, and stays that way.
- **Stream.** Writers and extractors must never hold a whole file or archive in memory.
- **Hostile archives:** readers must raise `PackportError` and nothing else, and extraction must never write outside the destination folder or create links.
- **Check against real tools.** New output should be tested against at least one independent reader (7-Zip, libarchive, unrar), as `tests/test_interop.py` does.
- **Changelog:** add a dated entry to [CHANGELOG.md](CHANGELOG.md) for anything a user would notice.

## License

By contributing, you agree that your contribution is licensed under the [MIT License](LICENSE).
