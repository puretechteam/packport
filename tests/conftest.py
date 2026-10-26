import os
import random
import shutil
import subprocess
from pathlib import Path

import pytest


def _first(*candidates):
    for c in candidates:
        if c and Path(c).is_file():
            return str(c)
    return None


SEVEN_ZIP = _first(shutil.which("7z"), shutil.which("7z.exe"), "C:/Program Files/7-Zip/7z.exe",
                   "C:/Program Files (x86)/7-Zip/7z.exe")
# libarchive's bsdtar: Windows ships it as tar.exe; elsewhere "tar" is usually GNU tar, which can't read RAR
BSDTAR = _first("C:/Windows/System32/tar.exe" if os.name == "nt" else None, shutil.which("bsdtar"))
GZIP = shutil.which("gzip")
# calibre bundles RARLAB's own unrar library (through unrardll), and reads comics from CBR files
CALIBRE_DEBUG = _first(shutil.which("calibre-debug"), "C:/Program Files/Calibre2/calibre-debug.exe")
EBOOK_CONVERT = _first(shutil.which("ebook-convert"), "C:/Program Files/Calibre2/ebook-convert.exe")

needs_7z = pytest.mark.skipif(SEVEN_ZIP is None, reason="7-Zip isn't installed")
needs_bsdtar = pytest.mark.skipif(BSDTAR is None, reason="bsdtar (Windows tar.exe) isn't available")
needs_unrar = pytest.mark.skipif(CALIBRE_DEBUG is None, reason="calibre (which bundles unrar) isn't installed")

# Every name works with 7-Zip. Windows' tar.exe converts names to the system's ANSI code page and
# skips any it can't represent (it does the same with zip and tar files made by Python), so its
# tests use names that fit Windows-1252.
LATIN_NAMES = ["café/crème brûlée.txt", "Ünïcödé dir/ñ/deep.txt", "naïve résumé.md"]
UNICODE_NAMES = LATIN_NAMES + ["日本語のファイル.txt", "Ελληνικά/κείμενο.txt", "emoji 😀🎉/party 🎈.bin",
                               "中文目录/空文件.dat"]

MTIME = 981173106  # 2001-02-03 04:05:06 UTC, an even second (DOS times have 2-second steps)


def make_tree(root: Path, names=UNICODE_NAMES) -> Path:
    """A folder with nested folders, empty folders, empty files, odd sizes and Unicode names."""
    rng = random.Random(42)
    files = {
        "readme.txt": b"hello\n",
        "empty.txt": b"",
        "nested/a/b/c/data.bin": rng.randbytes(70001),
        "nested/a/sibling.txt": b"x" * 1001,
        "nested/a/b/text.txt": b"the quick brown fox " * 500,
    }
    for i, n in enumerate(names):
        files[n] = b"" if n.endswith(".dat") else (n.encode() * (i + 1))
    for name, data in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    for d in ["empty folder", "nested/a/b/empty inside"]:
        (root / d).mkdir(parents=True)
    os.utime(root / "readme.txt", (MTIME, MTIME))
    return root


def read_tree(root: Path) -> dict:
    """{relative path: bytes, or None for a folder}."""
    out = {}
    for dirpath, dirs, files in os.walk(root):
        rel = Path(dirpath).relative_to(root)
        for d in dirs:
            out[(rel / d).as_posix()] = None
        for f in files:
            out[(rel / f).as_posix()] = (Path(dirpath) / f).read_bytes()
    return out


def run(*args, ok=True) -> subprocess.CompletedProcess:
    r = subprocess.run([str(a) for a in args], capture_output=True, timeout=600, check=False)
    if ok:
        assert r.returncode == 0, (args, r.stdout.decode(errors="replace"), r.stderr.decode(errors="replace"))
    return r


def extract_7z(archive: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    run(SEVEN_ZIP, "x", "-y", f"-o{dest}", archive)
    return dest


def extract_bsdtar(archive: Path, dest: Path, *options) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    run(BSDTAR, *options, "-xf", archive, "-C", dest)
    return dest


def unrar(mode: str, archive: Path, *args, ok=True):
    """Run tests/unrar_helper.py in calibre's Python: unrar's view of the headers, after
    extracting or verifying (see the helper). Returns the parsed JSON, or the process on failure."""
    import json
    helper = Path(__file__).with_name("unrar_helper.py")
    r = run(CALIBRE_DEBUG, "-e", helper, mode, archive, *args, ok=ok)
    if r.returncode:
        return r
    return json.loads(r.stdout.decode("utf-8").strip().splitlines()[-1])


def sparse_file(path: Path, size: int, marks: dict) -> Path:
    """A file of ``size`` bytes that is mostly holes, with ``marks`` ({offset: bytes}) written in."""
    path.write_bytes(b"")
    if os.name == "nt":
        subprocess.run(["fsutil", "sparse", "setflag", str(path)], capture_output=True, check=False)
    with open(path, "r+b") as f:
        for offset, data in sorted(marks.items()):
            f.seek(offset)
            f.write(data)
        if f.seek(0, 2) < size:
            f.seek(size - 1)  # not truncate(): on Windows that writes out every zero
            f.write(b"\0")
    return path


@pytest.fixture
def unicode_tree(tmp_path) -> Path:
    return make_tree(tmp_path / "src")


@pytest.fixture
def latin_tree(tmp_path) -> Path:
    return make_tree(tmp_path / "src", LATIN_NAMES)
