"""RAR files written by packport, read by RARLAB's own unrar library (the reference reader, bundled
with calibre) and by calibre's comic book reader. Skips when calibre isn't installed."""

import random
import struct
import zipfile
import zlib

import pytest
from conftest import EBOOK_CONVERT, MTIME, needs_unrar, read_tree, run, unrar
from test_damaged import LATIN_POOL, UNICODE_POOL, as_dict, random_tree

import packport
from packport.rar import dos_time

pytestmark = needs_unrar


def test_unrar_extracts_identically(unicode_tree, tmp_path):
    entries = packport.write_rar(tmp_path / "out.rar", packport.tree(unicode_tree))
    seen = unrar("extract", tmp_path / "out.rar", tmp_path / "x")
    assert read_tree(tmp_path / "x") == read_tree(unicode_tree)
    heads = {h["filename"].replace("\\", "/"): h for h in seen["headers"]}
    assert list(heads) == [e.name for e in entries]  # Unicode names exactly
    for e in entries:
        h = heads[e.name]
        assert h["is_dir"] == e.is_dir and h["method"] == 0x30 and h["host_os"] == 2
        assert h["unpack_size"] == h["pack_size"] == e.size()
        if not e.is_dir:
            assert h["file_crc"] == zlib.crc32(e.source.read_bytes())
    # unrar reports the raw DOS time (calibre's wrapper then misapplies it to the extracted files
    # as if it were a Unix time, for any RAR 4 archive, so the files' own times aren't checked)
    assert heads["readme.txt"]["file_time"] == dos_time(MTIME)


@pytest.mark.parametrize("seed", range(3))
def test_unrar_extracts_random_trees(tmp_path, seed):
    items = random_tree(random.Random(300 + seed), UNICODE_POOL if seed else LATIN_POOL)
    packport.write_rar(tmp_path / "r.rar", items)
    unrar("extract", tmp_path / "r.rar", tmp_path / "x")
    assert read_tree(tmp_path / "x") == as_dict(items)


def test_unrar_checks_our_crcs(tmp_path):
    # proves unrar really checks the data CRCs packport writes: flip one data byte and it refuses
    packport.write_rar(tmp_path / "ok.rar", {"a.txt": b"hello world"})
    data = bytearray((tmp_path / "ok.rar").read_bytes())
    data[data.index(b"hello world")] ^= 1
    (tmp_path / "bad.rar").write_bytes(bytes(data))
    r = unrar("extract", tmp_path / "bad.rar", tmp_path / "x", ok=False)
    assert r.returncode != 0 and b"ERAR_BAD_DATA" in r.stderr  # unrar's CRC error


def _png(rgb, w=64, h=96) -> bytes:
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
    rows = b"".join(b"\0" + bytes(rgb) * w for _ in range(h))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


@pytest.mark.skipif(EBOOK_CONVERT is None, reason="calibre isn't installed")
def test_calibre_reads_our_cbr_as_a_comic(tmp_path):
    pages = {f"Comic é/page {i:02}.png": _png((40 * i, 200 - 30 * i, 90)) for i in range(1, 5)}
    packport.write_rar(tmp_path / "comic.cbr", pages)
    run(EBOOK_CONVERT, tmp_path / "comic.cbr", tmp_path / "comic.epub")
    with zipfile.ZipFile(tmp_path / "comic.epub") as z:
        images = [n for n in z.namelist() if n.lower().endswith((".png", ".jpg", ".jpeg"))]
    assert len(images) >= len(pages)
