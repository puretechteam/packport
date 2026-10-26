"""Archives written by packport, extracted by other software. Each test skips when that software
isn't installed: 7-Zip, libarchive's bsdtar (Windows' own tar.exe) and gzip (which reads .Z)."""

import io
import os
import tarfile

import pytest
from conftest import (
    BSDTAR,
    GZIP,
    MTIME,
    SEVEN_ZIP,
    extract_7z,
    extract_bsdtar,
    needs_7z,
    needs_bsdtar,
    read_tree,
    run,
)
from test_lzw import PAYLOADS

import packport
from packport.__main__ import main

WRITERS = {"rar": packport.write_rar, "cbr": packport.write_rar, "cpio": packport.write_cpio}
# libarchive reads cpio names in the system code page unless told they are UTF-8
BSDTAR_OPTIONS = {"cpio": ["--options", "hdrcharset=UTF-8"]}


def _check_times(folder, fmt, dst_quirk=False):
    off = abs(os.path.getmtime(folder / "readme.txt") - MTIME)
    if dst_quirk:
        # RAR stores local time. 7-Zip converts it with today's daylight saving offset rather than
        # the one in force on that date (bsdtar and unrar use the right one), so allow an hour.
        off = min(off, abs(off - 3600))
    assert off <= (2 if fmt != "cpio" else 0)


@needs_7z
@pytest.mark.parametrize("fmt", WRITERS)
def test_7zip_extracts_identically(unicode_tree, tmp_path, fmt):
    archive = tmp_path / f"out.{fmt}"
    WRITERS[fmt](archive, packport.tree(unicode_tree))
    run(SEVEN_ZIP, "t", archive)  # checks every CRC
    out = extract_7z(archive, tmp_path / "x")
    assert read_tree(out) == read_tree(unicode_tree)
    _check_times(out, fmt, dst_quirk=fmt != "cpio")


@needs_bsdtar
@pytest.mark.parametrize("fmt", WRITERS)
def test_bsdtar_extracts_identically(latin_tree, tmp_path, fmt):
    archive = tmp_path / f"out.{fmt}"
    WRITERS[fmt](archive, packport.tree(latin_tree))
    out = extract_bsdtar(archive, tmp_path / "x", *BSDTAR_OPTIONS.get(fmt, []))
    assert read_tree(out) == read_tree(latin_tree)
    _check_times(out, fmt)


@needs_7z
@pytest.mark.parametrize("name", PAYLOADS)
def test_7zip_reads_dot_z(tmp_path, name):
    src = tmp_path / "payload.bin"
    src.write_bytes(PAYLOADS[name])
    packport.write_z(tmp_path / "payload.bin.Z", src)
    out = extract_7z(tmp_path / "payload.bin.Z", tmp_path / "x")
    assert (out / "payload.bin").read_bytes() == PAYLOADS[name]


@pytest.mark.skipif(GZIP is None, reason="gzip isn't installed")
@pytest.mark.parametrize("name", PAYLOADS)
def test_gzip_reads_dot_z(tmp_path, name):
    (tmp_path / "p.Z").write_bytes(packport.compress(PAYLOADS[name]))
    assert run(GZIP, "-dc", tmp_path / "p.Z").stdout == PAYLOADS[name]


@needs_bsdtar
def test_bsdtar_reads_dot_z(tmp_path):
    # bsdtar only extracts archives, so the .Z holds a tar of every test payload
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for i, data in enumerate(PAYLOADS.values()):
            info = tarfile.TarInfo(f"payload{i}.bin")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    (tmp_path / "all.tar.Z").write_bytes(packport.compress(buf.getvalue()))
    out = extract_bsdtar(tmp_path / "all.tar.Z", tmp_path / "x")
    assert read_tree(out) == {f"payload{i}.bin": d for i, d in enumerate(PAYLOADS.values())}


@needs_bsdtar
@pytest.mark.parametrize("name", [n for n in PAYLOADS if PAYLOADS[n]])
def test_same_bytes_as_libarchive(tmp_path, name):
    # libarchive's compress writer follows the original compress, CLEAR heuristics included, so
    # the two outputs match byte for byte. (For empty input libarchive writes a stray code that
    # decodes as one zero byte; packport writes just the header, like compress.)
    (tmp_path / "p.bin").write_bytes(PAYLOADS[name])
    run(BSDTAR, "-cZf", tmp_path / "lib.Z", "--format", "raw", "-C", tmp_path, "p.bin")
    assert packport.compress(PAYLOADS[name]) == (tmp_path / "lib.Z").read_bytes()


@needs_bsdtar
def test_same_bytes_as_libarchive_past_8_mb(tmp_path):
    # past 8 MB compress (and libarchive) work out the CLEAR ratio with less precision
    from test_lzw import text
    data = text(9_000_000) + bytes(range(256)) * 4000 + text(2_000_000, 2)
    (tmp_path / "p.bin").write_bytes(data)
    run(BSDTAR, "-cZf", tmp_path / "lib.Z", "--format", "raw", "-C", tmp_path, "p.bin")
    assert packport.compress(data) == (tmp_path / "lib.Z").read_bytes()


@needs_bsdtar
def test_bsdtar_reads_tar_z(latin_tree, tmp_path):
    packport.write_tar_z(tmp_path / "out.tar.Z", packport.tree(latin_tree))
    out = extract_bsdtar(tmp_path / "out.tar.Z", tmp_path / "x")
    assert read_tree(out) == read_tree(latin_tree)
    _check_times(out, "cpio")


def test_tar_z_round_trip(unicode_tree, tmp_path):
    packport.pack(tmp_path / "out.taz", unicode_tree)
    with tarfile.open(fileobj=io.BytesIO(packport.decompress((tmp_path / "out.taz").read_bytes()))) as tf:
        tf.extractall(tmp_path / "x", filter="data")
    assert read_tree(tmp_path / "x" / "src") == read_tree(unicode_tree)


def test_cli(unicode_tree, tmp_path, capsys):
    assert main([str(unicode_tree), str(tmp_path / "a.cbr")]) == 0
    assert "a.cbr" in capsys.readouterr().out
    names = [m.name for m in packport.read_rar(tmp_path / "a.cbr")]
    assert names[0] == "src" and "src/empty folder" in names and "src/nested/a/b/c/data.bin" in names
    assert main([str(unicode_tree / "readme.txt"), str(unicode_tree / "empty.txt"), str(tmp_path / "b.cpio")]) == 0
    assert [m.name for m in packport.read_cpio(tmp_path / "b.cpio")] == ["readme.txt", "empty.txt"]
    assert main([str(unicode_tree / "nested/a/b/text.txt"), str(tmp_path / "t.txt.Z")]) == 0
    assert packport.decompress((tmp_path / "t.txt.Z").read_bytes()) == (unicode_tree / "nested/a/b/text.txt").read_bytes()
    assert main([str(unicode_tree), str(tmp_path / "c.Z")]) == 1
    assert main([str(unicode_tree / "readme.txt"), str(tmp_path / "c.zip")]) == 1
    assert main([str(tmp_path / "missing"), str(tmp_path / "c.rar")]) == 1
    assert "single file" in capsys.readouterr().err


def test_format_of():
    assert packport.format_of("x.TAR.Z") == "tar.z"
    assert packport.format_of("x.Z") == "z"
    assert packport.format_of("Comic.CBR") == "cbr"
    with pytest.raises(packport.PackportError):
        packport.format_of("x.7z")
