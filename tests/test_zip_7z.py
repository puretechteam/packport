"""7z and ZIP: archives 7-Zip wrote with every method packport reads (data/made, see
make_fixtures.py), PKZIP 1's Shrink and Implode (data/commons-compress: Apache Commons Compress's
test archives, under its license), encrypted members, damaged and unusual ZIP layouts, and
damaged input that may only ever raise PackportError."""

import hashlib
import io
import json
import random
import struct
import zipfile
from pathlib import Path

import pytest
from conftest import zstd_marked
from ppmd8_writer import zip_one

import packport
from packport import EncryptedError, PackportError

MADE = Path(__file__).parent / "data" / "made"
LIBARCHIVE = Path(__file__).parent / "data" / "libarchive"
COMMONS = Path(__file__).parent / "data" / "commons-compress"
EXPECTED = json.loads((MADE / "expected.json").read_text(encoding="utf-8"))
OLD = json.loads((COMMONS / "expected.json").read_text(encoding="utf-8"))


def _hashes(src) -> dict:
    with packport.open(src) as a:
        return {m.name: hashlib.sha256(s.read()).hexdigest() for m, s in a.files()}


@pytest.mark.parametrize("name", zstd_marked(sorted(k for k in EXPECTED if not k.endswith(".Z"))))  # .iso.Z: test_iso.py
def test_same_files_as_7zip(name):
    assert _hashes(MADE / name) == EXPECTED[name]


@pytest.mark.parametrize("name", sorted(OLD))
def test_shrink_and_implode_as_7zip_reads_them(name):
    # 4 KB and 8 KB windows, two and three trees, and Shrink
    assert _hashes(COMMONS / name) == OLD[name]


def test_formats_are_told_apart():
    assert packport.detect(MADE / "lzma.7z") == "7z"
    assert packport.detect(MADE / "deflate64.zip") == "zip"
    assert packport.detect(LIBARCHIVE / "test_read_format_zip_jar.jar") == "zip"
    assert packport.detect(LIBARCHIVE / "test_read_format_zip_sfx") == "zip"  # a program with a ZIP after it


def test_folders_and_empty_files_are_listed():
    with packport.open(MADE / "deflate64.zip") as a:
        kinds = {m.name: (m.is_dir, m.size) for m in a.members}
    assert kinds["sub/empty dir"] == (True, 0)
    assert kinds["sub/empty.txt"] == (False, 0)


@pytest.mark.parametrize("name", ["test_read_format_zip_traditional_encryption_data.zip",
                                  "test_read_format_zip_winzip_aes128.zip",
                                  "test_read_format_zip_encryption_header.zip",
                                  "test_read_format_7zip_encryption.7z"])
def test_encrypted_members_are_refused(name):
    with packport.open(LIBARCHIVE / name) as a:
        assert all(m.encrypted for m in a.members if m.is_file)
        with pytest.raises(EncryptedError):
            for _m, s in a.files():
                s.read()


@pytest.mark.parametrize("name, plain", [("test_read_format_zip_encryption_partially.zip", "bar.txt"),
                                         ("test_read_format_7zip_encryption_partially.7z", "bar_unencrypted.txt")])
def test_the_plain_members_of_a_partly_encrypted_archive_can_be_read(name, plain):
    with packport.open(LIBARCHIVE / name) as a:
        assert {m.name for m in a.members if m.encrypted} and plain not in {m.name for m in a.members if m.encrypted}
        assert a.read(plain)
        with pytest.raises(EncryptedError):
            list(a.files())


def test_an_encrypted_7z_header_is_refused():
    with pytest.raises(EncryptedError):
        packport.open(LIBARCHIVE / "test_read_format_7zip_encryption_header.7z")


def test_a_zip_without_its_central_directory_is_read_from_its_local_headers():
    data = (MADE / "deflate64.zip").read_bytes()
    cut = data[:data.find(b"PK\x01\x02")]  # the central directory and end record are gone
    assert _hashes(cut) == EXPECTED["deflate64.zip"]


@pytest.mark.parametrize("method", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA])
def test_sizes_after_the_data_are_found_when_the_directory_is_gone(method):
    class Unseekable(io.RawIOBase):  # zipfile then writes each member's sizes after its data
        def __init__(self):
            self.out = bytearray()

        def writable(self):
            return True

        def write(self, b):
            self.out += b
            return len(b)

    sink = Unseekable()
    files = {"a.txt": b"hello " * 3000, "b/c.bin": random.Random(1).randbytes(5000), "d.txt": b"PK\x07\x08 inside"}
    with zipfile.ZipFile(sink, "w", compression=method) as z:
        for name, body in files.items():
            z.writestr(name, body)
    data = bytes(sink.out)
    assert struct.unpack_from("<H", data, 6)[0] & 8
    cut = data[:data.find(b"PK\x01\x02")]
    with packport.open(cut) as a:
        assert {m.name: s.read() for m, s in a.files()} == files


def test_data_in_front_of_a_zip_is_skipped():
    data = (MADE / "lzma.zip").read_bytes()
    assert _hashes(b"MZ" + bytes(5000) + data) == EXPECTED["lzma.zip"]  # as a self-extractor has


def test_an_empty_zip_has_no_members():
    with packport.open(b"PK\x05\x06" + bytes(18)) as a:
        assert a.members == []


@pytest.mark.parametrize("method, what", [(2, "Reduce"), (10, "DCL Implode"), (97, "WavPack"), (200, "method 200")])
def test_methods_packport_lacks_are_named(method, what):
    with packport.open(zip_one("x.bin", b"data", b"????", method)) as a, \
            pytest.raises(PackportError, match=what):
        a.read("x.bin")


def test_a_bad_checksum_is_caught():
    data = bytearray((MADE / "deflate.zip").read_bytes())
    at = data.find(b"PK\x01\x02")
    data[at + 16] ^= 1  # the first member's CRC in the central directory
    with pytest.raises(PackportError, match="checksum"):
        _hashes(bytes(data))


def test_ppmd_settings_it_cant_read_are_refused():
    with packport.open(zip_one("x.bin", b"data", struct.pack("<H", 5 | 2 << 12) + bytes(8), 98)) as a, \
            pytest.raises(PackportError, match="restore method 2"):
        a.read("x.bin")


def test_extract_unpacks_a_zip_safely(tmp_path):
    names = []
    packport.extract(MADE / "bzip2.zip", tmp_path / "out", on_skip=names.append)
    got = {p.relative_to(tmp_path / "out").as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
           for p in (tmp_path / "out").rglob("*") if p.is_file()}
    assert got == EXPECTED["bzip2.zip"]
    assert names == []


@pytest.mark.parametrize("name", ["deflate64.zip", "bzip2.zip", "lzma.zip", "deflate64.7z", "bcj2.7z",
                                  "arm64_lzma2.7z", "header_plain.7z", "shrink.zip", "../commons-compress/SHRUNK.ZIP",
                                  "../commons-compress/imploding-4Kdict-2trees.zip",
                                  "../commons-compress/imploding-8Kdict-3trees.zip"])
def test_damaged_archives_raise_only_packport_error(name):
    rng = random.Random(name)
    data = (MADE / name).read_bytes()
    bad = []
    for _ in range(40):
        b = bytearray(data)
        for _ in range(rng.randint(1, 8)):
            b[rng.randrange(len(b))] = rng.randrange(256)
        if rng.random() < 0.3:
            b = b[:rng.randrange(len(b))]
        try:
            with packport.open(bytes(b)) as a:
                for _m, s in a.files():
                    s.read()
        except PackportError:
            pass
        except Exception as e:  # noqa: BLE001
            bad.append(f"{type(e).__name__}: {e}")
    assert bad == []


def test_damaged_ppmd_raises_only_packport_error():
    rng = random.Random(5)
    bad = []
    for name in ("test_read_format_zip_ppmd8.zipx", "test_read_format_7zip_ppmd.7z"):
        data = (LIBARCHIVE / name).read_bytes()
        for _ in range(40):
            b = bytearray(data)
            for _ in range(rng.randint(1, 4)):
                b[rng.randrange(30, len(b))] = rng.randrange(256)
            try:
                with packport.open(bytes(b)) as a:
                    for _m, s in a.files():
                        s.read()
            except PackportError:
                pass
            except Exception as e:  # noqa: BLE001
                bad.append(f"{name}: {type(e).__name__}: {e}")
    assert bad == []


def test_the_command_line_lists_and_extracts(tmp_path, capsys):
    from packport.__main__ import main
    assert main(["--list", str(MADE / "bcj2.7z")]) == 0
    listing = capsys.readouterr().out
    assert "sub/code.bin" in listing and "6 entries (7z)" in listing
    assert main(["-x", str(MADE / "deflate64.zip"), str(tmp_path / "out")]) == 0
    got = {p.relative_to(tmp_path / "out").as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
           for p in (tmp_path / "out").rglob("*") if p.is_file()}
    assert got == EXPECTED["deflate64.zip"]
    assert main(["--list", str(tmp_path / "missing.zip")]) == 1


def test_damaged_deflate_data_is_caught_when_the_directory_is_gone():
    """With no central directory, a Deflate member whose sizes follow its data is checked
    against the CRC stored after it, not one worked out from the (damaged) data itself."""
    class Unseekable(io.RawIOBase):
        def __init__(self):
            self.out = bytearray()

        def writable(self):
            return True

        def write(self, b):
            self.out += b
            return len(b)

    sink = Unseekable()
    body = b"the quick brown fox " * 200
    with zipfile.ZipFile(sink, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=0) as z:
        z.writestr("a.txt", body)  # level 0: stored Deflate blocks, so a changed byte still decodes
    data = bytearray(sink.out[:sink.out.find(b"PK\x01\x02")])
    at = data.find(b"quick")
    data[at] ^= 0x20  # "Quick": the stream is still valid Deflate
    with pytest.raises(PackportError, match="checksum"), packport.open(bytes(data)) as a:
        for _m, s in a.files():
            s.read()
