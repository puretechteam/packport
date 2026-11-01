"""Reading compressed RAR (RAR 5: LZ, filters, solid, volumes, BLAKE2sp; RAR 2.9-4.x: LZ, PPMd,
RAR's standard filters, solid, volumes), CAB, 7z (every coder and filter), ZIP (every method
packport reads, ZIP64, odd layouts) and LZH (header levels 0-2, -lh0-, -lh5- to -lh7-), on
libarchive's own test archives (data/libarchive, under
libarchive's license, COPYING-libarchive.txt). expected.json holds the SHA-256 of every file
7-Zip extracts from each; packport has to give the same bytes."""

import hashlib
import json
from pathlib import Path

import pytest
from conftest import SEVEN_ZIP, needs_7z, run, zstd_marked

import packport
from packport import PackportError

DATA = Path(__file__).parent / "data" / "libarchive"
EXPECTED = json.loads((DATA / "expected.json").read_text(encoding="utf-8"))

# where packport and 7-Zip part ways on purpose: what 7-Zip makes of a member, and why packport doesn't
DIFFERENT = {
    # a symbolic link: 7-Zip writes a file holding the target, packport (like extract_cpio) leaves links out
    "testlink", "testdir/testsymlink5", "testdir/testsymlink6", "testsymlink", "testsymlink2", "testsymlink3",
    "testsymlink4", "表だよ/ファイル",
    # a name stored without RAR's Unicode flag in UTF-8: 7-Zip reads it in the DOS code page, packport as UTF-8
    "abcdefghijklmnopqrsπâåπé╣πâê.txt",
    # symbolic links in 7z and ZIP archives
    "symlink", "symlinkfile", "libxkbcommon-x11.so", "libxkbcommon-x11.so.0",
    "_installdir/abc_tools/2000.9-beta11/bin/abc_measurement_analysis_sample",
}
OURS_ONLY = {
    "abcdefghijklmnopqrsテスト.txt",  # the same file as the one above, named as it was meant
    "ПРИВЕТ",  # next to "привет": 7-Zip writes both to one file on Windows, where case doesn't count
}


# names 7-Zip turns into DOS code page mojibake or underscores, and what they are: Shift_JIS and
# UTF-16 names in LZH archives
RENAMED = {
    "test_read_format_lha_filename_cp932.lzh": {"è┐ÄÜ.txt": "漢字.txt", "ò/.txt": "表.txt"},
    "test_read_format_lha_filename_utf16.lzh": {
        "______.txt": "äöüÄÖÜ.txt", "______/______.txt": "ÜÖÄüöä/äöüÄÖÜ.txt",
        "______/âeâXâg.txt": "ÜÖÄüöä/テスト.txt", "âeâXâg/______.txt": "テスト/äöüÄÖÜ.txt"},
}


def _named_like_packport(name: str) -> str:
    """7-Zip shows a ZIP name's bytes that aren't UTF-8 as U+EF80-U+EFFF; packport reads such a
    name in the DOS code page, as zipfile does."""
    if not any(0xEF80 <= ord(c) < 0xF000 for c in name):
        return name
    raw = b"".join(bytes([ord(c) - 0xEF00]) if 0xEF80 <= ord(c) < 0xF000 else c.encode() for c in name)
    return raw.decode("cp437")


def _hashes(path: Path) -> dict:
    with packport.open(path) as a:
        return {m.name: hashlib.sha256(s.read()).hexdigest() for m, s in a.files()}


@pytest.mark.parametrize("name", zstd_marked(sorted(EXPECTED)))
def test_same_files_as_7zip(name):
    ours = _hashes(DATA / name)
    renamed = RENAMED.get(name, {})
    theirs = {renamed.get(k, _named_like_packport(k)): v for k, v in EXPECTED[name].items() if k not in DIFFERENT}
    assert {k: v for k, v in ours.items() if k not in OURS_ONLY} == theirs


def test_lzh_header_level_3():
    # 7-Zip doesn't read level 3; it holds the same two files as the level 0 archive
    assert _hashes(DATA / "test_read_format_lha_header3.lzh") == EXPECTED["test_read_format_lha_header0.lzh"]


@pytest.mark.parametrize("name", ["test_read_format_lha_oversize_header.lzh", "test_fuzz.lzh"])
def test_hostile_lzh_headers_are_refused_or_skipped(name):
    # a header claiming 4 GB, and libarchive's fuzzed archive: only PackportError, or files whose CRC checks
    try:
        _hashes(DATA / name)
    except PackportError:
        pass


def test_formats_are_told_apart():
    assert packport.detect(DATA / "test_read_format_lha_lh6.lzh") == "lzh"
    assert packport.detect(DATA / "test_read_format_rar5_compressed.rar") == "rar5"
    assert packport.detect(DATA / "test_read_format_rar_compress_best.rar") == "rar"
    assert packport.detect(DATA / "test_read_format_rar_sfx.exe") == "rar"  # self-extracting


@pytest.mark.parametrize("volume", ["part01", "part05", "part08"])
def test_a_rar5_set_opens_from_any_volume(volume):
    first = _hashes(DATA / "test_read_format_rar5_multiarchive.part01.rar")
    assert _hashes(DATA / f"test_read_format_rar5_multiarchive.{volume}.rar") == first


def test_a_missing_volume_is_reported(tmp_path):
    for k in (1, 2, 3):  # the set without its last volume
        src = DATA / f"test_read_format_rar_multivolume.part{k:04d}.rar"
        (tmp_path / src.name).write_bytes(src.read_bytes())
    with pytest.raises(PackportError, match="isn't there|cut short"):
        _hashes(tmp_path / "test_read_format_rar_multivolume.part0001.rar")


def test_ppmd_and_lz_blocks_in_one_file():
    # RAR switches between PPMd and LZ inside this file; 241 MB of output
    ours = _hashes(DATA / "test_read_format_rar_ppmd_lzss_conversion.rar")
    assert ours == EXPECTED["test_read_format_rar_ppmd_lzss_conversion.rar"]


def test_damaged_rar_raises_only_packport_error():
    import random
    rng = random.Random(3)
    bad = []
    for name in ("test_read_format_rar5_compressed.rar", "test_read_format_rar_compress_normal.rar",
                 "test_read_format_rar_filter.rar", "test_read_format_rar5_arm.rar"):
        data = (DATA / name).read_bytes()
        for _ in range(60):
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
                bad.append(f"{name}: {type(e).__name__}: {e}")
    assert bad == []


@needs_7z
@pytest.mark.parametrize("name", ["test_read_format_rar5_solid.rar", "test_read_format_rar_filter.rar"])
def test_7zip_agrees_today(tmp_path, name):
    run(SEVEN_ZIP, "x", "-y", f"-o{tmp_path}", DATA / name)
    theirs = {p.relative_to(tmp_path).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in tmp_path.rglob("*") if p.is_file()}
    assert _hashes(DATA / name) == theirs


@pytest.mark.parametrize("name", ["test_read_format_lha_lh6.lzh", "test_read_format_lha_lh7.lzh",
                                  "test_read_format_lha_header1.lzh", "test_read_format_lha_header2.lzh",
                                  "test_read_format_lha_filename_utf16.lzh"])
def test_damaged_lzh_raises_only_packport_error(name):
    import random
    rng = random.Random(name)
    data = (DATA / name).read_bytes()
    bad = []
    for _ in range(150):
        b = bytearray(data)
        for _ in range(rng.randint(1, 6)):
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
