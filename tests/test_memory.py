"""Reading keeps memory bounded: a member far bigger than the limit is unpacked a piece at a time,
in every format, never held whole (input or output). Peaks are measured with tracemalloc while the
whole archive is read in 64 KB reads. For the methods packport decodes slowly in pure Python, the
pieces are made smaller (``packport.entries.CHUNK``) so a small member shows the same thing.
tracemalloc sees Python's allocations, not those of packport-native's decoders, so CI runs this
file with PACKPORT_PURE=1 as well."""

import gc
import os
import random
import struct
import tracemalloc
import zlib

import pytest
from conftest import SEVEN_ZIP, needs_7z, run

import packport
from packport import entries

MB = 1 << 20
MAKECAB = r"C:\Windows\System32\makecab.exe"
needs_makecab = pytest.mark.skipif(os.name != "nt" or not os.path.isfile(MAKECAB), reason="makecab.exe isn't here")


def _data(n: int, seed: int = 1) -> bytes:
    """n bytes that LZ coders pack well (repeated 64 KB blocks with a changed byte in each)."""
    rng = random.Random(seed)
    block = bytearray(rng.randbytes(1 << 16))
    out = bytearray()
    while len(out) < n:
        block[rng.randrange(len(block))] = rng.randrange(256)
        out += block
    return bytes(out[:n])


def _peak(path) -> tuple[int, int]:
    """(bytes read, peak bytes allocated) reading every member of path in 64 KB reads."""
    gc.collect()
    tracemalloc.start()
    try:
        total = 0
        with packport.open(path) as archive:
            for _m, stream in archive.files():
                while chunk := stream.read(1 << 16):
                    total += len(chunk)
        return total, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def _source(tmp_path, data: bytes, name: str = "big.bin"):
    folder = tmp_path / "src"
    folder.mkdir(exist_ok=True)
    (folder / name).write_bytes(data)
    return folder / name


def _check(path, size: int, limit: int) -> None:
    total, peak = _peak(path)
    print(f"{path.name}: peak {peak / MB:.1f} MB for {size / MB:.0f} MB")
    assert total == size
    assert peak < limit, f"peak {peak / MB:.1f} MB reading a {size / MB:.0f} MB member (limit {limit / MB:.1f} MB)"


@pytest.fixture
def small_pieces(monkeypatch):
    """Decoders hand out 64 KB pieces instead of 1 MB ones."""
    monkeypatch.setattr(entries, "CHUNK", 1 << 16)


# ---- stored and C-speed methods: 64 MB members, 16 MB limit

def test_rar4_stored(tmp_path):
    src = _source(tmp_path, _data(64 * MB))
    packport.write_rar(tmp_path / "a.rar", [src])
    _check(tmp_path / "a.rar", 64 * MB, 16 * MB)


def _vint(n: int) -> bytes:
    out = bytearray()
    while True:
        out.append((n & 0x7F) | (0x80 if n > 0x7F else 0))
        n >>= 7
        if not n:
            return bytes(out)


def _rar5_header(kind: int, flags: int, body: bytes, data_size: int | None = None) -> bytes:
    fields = _vint(kind) + _vint(flags) + (_vint(data_size) if data_size is not None else b"") + body
    head = _vint(len(fields)) + fields
    return struct.pack("<I", zlib.crc32(head)) + head


def _rar5_stored(name: str, data: bytes) -> bytes:
    """A RAR 5 archive holding one stored file (the format as RARLAB documents it)."""
    file_body = (_vint(0x4) + _vint(len(data)) + _vint(0x20) + struct.pack("<I", zlib.crc32(data))
                 + _vint(0) + _vint(0) + _vint(len(name)) + name.encode())
    return (b"Rar!\x1a\x07\x01\x00" + _rar5_header(1, 0, _vint(0)) + _rar5_header(2, 2, file_body, len(data))
            + data + _rar5_header(5, 0, _vint(0)))


def test_rar5_stored(tmp_path):
    data = _data(64 * MB)
    (tmp_path / "a.rar").write_bytes(_rar5_stored("big.bin", data))
    del data
    _check(tmp_path / "a.rar", 64 * MB, 16 * MB)


@needs_7z
@pytest.mark.parametrize("method", ["Copy", "LZMA2:d=1m", "BZip2", "Deflate"])  # a small LZMA2 dictionary
def test_7z(tmp_path, method):
    src = _source(tmp_path, _data(64 * MB))
    run(SEVEN_ZIP, "a", "-t7z", f"-m0={method}", tmp_path / "a.7z", src)
    _check(tmp_path / "a.7z", 64 * MB, 16 * MB)


@needs_7z
def test_7z_bcj2(tmp_path, small_pieces):
    # four input streams and their LZMA decoders cost what they cost; what matters is that a member
    # twice the size doesn't take more
    rng = random.Random(3)
    code = b"".join(b"\x55\x8b\xec\xe8" + rng.randbytes(4) + b"\x90" * rng.randint(0, 20) for _ in range(40_000))
    peaks = []
    for size in (4 * MB, 8 * MB):
        folder = tmp_path / str(size)
        folder.mkdir()
        src = _source(folder, (code * (size // len(code) + 1))[:size], "big.exe")
        run(SEVEN_ZIP, "a", "-t7z", "-mx1", "-mf=BCJ2", folder / "a.7z", src)  # -mx1: small dictionaries
        total, peak = _peak(folder / "a.7z")
        assert total == size
        peaks.append(peak)
    assert peaks[1] - peaks[0] < MB // 2, f"peaks {peaks[0] / MB:.1f} and {peaks[1] / MB:.1f} MB"


@needs_7z
@pytest.mark.parametrize("method", ["Copy", "Deflate"])
def test_zip(tmp_path, method):
    src = _source(tmp_path, _data(64 * MB))
    run(SEVEN_ZIP, "a", "-tzip", f"-mm={method}", tmp_path / "a.zip", src)
    _check(tmp_path / "a.zip", 64 * MB, 16 * MB)


@needs_makecab
@pytest.mark.parametrize("compression", ["MSZIP", "LZX"])
def test_cab(tmp_path, compression):
    size = 64 * MB if compression == "MSZIP" else 16 * MB
    src = _source(tmp_path, _data(size))
    ddf = tmp_path / "a.ddf"
    ddf.write_text("\n".join([
        ".OPTION EXPLICIT", ".Set CabinetNameTemplate=a.cab", f".Set DiskDirectoryTemplate={tmp_path}",
        ".Set Cabinet=on", ".Set Compress=on", ".Set MaxDiskSize=0", f".Set CompressionType={compression}",
        f".Set RptFileName={tmp_path / 'r.txt'}", f".Set InfFileName={tmp_path / 'i.txt'}", f'"{src}" "big.bin"']) + "\n")
    run(MAKECAB, "/F", ddf)
    _check(tmp_path / "a.cab", size, size // 4)


@pytest.mark.parametrize("method", ["lzma", "zlib", "bzip2"])
def test_nsis_solid(tmp_path, monkeypatch, method):
    import test_nsis
    data = _data(48 * MB)
    monkeypatch.setattr(test_nsis, "FILES", {"bin/big.bin": data, "doc/small.txt": b"small"})
    (tmp_path / "setup.exe").write_bytes(test_nsis._installer(method, solid=True, unicode=True))
    del data
    _check(tmp_path / "setup.exe", 48 * MB + 5, 16 * MB)


def test_wim(tmp_path):
    src = _source(tmp_path, _data(64 * MB))
    packport.write_wim(tmp_path / "a.wim", [src])
    _check(tmp_path / "a.wim", 64 * MB, 16 * MB)


# ---- methods packport decodes in Python: small pieces, so a small member shows the same

@needs_7z
def test_zip_deflate64(tmp_path, small_pieces):
    src = _source(tmp_path, _data(4 * MB))
    run(SEVEN_ZIP, "a", "-tzip", "-mm=Deflate64", tmp_path / "a.zip", src)
    _check(tmp_path / "a.zip", 4 * MB, 1 * MB)


@needs_7z
def test_7z_deflate64(tmp_path, small_pieces):
    src = _source(tmp_path, _data(4 * MB))
    run(SEVEN_ZIP, "a", "-t7z", "-m0=Deflate64", tmp_path / "a.7z", src)
    _check(tmp_path / "a.7z", 4 * MB, 1 * MB)


# PPMd and LZH: the pure-Python decoders under tracemalloc take tens of minutes for a 1 MB
# member, so these show streaming another way: by the first 64 KB of output, under half of the
# packed data has been read (read whole first, all of it would have been)

def _text(n: int, seed: int = 2) -> bytes:
    """n bytes of word salad: it packs a few times smaller, not to nothing."""
    rng = random.Random(seed)
    words = [bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(2, 9))) for _ in range(2000)]
    out = b" ".join(rng.choice(words) for _ in range(n // 5))
    return (out * 2)[:n]


def _streams(path, size: int, monkeypatch) -> None:
    read = [0]
    real = packport.archive.Source.read_at

    def counting(self, offset, n):
        data = real(self, offset, n)
        read[0] += len(data)
        return data

    monkeypatch.setattr(packport.archive.Source, "read_at", counting)
    packed = path.stat().st_size
    with packport.open(path) as archive:
        at_open = read[0]
        for _m, stream in archive.files():
            total = len(stream.read(1 << 16))
            by_first = read[0] - at_open
            while chunk := stream.read(1 << 20):
                total += len(chunk)
    assert total == size
    assert by_first < packed / 2, f"{by_first} of {packed} packed bytes read before the first 64 KB came out"


@needs_7z
def test_7z_ppmd(tmp_path, small_pieces, monkeypatch):
    src = _source(tmp_path, _text(MB))
    run(SEVEN_ZIP, "a", "-t7z", "-m0=PPMd:mem=1m:o=4", tmp_path / "a.7z", src)
    _streams(tmp_path / "a.7z", MB, monkeypatch)


@needs_7z
def test_zip_ppmd(tmp_path, small_pieces, monkeypatch):
    src = _source(tmp_path, _text(MB))
    run(SEVEN_ZIP, "a", "-tzip", "-mm=PPMd", "-mmem=1m", "-mo=4", tmp_path / "a.zip", src)
    _streams(tmp_path / "a.zip", MB, monkeypatch)


def test_lzh(tmp_path, small_pieces, monkeypatch):
    from lzss_writer import lzh_archive
    data = _text(MB)
    (tmp_path / "a.lzh").write_bytes(lzh_archive({"big.bin": data}, "lh5"))
    _streams(tmp_path / "a.lzh", MB, monkeypatch)


# ---- the multi-gigabyte case, through packport.open (test_large.py checks other extractors)

@pytest.mark.skipif(not os.environ.get("PACKPORT_SLOW"), reason="set PACKPORT_SLOW=1 to run")
def test_5_gb_rar_member(tmp_path):
    size = 5 << 30
    src = tmp_path / "src" / "huge.bin"
    src.parent.mkdir()
    block = random.Random(9).randbytes(MB)
    with open(src, "wb") as f:
        f.writelines(block for _ in range(size // MB))
    packport.write_rar(tmp_path / "huge.rar", [src])
    src.unlink()
    _check(tmp_path / "huge.rar", size, 64 * MB)
