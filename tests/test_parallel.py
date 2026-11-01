"""Decoding ahead in threads (parallel.py) changes nothing but the time: the same files, the same
bytes, in the same order, with one thread and with several; and damage in one file still comes
out at that file, after the ones before it."""

import hashlib
import random
from pathlib import Path

import pytest
from conftest import SEVEN_ZIP, needs_7z, run

import packport
from packport import PackportError, parallel

LIBARCHIVE = Path(__file__).parent / "data" / "libarchive"


def _read(src) -> list:
    with packport.open(src) as a:
        return [(m.name, hashlib.sha256(s.read()).hexdigest()) for m, s in a.files()]


def _both(src, monkeypatch) -> tuple[list, list]:
    monkeypatch.setenv("PACKPORT_THREADS", "1")
    one = _read(src)
    monkeypatch.setenv("PACKPORT_THREADS", "8")
    return one, _read(src)


@needs_7z
def test_7z_folders(tmp_path, monkeypatch):
    rng = random.Random(4)
    src = tmp_path / "src"
    src.mkdir()
    for k in range(20):
        (src / f"f{k:02d}.bin").write_bytes(rng.randbytes(1000) * rng.randint(50, 400))
    run(SEVEN_ZIP, "a", "-t7z", "-ms=off", tmp_path / "a.7z", str(src) + "/*")  # a folder per file
    one, many = _both(tmp_path / "a.7z", monkeypatch)
    assert len(one) == 20 and one == many


@pytest.mark.parametrize("name", ["test_read_format_rar5_multiple_files.rar", "test_read_format_rar_noeof.rar",
                                  "test_read_format_rar_unicode.rar"])
def test_non_solid_rar(name, monkeypatch):
    if not (LIBARCHIVE / name).is_file():
        pytest.skip(f"{name} isn't in tests/data/libarchive")
    one, many = _both(LIBARCHIVE / name, monkeypatch)
    assert one == many and len(one) >= 1


def test_wim(tmp_path, monkeypatch):
    rng = random.Random(6)
    src = tmp_path / "src"
    src.mkdir()
    for k in range(10):
        (src / f"f{k}.bin").write_bytes(rng.randbytes(rng.randint(1, 300_000)))
    packport.write_wim(tmp_path / "a.wim", packport.tree(src))
    one, many = _both(tmp_path / "a.wim", monkeypatch)
    assert one == many and len(one) == 10


@needs_7z
def test_damage_comes_out_at_its_file(tmp_path, monkeypatch):
    rng = random.Random(8)
    src = tmp_path / "src"
    src.mkdir()
    for k in range(9):
        (src / f"f{k}.txt").write_bytes(b" ".join(rng.randbytes(3).hex().encode() for _ in range(20_000)))
    run(SEVEN_ZIP, "a", "-t7z", "-ms=off", tmp_path / "a.7z", str(src) + "/*")
    with packport.open(tmp_path / "a.7z") as a:
        middle = sorted((m for m in a.members if m.is_file), key=lambda m: m.name)[4]
    data = bytearray((tmp_path / "a.7z").read_bytes())
    # damage the middle file's packed data (7z keeps folders in order from offset 32)
    folder = middle.ref[0]
    with packport.open(bytes(data)) as a:
        pos, size = a.packs[folder]
    data[pos + size // 2] ^= 0xFF
    monkeypatch.setenv("PACKPORT_THREADS", "8")
    got = []
    with pytest.raises(PackportError), packport.open(bytes(data)) as a:
        for m, s in a.files():
            s.read()
            got.append(m.name)
    assert middle.name not in got and len(got) == sum(1 for m in a.members if m.is_file and m.ref[0] < folder)


def test_threads_setting(monkeypatch):
    monkeypatch.setenv("PACKPORT_THREADS", "3")
    assert parallel.threads() == 3
    monkeypatch.setenv("PACKPORT_THREADS", "x")
    assert 1 <= parallel.threads() <= 8
    assert list(parallel.ordered([lambda k=k: k * k for k in range(50)], ahead=4)) == [k * k for k in range(50)]


def test_streamed_keeps_order_and_raises_where_it_happened():
    import threading

    from packport.parallel import streamed

    seen = []

    def chunks():
        for k in range(10):
            seen.append(threading.current_thread().name)
            yield k
        raise PackportError("damaged after 10")

    got = []
    with pytest.raises(PackportError, match="after 10"):
        got.extend(streamed(chunks()))  # what came before the damage stays in got
    assert got == list(range(10))
    assert set(seen) == {"packport-stream"}


def test_streamed_stops_its_thread_when_the_reader_stops():
    import threading

    from packport.parallel import streamed

    closed = threading.Event()

    def endless():
        try:
            while True:
                yield b"x" * 1000
        finally:
            closed.set()

    it = streamed(endless())
    assert next(it) == b"x" * 1000
    it.close()
    assert closed.wait(5)
    assert not [t for t in threading.enumerate() if t.name == "packport-stream"]


def test_streamed_with_one_thread_is_the_same_iterator(monkeypatch):
    from packport.parallel import streamed

    monkeypatch.setenv("PACKPORT_THREADS", "1")
    assert list(streamed(iter([1, 2, 3]))) == [1, 2, 3]
