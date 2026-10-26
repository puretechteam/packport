"""Damaged or hostile archives must only ever raise PackportError, never crash or hang; and
randomly generated trees must come back exactly as they went in."""

import io
import random
import tarfile

import pytest
from conftest import (
    MTIME,
    extract_7z,
    extract_bsdtar,
    make_tree,
    needs_7z,
    needs_bsdtar,
    read_tree,
)
from test_lzw import PAYLOADS

import packport
from packport import PackportError


def _samples(tmp_path):
    root = make_tree(tmp_path / "src")
    packport.write_rar(tmp_path / "s.rar", packport.tree(root))
    packport.write_cpio(tmp_path / "s.cpio", packport.tree(root))
    return {
        "rar": (tmp_path / "s.rar").read_bytes(),
        "cpio": (tmp_path / "s.cpio").read_bytes(),
        "z": packport.compress(PAYLOADS["text, then noise, then text"][:200_000]),
    }


READERS = {"rar": packport.read_rar, "cpio": packport.read_cpio,
           "z": lambda data: packport.decompress(data, max_size=50_000_000)}


@pytest.mark.parametrize("kind", READERS)
def test_corrupted_archives_raise_packport_error(tmp_path, kind):
    data = _samples(tmp_path)[kind]
    rng = random.Random(kind)
    for _ in range(300):
        b = bytearray(data)
        for _ in range(rng.randint(1, 8)):
            b[rng.randrange(len(b))] = rng.randrange(256)
        if rng.random() < 0.2:
            b = b[:rng.randrange(len(b))]
        try:
            READERS[kind](bytes(b))
        except PackportError:
            pass


@pytest.mark.parametrize("kind", READERS)
def test_truncated_archives_raise_packport_error(tmp_path, kind):
    data = _samples(tmp_path)[kind]
    for cut in range(0, len(data), max(1, len(data) // 400)):
        try:
            READERS[kind](data[:cut])
        except PackportError:
            pass


def test_random_bytes_raise_packport_error():
    rng = random.Random(9)
    for _ in range(300):
        junk = rng.randbytes(rng.randint(0, 400))
        for prefix in (b"", b"Rar!\x1a\x07\x00", b"070701", b"\x1f\x9d\x90"):
            for read in READERS.values():
                try:
                    read(prefix + junk)
                except PackportError:
                    pass


def test_dot_z_bomb_is_capped():
    bomb = packport.compress(bytes(20_000_000))
    with pytest.raises(PackportError, match="more than"):
        packport.decompress(bomb, max_size=1_000_000)


def test_rar_header_crc_is_checked(tmp_path):
    data = bytearray(_samples(tmp_path)["rar"])
    data[30] ^= 0xFF  # inside the first file header
    with pytest.raises(PackportError, match="checksum"):
        packport.read_rar(bytes(data))


def test_rar_data_crc_is_checked():
    out = io.BytesIO()
    with packport.RarWriter(out) as rar:
        rar.add("a.txt", b"hello")
    data = bytearray(out.getvalue())
    data[20 + 37] ^= 1  # first data byte
    with pytest.raises(PackportError, match="checksum"):
        packport.read_rar(bytes(data))


# ---------------------------------------------------------------- random trees

UNICODE_POOL = "abcdefghijklmnopqrstuvwxyz0123456789 -_.éñüøå日本語中文ひらがなκόσμε😀🎉"
LATIN_POOL = "abcdefghijklmnopqrstuvwxyz0123456789 -_éñüøåç"


def random_tree(rng: random.Random, pool: str, depth: int = 0) -> list:
    """[(name, bytes | None)], names unique ignoring case (Windows folders are case-insensitive)."""
    out, used = [], set()
    for _ in range(rng.randint(0, 6 if depth < 3 else 0) or 1):
        name = "".join(rng.choice(pool) for _ in range(rng.randint(1, 12))).strip(" .") or "x"
        if name.casefold() in used:
            continue
        used.add(name.casefold())
        if rng.random() < 0.3 and depth < 3:
            out.append((name, None))
            out += [(f"{name}/{n}", d) for n, d in random_tree(rng, pool, depth + 1)]
        else:
            size = rng.choice([0, 1, 3, 4, 5, rng.randint(0, 5000), rng.randint(0, 70000)])
            out.append((name, rng.randbytes(size)))
    return out


def as_dict(items) -> dict:
    return {n: d for n, d in items}


def tar_z_members(data: bytes) -> dict:
    out = {}
    with tarfile.open(fileobj=io.BytesIO(packport.decompress(data))) as tf:
        for m in tf:
            out[m.name] = None if m.isdir() else tf.extractfile(m).read()
    return out


@pytest.mark.parametrize("seed", range(30))
def test_random_trees_round_trip(seed):
    rng = random.Random(seed)
    items = random_tree(rng, UNICODE_POOL)
    entries = [packport.Entry(n, d, mtime=MTIME + 2 * i) for i, (n, d) in enumerate(items)]
    for write, read in [(packport.write_rar, packport.read_rar), (packport.write_cpio, packport.read_cpio)]:
        out = io.BytesIO()
        write(out, entries)
        back = read(out.getvalue())
        assert [(m.name, None if m.is_dir else m.data) for m in back] == items
        if write is packport.write_cpio:
            assert [m.mtime for m in back] == [e.mtime for e in entries]
    out = io.BytesIO()
    packport.write_tar_z(out, entries)
    assert tar_z_members(out.getvalue()) == as_dict(items)


@needs_7z
@pytest.mark.parametrize("seed", range(5))
def test_random_trees_extract_with_7zip(tmp_path, seed):
    items = random_tree(random.Random(100 + seed), UNICODE_POOL)
    for fmt, write in [("rar", packport.write_rar), ("cpio", packport.write_cpio)]:
        write(tmp_path / f"r.{fmt}", items)
        assert read_tree(extract_7z(tmp_path / f"r.{fmt}", tmp_path / fmt)) == as_dict(items)


@needs_bsdtar
@pytest.mark.parametrize("seed", range(5))
def test_random_trees_extract_with_bsdtar(tmp_path, seed):
    items = random_tree(random.Random(200 + seed), LATIN_POOL)
    for fmt, write, opts in [("rar", packport.write_rar, []),
                             ("cpio", packport.write_cpio, ["--options", "hdrcharset=UTF-8"]),
                             ("tar.Z", packport.write_tar_z, [])]:
        write(tmp_path / f"r.{fmt}", items)
        assert read_tree(extract_bsdtar(tmp_path / f"r.{fmt}", tmp_path / fmt, *opts)) == as_dict(items)
