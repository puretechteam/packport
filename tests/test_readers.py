"""packport.open and packport.extract on the small container formats: CPIO in all three formats,
ar (GNU and BSD), .deb, .rpm, xar and .pkg, and split volumes. Archives come from libarchive
(Windows' tar.exe) where it writes the format, or are built here from the format's description;
7-Zip and libarchive read them too, and every reader has to agree with them."""

import gzip
import io
import lzma
import os
import struct
import tarfile
import zlib

import pytest
from conftest import BSDTAR, extract_7z, needs_7z, needs_bsdtar, read_tree, run

import packport
from packport import PackportError


def contents(src) -> dict:
    """{name: bytes or None for a folder} as packport reads it."""
    with packport.open(src) as a:
        out = {m.name: None for m in a.members if m.is_dir}
        out.update({m.name: s.read() for m, s in a.files()})
    return out


def files_only(tree: dict) -> dict:
    return {k: v for k, v in tree.items() if v is not None}


# ---- CPIO, every format


@needs_bsdtar
@pytest.mark.parametrize("fmt", ["newc", "odc", "bin"])
def test_cpio_formats_libarchive_writes(latin_tree, tmp_path, fmt):
    run(BSDTAR, "--format", fmt, "--options", "hdrcharset=UTF-8", "-cf", tmp_path / "a.cpio", "-C", latin_tree, ".")
    assert packport.detect(tmp_path / "a.cpio") == "cpio"
    got = {k.removeprefix("./"): v for k, v in contents(tmp_path / "a.cpio").items() if k != "."}
    assert got == read_tree(latin_tree)
    assert {m.name.removeprefix("./"): m.data for m in packport.read_cpio(tmp_path / "a.cpio")
            if not m.is_dir and m.name != "."} == files_only(read_tree(latin_tree))


def test_big_endian_old_binary_cpio():
    # two members and the trailer, as a big-endian machine wrote them (libarchive writes little-endian)
    def member(name: bytes, data: bytes, mode: int) -> bytes:
        n = name + b"\0"
        head = struct.pack(">13H", 0o070707, 1, 7, mode, 0, 0, 1, 0, 0x3A, 0x1234, len(n), len(data) >> 16,
                           len(data) & 0xFFFF)
        return head + n + bytes(len(n) % 2) + data + bytes(len(data) % 2)
    raw = member(b"dir", b"", 0o040755) + member(b"dir/odd.txt", b"odd!!", 0o100644) + member(b"TRAILER!!!", b"", 0)
    assert contents(raw) == {"dir": None, "dir/odd.txt": b"odd!!"}
    with packport.open(raw) as a:
        assert a.members[1].mtime == 0x3A1234


@needs_7z
@needs_bsdtar
def test_odc_writer_reads_back_everywhere(latin_tree, tmp_path):
    packport.write_cpio(tmp_path / "ours.cpio", packport.tree(latin_tree), fmt="odc")
    assert (tmp_path / "ours.cpio").read_bytes()[:6] == b"070707"
    expected = read_tree(latin_tree)
    assert contents(tmp_path / "ours.cpio") == expected
    assert read_tree(extract_7z(tmp_path / "ours.cpio", tmp_path / "7z")) == expected
    from conftest import extract_bsdtar
    assert read_tree(extract_bsdtar(tmp_path / "ours.cpio", tmp_path / "bsd", "--options", "hdrcharset=UTF-8")) == expected


def test_cpio_symlinks_and_hard_links():
    def newc(name, data, mode, ino, nlink):
        n = name.encode() + b"\0"
        fields = (ino, mode, 0, 0, nlink, 0, len(data), 0, 0, 0, 0, len(n), 0)
        head = b"070701" + b"".join(b"%08X" % f for f in fields) + n
        return head + bytes(-len(head) % 4) + data + bytes(-len(data) % 4)
    raw = (newc("a", b"", 0o100644, 5, 2) + newc("b", b"shared", 0o100644, 5, 2)
           + newc("link", b"b", 0o120777, 6, 1) + newc("TRAILER!!!", b"", 0, 0, 1))
    with packport.open(raw) as a:
        assert [(m.name, m.link) for m in a.members] == [("a", None), ("b", None), ("link", "b")]
        assert {m.name: s.read() for m, s in a.files()} == {"a": b"shared", "b": b"shared"}


# ---- ar and .deb


def _gnu_ar(members: dict) -> bytes:
    """GNU ar with a // long-name table, the way GNU ar (binutils) writes one."""
    table, refs = b"", {}
    for name in members:
        if len(name) > 15:
            refs[name] = len(table)
            table += name.encode() + b"/\n"
    out = b"!<arch>\n"

    def header(name: bytes, size: int) -> bytes:
        return name.ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"100644".ljust(8) + \
            str(size).encode().ljust(10) + b"`\n"
    if table:
        out += header(b"//", len(table)) + table + b"\n" * (len(table) % 2)
    for name, data in members.items():
        field = f"/{refs[name]}".encode() if name in refs else name.encode() + b"/"
        out += header(field, len(data)) + data + b"\n" * (len(data) % 2)
    return out


def test_gnu_ar_with_long_names():
    members = {"short.o": b"abc", "a_rather_long_member_name.o": b"x" * 7, "another_long_member_name.o": b""}
    assert packport.detect(_gnu_ar(members)) == "ar"
    assert contents(_gnu_ar(members)) == members


@needs_7z
@needs_bsdtar
@pytest.mark.parametrize("fmt", ["ar", "arbsd"])
def test_ar_libarchive_writes(tmp_path, fmt):
    folder = tmp_path / "src"
    folder.mkdir()
    files = {"a.txt": b"hello\n", "odd": b"123", "long_member_name_of_a_bsd_kind.bin": os.urandom(5000)}
    for name, data in files.items():
        (folder / name).write_bytes(data)
    run(BSDTAR, "--format", fmt, "-cf", tmp_path / "t.a", "-C", folder, *files)
    assert contents(tmp_path / "t.a") == files
    assert files_only(read_tree(extract_7z(tmp_path / "t.a", tmp_path / "7z"))) == files


def _tar(files: dict, compress) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            if data is None:
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tf.addfile(info)
            else:
                info.size, info.mode = len(data), 0o644
                tf.addfile(info, io.BytesIO(data))
    return compress(buf.getvalue())


def _deb(data_kind=".xz") -> bytes:
    control = _tar({"./": None, "./control": b"Package: demo\nVersion: 1.0\n", "./postinst": b"#!/bin/sh\n"},
                   gzip.compress)
    payload = {"./": None, "./usr/": None, "./usr/bin/": None, "./usr/bin/demo": b"\x7fELF demo",
               "./usr/share/doc/demo/README": b"read me"}
    pack = {".xz": lzma.compress, ".gz": gzip.compress, "": lambda b: b}[data_kind]
    return _gnu_ar({"debian-binary": b"2.0\n", "control.tar.gz": control, f"data.tar{data_kind}": _tar(payload, pack)})


@pytest.mark.parametrize("kind", [".xz", ".gz", ""])
def test_deb_unpacks_like_dpkg_deb(kind):
    deb = _deb(kind)
    assert packport.detect(deb) == "deb"
    got = contents(deb)
    assert files_only(got) == {"DEBIAN/control": b"Package: demo\nVersion: 1.0\n", "DEBIAN/postinst": b"#!/bin/sh\n",
                               "usr/bin/demo": b"\x7fELF demo", "usr/share/doc/demo/README": b"read me"}
    assert got["usr/bin"] is None and got["DEBIAN"] is None


# ---- RPM


def _rpm_header(tags: list[tuple[int, int, bytes, int]]) -> bytes:
    index, store = b"", b""
    for tag, kind, data, count in tags:
        index += struct.pack(">IIII", tag, kind, len(store), count)
        store += data
    return b"\x8e\xad\xe8\x01" + bytes(4) + struct.pack(">II", len(tags), len(store)) + index + store


def _rpm(payload_files: dict, compressor: str, raw: bytes | None = None) -> bytes:
    """An RPM put together from the format's description: lead, signature, header, payload (the
    files as CPIO, or raw as the payload instead)."""
    if raw is None:
        buf = io.BytesIO()
        cpio = packport.CpioWriter(buf)
        for name, data in payload_files.items():
            cpio.add(name, data, is_dir=data is None)
        cpio.close()
        raw = buf.getvalue()
    packed = {"gzip": gzip.compress, "xz": lzma.compress, "bzip2": __import__("bz2").compress}[compressor](raw)
    lead = b"\xed\xab\xee\xdb\x03\x00" + struct.pack(">hh", 0, 1) + b"demo-1.0-1".ljust(66, b"\0") + \
        struct.pack(">hh", 1, 5) + bytes(16)
    head = _rpm_header([(1000, 6, b"demo\0", 1), (1124, 6, b"cpio\0", 1), (1125, 6, compressor.encode() + b"\0", 1)])
    sig = _rpm_header([(1000, 4, struct.pack(">I", len(head) + len(packed)), 1)])  # SIZE: header and payload
    sig += bytes(-len(sig) % 8)
    return lead + sig + head + packed


@needs_7z
@needs_bsdtar
@pytest.mark.parametrize("compressor", ["gzip", "xz", "bzip2"])
def test_rpm_unpacks_like_rpm2cpio(tmp_path, compressor):
    files = {"./usr": None, "./usr/bin": None, "./usr/bin/demo": b"#!/bin/sh\necho demo\n", "./etc/demo.conf": b"x=1\n"}
    rpm = _rpm(files, compressor)
    (tmp_path / "demo.rpm").write_bytes(rpm)
    assert packport.detect(rpm) == "rpm"
    expected = {"usr/bin/demo": b"#!/bin/sh\necho demo\n", "etc/demo.conf": b"x=1\n"}
    assert files_only(contents(rpm)) == expected
    # libarchive reads the payload's files straight from the package, as packport does
    from conftest import extract_bsdtar
    assert files_only(read_tree(extract_bsdtar(tmp_path / "demo.rpm", tmp_path / "bsd"))) == expected
    # 7-Zip shows the RPM's payload as one compressed CPIO inside
    inner = list((extract_7z(tmp_path / "demo.rpm", tmp_path / "7z")).iterdir())
    assert len(inner) == 1


# ---- xar and .pkg


@needs_7z
@needs_bsdtar
def test_xar_libarchive_writes(latin_tree, tmp_path):
    run(BSDTAR, "--format", "xar", "-cf", tmp_path / "t.xar", "-C", latin_tree, ".")
    assert packport.detect(tmp_path / "t.xar") == "xar"
    expected = read_tree(latin_tree)
    # tar.exe writes names that aren't ASCII encoded twice (the UTF-8 of their UTF-8 read as Latin-1:
    # "café" is stored as "cafÃ©"), so the archive matches the source tree only on the ASCII ones;
    # test_xar_names below has the rest
    ascii_only = {k: v for k, v in files_only(expected).items() if k.isascii()}
    got = {k.removeprefix("./"): v for k, v in contents(tmp_path / "t.xar").items() if k not in (".", "")}
    assert {k: v for k, v in files_only(got).items() if k.isascii()} == ascii_only
    assert {k: v for k, v in files_only(read_tree(extract_7z(tmp_path / "t.xar", tmp_path / "7z"))).items()
            if k.isascii() and k != "[TOC].xml"} == ascii_only  # 7-Zip adds the table of contents as a file


def test_xar_names_compression_and_folders():
    import base64
    import bz2
    heap, files = b"", []
    for name, data, style, packer in (("plain.txt", b"plain", "application/octet-stream", lambda b: b),
                                      ("zlib.txt", b"zz" * 100, "application/x-gzip", zlib.compress),
                                      ("bz.txt", b"bb" * 100, "application/x-bzip2", bz2.compress),
                                      ("xz.txt", b"xx" * 100, "application/x-xz", lzma.compress)):
        packed = packer(data)
        files.append(f'<file id="{len(files) + 2}"><name>{name}</name><type>file</type><mode>0644</mode>'
                     f'<data><offset>{len(heap)}</offset><length>{len(packed)}</length><size>{len(data)}</size>'
                     f'<encoding style="{style}"/></data></file>')
        heap += packed
    encoded = base64.b64encode("日本語.txt".encode()).decode()
    files.append(f'<file id="9"><name enctype="base64">{encoded}</name><type>file</type>'
                 f'<data><offset>0</offset><length>5</length><size>5</size></data></file>')
    toc = ('<?xml version="1.0" encoding="UTF-8"?><xar><toc><file id="1"><name>café</name><type>directory</type>'
           + "".join(files) + '<file id="10"><name>lien</name><type>symlink</type><link type="file">plain.txt</link>'
           '</file></file></toc></xar>').encode()
    packed = zlib.compress(toc)
    raw = b"xar!" + struct.pack(">HHQQI", 28, 1, len(packed), len(toc), 0) + packed + heap
    got = contents(raw)
    assert got == {"café": None, "café/plain.txt": b"plain", "café/zlib.txt": b"zz" * 100,
                   "café/bz.txt": b"bb" * 100, "café/xz.txt": b"xx" * 100, "café/日本語.txt": b"plain"}
    with packport.open(raw) as a:
        assert [m.link for m in a.members if m.name.endswith("lien")] == ["plain.txt"]


@needs_bsdtar
def test_pkg_expands_its_payload_and_scripts(tmp_path):
    root = tmp_path / "pkg"
    (root / "Contents").mkdir(parents=True)
    payload_files = {"./Applications": None, "./Applications/Demo.app": None,
                     "./Applications/Demo.app/Info.plist": b"<plist/>"}
    buf = io.BytesIO()
    with packport.CpioWriter(buf, "odc") as cpio:
        for name, data in payload_files.items():
            cpio.add(name.removeprefix("./"), data, is_dir=data is None)
    (root / "Payload").write_bytes(gzip.compress(buf.getvalue()))
    scripts = io.BytesIO()
    with packport.CpioWriter(scripts, "odc") as cpio:
        cpio.add("postinstall", b"#!/bin/sh\n")
    (root / "Scripts").write_bytes(gzip.compress(scripts.getvalue()))
    (root / "PackageInfo").write_bytes(b"<pkg-info/>")
    run(BSDTAR, "--format", "xar", "-cf", tmp_path / "demo.pkg", "-C", root, "Payload", "Scripts", "PackageInfo")
    assert packport.detect(tmp_path / "demo.pkg") == "pkg"
    assert files_only(contents(tmp_path / "demo.pkg")) == {
        "Payload/Applications/Demo.app/Info.plist": b"<plist/>", "Scripts/postinstall": b"#!/bin/sh\n",
        "PackageInfo": b"<pkg-info/>"}


def _tracked_temp_files(monkeypatch) -> list:
    """Every temporary file packport makes from now on. On Windows a dropped one closes itself
    without a word, so a leak only showed as a ResourceWarning on Linux."""
    import tempfile
    made, real = [], tempfile.TemporaryFile

    def temporary_file(*args, **kwargs):
        made.append(real(*args, **kwargs))
        return made[-1]
    monkeypatch.setattr(tempfile, "TemporaryFile", temporary_file)
    return made


def _pkg(payload: bytes, style: str) -> bytes:
    """A .pkg (a xar archive) by hand: a Payload stored with the given encoding, and PackageInfo."""
    heap, files = b"", []
    for name, data, enc in (("Payload", payload, style), ("PackageInfo", b"<pkg-info/>", "application/octet-stream")):
        files.append(f'<file id="{len(files) + 1}"><name>{name}</name><type>file</type><mode>0644</mode>'
                     f'<data><offset>{len(heap)}</offset><length>{len(data)}</length><size>{len(data) * 4}</size>'
                     f'<encoding style="{enc}"/></data></file>')
        heap += data
    toc = ('<?xml version="1.0" encoding="UTF-8"?><xar><toc>' + "".join(files) + "</toc></xar>").encode()
    packed = zlib.compress(toc)
    return b"xar!" + struct.pack(">HHQQI", 28, 1, len(packed), len(toc), 0) + packed + heap


def test_a_refused_rpm_closes_its_temporary_file(monkeypatch):
    made = _tracked_temp_files(monkeypatch)
    rpm = _rpm({}, "gzip", raw=b"not a CPIO archive at all " * 20)  # the payload unpacks; what's in it is bad
    with pytest.raises(PackportError):
        packport.open(rpm)
    assert made and all(f.closed for f in made)


def test_a_refused_pkg_closes_its_temporary_files(monkeypatch):
    made = _tracked_temp_files(monkeypatch)
    pkg = _pkg(b"\xfd7zXZ\x00 damaged xz data " * 4, "application/x-xz")
    assert packport.detect(pkg) == "pkg"
    with pytest.raises(PackportError), packport.open(pkg) as a:
        for _m, s in a.files():
            s.read()
    assert made and all(f.closed for f in made)


def test_pbzx_payload():
    plain = b"pbzx payload " * 1000
    chunk = lzma.compress(plain[:6000])
    stream = b"pbzx" + struct.pack(">Q", 6000) + struct.pack(">QQ", 6000, len(chunk)) + chunk + \
        struct.pack(">QQ", 0, len(plain) - 6000) + plain[6000:]
    from packport.xar import pbzx
    assert pbzx(io.BytesIO(stream)) == plain


def test_xar_refuses_entity_declarations():
    toc = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><xar><toc>&a;</toc></xar>'
    packed = zlib.compress(toc)
    raw = b"xar!" + struct.pack(">HHQQI", 28, 1, len(packed), len(toc), 0) + packed
    with pytest.raises(PackportError, match="entities"):
        packport.open(raw)


# ---- volumes, extraction, refusals


def test_split_volumes_are_joined(tmp_path):
    buf = io.BytesIO()
    with packport.CpioWriter(buf) as cpio:
        cpio.add("big.bin", os.urandom(300_000))
    data = buf.getvalue()
    for k in range(4):
        (tmp_path / f"set.cpio.{k + 1:03d}").write_bytes(data[k * 100_000:(k + 1) * 100_000])
    got = contents(tmp_path / "set.cpio.001")
    assert got["big.bin"] == packport.read_cpio(data)[0].data


def test_extract_keeps_names_inside_and_says_what_it_renamed(tmp_path):
    raw = _gnu_ar({"CON": b"device", "a:b": b"stream", "fine.txt": b"ok"})
    renamed = []
    written = packport.extract(raw, tmp_path / "out", on_rename=lambda name, path: renamed.append((name, path.name)))
    assert sorted(p.name for p in written) == (["_CON", "a_b", "fine.txt"] if os.name == "nt" else ["CON", "a:b", "fine.txt"])
    if os.name == "nt":
        assert sorted(renamed) == [("CON", "_CON"), ("a:b", "a_b")]


def test_extract_skips_names_that_climb_out(tmp_path):
    def newc(name, data, mode):
        n = name.encode() + b"\0"
        fields = (1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(n), 0)
        head = b"070701" + b"".join(b"%08X" % f for f in fields) + n
        return head + bytes(-len(head) % 4) + data + bytes(-len(data) % 4)
    raw = newc("../evil", b"x", 0o100644) + newc("/abs/ok", b"y", 0o100644) + newc("C:/drive", b"z", 0o100644) \
        + newc("dev", b"", 0o020644) + newc("TRAILER!!!", b"", 0)
    skipped = []
    packport.extract(raw, tmp_path / "out", on_skip=skipped.append)
    assert read_tree(tmp_path / "out") == {"abs": None, "abs/ok": b"y"}
    assert sorted(skipped) == ["../evil", "C:/drive", "dev"]
    assert not (tmp_path / "evil").exists()


def test_extract_checks_the_declared_size_first(tmp_path):
    raw = _gnu_ar({"a": b"x" * 1000, "b": b"y" * 1000})
    with pytest.raises(PackportError, match="more than 1,500 bytes"):
        packport.extract(raw, tmp_path / "out", max_size=1500)
    assert not any((tmp_path / "out").iterdir())


def test_unknown_data_is_refused():
    with pytest.raises(PackportError, match="doesn't know"):
        packport.open(b"just some bytes")
    assert packport.detect(b"just some bytes") is None


def test_open_takes_a_file_object(tmp_path):
    raw = _gnu_ar({"x": b"1"})
    with packport.open(io.BytesIO(raw)) as a:
        assert a.fmt == "ar" and a.read("x") == b"1"


def test_damaged_files_raise_only_packport_error():
    import random
    rng = random.Random(7)
    samples = [_deb(), _rpm({"./a": b"abc"}, "gzip"), _gnu_ar({"name_long_enough_for_table": b"q" * 50})]
    bad = []
    for sample in samples:
        for _ in range(300):
            b = bytearray(sample)
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


def test_paths_are_relative_and_folders_listed(latin_tree, tmp_path):
    raw = _deb()
    with packport.open(raw) as a:
        assert all(not m.name.startswith("/") for m in a.members)
        assert any(m.is_dir and m.name == "usr" for m in a.members)


def test_extract_never_writes_more_than_a_member_declares(tmp_path):
    # a ZIP whose headers say 1,000 bytes for a member that unpacks to 1 MB: reading stops at the
    # declared size, so a lying header can't get past the size checks made from it
    import struct
    import zipfile
    data = bytes(range(256)) * 4096
    with zipfile.ZipFile(tmp_path / "liar.zip", "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("big.bin", data)
    raw = bytearray((tmp_path / "liar.zip").read_bytes())
    local = raw.find(b"PK\x03\x04")
    central = raw.find(b"PK\x01\x02")
    struct.pack_into("<I", raw, local + 22, 1000)    # the local header's uncompressed size
    struct.pack_into("<I", raw, central + 24, 1000)  # the central directory's
    (tmp_path / "liar.zip").write_bytes(bytes(raw))
    with pytest.raises(PackportError):
        packport.extract(tmp_path / "liar.zip", tmp_path / "out")
    written = list((tmp_path / "out").rglob("*.bin"))
    assert all(p.stat().st_size <= 1000 for p in written)
