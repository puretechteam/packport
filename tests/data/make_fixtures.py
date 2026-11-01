"""Makes tests/data/made: 7z and ZIP archives written by 7-Zip with the methods packport reads,
over generated content (words, random bytes, and x86-like code full of CALL instructions), plus
expected.json with the SHA-256 of every file 7-Zip extracts from each.

What 7-Zip reads but doesn't write comes from the test-only encoders in tests/: ZIP's PPMd
"cut off" restore method and Shrink (ppmd8_writer.py, shrink_writer.py), and LZH and ARJ
(lzss_writer.py). 7-Zip has to extract each of those to the original bytes.

ISO images with El Torito boot images come from libarchive's ISO writer (Windows' tar.exe), and
UDF images (revisions 1.02 to 2.50, and a bridge disc with ISO 9660 and Joliet too) from
Windows' own IMAPI2 (make_udf.ps1). Disc images are kept compressed with packport's .Z (they're
mostly zeros). squashfs images (gzip, xz, zstd; LZ4 too, which 7-Zip doesn't read, compressed by
the lz4 module, the reference library) come from the test-only writer in squashfs_writer.py.

Needs 7-Zip (C:/Program Files/7-Zip/7z.exe) and tar.exe. Run it from the packport folder:
    python tests/data/make_fixtures.py
"""

import hashlib
import json
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from lzss_writer import arj_archive, lzh_archive
from ppmd8_writer import encode, zip_one
from shrink_writer import shrink
from squashfs_writer import GZIP, LZ4, XZ, ZSTD
from squashfs_writer import write as squashfs

import packport

SEVEN = "C:/Program Files/7-Zip/7z.exe"
TAR = "C:/Windows/System32/tar.exe"
OUT = Path(__file__).parent / "made"
JOBS = {
    "lzma.7z": ["-m0=LZMA"],
    "lzma2_solid_blocks.7z": ["-m0=LZMA2", "-ms=64k"],
    "ppmd_restart.7z": ["-m0=PPMd:o=32:mem=1m"],  # the model fills its memory and starts over
    "deflate64.7z": ["-m0=Deflate64"],
    "bzip2.7z": ["-m0=BZip2"],
    "bcj2.7z": ["-m0=BCJ2", "-m1=LZMA:d=1m", "-m2=LZMA:d=64k", "-m3=LZMA:d=64k", "-mb0:1", "-mb0s1:2", "-mb0s2:3"],
    "arm64_lzma2.7z": ["-m0=ARM64", "-m1=LZMA2"],
    "x86_bzip2.7z": ["-m0=BCJ", "-m1=BZip2"],
    "delta_ppmd.7z": ["-m0=Delta:4", "-m1=PPMd"],
    "header_plain.7z": ["-m0=LZMA2", "-mhc=off"],
    "deflate64.zip": ["-tzip", "-mm=Deflate64"],
    "bzip2.zip": ["-tzip", "-mm=BZip2"],
    "lzma.zip": ["-tzip", "-mm=LZMA"],
    "ppmd_restart.zip": ["-tzip", "-mm=PPMd:o=16:mem=1m"],  # the model fills its memory and starts over
    "deflate.zip": ["-tzip", "-mm=Deflate"],
}


def content(src: Path) -> None:
    rng = random.Random(7)
    words = [bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(2, 9))) for _ in range(3000)]
    (src / "sub" / "empty dir").mkdir(parents=True)
    (src / "text.txt").write_bytes(b" ".join(rng.choice(words) for _ in range(12_000)))
    (src / "random.bin").write_bytes(rng.randbytes(8_000))
    code = bytearray()
    while len(code) < 16_000:  # instructions with relative CALLs and JMPs to nearby addresses
        code += rng.randbytes(rng.randint(1, 12))
        code += bytes([rng.choice((0xE8, 0xE9))]) + rng.randrange(-4096, 4096).to_bytes(4, "little", signed=True)
    (src / "sub" / "code.bin").write_bytes(bytes(code))
    (src / "sub" / "empty.txt").write_bytes(b"")


def main() -> None:
    shutil.rmtree(OUT, ignore_errors=True)
    OUT.mkdir()
    expected = {}
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        content(src)
        for name, opts in JOBS.items():
            subprocess.run([SEVEN, "a", "-bd", str(OUT / name), *opts, str(src) + "/*"], check=True,
                           capture_output=True)
            out = Path(tmp) / name
            subprocess.run([SEVEN, "x", "-y", f"-o{out}", str(OUT / name)], check=True, capture_output=True)
            expected[name] = {p.relative_to(out).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in sorted(out.rglob("*")) if p.is_file()}
        # from the test-only encoders: 7-Zip has to read each back
        text = (src / "text.txt").read_bytes()
        for name, data, packed, method in (("ppmd_cut_off.zip", text * 3, encode(text * 3, 16, 1, 1), 98),
                                           ("shrink.zip", text, shrink(text), 1)):
            (OUT / name).write_bytes(zip_one("text.txt", data, packed, method))
            out = Path(tmp) / name
            subprocess.run([SEVEN, "x", "-y", f"-o{out}", str(OUT / name)], check=True, capture_output=True)
            assert (out / "text.txt").read_bytes() == data, f"7-Zip reads {name} differently"
            expected[name] = {"text.txt": hashlib.sha256(data).hexdigest()}
        files = {p.relative_to(src).as_posix(): p.read_bytes() for p in sorted(src.rglob("*")) if p.is_file()}
        files["one byte.txt"] = b"x"  # a block holding a single literal
        built = {f"{m}.lzh": lzh_archive(files, m) for m in ("lh5", "lh6", "lh7")}
        built.update({f"method{m}.arj": arj_archive(files, m) for m in (1, 4)})
        for name, data in built.items():
            (OUT / name).write_bytes(data)
            out = Path(tmp) / name
            subprocess.run([SEVEN, "x", "-y", f"-o{out}", str(OUT / name)], check=True, capture_output=True)
            got = {p.relative_to(out).as_posix(): p.read_bytes() for p in out.rglob("*") if p.is_file()}
            assert got == files, f"7-Zip reads {name} differently"
            expected[name] = {k: hashlib.sha256(v).hexdigest() for k, v in sorted(files.items())}
        boot = Path(tmp) / "boot"
        (boot / "docs").mkdir(parents=True)
        (boot / "docs" / "readme.txt").write_bytes(b"hello disc\n" * 100)
        (boot / "floppy.img").write_bytes(bytes([0xEB, 0x3C, 0x90]) + b"PACKPORT" + bytes(1474560 - 11))
        (boot / "loader.bin").write_bytes(bytes(range(256)) * 16)
        for name, options, image in (("eltorito_floppy.iso", "boot=floppy.img,boot-type=fd", "floppy.img"),
                                     ("eltorito_noemul.iso", "boot=loader.bin,boot-type=no-emulation,boot-load-size=4",
                                      "loader.bin")):
            iso = Path(tmp) / name
            subprocess.run([TAR, "--format", "iso9660", "--options", options, "-cf", str(iso), image, "docs"],
                           check=True, capture_output=True, cwd=boot)
            (OUT / (name + ".Z")).write_bytes(packport.compress(iso.read_bytes()))
            out = Path(tmp) / (name + ".x")
            subprocess.run([SEVEN, "x", "-y", f"-o{out}", str(iso)], check=True, capture_output=True)
            expected[name + ".Z"] = {p.relative_to(out).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                                     for p in sorted(out.rglob("*")) if p.is_file()}
        udf_src = Path(tmp) / "udf"
        (udf_src / "folder" / "deeper folder").mkdir(parents=True)
        (udf_src / "readme.txt").write_bytes(b"hello udf " * 300)
        (udf_src / "folder" / "random.bin").write_bytes(random.Random(4).randbytes(20_000))
        long_name = "a file with a long name, accents éè and more than sixty-four characters.txt"
        (udf_src / "folder" / "deeper folder" / long_name).write_bytes(b"x" * 5000)
        (udf_src / "folder" / "empty.txt").write_bytes(b"")
        (udf_src / "日本語.txt").write_bytes("テキスト".encode() * 100)
        udf_out = Path(tmp) / "udf_out"
        udf_out.mkdir()
        subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                        str(Path(__file__).parent / "make_udf.ps1"), "-Source", str(udf_src), "-OutDir", str(udf_out)],
                       check=True, capture_output=True)
        for iso in sorted(udf_out.glob("*.iso")):
            (OUT / (iso.name + ".Z")).write_bytes(packport.compress(iso.read_bytes()))
            out = Path(tmp) / (iso.name + ".x")
            subprocess.run([SEVEN, "x", "-y", f"-o{out}", str(iso)], check=True, capture_output=True)
            expected[iso.name + ".Z"] = {p.relative_to(out).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                                         for p in sorted(out.rglob("*")) if p.is_file()}
        rng = random.Random(9)
        sq_files = {"text.txt": (src / "text.txt").read_bytes(), "sub/random.bin": rng.randbytes(9000),
                    "sub/holes.bin": b"start" + bytes(20000) + b"end" * 2000, "sub/empty dir": None, "tiny.txt": b"x",
                    **{f"many/file_{k:03d}.txt": f"file {k}".encode() * k for k in range(300)}}
        sq_want = {k: v for k, v in sq_files.items() if v is not None}
        for comp, name in ((GZIP, "gzip.sqfs"), (XZ, "xz.sqfs"), (ZSTD, "zstd.sqfs"), (LZ4, "lz4.sqfs")):
            (OUT / name).write_bytes(squashfs(sq_files, comp))
            if comp != LZ4:
                out = Path(tmp) / name
                subprocess.run([SEVEN, "x", "-y", f"-o{out}", str(OUT / name)], check=True, capture_output=True)
                got = {p.relative_to(out).as_posix(): p.read_bytes() for p in out.rglob("*") if p.is_file()}
                assert got == sq_want, f"7-Zip reads {name} differently"
            expected[name] = {k: hashlib.sha256(v).hexdigest() for k, v in sorted(sq_want.items())}
    (OUT / "expected.json").write_text(json.dumps(expected, indent=1) + "\n", encoding="utf-8")
    print(len(expected), "archives,", sum(p.stat().st_size for p in OUT.iterdir()), "bytes")


if __name__ == "__main__":
    main()
