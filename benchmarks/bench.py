"""Extraction speed: 7-Zip against packport, with its Python decoders and with packport-native.

    python benchmarks/bench.py WORK [--runs 3] [--only NAME ...]

Builds its archives in WORK/fixtures (once; deterministic data) with the tools there are: 7-Zip
(7z, ZIP), makecab (CAB), Windows' IMAPI2 (UDF), packport (stored RAR, WIM) and the test-only
writers (squashfs, LZH), plus libarchive's big RAR 4 test from tests/data. Every archive is then
extracted to WORK/out by each tool, best of --runs: 7-Zip as ConvertAll 1.2 ran it (a process
per archive, `7z x`), packport in a process of its own that times packport.extract (so its start
is left out, as an app that has it loaded would see it), with PACKPORT_PURE=1 for the Python
decoders. PACKPORT_NSIS_SAMPLE adds a row for that NSIS installer. Prints a Markdown table.
Runs one archive at a time; packport-native uses up to 8 threads (PACKPORT_THREADS)."""

from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SEVEN_ZIP = shutil.which("7z") or r"C:\Program Files\7-Zip\7z.exe"
MAKECAB = r"C:\Windows\System32\makecab.exe"
MB = 1 << 20


def text(n: int, seed: int = 1) -> bytes:
    rng = random.Random(seed)
    words = [bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(2, 10))) for _ in range(5000)]
    lines = []
    size = 0
    while size < n:
        line = b" ".join(rng.choice(words) for _ in range(rng.randint(5, 15))) + b".\n"
        lines.append(line)
        size += len(line)
    return b"".join(lines)[:n]


def code(n: int, seed: int = 2) -> bytes:
    rng = random.Random(seed)
    out = bytearray()
    while len(out) < n:
        out += b"\x55\x8b\xec" + rng.choice([b"\xe8", b"\xe9", b"\x0f\x84"]) + rng.randbytes(4) + rng.randbytes(rng.randint(0, 24))
    return bytes(out[:n])


def folder(where: Path, files: dict) -> Path:
    shutil.rmtree(where, ignore_errors=True)
    where.mkdir(parents=True)
    for name, data in files.items():
        (where / name).parent.mkdir(parents=True, exist_ok=True)
        (where / name).write_bytes(data)
    return where


def run(*args) -> None:
    subprocess.run([str(a) for a in args], check=True, capture_output=True)


def fixtures(work: Path) -> dict[str, Path]:
    """name -> archive, built once."""
    fx = work / "fixtures"
    fx.mkdir(parents=True, exist_ok=True)
    src = work / "src"
    out: dict[str, Path] = {}

    def make(name: str, build):
        path = fx / name
        if not path.exists():
            build(path)
        out[name] = path

    t64 = text(64 * MB)
    sevenz = Path(SEVEN_ZIP).is_file()
    if sevenz:
        make("7z-lzma2.7z", lambda p: run(SEVEN_ZIP, "a", "-t7z", "-m0=LZMA2", p,
                                          folder(src / "lzma2", {"text.txt": t64}) / "text.txt"))
        make("7z-lzma2-folders.7z", lambda p: run(SEVEN_ZIP, "a", "-t7z", "-ms=off", "-m0=LZMA2", p, str(folder(
            src / "folders", {f"part{k:02d}.txt": t64[k * 2 * MB:(k + 1) * 2 * MB] for k in range(32)})) + "/*"))
        make("7z-bcj2.7z", lambda p: run(SEVEN_ZIP, "a", "-t7z", "-mf=BCJ2", p,
                                         folder(src / "bcj2", {"program.exe": code(16 * MB)}) / "program.exe"))
        make("7z-ppmd.7z", lambda p: run(SEVEN_ZIP, "a", "-t7z", "-m0=PPMd", p,
                                         folder(src / "ppmd", {"text.txt": t64[:6 * MB]}) / "text.txt"))
        make("7z-deflate64.7z", lambda p: run(SEVEN_ZIP, "a", "-t7z", "-m0=Deflate64", p,
                                              folder(src / "d64", {"text.txt": t64[:16 * MB]}) / "text.txt"))
        make("zip-deflate64.zip", lambda p: run(SEVEN_ZIP, "a", "-tzip", "-mm=Deflate64", p,
                                                folder(src / "d64z", {"text.txt": t64[:16 * MB]}) / "text.txt"))
        make("zip-ppmd.zip", lambda p: run(SEVEN_ZIP, "a", "-tzip", "-mm=PPMd", p,
                                           folder(src / "ppmdz", {"text.txt": t64[:6 * MB]}) / "text.txt"))
        make("zip-bzip2.zip", lambda p: run(SEVEN_ZIP, "a", "-tzip", "-mm=BZip2", p,
                                            folder(src / "bz", {"text.txt": t64[:32 * MB]}) / "text.txt"))
    if Path(MAKECAB).is_file():
        for kind in ("LZX", "MSZIP"):
            def cab(p, kind=kind):
                s = folder(src / f"cab-{kind}", {"text.txt": t64[:32 * MB]})
                ddf = s / "a.ddf"
                ddf.write_text("\n".join([
                    ".OPTION EXPLICIT", f".Set CabinetNameTemplate={p.name}", f".Set DiskDirectoryTemplate={p.parent}",
                    ".Set Cabinet=on", ".Set Compress=on", ".Set MaxDiskSize=0", f".Set CompressionType={kind}",
                    ".Set CompressionMemory=21", f".Set RptFileName={s / 'r.txt'}", f".Set InfFileName={s / 'i.txt'}",
                    f'"{s / "text.txt"}" "text.txt"']) + "\n")
                run(MAKECAB, "/F", ddf)
            make(f"cab-{kind.lower()}.cab", cab)
    sys.path.insert(0, str(ROOT / "src"))
    sys.path.insert(0, str(ROOT / "tests"))
    import packport
    rng = random.Random(3)
    pages = {f"page{k:03d}.jpg": b"\xff\xd8\xff\xe0" + rng.randbytes(rng.randint(400_000, 1_200_000)) for k in range(64)}
    make("cbr-stored.cbr", lambda p: packport.write_rar(p, packport.tree(folder(src / "pages", pages))))
    make("wim-stored.wim", lambda p: packport.write_wim(p, packport.tree(folder(src / "wim", {
        f"f{k:02d}.bin": t64[k * 2 * MB:(k + 1) * 2 * MB] for k in range(32)}))))
    import squashfs_writer
    for name, comp in (("gzip", 1), ("xz", 4), ("zstd", 6)):
        if name == "zstd":
            try:
                from backports import zstd
            except ImportError:
                try:
                    from compression import zstd  # noqa: F401
                except ImportError:
                    continue
        make(f"squashfs-{name}.sqfs", lambda p, comp=comp: p.write_bytes(squashfs_writer.write(
            {"text.txt": t64[:32 * MB]}, comp, block_size=1 << 17)))
    from lzss_writer import lzh_archive
    make("lzh-lh5.lzh", lambda p: p.write_bytes(lzh_archive({"text.txt": t64[:4 * MB]}, "lh5")))
    if os.name == "nt":
        udf = fx / "udf250.iso"
        if not udf.exists():
            s = folder(src / "udf", {f"f{k:02d}.bin": t64[k * 4 * MB:(k + 1) * 4 * MB] for k in range(16)})
            (src / "udfout").mkdir(parents=True, exist_ok=True)
            run("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ROOT / "tests" / "data" / "make_udf.ps1",
                "-Source", s, "-OutDir", src / "udfout")
            shutil.copyfile(src / "udfout" / "udf250.iso", udf)
        out["udf250.iso"] = udf
    rar4 = ROOT / "tests" / "data" / "libarchive" / "test_read_format_rar_ppmd_lzss_conversion.rar"
    if rar4.is_file():
        out["rar4-lz-ppmd (libarchive).rar"] = rar4
    nsis = os.environ.get("PACKPORT_NSIS_SAMPLE")
    if nsis and Path(nsis).is_file():
        out["nsis (" + Path(nsis).name + ")"] = Path(nsis)
    shutil.rmtree(src, ignore_errors=True)
    return out


CHILD = r"""
import json, shutil, sys, time
from pathlib import Path
import packport
src, dest, runs = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
best = None
for _ in range(runs):
    shutil.rmtree(dest, ignore_errors=True)
    t = time.perf_counter()
    packport.extract(src, dest)
    dt = time.perf_counter() - t
    best = dt if best is None else min(best, dt)
size = sum(p.stat().st_size for p in dest.rglob("*") if p.is_file())
shutil.rmtree(dest, ignore_errors=True)
print(json.dumps({"seconds": best, "bytes": size, "native": packport.accelerated()}))
"""


def time_packport(src: Path, dest: Path, runs: int, pure: bool) -> dict:
    env = dict(os.environ)
    env.pop("PACKPORT_PURE", None)
    if pure:
        env["PACKPORT_PURE"] = "1"
    r = subprocess.run([sys.executable, "-c", CHILD, str(src), str(dest), str(runs)], env=env, capture_output=True,
                       text=True, check=True)
    return json.loads(r.stdout.strip().splitlines()[-1])


def time_7zip(src: Path, dest: Path, runs: int) -> float:
    best = None
    for _ in range(runs):
        shutil.rmtree(dest, ignore_errors=True)
        t = time.perf_counter()
        subprocess.run([SEVEN_ZIP, "x", "-y", "-bd", f"-o{dest}", str(src)], capture_output=True, check=False)
        dt = time.perf_counter() - t
        best = dt if best is None else min(best, dt)
    shutil.rmtree(dest, ignore_errors=True)
    return best


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("work", type=Path)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--pure-runs", type=int, default=1, help="runs for the Python decoders (slow on PPMd)")
    a = ap.parse_args()
    rows = []
    for name, path in fixtures(a.work).items():
        if a.only and not any(x in name for x in a.only):
            continue
        dest = a.work / "out"
        seven = time_7zip(path, dest, a.runs) if Path(SEVEN_ZIP).is_file() else None
        native = time_packport(path, dest, a.runs, pure=False)
        pure = time_packport(path, dest, a.pure_runs, pure=True)
        rows.append((name, path.stat().st_size, native["bytes"], seven, pure["seconds"], native["seconds"]))
        print(f"{name}: 7-Zip {seven:.3f} s, Python {pure['seconds']:.3f} s, native {native['seconds']:.3f} s"
              f" ({native['bytes'] / 1e6:.1f} MB)", flush=True)
    print()
    print("| Archive | Size | Unpacked | 7-Zip | packport (Python) | packport (native) | native vs 7-Zip |")
    print("|---|---|---|---|---|---|---|")
    for name, size, out, seven, pure, native in rows:
        ratio = f"{seven / native:.1f}x faster" if seven and native < seven else f"{native / seven:.1f}x slower" if seven else ""
        print(f"| {name} | {size / 1e6:.1f} MB | {out / 1e6:.1f} MB | {seven:.2f} s | {pure:.2f} s | {native:.2f} s | {ratio} |")


if __name__ == "__main__":
    main()
