"""Cabinets made by Windows' own makecab.exe (skipped where it isn't): stored, MSZIP, LZX at every
window size, and a set spanning several cabinets with a folder split between them."""

import os
import random
import shutil
import subprocess
from pathlib import Path

import pytest

import packport
from packport import PackportError

MAKECAB = shutil.which("makecab") or (r"C:\Windows\System32\makecab.exe" if os.name == "nt" else None)
needs_makecab = pytest.mark.skipif(not MAKECAB or not Path(MAKECAB).is_file(), reason="makecab.exe isn't here")
FILES = {"text.txt": None, "random.bin": None, "sub/program.bin": None, "sub/empty.txt": b"", "sub/small.txt": b"small\r\n" * 3}


def _sources(tmp_path) -> dict:
    rng = random.Random(5)
    words = [bytes(rng.choice(b"abcdefghij") for _ in range(rng.randint(2, 9))) for _ in range(300)]
    data = {"text.txt": b" ".join(rng.choice(words) for _ in range(60_000)), "random.bin": rng.randbytes(70_000),
            # x86 calls (E8 and a 32-bit address) for LZX's E8 translation
            "sub/program.bin": b"".join(b"\x55\x8b\xec\xe8" + rng.randbytes(4) + b"\x90" * rng.randint(0, 20)
                                        for _ in range(4000)),
            "sub/empty.txt": b"", "sub/small.txt": b"small\r\n" * 3}
    for name, content in data.items():
        (tmp_path / "src" / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "src" / name).write_bytes(content)
    return data


def _makecab(tmp_path, name: str, settings: list[str]) -> Path:
    template = f"{name}*.cab" if any(s.startswith("MaxDiskSize=") for s in settings) else f"{name}.cab"
    lines = [".OPTION EXPLICIT", f".Set CabinetNameTemplate={template}", f".Set DiskDirectoryTemplate={tmp_path}",
             ".Set Cabinet=on", ".Set Compress=on", ".Set MaxDiskSize=0", f".Set RptFileName={tmp_path / 'r.txt'}",
             f".Set InfFileName={tmp_path / 'i.txt'}"] + [f".Set {s}" for s in settings]
    lines += [f'"{tmp_path / "src" / f}" "{f.replace("/", chr(92))}"' for f in FILES]
    ddf = tmp_path / f"{name}.ddf"
    ddf.write_text("\n".join(lines) + "\n")
    r = subprocess.run([MAKECAB, "/F", str(ddf)], capture_output=True, text=True, timeout=300, check=False)
    assert r.returncode == 0, r.stdout
    return tmp_path / (f"{name}1.cab" if "*" in template else f"{name}.cab")


def _contents(path) -> dict:
    with packport.open(path) as a:
        return {m.name: s.read() for m, s in a.files()}


@needs_makecab
@pytest.mark.parametrize("kind", ["none", "mszip", *(f"lzx{b}" for b in range(15, 22))])
def test_makecab_cabinets(tmp_path, kind):
    data = _sources(tmp_path)
    settings = {"none": ["Compress=off"], "mszip": ["CompressionType=MSZIP"]}.get(
        kind, ["CompressionType=LZX", f"CompressionMemory={kind[3:]}"])
    cab = _makecab(tmp_path, kind, settings)
    assert packport.detect(cab) == "cab"
    assert _contents(cab) == data


@needs_makecab
def test_a_cabinet_set_reads_from_any_cabinet(tmp_path):
    data = _sources(tmp_path)
    first = _makecab(tmp_path, "set", ["CompressionType=LZX", "CompressionMemory=18", "MaxDiskSize=51200"])
    cabs = sorted(tmp_path.glob("set*.cab"))
    assert len(cabs) >= 3
    for cab in (first, cabs[1], cabs[-1]):
        assert _contents(cab) == data
    cabs[-1].unlink()
    with pytest.raises(PackportError, match="isn't here"):
        _contents(first)


def test_damaged_cabinets_raise_only_packport_error():
    data = (Path(__file__).parent / "data" / "libarchive" / "test_fuzz.cab").read_bytes()
    rng = random.Random(11)
    bad = []
    for _ in range(300):
        b = bytearray(data)
        for _ in range(rng.randint(1, 6)):
            b[rng.randrange(len(b))] = rng.randrange(256)
        if rng.random() < 0.3:
            b = b[:rng.randrange(len(b))]
        try:
            _contents(bytes(b))
        except PackportError:
            pass
        except Exception as e:  # noqa: BLE001
            bad.append(f"{type(e).__name__}: {e}")
    assert bad == []
