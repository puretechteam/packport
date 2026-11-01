"""Makes tests/data/dfvfs from dfvfs's test images (github.com/log2timeline/dfvfs, Apache License
2.0): each image compressed with packport's .Z (they're mostly empty space), and expected.json
with the SHA-256 of every file packport reads from each, after checking that 7-Zip extracts the
same files. 7-Zip's extra entries are left out of that check: its [SYSTEM] and [SYS] files
(NTFS and ext metadata), macOS's hidden .fseventsd, symbolic links (packport leaves links out),
and the folder 7-Zip names after an HFS+ volume.

Images 7-Zip doesn't read are kept for what they test: encrypted and pooled volumes, which
packport refuses (only their first 64 KB, which is what the refusal needs).

Run it from the packport folder, with dfvfs's test_data folder:
    python tests/data/make_dfvfs_fixtures.py PATH/TO/dfvfs/test_data
"""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import packport

SEVEN = "C:/Program Files/7-Zip/7z.exe"
OUT = Path(__file__).parent / "dfvfs"
IMAGES = ["fat12.raw", "ext2.raw", "ext4.raw", "ntfs.raw", "hfsplus.raw", "apfs.raw", "mbr.raw", "gpt.raw",
          "ext2.vhd", "ext2.vhdx", "ext2.vmdk", "ext2.qcow2", "ntfs-parent.vhd", "ntfs-differential.vhd",
          "fat-parent.vhdx", "fat-differential.vhdx", "hfsplus_zlib.dmg", "apm.dmg"]
REFUSED = ["luks1.raw", "lvm.raw", "bdetogo.raw", "hfsplus.sparseimage", "apfs_encrypted.dmg"]
SKIP = ("[SYSTEM]", "[SYS]", ".fseventsd")


def _seven(image: Path, tmp: Path) -> dict[str, str]:
    out = tmp / ("7z-" + image.name)
    subprocess.run([SEVEN, "x", "-y", f"-o{out}", str(image)], capture_output=True, check=False)  # links fail
    found = {}
    for p in out.rglob("*"):
        if p.is_file():
            rel = p.relative_to(out).as_posix()
            found[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return found


def _normal(files: dict[str, str], links: set[str]) -> dict[str, str]:
    out = {}
    for rel, digest in files.items():
        if rel.startswith("hfsplus_test/"):  # 7-Zip's folder named after the volume
            rel = rel.split("/", 1)[1]
        if any(part in SKIP for part in rel.split("/")) or rel in links or rel.split("/")[-1] in links:
            continue
        out[rel] = digest
    return out


def main() -> None:
    src = Path(sys.argv[1])
    shutil.rmtree(OUT, ignore_errors=True)
    OUT.mkdir()
    shutil.copy2(src.parent / "LICENSE", OUT / "LICENSE-dfvfs.txt")
    expected = {}
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for name in IMAGES:
            image = src / name
            (OUT / (name + ".Z")).write_bytes(packport.compress(image.read_bytes()))
            with packport.open(image) as a:
                links = {m.name for m in a.members if m.link is not None}
                ours = {m.name: hashlib.sha256(s.read()).hexdigest() for m, s in a.files()}
            if any(m.split("/", 1)[0][:1].isdigit() and " " in m.split("/", 1)[0] for m in ours):
                # several partitions: 7-Zip writes each out as an image; it has to read the same
                # files from each as packport does from that partition's folder
                out = tmp / ("7z-" + name)
                subprocess.run([SEVEN, "x", "-y", f"-o{out}", str(image)], capture_output=True, check=True)
                leaf_links = {n.rsplit("/", 1)[-1] for n in links}
                theirs_parts = sorted(json.dumps(_normal(_seven(p, tmp), leaf_links), sort_keys=True)
                                      for p in out.iterdir() if p.is_file())
                ours_parts = {}
                for rel, digest in ours.items():
                    top, _, rest = rel.partition("/")
                    ours_parts.setdefault(top, {})[rest] = digest
                for part in ours_parts.values():
                    assert json.dumps(part, sort_keys=True) in theirs_parts, (name, sorted(part))
            else:
                theirs = _normal(_seven(image, tmp), links)
                assert ours == theirs, (name, sorted(set(ours) ^ set(theirs)))
            expected[name] = ours
        for name in REFUSED:
            data = (src / name).read_bytes()
            if name != "apfs_encrypted.dmg":
                data = data[:64 << 10]
            (OUT / (name + ".Z")).write_bytes(packport.compress(data))
    (OUT / "expected.json").write_text(json.dumps(expected, indent=1) + "\n", encoding="utf-8")
    print(len(expected), "images,", len(REFUSED), "refused,", sum(p.stat().st_size for p in OUT.iterdir()), "bytes")


if __name__ == "__main__":
    main()
