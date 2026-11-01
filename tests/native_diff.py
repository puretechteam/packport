"""What every fixture (and damaged copies of it) reads as, for comparing packport's compiled
decoders with its Python ones: run once as is and once with PACKPORT_PURE=1, and compare.

    python tests/native_diff.py N OUT.json     # N damaged copies of each fixture

Each case is a fixture's name and copy number; its result is the SHA-256 of every member's name
and data, in order, or "PackportError" (the message may differ between the two decoders: where
damage is noticed can)."""

from __future__ import annotations

import hashlib
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from fuzz_readers import fixtures, load, mutations

import packport

READ_LIMIT = 64 << 20


def result(data: bytes) -> str:
    h = hashlib.sha256()
    read = 0
    try:
        with packport.open(data) as archive:
            for m, stream in archive.files():
                h.update(m.name.encode("utf-8", "surrogatepass"))
                while read < READ_LIMIT and (chunk := stream.read(min(1 << 20, READ_LIMIT - read))):
                    read += len(chunk)  # the same bytes both ways, however each decoder hands them out
                    h.update(chunk)
                if read >= READ_LIMIT:
                    break
    except packport.PackportError:
        return "PackportError"
    return h.hexdigest()


def results(n: int) -> dict[str, str]:
    out = {}
    for path in fixtures():
        data = load(path)
        name = path.relative_to(Path(__file__).parent / "data").as_posix()
        out[f"{name}#0"] = result(data)
        for k, (_how, damaged) in enumerate(mutations(data, random.Random(name), n), 1):
            out[f"{name}#{k}"] = result(damaged)
    return out


if __name__ == "__main__":
    Path(sys.argv[2]).write_text(json.dumps({"accelerated": packport.accelerated(),
                                             "results": results(int(sys.argv[1]))}), encoding="utf-8")
