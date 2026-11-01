"""Fuzzing every reader with damaged copies of the test archives (tests/data).

Each fixture is changed in three ways, from a seed: random bytes changed where it has data, cut
short at a random point, or a header field (2, 4 or 8 bytes in its first 64 KB, either byte order)
set to 0, 1, 0x7FFF..., 0xFFFF... Each damaged copy is opened and every file read in full. Only
PackportError (EncryptedError is one) may come out. A case is also a finding when it runs out of
memory, kills its worker (a crash in native code), or is stuck: over 5 seconds at under 20 KB/s of output and over 10 times as long as the
intact fixture takes (the pure-Python PPMd decodes at about 0.1 MB/s, slower on a busy machine),
or over 60 seconds in all.

The cases run in worker processes, each held to 1 GB by a Windows job object (which counts what
liblzma and zlib allocate too), with MemoryError taken out of the errors packport reports as
damage: a memory bomb shows up here as MemoryError instead of as "damaged". (tracemalloc isn't
used: it slows the pure-Python decoders down by 40 times.) Run it directly for the deep pass:

    python tests/fuzz_readers.py 200 [findings.txt]   # cases per fixture, and where to list findings
"""

from __future__ import annotations

import gc
import os
import random
import sys
import time
import traceback
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

DATA = Path(__file__).parent / "data"
SKIP_SUFFIXES = {".json", ".txt", ".md", ".py", ".ps1", ".sh"}
TIME_LIMIT = 5.0     # seconds, at under STUCK_RATE bytes a second
STUCK_RATE = 20_000
SLOWER = 10          # ... and over this many times as long as the intact fixture takes
HARD_LIMIT = 60.0
READ_LIMIT = 256 << 20  # a case stops reading here: a damaged header can promise any amount of output
JOB_LIMIT = 1 << 30


def fixtures() -> list[Path]:
    out = []
    for p in sorted(DATA.rglob("*")):
        if p.is_file() and p.suffix.lower() not in SKIP_SUFFIXES and not p.name.upper().startswith(
                ("LICENSE", "NOTICE", "COPYING")):
            out.append(p)
    return out


def load(path: Path) -> bytes:
    """The fixture's bytes; a .Z one is unpacked first (the .Z itself is fuzzed in test_lzw.py)."""
    import packport
    data = path.read_bytes()
    if path.suffix == ".Z":
        try:
            return packport.decompress(data)
        except packport.PackportError:
            return data
    return data


def mutations(data: bytes, rng: random.Random, n: int):
    """n damaged copies of data: (how it was damaged, bytes)."""
    hot = [k for k in range(0, min(len(data), 2 << 20), max(1, min(len(data), 2 << 20) // 50_000)) if data[k]] or [0]
    for k in range(n):
        b = bytearray(data)
        kind = k % 3
        if kind == 0 and data:
            for _ in range(rng.randint(1, 12)):
                b[rng.choice(hot)] = rng.randrange(256)
            yield "bytes", bytes(b)
        elif kind == 1 and len(data) > 1:
            cut = rng.randrange(1, len(data))
            yield f"cut at {cut}", bytes(b[:cut])
        elif data:
            width = rng.choice((2, 4, 8))
            at = rng.randrange(0, max(1, min(len(data), 1 << 16) - width))
            value = rng.choice((0, 1, (1 << (8 * width - 1)) - 1, (1 << (8 * width)) - 1))
            order = rng.choice(("little", "big"))
            b[at:at + width] = value.to_bytes(width, order)
            yield f"{width} bytes at {at} = {value:#x} ({order})", bytes(b)


def stuck(seconds: float, read: int, intact: float) -> bool:
    """Whether a case that read read bytes in seconds is stuck (intact: the fixture's own time)."""
    if seconds > HARD_LIMIT:
        return True
    return seconds > TIME_LIMIT and read / seconds < STUCK_RATE and seconds > SLOWER * intact


def run_case(data: bytes, intact: float = 0.0) -> tuple[str | None, float]:
    """(finding or None, seconds) for opening data and reading every file; intact: how long the
    undamaged fixture takes."""
    import packport
    start = time.perf_counter()
    finding = None
    read = 0
    try:
        with packport.open(data) as archive:
            for _m, stream in archive.files():
                while read < READ_LIMIT and (chunk := stream.read(1 << 20)):
                    read += len(chunk)
                if read >= READ_LIMIT:
                    break
    except packport.PackportError:
        pass
    except BaseException as e:
        # pyo3 turns a Rust panic into PanicException, which is a BaseException
        if not isinstance(e, Exception) and type(e).__name__ != "PanicException":
            raise
        tb = traceback.extract_tb(e.__traceback__)[-1]
        finding = f"{type(e).__name__}: {e} (at {Path(tb.filename).name}:{tb.lineno})"
    seconds = time.perf_counter() - start
    gc.collect()  # what a damaged case leaves in reference cycles goes before the next case
    if finding is None and stuck(seconds, read, intact):
        finding = f"took {seconds:.1f} s for {read >> 10} KB"
    return finding, seconds


def _limit_memory() -> None:
    """Hold this process to JOB_LIMIT (Windows), and let MemoryError through as itself."""
    import packport.archive
    import packport.squashfs
    for module in (packport.archive, packport.squashfs):
        module.DAMAGED = tuple(e for e in module.DAMAGED if e is not MemoryError)
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes

    class IoCounters(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in ("r", "w", "o", "rb", "wb", "ob")]

    class Basic(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class Extended(ctypes.Structure):
        _fields_ = [("Basic", Basic), ("Io", IoCounters), ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    job = k32.CreateJobObjectW(None, None)
    info = Extended()
    info.Basic.LimitFlags = 0x100  # JOB_OBJECT_LIMIT_PROCESS_MEMORY
    info.ProcessMemoryLimit = JOB_LIMIT
    k32.SetInformationJobObject(wintypes.HANDLE(job), 9, ctypes.byref(info), ctypes.sizeof(info))
    k32.AssignProcessToJobObject(wintypes.HANDLE(job), wintypes.HANDLE(k32.GetCurrentProcess()))


def fuzz_fixture(args: tuple[str, int]) -> tuple[str, int, list[str], float]:
    """(fixture, cases run, findings, slowest case in seconds) for one fixture."""
    path, n = Path(args[0]), args[1]
    data = load(path)
    rng = random.Random(path.name)
    findings, slowest, cases = [], 0.0, 0
    _, intact = run_case(data)
    for how, damaged in mutations(data, rng, n):
        finding, seconds = run_case(damaged, intact)
        cases += 1
        slowest = max(slowest, seconds)
        if finding:
            findings.append(f"{path.relative_to(DATA)}: {how}: {finding}")
    return str(path.relative_to(DATA)), cases, findings, slowest


def _die_for_test(job: str) -> str:
    """For the tests of run_jobs: a job that kills its worker the way a native crash does."""
    if job == "die":
        os._exit(3)
    return job


def run_jobs(func, jobs: list, workers: int) -> tuple[list, list]:
    """(results, jobs whose worker died) for func over jobs in worker processes. A dead worker
    (a crash in native code, or the job object's memory limit) takes the pool down with it, so the
    jobs that were running are tried again one at a time, to tell which one killed it."""
    from concurrent.futures.process import BrokenProcessPool
    results: dict[int, object] = {}
    died: list = []
    todo = list(range(len(jobs)))
    while todo:
        pool = ProcessPoolExecutor(max_workers=workers if len(todo) > 1 else 1, initializer=_limit_memory)
        futures = {i: pool.submit(func, jobs[i]) for i in todo}
        broken = []
        for i, fut in futures.items():
            try:
                results[i] = fut.result()
            except BrokenProcessPool:
                broken.append(i)
        pool.shutdown(cancel_futures=True)
        if len(broken) == 1 or (broken and workers == 1):
            died.append(jobs[broken[0]])
            broken = broken[1:]
        todo, workers = broken, 1 if broken else workers
    return [results[i] for i in sorted(results)], died


def fuzz(n: int, workers: int | None = None) -> tuple[int, list[str]]:
    """Fuzz every fixture with n cases; returns (cases run, findings)."""
    workers = workers or max(1, min(8, int((os.cpu_count() or 2) * 0.5)))  # about half the machine
    jobs = [(str(p), n) for p in fixtures()]
    results, died = run_jobs(fuzz_fixture, jobs, workers)
    total, found = 0, [f"{Path(job[0]).relative_to(DATA)}: a case killed its worker process" for job in died]
    for _name, cases, findings, _slowest in results:
        total += cases
        found += findings
    return total, found


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    start = time.perf_counter()
    total, found = fuzz(count)
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    if out:
        out.write_text("".join(f + "\n" for f in found), encoding="utf-8")
    for f in found:
        print(f)
    print(f"{total} cases over {len(fixtures())} fixtures, {len(found)} findings, {time.perf_counter() - start:.0f} s")
