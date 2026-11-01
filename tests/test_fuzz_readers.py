"""Every reader against damaged copies of every test archive (see fuzz_readers.py): only
PackportError comes out, no case runs out of its 1 GB, and none is stuck. A few cases
per fixture here; PACKPORT_FUZZ=N runs N per fixture."""

import os

from fuzz_readers import fixtures, fuzz, stuck


def test_damaged_copies_of_every_fixture():
    n = int(os.environ.get("PACKPORT_FUZZ", "6"))
    total, found = fuzz(n)
    assert total >= n * len(fixtures()) * 0.9
    assert found == []


def test_what_counts_as_stuck():
    assert not stuck(4.0, 0, 0.0)  # quick, whatever it read
    assert stuck(6.0, 40 << 10, 0.1)  # slow, little output, and far slower than the intact archive
    assert not stuck(7.1, 40 << 10, 3.5)  # as slow as the slow decoder is on the intact archive
    assert not stuck(6.0, 1 << 30, 0.1)  # slow but reading fast: a big archive
    assert stuck(61.0, 1 << 30, 30.0)  # over a minute is always too long


def test_a_rust_panic_is_a_finding(monkeypatch):
    """pyo3 turns a Rust panic into PanicException, a BaseException: it's recorded, not let through."""
    from fuzz_readers import run_case

    import packport

    class PanicException(BaseException):
        pass

    def panics(_data):
        raise PanicException("index out of bounds")

    monkeypatch.setattr(packport, "open", panics)
    finding, _ = run_case(b"x")
    assert finding and finding.startswith("PanicException: index out of bounds")


def test_a_worker_that_dies_is_a_finding():
    """A case that kills its worker (a crash in native code, or the 1 GB job limit) is recorded,
    and the other fixtures still run."""
    from fuzz_readers import _die_for_test, run_jobs

    results, died = run_jobs(_die_for_test, ["ok", "die", "ok"], workers=1)
    assert results == ["ok", "ok"]
    assert died == ["die"]
