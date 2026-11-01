"""packport's compiled decoders (packport-native) against its Python ones: every fixture in
tests/data, and damaged copies of each, read the same both ways (the same bytes, or a
PackportError both ways). Skipped where packport-native isn't installed. PACKPORT_FUZZ=N
compares N damaged copies of each fixture (2 by default)."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import packport

pytestmark = pytest.mark.skipif(not packport.accelerated(), reason="packport-native isn't installed")
HERE = Path(__file__).parent


def _run(tmp_path, pure: bool) -> dict:
    out = tmp_path / ("pure.json" if pure else "native.json")
    env = dict(os.environ)
    env.pop("PACKPORT_PURE", None)
    if pure:
        env["PACKPORT_PURE"] = "1"
    n = os.environ.get("PACKPORT_FUZZ", "2")
    subprocess.run([sys.executable, str(HERE / "native_diff.py"), n, str(out)], env=env, check=True, timeout=3600)
    return json.loads(out.read_text(encoding="utf-8"))


def test_compiled_and_python_decoders_read_every_fixture_the_same(tmp_path):
    native, pure = _run(tmp_path, pure=False), _run(tmp_path, pure=True)
    assert native["accelerated"] and not pure["accelerated"]
    assert native["results"].keys() == pure["results"].keys()
    differ = [k for k in native["results"] if native["results"][k] != pure["results"][k]]
    assert differ == [], f"{len(differ)} of {len(native['results'])} cases differ, e.g. {differ[:5]}"
    assert sum(v != "PackportError" for v in native["results"].values()) > 200  # most fixtures do read


def test_the_switch():
    from packport import _accel
    assert _accel.VERSION == packport.__version__  # packport-native ships with each packport release
    assert packport.accelerated()


def test_version_says_which_decoders():
    env = dict(os.environ)
    env.pop("PACKPORT_PURE", None)
    run = [sys.executable, "-m", "packport", "--version"]
    native = subprocess.run(run, env=env, capture_output=True, text=True, check=True).stdout
    pure = subprocess.run(run, env={**env, "PACKPORT_PURE": "1"}, capture_output=True, text=True, check=True).stdout
    assert native.strip() == f"packport {packport.__version__} (with packport-native)"
    assert pure.strip() == f"packport {packport.__version__} (Python decoders)"
