"""packport's compiled decoders (the optional packport-native package), when they're installed.

Each decoder module keeps its pure-Python code and takes the compiled one in its place when
``native`` has it: the same results, decoded many times faster. ``PACKPORT_PURE=1`` keeps
packport on the Python code (the tests run both ways); a packport-native of another version is
left alone, since its decoders may not match this packport's."""

from __future__ import annotations

import os

VERSION = "0.4.0"  # the packport-native this packport is made for (it ships with each release)

native = None
_other = None  # the version of a packport-native that is installed but doesn't match
if not os.environ.get("PACKPORT_PURE"):
    try:
        import packport_native as _native
    except ImportError:
        pass
    else:
        if getattr(_native, "__version__", None) == VERSION:
            native = _native
        else:
            _other = str(getattr(_native, "__version__", "of an unknown version"))
            import warnings
            warnings.warn(f"packport-native {_other} is installed, but this packport {VERSION} needs packport-native "
                          f"{VERSION}: it isn't used, so archives are decoded by the (much slower) Python decoders. "
                          f"Install packport-native {VERSION} to fix it.", RuntimeWarning, stacklevel=2)


def accelerated() -> bool:
    """Whether the compiled decoders are in use."""
    return native is not None


def mismatch() -> str | None:
    """The version of an installed packport-native that isn't used because it doesn't match, or None."""
    return _other


def pump(decoder, inp, size: int | None):
    """The output of a compiled streaming decoder (feed, finish, read, eof), fed from inp (a
    readable) entries.CHUNK at a time: size bytes at most, or until it ends. If the data runs out
    first, what came out is all there is (the caller finds it short)."""
    from . import entries
    read_size = entries.CHUNK
    left = size
    while left is None or left > 0:
        out = decoder.read(entries.CHUNK if left is None else min(entries.CHUNK, left))
        if out:
            if left is not None:
                left -= len(out)
            yield out
            continue
        if decoder.eof or decoder.finished:
            return
        data = inp.read(read_size)
        if data:
            decoder.feed(data)
        else:
            decoder.finish()
