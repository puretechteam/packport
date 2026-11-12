"""Decoding ahead in threads: independent pieces of an archive (a non-solid archive's small files,
7z folders, WIM chunks) are decoded by a pool while earlier ones are handed out, results kept in
archive order. packport-native's decoders and zlib, bz2 and lzma let go of the GIL while they
work, so this uses more than one core; the pure-Python decoders gain little from it.

``PACKPORT_THREADS`` sets the number of threads (1: none); by default one less than the cores,
at most 8."""

from __future__ import annotations

import os
import threading
from collections import deque
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from typing import TypeVar

T = TypeVar("T")
_pool: ThreadPoolExecutor | None = None
_lock = threading.Lock()


def threads() -> int:
    v = os.environ.get("PACKPORT_THREADS")
    if v:
        try:
            return max(1, int(v))
        except ValueError:
            pass
    return max(1, min(8, (os.cpu_count() or 2) - 1))


def _get_pool() -> ThreadPoolExecutor:
    global _pool
    with _lock:
        if _pool is None:
            _pool = ThreadPoolExecutor(max_workers=threads(), thread_name_prefix="packport")
        return _pool


def ordered(jobs: Iterable[Callable[[], T]], ahead: int | None = None) -> Iterator[T]:
    """Each job's result, in order, with at most `ahead` jobs running or done but not yet taken
    (2 x threads by default). With one thread, the jobs simply run in turn. An exception comes
    out where its job's result would have."""
    n = threads()
    if n <= 1:
        for job in jobs:
            yield job()
        return
    ahead = ahead or 2 * n
    pool = _get_pool()
    queue: deque[Future] = deque()
    it = iter(jobs)
    try:
        for job in it:
            queue.append(pool.submit(job))
            if len(queue) >= ahead:
                yield queue.popleft().result()
        while queue:
            yield queue.popleft().result()
    finally:
        for f in queue:
            f.cancel()


_END = object()


def streamed(chunks: Iterable[T], depth: int = 4) -> Iterator[T]:
    """chunks produced in a thread of their own, at most depth ahead of the one taking them: a
    decoder runs while what it already gave is being written, or several decoders that feed one
    coder (BCJ2's four streams) run side by side. An exception comes out where it happened in the
    sequence; stopping early (close()) ends the thread. With one thread allowed, chunks as they are."""
    if threads() <= 1:
        yield from chunks
        return
    import queue
    q: queue.Queue = queue.Queue(depth)
    stop = threading.Event()

    def put(item) -> bool:
        while not stop.is_set():
            try:
                q.put(item, timeout=0.1)
                return True
            except queue.Full:
                continue
        return False

    def run() -> None:
        try:
            for chunk in chunks:
                if not put((chunk, None)):
                    return
            put((_END, None))
        except BaseException as e:
            put((_END, e))
        finally:
            close = getattr(chunks, "close", None)
            if close:
                close()  # here, in the thread that ran it

    worker = threading.Thread(target=run, name="packport-stream", daemon=True)
    worker.start()
    try:
        while True:
            chunk, error = q.get()
            if chunk is _END:
                if error is not None:
                    raise error
                return
            yield chunk
    finally:
        stop.set()
        worker.join()
