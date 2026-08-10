"""Small dependency-free counters and timings for autonomous runs."""
from __future__ import annotations

import time
from collections import Counter
from contextlib import contextmanager
from typing import Iterator

COUNTERS = Counter()


def increment(name: str, value: int = 1) -> None:
    COUNTERS[name] += value


@contextmanager
def measure(name: str) -> Iterator[None]:
    start = time.perf_counter()
    try:
        yield
        increment(name + ".success")
    except Exception:
        increment(name + ".error")
        raise
    finally:
        increment(name + ".ms", int((time.perf_counter() - start) * 1000))


def snapshot():
    return dict(COUNTERS)
