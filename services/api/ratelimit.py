"""A tiny in-process, per-client sliding-window rate limiter.

Used to throttle brute-force login attempts on the BFF without pulling in a
dependency (Redis, slowapi, …). State is process-local: good enough for a single
BFF instance; behind multiple replicas each gets its own window, which still
caps any one node. Pure stdlib — a dict of deque[timestamps] guarded by a lock.
"""
from __future__ import annotations

import os
import threading
import time
from collections import deque

# Allow N attempts per WINDOW seconds, per client IP. Configurable via env so
# the demo / tests can loosen it without touching code. Default is deliberately
# generous (the goal is to stop brute force, not legitimate retries).
LIMIT = int(os.environ.get("MIRAIGE_LOGIN_RATELIMIT", "100"))
WINDOW_S = float(os.environ.get("MIRAIGE_LOGIN_RATELIMIT_WINDOW_S", "60"))

# Stop the key map from growing without bound under spoofed/rotating IPs.
_MAX_KEYS = 10_000

_hits: dict[str, deque[float]] = {}
_lock = threading.Lock()


def _prune(now: float) -> None:
    """Drop keys whose every timestamp has aged out of the window."""
    stale = [ip for ip, hits in _hits.items() if not hits or now - hits[-1] > WINDOW_S]
    for ip in stale:
        _hits.pop(ip, None)


def check_and_record(ip: str) -> bool:
    """Record an attempt from `ip`; return False if it is over the limit.

    Uses time.monotonic() so it is immune to wall-clock jumps. Returns True when
    the attempt is allowed (and counted), False when the caller should reject it.
    """
    now = time.monotonic()
    with _lock:
        # Opportunistically bound memory before inserting a brand-new key.
        if ip not in _hits and len(_hits) >= _MAX_KEYS:
            _prune(now)

        hits = _hits.setdefault(ip, deque())
        cutoff = now - WINDOW_S
        while hits and hits[0] <= cutoff:
            hits.popleft()

        if len(hits) >= LIMIT:
            return False

        hits.append(now)
        return True


def reset() -> None:
    """Clear all recorded attempts (test helper)."""
    with _lock:
        _hits.clear()
