"""Red-team launcher · run the attack simulator as a tracked subprocess.

The console fires a calibrated attack at the protected target and watches it land
in the detection cascade. Each launch is a separate
``python -m services.attack_simulator.attack`` process, tracked in-memory with a
small ring buffer of its output so the UI can tail it live and stop it.

State is intentionally in-process: a launcher is a single-operator control, not a
job queue. Finished runs linger briefly so the UI can show their outcome, then
get reaped.
"""
from __future__ import annotations

import asyncio
import os
import re
import sys
import time
import uuid
from collections import deque
from dataclasses import dataclass, field

# CLI levels the console is allowed to fire — the calibrated tier demos plus the
# end-to-end scenarios. (attack.py also exposes historical aliases we don't surface.)
ALLOWED_LEVELS: tuple[str, ...] = (
    "noisy", "evasive", "stealth", "ai-agent", "apt",
    "naive-full", "hardened-agent", "apt-bypass",
)

ATTACK_TARGET = os.environ.get("ATTACK_TARGET", "http://fake_portal_prod:8080")
MAX_DURATION_S = 600        # hard cap — a runaway launch can't pin the box
MAX_CONCURRENT = 8          # refuse to spawn more than this many live at once
_LOG_LINES = 200            # ring-buffer depth per run
_RETAIN_FINISHED_S = 300    # keep a finished run visible this long, then reap

# ai-agent level uses server-configured creds — never client-supplied. Absent →
# attack.py falls back to its scripted brain (no real LLM spend).
_AI_ENDPOINT = os.environ.get("AI_ENDPOINTS_BASE_URL", "")
_AI_KEY = os.environ.get("AI_ENDPOINTS_API_KEY", "")
_AI_MODEL = os.environ.get("AI_MODEL_GENERATOR", "") or os.environ.get("AI_MODEL_CLASSIFIER", "")

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


@dataclass
class _Run:
    id: str
    level: str
    target: str
    duration: int
    source_ip: str
    started_at: float
    proc: asyncio.subprocess.Process
    lines: deque[str] = field(default_factory=lambda: deque(maxlen=_LOG_LINES))
    rc: int | None = None


_RUNS: dict[str, _Run] = {}


def _source_ip(seed: str) -> str:
    """A stable-per-run source IP so each launch reads as its own session.

    The target runs in DIRECT mode (no LB rewriting XFF), so attack.py's
    ``--source-ip`` becomes the Sentinel session key — one fresh engagement per
    launch instead of every attack collapsing onto the BFF's own IP.
    """
    n = int(seed, 16)
    return f"10.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{(n % 254) + 1}"


def view(run: _Run) -> dict:
    """JSON-safe snapshot of a run (no process handle)."""
    return {
        "id": run.id,
        "level": run.level,
        "target": run.target,
        "duration": run.duration,
        "source_ip": run.source_ip,
        "elapsed": round(time.time() - run.started_at, 1),
        "running": run.rc is None,
        "returncode": run.rc,
    }


def _reap() -> None:
    now = time.time()
    stale = [
        rid for rid, r in _RUNS.items()
        if r.rc is not None and now - r.started_at > _RETAIN_FINISHED_S
    ]
    for rid in stale:
        _RUNS.pop(rid, None)


async def _pump(run: _Run) -> None:
    """Drain the child's stdout into its ring buffer, then record the exit code."""
    assert run.proc.stdout is not None
    try:
        async for raw in run.proc.stdout:
            run.lines.append(_ANSI.sub("", raw.decode("utf-8", "replace")).rstrip())
    finally:
        run.rc = await run.proc.wait()


async def launch(level: str, duration: int, rps: int | None = None) -> dict:
    """Spawn one calibrated attack against the configured target.

    Raises ValueError on a bad level/duration, RuntimeError when MAX_CONCURRENT
    live runs are already in flight.
    """
    if level not in ALLOWED_LEVELS:
        raise ValueError(f"unknown level: {level!r}")
    duration = max(1, min(int(duration), MAX_DURATION_S))

    _reap()
    if sum(1 for r in _RUNS.values() if r.rc is None) >= MAX_CONCURRENT:
        raise RuntimeError("too many attacks running")

    rid = uuid.uuid4().hex[:12]
    src = _source_ip(rid)
    argv = [
        sys.executable, "-m", "services.attack_simulator.attack",
        "--target", ATTACK_TARGET,
        "--level", level,
        "--duration", str(duration),
        "--source-ip", src,
    ]
    if rps:
        argv += ["--rps", str(int(rps))]
    if level == "ai-agent" and _AI_ENDPOINT and _AI_KEY:
        argv += ["--ai-endpoint", _AI_ENDPOINT, "--ai-key", _AI_KEY]
        if _AI_MODEL:
            argv += ["--ai-model", _AI_MODEL]

    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    run = _Run(rid, level, ATTACK_TARGET, duration, src, time.time(), proc)
    _RUNS[rid] = run
    asyncio.create_task(_pump(run))
    return view(run)


def list_runs() -> list[dict]:
    _reap()
    runs = sorted(_RUNS.values(), key=lambda r: r.started_at, reverse=True)
    return [view(r) for r in runs]


def stop(rid: str) -> bool:
    """SIGTERM a live run. Returns False if the id is unknown."""
    run = _RUNS.get(rid)
    if run is None:
        return False
    if run.rc is None:
        try:
            run.proc.terminate()
        except ProcessLookupError:
            pass
    return True


def logs(rid: str) -> list[str] | None:
    run = _RUNS.get(rid)
    return list(run.lines) if run else None
