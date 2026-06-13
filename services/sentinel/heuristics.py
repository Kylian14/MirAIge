"""Pre-LLM heuristics and helper functions for the sliding window."""
from __future__ import annotations

from services.shared.models import AttackVector, LogEvent

_TRAVERSAL = ["../", "..\\", "%2e%2e", "/etc/passwd", "/etc/shadow", "/proc/self", "win.ini", "boot.ini"]
_INJECTION = ["union select", "union%20select", "or 1=1", "or%201=1", "sleep(", "benchmark(", "waitfor delay"]
_BRUTE = ["/login", "/auth", "/signin", "/wp-login", "/admin"]
_RECON = ["/.env", "/.git", "/.aws", "/.kube", "/.ssh", "/swagger", "/openapi", "/api-docs", "/server-status", "/phpinfo"]
_AI_UA = ["python-httpx", "openai/python", "chatgpt-user", "gptbot", "claudebot", "claude-web", "oai-searchbot"]


def compute_rps(window: list[LogEvent]) -> float:
    """Compute requests-per-second over the sliding window."""
    if len(window) < 2:
        return 0.0
    dt = (window[-1].timestamp - window[0].timestamp).total_seconds()
    if dt < 0.001:
        return float(len(window))
    return len(window) / dt


def looks_suspicious(window: list[LogEvent], *, rps_threshold: float) -> bool:
    """Cheap first-pass filter before T1/T2 to avoid spending compute."""
    if not window:
        return False

    if compute_rps(window) >= rps_threshold:
        return True

    for ev in window:
        path = (ev.path or "").lower()
        raw = (ev.raw or "").lower()

        for marker in _TRAVERSAL + _INJECTION + _RECON:
            if marker in path:
                return True

        for ua in _AI_UA:
            if ua in raw:
                return True

    status_codes = [ev.status_code for ev in window if ev.status_code is not None]
    if len(status_codes) >= 5:
        ratio_4xx = sum(1 for s in status_codes if 400 <= s < 500) / len(status_codes)
        if ratio_4xx > 0.5:
            return True

    return False


def dominant_vector(window: list[LogEvent]) -> AttackVector:
    """Best-guess attack vector from path patterns, used as fallback."""
    votes: dict[AttackVector, int] = {v: 0 for v in AttackVector}

    for ev in window:
        path = (ev.path or "").lower()
        raw = (ev.raw or "").lower()

        for m in _TRAVERSAL:
            if m in path:
                votes[AttackVector.TRAVERSAL] += 1
                break

        for m in _INJECTION:
            if m in path:
                votes[AttackVector.INJECTION] += 1
                break

        for m in _BRUTE:
            if m in path and (ev.method or "").upper() == "POST":
                votes[AttackVector.BRUTE_FORCE] += 1
                break

        for m in _RECON:
            if m in path:
                votes[AttackVector.RECON] += 1
                break

        for ua in _AI_UA:
            if ua in raw:
                votes[AttackVector.AI_RECON] += 1
                break

    candidates = {v: c for v, c in votes.items() if v != AttackVector.UNKNOWN}
    best = max(candidates, key=lambda v: candidates[v])
    return best if candidates[best] > 0 else AttackVector.RECON
