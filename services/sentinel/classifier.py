"""Sentinel Tier 2 LLM classifier (OVH AI Endpoints, OpenAI-compatible).

Called only for ambiguous T1 cases (~5% of traffic).
Fail-closed: any error returns confidence=0 to avoid false-positive MTD triggers.

Security hygiene before sending to LLM:
  - Request paths truncated to 120 chars
  - Control characters escaped
  - max_tokens=200, temperature=0.1
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from uuid import uuid4

import httpx

from services.shared.models import AttackVector, DetectionVerdict, LogEvent, TierVerdict

_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_PATHS_IN_PROMPT = 20
_TIMEOUT_S = 8.0

# Running total of the REAL tokens consumed by T2 (the OVH API `usage` field) = the defender's
# true LLM cost. Exposed via /stats, reset to 0 by /admin/reset.
LLM_TOKENS_TOTAL = 0

_SYSTEM_PROMPT = """\
You are a network security analyst classifying HTTP traffic windows.
Respond ONLY with a valid JSON object containing exactly:
  {"vector": "<one of: recon|brute_force|traversal|injection|ai-recon|unknown>",
   "confidence": <float 0.0-1.0>,
   "rationale": "<one sentence>"}
Do not add any other keys or prose outside the JSON object."""

_USER_TEMPLATE = """\
Classify this 10-second HTTP window from a single source IP.

Source IP: {src_ip}
Request count: {n_events}
Rate: {rate_rps:.1f} req/s
Inter-arrival mean: {inter_ms:.0f} ms
4xx ratio: {ratio_4xx:.0%}
Sample paths (up to {max_paths}):
{paths_block}

Sigma rule hits: {sigma_hits}
"""


def _sanitize(text: str, max_len: int = 200) -> str:
    """Truncate and escape control characters to prevent prompt injection."""
    text = _CTRL_RE.sub(lambda m: f"\\x{ord(m.group()):02x}", text)
    return text[:max_len]


def _build_prompt(window: list[LogEvent], features: dict) -> str:
    paths = []
    for ev in window[:_MAX_PATHS_IN_PROMPT]:
        path = _sanitize(ev.path or "", 120)
        status = f" [{ev.status_code}]" if ev.status_code else ""
        paths.append(f"  {ev.method or 'GET'} {path}{status}")

    return _USER_TEMPLATE.format(
        src_ip=_sanitize(window[0].src_ip, 45) if window else "unknown",
        n_events=features.get("n_events", len(window)),
        rate_rps=features.get("rate_rps", 0.0),
        inter_ms=features.get("inter_arrival_mean_ms", 0.0),
        ratio_4xx=features.get("ratio_4xx", 0.0),
        max_paths=_MAX_PATHS_IN_PROMPT,
        paths_block="\n".join(paths) or "  (none)",
        sigma_hits=features.get("sigma_hits_in_window", 0),
    )


def _coerce_vector(raw: str) -> AttackVector:
    """Map an LLM label to AttackVector, tolerant of both separators.

    The enum mixes conventions (`ai-recon` with a hyphen, `brute_force` with an
    underscore): a blind `.replace()` broke `brute_force` into `brute-force` into
    UNKNOWN. We try the value as-is, then with each separator normalized.
    """
    s = (raw or "unknown").strip().lower()
    for candidate in (s, s.replace("_", "-"), s.replace("-", "_")):
        try:
            return AttackVector(candidate)
        except ValueError:
            continue
    return AttackVector.UNKNOWN


def _parse_response(text: str, window: list[LogEvent]) -> DetectionVerdict:
    """Parse JSON response; on any error return confidence=0 (fail-closed)."""
    try:
        data = json.loads(text)
        vector = _coerce_vector(str(data.get("vector", "unknown")))
        confidence = float(data.get("confidence", 0.0))
        confidence = max(0.0, min(1.0, confidence))
        rationale = _sanitize(str(data.get("rationale", "")), 300)
    except Exception:
        return _fail_closed(window)

    src_ip = window[0].src_ip if window else "unknown"
    now = datetime.now(tz=timezone.utc)
    return DetectionVerdict(
        request_id=str(uuid4()),
        attacker_ip=src_ip,
        vector=vector,
        confidence=confidence,
        rationale=rationale,
        rate_rps=0.0,
        window_start=window[0].timestamp if window else now,
        window_end=window[-1].timestamp if window else now,
        tier_trace=[TierVerdict(tier="T2", triggered=confidence > 0, confidence=confidence,
                                vector=vector, rationale=rationale)],
    )


def _fail_closed(window: list[LogEvent]) -> DetectionVerdict:
    src_ip = window[0].src_ip if window else "unknown"
    now = datetime.now(tz=timezone.utc)
    return DetectionVerdict(
        request_id=str(uuid4()),
        attacker_ip=src_ip,
        vector=AttackVector.UNKNOWN,
        confidence=0.0,
        rationale="T2 unavailable or parse error — fail-closed",
        rate_rps=0.0,
        window_start=window[0].timestamp if window else now,
        window_end=window[-1].timestamp if window else now,
        tier_trace=[TierVerdict(tier="T2", triggered=False, confidence=0.0,
                                vector=None, rationale="fail-closed")],
    )


class LLMClassifier:
    """Tier 2 classifier wrapping OVH AI Endpoints (OpenAI-compatible)."""

    def __init__(self, *, base_url: str, api_key: str, model: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.enabled = bool(base_url and api_key)

    async def classify(self, window: list[LogEvent], features: dict | None = None) -> DetectionVerdict:
        """Classify a window via the LLM. Fail-closed on any error."""
        if not self.enabled or not window:
            return _fail_closed(window)

        feats = features or {}
        prompt = _build_prompt(window, feats)

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
            "max_tokens": 200,
            "temperature": 0.1,
        }

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT_S) as client:
                resp = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                global LLM_TOKENS_TOTAL
                LLM_TOKENS_TOTAL += int((data.get("usage") or {}).get("total_tokens", 0) or 0)
                content = data["choices"][0]["message"]["content"]
                return _parse_response(content, window)
        except Exception:
            return _fail_closed(window)
