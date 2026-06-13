"""Sentinel Tier 1: feature extraction + XGBoost classifier (ADR-003).

T1 loads a multiclass XGBoost model (trained offline by train_tier1.py)
and classifies the 10s window into {benign, recon, brute_force, ai_recon, injection,
traversal}. Local inference takes ~µs. Fallback: calibrated heuristic scoring if the
model or the xgboost lib is unavailable (robustness / cold start).

Key discriminant: inter_arrival_mean_ms < 1700 ms signals AI agent pacing
(median observed: ~1.2 s for LLM-driven recon vs >5 s for human browsing).
"""
from __future__ import annotations

import logging
import math
from collections import Counter
from pathlib import Path

from services.shared.models import AttackVector, LogEvent, WindowFeatures

log = logging.getLogger("sentinel.tier1")

# Timing threshold from research paper (§5)
_AI_TIMING_MS = 1700.0

# S4 · OWASP recon families: multi-family coverage within a window signals a
# broad scanner (re-applied after the revert of the feature/Attaque merge).
_OWASP_BUCKETS = {
    "secrets_env": ("/.env", "/.git", "/config", "/.aws", "/.kube", "/.ssh", "/secrets"),
    "api_enum":    ("/api/", "/v1/", "/graphql", "/swagger", "/openapi", "/.well-known"),
    "admin":       ("/admin", "/manager", "/actuator", "/wp-admin", "/console", "/phpmyadmin"),
    "backup":      ("/backup", "/dump", ".sql", ".bak", "/db_", "/archive"),
    "infra":       ("/var/log", "/etc/", "/proc/", "/metadata", "/.docker", "/server-status"),
}


def _owasp_coverage(window: list[LogEvent]) -> float:
    """Fraction of OWASP recon families hit within the window, in [0,1]."""
    paths = [(ev.path or "").lower() for ev in window]
    hit = sum(
        1 for needles in _OWASP_BUCKETS.values()
        if any(any(nd in p for nd in needles) for p in paths)
    )
    return hit / len(_OWASP_BUCKETS)


# ── Feature extraction ─────────────────────────────────────────────────────


def _ua_entropy(window: list[LogEvent]) -> float:
    """Shannon entropy of User-Agent strings inferred from raw log lines."""
    uas: list[str] = []
    for ev in window:
        raw = ev.raw or ""
        # CLF/ELF format: ... "GET /path" STATUS SIZE "referer" "UA"
        parts = raw.split('"')
        ua = parts[5].strip() if len(parts) >= 6 else raw[-80:]
        uas.append(ua)

    if not uas:
        return 0.0
    counts = Counter(uas)
    total = len(uas)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def extract_features(window: list[LogEvent], sigma_hits: int = 0) -> WindowFeatures:
    """Build a WindowFeatures vector from a 10-second event window."""
    n = len(window)
    if n == 0:
        return WindowFeatures(
            rate_rps=0.0, n_events=0, n_unique_paths=0, unique_path_ratio=0.0,
            ua_entropy=0.0, ratio_4xx=0.0, ratio_5xx=0.0, ratio_200=0.0,
            inter_arrival_mean_ms=0.0, inter_arrival_p95_ms=0.0,
            n_distinct_status=0, n_distinct_methods=0, sigma_hits_in_window=0,
        )

    timestamps = [ev.timestamp for ev in window]
    dt = (timestamps[-1] - timestamps[0]).total_seconds()
    rate_rps = n / max(dt, 0.001)

    paths = [ev.path or "" for ev in window]
    n_unique = len(set(paths))

    status_codes = [ev.status_code for ev in window if ev.status_code is not None]
    ns = len(status_codes) or 1
    ratio_4xx = sum(1 for s in status_codes if 400 <= s < 500) / ns
    ratio_5xx = sum(1 for s in status_codes if s >= 500) / ns
    ratio_200 = sum(1 for s in status_codes if s == 200) / ns

    # Inter-arrival times (ms)
    arrivals_ms = [
        (timestamps[i] - timestamps[i - 1]).total_seconds() * 1000
        for i in range(1, len(timestamps))
    ]
    if arrivals_ms:
        inter_mean = sum(arrivals_ms) / len(arrivals_ms)
        sorted_a = sorted(arrivals_ms)
        p95_idx = min(int(0.95 * len(sorted_a)), len(sorted_a) - 1)
        inter_p95 = sorted_a[p95_idx]
    else:
        inter_mean = 0.0
        inter_p95 = 0.0

    methods = [ev.method or "" for ev in window]

    return WindowFeatures(
        rate_rps=rate_rps,
        n_events=n,
        n_unique_paths=n_unique,
        unique_path_ratio=n_unique / n,
        ua_entropy=_ua_entropy(window),
        ratio_4xx=ratio_4xx,
        ratio_5xx=ratio_5xx,
        ratio_200=ratio_200,
        inter_arrival_mean_ms=inter_mean,
        inter_arrival_p95_ms=inter_p95,
        n_distinct_status=len(set(status_codes)),
        n_distinct_methods=len(set(methods)),
        sigma_hits_in_window=sigma_hits,
        owasp_coverage=_owasp_coverage(window),
    )


# ── Tier 1 model · XGBoost (ADR-003) ────────────────────────────────────────
# Feature order is FROZEN: must match training exactly
# (train_tier1.py imports this same list).
FEATURE_ORDER = [
    "rate_rps", "n_events", "unique_path_ratio", "ua_entropy",
    "ratio_4xx", "ratio_5xx", "ratio_200",
    "inter_arrival_mean_ms", "inter_arrival_p95_ms",
    "n_distinct_status", "n_distinct_methods",
    "sigma_hits_in_window", "owasp_coverage",
]
# Model class index: 0 = benign, the rest map to AttackVector.
CLASSES = ["benign", "recon", "brute_force", "ai_recon", "injection", "traversal"]
CLASS_TO_VECTOR = {
    1: AttackVector.RECON, 2: AttackVector.BRUTE_FORCE, 3: AttackVector.AI_RECON,
    4: AttackVector.INJECTION, 5: AttackVector.TRAVERSAL,
}
_MODEL_PATH = Path(__file__).parent / "models" / "tier1_xgboost.json"
_booster = None
_model_tried = False


def _load_model():
    """Load the XGBoost Booster once (lazy). None if unavailable."""
    global _booster, _model_tried
    if _model_tried:
        return _booster
    _model_tried = True
    try:
        import xgboost as xgb  # lazy import: the heuristic fallback works without it
        if _MODEL_PATH.exists():
            b = xgb.Booster()
            b.load_model(str(_MODEL_PATH))
            _booster = b
            log.info("Tier1 XGBoost chargé (%s)", _MODEL_PATH.name)
        else:
            log.warning("Tier1 modèle absent (%s) — fallback heuristique", _MODEL_PATH)
    except Exception as e:  # xgboost missing / model corrupted, fall back to heuristic
        log.warning("Tier1 XGBoost indisponible (%s) — fallback heuristique", e)
    return _booster


def _features_to_row(f: WindowFeatures):
    import numpy as np
    return np.asarray(
        [[float(getattr(f, name, 0.0) or 0.0) for name in FEATURE_ORDER]],
        dtype="float32",
    )


# ── Classifier ─────────────────────────────────────────────────────────────


def predict(features: WindowFeatures) -> tuple[float, AttackVector]:
    """Classify the window via XGBoost (ADR-003); heuristic fallback.

    Returns (confidence in [0,1], attack_vector). Cascade bands:
      >= 0.85 : trigger MTD directly (skip T2)
      0.40 to 0.84 : escalate to T2 (LLM)
      < 0.40 : benign, discarded
    confidence = 1 - P(benign); vector = most likely attack class.
    """
    booster = _load_model()
    if booster is not None:
        try:
            import numpy as np
            probs = booster.inplace_predict(_features_to_row(features))[0]
            confidence = max(0.0, min(1.0, 1.0 - float(probs[0])))
            attack_idx = int(np.argmax(probs[1:])) + 1
            return confidence, CLASS_TO_VECTOR.get(attack_idx, AttackVector.UNKNOWN)
        except Exception as e:
            log.warning("Tier1 inférence XGBoost échec (%s) — fallback heuristique", e)
    return _heuristic_predict(features)


def _heuristic_predict(features: WindowFeatures) -> tuple[float, AttackVector]:
    """Calibrated heuristic scoring: fallback when XGBoost is unavailable."""
    score = 0.0

    # ── Velocity signal (high weight) ─────────────────────────────────
    if features.rate_rps > 50:
        score += 0.35
    elif features.rate_rps > 20:
        score += 0.25
    elif features.rate_rps > 5:
        score += 0.10

    # ── AI timing discriminant (highest individual weight) ────────────
    if 0 < features.inter_arrival_mean_ms < _AI_TIMING_MS:
        score += 0.35
    elif 0 < features.inter_arrival_mean_ms < 3000:
        score += 0.10

    # ── Error burst (probing behaviour) ───────────────────────────────
    if features.ratio_4xx > 0.6:
        score += 0.20
    elif features.ratio_4xx > 0.3:
        score += 0.10

    # ── Sigma hits accumulated in window ──────────────────────────────
    if features.sigma_hits_in_window >= 5:
        score += 0.25
    elif features.sigma_hits_in_window > 0:
        score += 0.10

    # ── Broad enumeration (high unique-path ratio) ────────────────────
    if features.unique_path_ratio > 0.8 and features.n_events >= 5:
        score += 0.15
    elif features.unique_path_ratio > 0.6 and features.n_events >= 5:
        score += 0.05

    # ── Single User-Agent (bot-like) ──────────────────────────────────
    if features.ua_entropy < 0.5 and features.n_events >= 3:
        score += 0.10

    # ── S4 · OWASP multi-family coverage (broad scanner): bounded additive signal ──
    if features.owasp_coverage >= 0.6:
        score += 0.15
    elif features.owasp_coverage >= 0.4:
        score += 0.08

    confidence = min(score, 1.0)

    # ── Vector determination ───────────────────────────────────────────
    if 0 < features.inter_arrival_mean_ms < _AI_TIMING_MS:
        vector = AttackVector.AI_RECON
    elif features.ratio_4xx > 0.5 and features.n_distinct_methods <= 1:
        vector = AttackVector.BRUTE_FORCE
    elif features.unique_path_ratio > 0.7:
        vector = AttackVector.RECON
    elif features.sigma_hits_in_window > 0:
        vector = AttackVector.INJECTION
    else:
        vector = AttackVector.UNKNOWN

    return confidence, vector


# Preload at Sentinel startup: the « Tier1 XGBoost chargé » log line (or the heuristic
# fallback warning) is emitted at boot, checkable via `docker logs miraige-sentinel | grep Tier1`.
_load_model()
