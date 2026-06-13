"""
Tier 1: XGBoost model training (ADR-003).

The model classifies a 10 s sliding window (WindowFeatures) into
{benign, recon, brute_force, ai_recon, injection, traversal}.

Methodological honesty: lacking a deployable labelled corpus (CIC-IDS2017
planned on the roadmap), we train on SYNTHETIC windows calibrated on the real
feature semantics (per-class distributions below). The model then runs real
XGBoost inference (~µs) on live features.
Retrainable on real traffic: replace `_sample()` with a corpus loader.

Usage:  python -m services.sentinel.train_tier1
Output: services/sentinel/models/tier1_xgboost.json
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import xgboost as xgb

# MUST match services/sentinel/tier1.py EXACTLY (FEATURE_ORDER + CLASSES).
# Duplicated here on purpose: the training script stays standalone (numpy + xgboost
# only), without pulling in the services' pydantic import chain.
FEATURE_ORDER = [
    "rate_rps", "n_events", "unique_path_ratio", "ua_entropy",
    "ratio_4xx", "ratio_5xx", "ratio_200",
    "inter_arrival_mean_ms", "inter_arrival_p95_ms",
    "n_distinct_status", "n_distinct_methods",
    "sigma_hits_in_window", "owasp_coverage",
]
CLASSES = ["benign", "recon", "brute_force", "ai_recon", "injection", "traversal"]

_SEED = 20260602
_N_PER_CLASS = 4000
_OUT = Path(__file__).parent / "models" / "tier1_xgboost.json"


def _sample(cls: str, rng: np.random.Generator) -> list[float]:
    """Sample a plausible feature vector for a given class.

    The ranges OVERLAP on purpose (realism) so the model learns boundaries
    rather than a trivial separation.
    """
    if cls == "benign":            # human browsing: slow, few 4xx, 200 dominant
        rps, inter = rng.uniform(0.05, 3.0), rng.uniform(2000, 15000)
        r4, r5, r2 = rng.uniform(0, 0.12), rng.uniform(0, 0.03), rng.uniform(0.80, 1.0)
        upr, uae = rng.uniform(0.20, 0.80), rng.uniform(0.4, 2.6)
        ne, ndm, nds, sig, owc = rng.integers(3, 30), rng.integers(1, 3), rng.integers(1, 3), 0, rng.uniform(0, 0.20)
    elif cls == "recon":           # broad scanner: fast, high 4xx, varied paths, wide OWASP coverage
        rps, inter = rng.uniform(4, 70), rng.uniform(40, 1600)
        r4, r5, r2 = rng.uniform(0.35, 0.90), rng.uniform(0, 0.05), rng.uniform(0.05, 0.50)
        upr, uae = rng.uniform(0.70, 1.0), rng.uniform(0, 0.6)
        ne, ndm, nds, sig, owc = rng.integers(10, 100), rng.integers(1, 3), rng.integers(2, 5), rng.integers(1, 9), rng.uniform(0.40, 1.0)
    elif cls == "brute_force":     # login hammering: same path, 401/403, single POST
        rps, inter = rng.uniform(2, 30), rng.uniform(150, 2500)
        r4, r5, r2 = rng.uniform(0.40, 0.95), rng.uniform(0, 0.03), rng.uniform(0, 0.30)
        upr, uae = rng.uniform(0.03, 0.30), rng.uniform(0, 0.8)
        ne, ndm, nds, sig, owc = rng.integers(10, 90), 1, rng.integers(1, 3), rng.integers(0, 6), rng.uniform(0, 0.30)
    elif cls == "ai_recon":        # LLM agent: VERY regular timing 300 to 1700 ms, methodical paths
        rps, inter = rng.uniform(0.8, 18), rng.uniform(300, 1700)
        r4, r5, r2 = rng.uniform(0.15, 0.70), rng.uniform(0, 0.04), rng.uniform(0.20, 0.70)
        upr, uae = rng.uniform(0.50, 1.0), rng.uniform(0, 0.5)
        ne, ndm, nds, sig, owc = rng.integers(5, 50), rng.integers(1, 3), rng.integers(2, 5), rng.integers(0, 6), rng.uniform(0.30, 0.95)
    elif cls == "injection":       # SQLi/payloads: high sigma_hits, a few 5xx
        rps, inter = rng.uniform(1, 30), rng.uniform(200, 4000)
        r4, r5, r2 = rng.uniform(0.20, 0.80), rng.uniform(0, 0.20), rng.uniform(0.10, 0.60)
        upr, uae = rng.uniform(0.30, 0.90), rng.uniform(0, 1.0)
        ne, ndm, nds, sig, owc = rng.integers(4, 50), rng.integers(1, 3), rng.integers(2, 5), rng.integers(2, 9), rng.uniform(0.10, 0.60)
    else:                          # traversal: ../, /etc/passwd → high sigma_hits
        rps, inter = rng.uniform(1, 30), rng.uniform(200, 4000)
        r4, r5, r2 = rng.uniform(0.30, 0.90), rng.uniform(0, 0.10), rng.uniform(0.05, 0.50)
        upr, uae = rng.uniform(0.40, 1.0), rng.uniform(0, 1.0)
        ne, ndm, nds, sig, owc = rng.integers(4, 50), rng.integers(1, 3), rng.integers(2, 5), rng.integers(2, 9), rng.uniform(0.20, 0.80)

    vals = {
        "rate_rps": rps, "n_events": ne, "unique_path_ratio": upr, "ua_entropy": uae,
        "ratio_4xx": r4, "ratio_5xx": r5, "ratio_200": r2,
        "inter_arrival_mean_ms": inter, "inter_arrival_p95_ms": inter * rng.uniform(1.0, 2.2),
        "n_distinct_status": nds, "n_distinct_methods": ndm,
        "sigma_hits_in_window": sig, "owasp_coverage": owc,
    }
    return [float(vals[k]) for k in FEATURE_ORDER]


def main() -> None:
    rng = np.random.default_rng(_SEED)
    X, y = [], []
    for label, cls in enumerate(CLASSES):
        for _ in range(_N_PER_CLASS):
            X.append(_sample(cls, rng))
            y.append(label)
    X = np.asarray(X, dtype="float32")
    y = np.asarray(y, dtype="int32")

    # Reproducible train/val split (80/20)
    idx = rng.permutation(len(y))
    X, y = X[idx], y[idx]
    cut = int(0.8 * len(y))
    Xtr, ytr, Xva, yva = X[:cut], y[:cut], X[cut:], y[cut:]

    dtrain = xgb.DMatrix(Xtr, label=ytr, feature_names=FEATURE_ORDER)
    dval = xgb.DMatrix(Xva, label=yva, feature_names=FEATURE_ORDER)
    params = {
        "objective": "multi:softprob", "num_class": len(CLASSES),
        "max_depth": 5, "eta": 0.3, "subsample": 0.9, "colsample_bytree": 0.9,
        "eval_metric": "mlogloss", "seed": _SEED,
    }
    booster = xgb.train(params, dtrain, num_boost_round=120,
                        evals=[(dval, "val")], verbose_eval=False)

    # Val metrics (numpy only, no sklearn)
    probs = booster.predict(dval)
    pred = probs.argmax(axis=1)
    acc = float((pred == yva).mean())
    print(f"val accuracy = {acc:.4f}  ({len(yva)} échantillons)")
    # Binary recall attack vs benign (benign = class 0)
    is_atk_true = yva != 0
    is_atk_pred = pred != 0
    tp = int((is_atk_pred & is_atk_true).sum()); fn = int((~is_atk_pred & is_atk_true).sum())
    fp = int((is_atk_pred & ~is_atk_true).sum())
    recall = tp / max(tp + fn, 1); precision = tp / max(tp + fp, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    print(f"attaque vs benign : precision={precision:.3f} recall={recall:.3f} F1={f1:.3f}")
    for i, cls in enumerate(CLASSES):
        m = yva == i
        if m.any():
            print(f"  {cls:12s} acc={float((pred[m] == i).mean()):.3f}")

    _OUT.parent.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(_OUT))
    print(f"modèle sauvegardé → {_OUT}")


if __name__ == "__main__":
    main()
