"""Sentinel · T0 to T1 to T2 cascade.

Cascade:
  T0  Sigma rules (deterministic)     : 60-70% of traffic dropped
  T1  Feature scoring (heuristic)     : ~25% of the remaining traffic
  T2  LLM via OVH AI Endpoints        : only the ~5% that are ambiguous

Endpoints:
  POST /logs             · ingest a batch of LogEvent
  POST /canary-hit       · Ghost Shell callback, confirmed AI agent (high-conf)
  GET  /health           · liveness
  GET  /state/{ip}       · debug, the sliding window of an IP
"""
from __future__ import annotations

import os
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Deque
from uuid import uuid4

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request

try:
    import redis  # type: ignore
except Exception:                              # redis-py missing, run in degraded mode
    redis = None  # type: ignore

from services.sentinel import classifier as classifier_mod
from services.sentinel import heuristics, tier0, tier1
from services.shared import logging_config
from services.shared.a2a_protocol import sign_request
from services.shared.secrets import check_reset_secret, resolve_secret
from services.shared.models import (
    AttackSignal,
    AttackVector,
    DetectionVerdict,
    LogEvent,
    TierVerdict,
)

log = logging_config.setup("sentinel")
app = FastAPI(title="Mir[AI]ge · Sentinel", version="1.0.0")

# ── Sliding window per src_ip ──────────────────────────────────────────────
WINDOW_SECONDS = 10
WINDOWS: dict[str, Deque[LogEvent]] = defaultdict(lambda: deque(maxlen=500))

# ── CUMULATIVE behavioral detector (covers the blind spot for slow AI agents) ──────────────
# An LLM agent "thinks" between two actions (inference latency 2-45 s), so often just one
# event per 10 s window, which makes the velocity cascade (T0/T1) structurally blind (85% of
# windows skipped during a campaign). Its real signature is not SPEED but BREADTH: it sweeps
# methodically through several families of sensitive resources (secrets, admin, backup, infra,
# API). We accumulate, per IP, the OWASP families touched over a long horizon; past the
# threshold we return an AI_RECON verdict, independent of velocity. Ref: Palisade (behavior > rate).
RECON_HORIZON_SECONDS = 300
RECON_FAMILY_THRESHOLD = 3            # >= 3 of the 5 distinct OWASP families
IP_RECON: dict[str, dict] = {}

_RECON_FAMILIES: dict[str, tuple[str, ...]] = {
    "secrets_env": ("/.env", "/.git", "/.aws", "/.kube", "/.ssh", "/secrets", "/vault", "/credential"),
    "api_enum":    ("/api/", "/v1/", "/graphql", "/swagger", "/openapi", "/.well-known", "/namespaces"),
    "admin":       ("/admin", "/manager", "/actuator", "/wp-admin", "/console", "/phpmyadmin"),
    "backup":      ("/backup", "/dump", ".sql", ".bak", "/db_", "/archive", "/s3"),
    "infra":       ("/var/log", "/etc/", "/proc/", "/metadata", "/server-status", "/fs/"),
}


def _recon_family(path: str) -> str | None:
    p = (path or "").lower()
    for fam, markers in _RECON_FAMILIES.items():
        if any(m in p for m in markers):
            return fam
    return None


def _cumulative_recon_check(ev: LogEvent, now: datetime, key: str, bg) -> bool:
    """Catch a methodical AI agent by the BREADTH of its recon (no velocity needed). Fires once per IP."""
    from services.shared.models import AttackVector, TierVerdict  # local import: no NameError
    fam = _recon_family(ev.path)
    if fam is None:
        return False
    rec = IP_RECON.get(ev.src_ip)
    if rec is None or (now - rec["last"]).total_seconds() > RECON_HORIZON_SECONDS:
        rec = {"families": set(), "first": now, "last": now, "fired": False}
        IP_RECON[ev.src_ip] = rec
    rec["families"].add(fam)
    rec["last"] = now
    if rec["fired"] or len(rec["families"]) < RECON_FAMILY_THRESHOLD or _cooldown_check(key):
        return False
    rec["fired"] = True
    STATS["cumulative_recon_triggered"] = STATS.get("cumulative_recon_triggered", 0) + 1
    fams = ",".join(sorted(rec["families"]))
    verdict = _make_verdict(
        ip=ev.src_ip, attacker_session=ev.session_id,
        vector=AttackVector.AI_RECON,
        confidence=0.86,
        rationale=f"recon cumulative : {len(rec['families'])}/5 familles OWASP en <{RECON_HORIZON_SECONDS}s ({fams})",
        rate_rps=0.0,
        window=[ev],
        tier_trace=[TierVerdict(tier="behavioral", triggered=True, confidence=0.86,
                                vector=AttackVector.AI_RECON,
                                rationale="largeur de recon OWASP — capte l'agent IA lent (hors vélocité)")],
    )
    bg.add_task(_emit_signal, verdict)
    return True
LAST_CLEANUP = datetime.now(tz=timezone.utc)
CLEANUP_INTERVAL = timedelta(seconds=60)

# ── Per-IP alert cooldown, prevent duplicate morphs for the same attacker ──
# Once we fire a signal for an IP, suppress further signals for the honeypot TTL.
ALERTED_IPS: dict[str, datetime] = {}
ALERT_COOLDOWN_SECONDS = int(os.environ.get("HONEYPOT_TTL_SECONDS", "1800"))

# ── Config ─────────────────────────────────────────────────────────────────
ORCHESTRATOR_URL = os.environ.get("ORCHESTRATOR_URL", "http://orchestrator:8002")
A2A_SECRET = resolve_secret("A2A_SHARED_SECRET", "dev-secret")
DETECTION_THRESHOLD = float(os.environ.get("SENTINEL_DETECTION_THRESHOLD", "0.75"))
RPS_THRESHOLD = float(os.environ.get("ATTACK_VELOCITY_RPS_THRESHOLD", "20"))
TARGET_INSTANCE_ID = os.environ.get("TARGET_VM_NAME", "miraige-portal-prod")
SENTINEL_STUB = os.environ.get("SENTINEL_STUB", "0") == "1"
RESET_SECRET = resolve_secret("MG_RESET_SECRET", "miraige-reset-2026")

_AI_BASE_URL = os.environ.get("AI_ENDPOINTS_BASE_URL", "")
_AI_KEY = os.environ.get("AI_ENDPOINTS_API_KEY", "")
_AI_MODEL = os.environ.get("AI_MODEL_CLASSIFIER", "Llama-3.1-8B-Instruct")

_classifier = classifier_mod.LLMClassifier(
    base_url=_AI_BASE_URL,
    api_key=_AI_KEY,
    model=_AI_MODEL,
)

# ── Redis client (store last DetectionVerdict per IP, for the dashboard) ──
_REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
_REDIS_CLIENT = None
_TRACE_TTL = ALERT_COOLDOWN_SECONDS  # same TTL as the cooldown
if redis is not None:
    try:
        _REDIS_CLIENT = redis.from_url(_REDIS_URL, socket_timeout=1.0)
        _REDIS_CLIENT.ping()
    except Exception:
        _REDIS_CLIENT = None

# ── Cascade counters (in-memory · for the /stats endpoint) ───────────────────
# Each ingested LogEvent bumps exactly ONE tier counter, which reflects
# where it stopped in the cascade.
STATS: dict[str, int] = {
    "events_total":          0,  # every ingestion
    "t0_eliminated":         0,  # 0 Sigma hits + heuristic gate negative, stopped after T0
    "t0_critical_triggered": 0,  # critical rule, direct trigger, skip T1/T2
    "t1_evaluations":        0,  # T1 was computed
    "t1_high_triggered":     0,  # T1 >= 0.85, direct trigger, skip T2
    "t1_benign":             0,  # T1 < 0.40, discard
    "t2_evaluations":        0,  # T1 in [0.40, 0.85), LLM called
    "t2_triggered":          0,  # T2 >= DETECTION_THRESHOLD, MTD
    "canary_triggered":      0,  # /canary-hit used
    "window_skipped_small":  0,  # window < 3 events, skip (but event counted as T0-eliminated)
}


def _store_verdict(verdict: DetectionVerdict) -> None:
    """Persist the latest verdict for this IP (TTL = cooldown). Best-effort."""
    if _REDIS_CLIENT is None:
        return
    try:
        payload = verdict.model_dump_json()
        _REDIS_CLIENT.setex(f"tier_trace:{verdict.attacker_ip}", _TRACE_TTL, payload)
        if verdict.attacker_session:
            _REDIS_CLIENT.setex(f"tier_trace:sess:{verdict.attacker_session}", _TRACE_TTL, payload)
    except Exception:
        pass


# ── Helpers ────────────────────────────────────────────────────────────────


def _prune_window(window: Deque[LogEvent], now: datetime) -> None:
    """Remove events older than WINDOW_SECONDS from the left of the deque."""
    cutoff = now - timedelta(seconds=WINDOW_SECONDS)
    if cutoff.tzinfo is not None:
        cutoff = cutoff.replace(tzinfo=None)
    while window:
        ts = window[0].timestamp
        if ts.tzinfo is not None:
            ts = ts.replace(tzinfo=None)
        if ts < cutoff:
            window.popleft()
        else:
            break


def _cooldown_check(ip: str) -> bool:
    """Return True if we should suppress a new signal for this IP (still in cooldown)."""
    now = datetime.now(tz=timezone.utc)
    last = ALERTED_IPS.get(ip)
    if last is not None:
        elapsed = (now - last).total_seconds()
        if elapsed < ALERT_COOLDOWN_SECONDS:
            return True
    ALERTED_IPS[ip] = now
    return False


async def _emit_signal(verdict: DetectionVerdict) -> None:
    """POST AttackSignal to Orchestrator (signed with HMAC-SHA256).
    Also persist the verdict in Redis so the dashboard can read it."""
    _store_verdict(verdict)

    signal = AttackSignal(
        request_id=verdict.request_id,
        attacker_ip=verdict.attacker_ip,
        attacker_session=verdict.attacker_session,
        target_instance_id=TARGET_INSTANCE_ID,
        vector=verdict.vector,
        confidence=verdict.confidence,
        rate_rps=verdict.rate_rps,
    )
    body = signal.model_dump_json().encode()
    headers = sign_request(body, secret=A2A_SECRET, agent_id="sentinel")
    headers["Content-Type"] = "application/json"

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(f"{ORCHESTRATOR_URL}/signal", content=body, headers=headers)
            resp.raise_for_status()
        log.info("signal_emitted ip=%s vector=%s confidence=%.2f",
                 verdict.attacker_ip, verdict.vector, verdict.confidence)
    except Exception as exc:
        log.warning("signal_emit_failed ip=%s error=%s", verdict.attacker_ip, exc)


def _make_verdict(
    ip: str,
    vector: AttackVector,
    confidence: float,
    rationale: str,
    rate_rps: float,
    window: list[LogEvent],
    tier_trace: list[TierVerdict],
    attacker_session: str | None = None,
) -> DetectionVerdict:
    now = datetime.now(tz=timezone.utc)
    return DetectionVerdict(
        request_id=str(uuid4()),
        attacker_ip=ip,
        attacker_session=attacker_session,
        vector=vector,
        confidence=confidence,
        rationale=rationale,
        rate_rps=rate_rps,
        window_start=window[0].timestamp if window else now,
        window_end=window[-1].timestamp if window else now,
        tier_trace=tier_trace,
    )


# ── Endpoints ──────────────────────────────────────────────────────────────


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "sentinel"}


@app.post("/logs")
async def ingest_logs(events: list[LogEvent], bg: BackgroundTasks) -> dict[str, int]:
    """Ingest a batch of LogEvent and run the T0 → T1 → T2 detection cascade."""
    global LAST_CLEANUP
    triggered = 0

    now = datetime.now(tz=timezone.utc)
    if now - LAST_CLEANUP > CLEANUP_INTERVAL:
        expired_ips = []
        for ip, deq in WINDOWS.items():
            _prune_window(deq, now)
            if not deq:
                expired_ips.append(ip)
        for ip in expired_ips:
            del WINDOWS[ip]
        LAST_CLEANUP = now

    for idx, ev in enumerate(events):
        STATS["events_total"] += 1
        now = datetime.now(tz=timezone.utc)
        # Window keyed by SESSION (mg_session cookie) when present, otherwise by IP, so we track by identity.
        key = ev.session_id or ev.src_ip
        window_deque = WINDOWS[key]
        window_deque.append(ev)
        _prune_window(window_deque, now)

        tier_trace: list[TierVerdict] = []

        # ── T0: per-event Sigma matching ──────────────────────────────
        t0_hits = tier0.match_event(ev, idx)
        critical_hits = [h for h in t0_hits if h.severity == "critical"]

        if critical_hits:
            STATS["t0_critical_triggered"] += 1
            hit = critical_hits[0]
            rps = heuristics.compute_rps(list(window_deque))
            vector = heuristics.dominant_vector(list(window_deque))
            tier_trace.append(TierVerdict(
                tier="T0",
                triggered=True,
                confidence=0.95,
                vector=vector,
                rationale=f"Sigma rule '{hit.rule_title}' matched (critical)",
            ))
            verdict = _make_verdict(
                ip=ev.src_ip, attacker_session=ev.session_id,
                vector=vector,
                confidence=0.95,
                rationale=f"T0 critical: {hit.rule_title}",
                rate_rps=rps,
                window=list(window_deque),
                tier_trace=tier_trace,
            )
            if not _cooldown_check(key):
                bg.add_task(_emit_signal, verdict)
                triggered += 1
                log.info("t0_critical_trigger ip=%s rule=%s", ev.src_ip, hit.rule_id)
            WINDOWS[key].clear()
            continue

        # ── CUMULATIVE behavioral detection (slow AI agents: ~1 event per window, so the
        #    velocity cascade below is blind). OWASP recon breadth, no speed needed. ──
        try:
            if _cumulative_recon_check(ev, now, key, bg):
                triggered += 1
                continue
        except Exception:
            pass

        # Accumulate sigma hits for T1 feature vector
        window_snapshot = list(window_deque)
        if len(window_snapshot) < 3:
            STATS["window_skipped_small"] += 1
            STATS["t0_eliminated"] += 1
            continue

        # ── Cheap heuristic gate (avoids spending T1/T2 compute) ──────
        if not heuristics.looks_suspicious(window_snapshot, rps_threshold=RPS_THRESHOLD):
            STATS["t0_eliminated"] += 1
            continue

        # ── SENTINEL_STUB mode: offline demo without LLM ─────────────
        if SENTINEL_STUB:
            STATS["t1_evaluations"] += 1   # honesty: we did go through the T1 phase
            rps = heuristics.compute_rps(window_snapshot)
            if rps > 100:
                STATS["t1_high_triggered"] += 1
                stub_vector = heuristics.dominant_vector(window_snapshot)
                verdict = _make_verdict(
                    ip=ev.src_ip, attacker_session=ev.session_id,
                    vector=stub_vector,
                    confidence=0.85,
                    rationale="stub mode: rps > 100 forced confidence",
                    rate_rps=rps,
                    window=window_snapshot,
                    tier_trace=[TierVerdict(tier="T1", triggered=True, confidence=0.85,
                                            vector=stub_vector, rationale="SENTINEL_STUB=1 · rps > 100")],
                )
                bg.add_task(_emit_signal, verdict)
                WINDOWS[key].clear()
                triggered += 1
                log.info("stub_trigger ip=%s rps=%.1f", ev.src_ip, rps)
            else:
                STATS["t1_benign"] += 1
            continue

        # ── T1: statistical feature scoring ───────────────────────────
        STATS["t1_evaluations"] += 1
        sigma_hits_count = sum(
            len(tier0.match_event(e, i)) for i, e in enumerate(window_snapshot)
        )
        features = tier1.extract_features(window_snapshot, sigma_hits=sigma_hits_count)
        t1_conf, t1_vector = tier1.predict(features)

        tier_trace.append(TierVerdict(
            tier="T1",
            triggered=t1_conf >= 0.40,
            confidence=t1_conf,
            vector=t1_vector,
            rationale=(
                f"rate={features.rate_rps:.1f} rps, "
                f"inter_mean={features.inter_arrival_mean_ms:.0f} ms, "
                f"4xx={features.ratio_4xx:.0%}, "
                f"sigma_hits={features.sigma_hits_in_window}, "
                f"ua_entropy={features.ua_entropy:.2f}, "
                f"unique_path_ratio={features.unique_path_ratio:.2f}"
            ),
        ))

        if t1_conf >= 0.85:
            STATS["t1_high_triggered"] += 1
            # High confidence, skip LLM, trigger directly
            verdict = _make_verdict(
                ip=ev.src_ip, attacker_session=ev.session_id,
                vector=t1_vector,
                confidence=t1_conf,
                rationale="T1 high-confidence detection",
                rate_rps=features.rate_rps,
                window=window_snapshot,
                tier_trace=tier_trace,
            )
            if not _cooldown_check(key):
                bg.add_task(_emit_signal, verdict)
                triggered += 1
                log.info("t1_trigger ip=%s conf=%.2f vector=%s", ev.src_ip, t1_conf, t1_vector)
            WINDOWS[key].clear()
            continue

        if t1_conf < 0.40:
            STATS["t1_benign"] += 1
            continue  # benign

        # ── T2: LLM for ambiguous cases (0.40 ≤ conf < 0.85) ─────────
        STATS["t2_evaluations"] += 1
        feat_dict = features.model_dump()
        verdict = await _classifier.classify(window_snapshot, features=feat_dict)

        # Merge T1 tier_trace into T2 verdict
        verdict.tier_trace = tier_trace + verdict.tier_trace

        # Use T1 rate_rps (T2 doesn't compute it)
        verdict.rate_rps = features.rate_rps
        verdict.attacker_session = ev.session_id

        if verdict.confidence >= DETECTION_THRESHOLD:
            STATS["t2_triggered"] += 1
            if not _cooldown_check(key):
                bg.add_task(_emit_signal, verdict)
                triggered += 1
                log.info("t2_trigger ip=%s conf=%.2f vector=%s", ev.src_ip, verdict.confidence, verdict.vector)
            WINDOWS[key].clear()

    return {"processed": len(events), "triggered": triggered}


@app.post("/admin/reset")
async def admin_reset(request: Request) -> dict:
    """Clear the Sentinel state (counters + windows + cooldowns). Protected by X-Mg-Reset."""
    if not check_reset_secret(request.headers.get("x-mg-reset"), RESET_SECRET):
        raise HTTPException(status_code=403, detail="forbidden")
    for k in STATS:
        STATS[k] = 0
    WINDOWS.clear()
    IP_RECON.clear()
    ALERTED_IPS.clear()
    classifier_mod.LLM_TOKENS_TOTAL = 0
    log.info("[reset] état Sentinel vidé (compteurs + fenêtres + cooldowns + tokens T2)")
    return {"service": "sentinel", "reset": True}


@app.post("/canary-hit")
async def canary_hit(request: Request, bg: BackgroundTasks) -> dict:
    """Feedback loop from Ghost Shell: an agent followed the PI canary.

    Called by Ghost Shell when POST /admin/acknowledge is triggered.
    This is a near-perfect AI discriminator (humans never follow PI canaries).
    Emits an AI_RECON signal with confidence=0.97 without waiting for T1/T2.

    Expected body: {"src_ip": "...", "session_id": "...", "canary_id": "..."}
    """
    try:
        body = await request.json()
        src_ip = str(body.get("src_ip", "unknown"))
        session_id = str(body.get("session_id", ""))
        canary_id = str(body.get("canary_id", "pi_notice_to_admins"))
    except Exception:
        src_ip = "unknown"
        session_id = ""
        canary_id = "pi_notice_to_admins"

    now = datetime.now(tz=timezone.utc)
    # Windows are keyed by session_id (signed cookie) when present, otherwise by
    # IP. So we look up by session first, then by IP, or else the canary rps would
    # always fall to 0 as soon as an mg_session cookie existed.
    sess_key = session_id if session_id and session_id != "global" else None
    window_snapshot = list(WINDOWS.get(sess_key) or WINDOWS.get(src_ip) or [])
    rps = heuristics.compute_rps(window_snapshot) if window_snapshot else 0.0

    verdict = DetectionVerdict(
        request_id=str(uuid4()),
        attacker_ip=src_ip,
        # FIX (reverted by the feature/Attaque merge): route THE offending session (signed cookie)
        # and NOT the cookieless fallback. Without this, the reroute creates a COOKIE !contains "."
        # rule that never matches a signed cookie, so the flag has no visible effect.
        attacker_session=session_id if session_id and session_id != "global" else None,
        vector=AttackVector.AI_RECON,
        confidence=0.97,
        rationale=(
            f"Reverse prompt injection canary triggered — "
            f"agent complied with '{canary_id}' instruction "
            f"(session {session_id}). Humans never do this."
        ),
        rate_rps=rps,
        window_start=window_snapshot[0].timestamp if window_snapshot else now,
        window_end=now,
        tier_trace=[
            TierVerdict(
                tier="T0",
                triggered=True,
                confidence=0.97,
                vector=AttackVector.AI_RECON,
                rationale=f"PI canary hit: {canary_id}",
            )
        ],
    )

    STATS["canary_triggered"] += 1
    if not _cooldown_check(src_ip):
        bg.add_task(_emit_signal, verdict)
    log.info("canary_pi_hit ip=%s session=%s canary=%s", src_ip, session_id, canary_id)
    return {"status": "recorded", "src_ip": src_ip, "confidence": 0.97}


@app.get("/state/{src_ip}")
async def debug_state(src_ip: str) -> dict:
    """Debug: inspect the rolling window for one IP."""
    window = list(WINDOWS.get(src_ip, []))
    return {
        "src_ip": src_ip,
        "events_in_window": len(window),
        "last_5": [e.model_dump(mode="json") for e in window[-5:]],
    }


@app.get("/flows")
async def list_flows() -> list[dict]:
    """Snapshot of every flow seen in the sliding window (for the dashboard).

    A "flow" = a window identified by session_id (or src_ip as a fallback).
    Cross-referenced on the dashboard side with Ghost Shell `/sessions` and the
    orchestrator `/state` to mark a flow as REROUTED.
    """
    now = datetime.now(tz=timezone.utc)
    out: list[dict] = []
    for key, deq in list(WINDOWS.items()):
        if not deq:
            continue
        events = list(deq)
        last = events[-1]
        first = events[0]
        # Real IP (the key may be a session_id)
        src_ip = last.src_ip
        session_id = last.session_id or (key if not last.src_ip == key else None)
        # Light heuristic "suspicious" score (rps + 4xx ratio)
        try:
            rps = heuristics.compute_rps(events)
        except Exception:
            rps = 0.0
        n4xx = sum(1 for e in events if e.status_code and 400 <= e.status_code < 500)
        ratio_4xx = (n4xx / len(events)) if events else 0.0
        cooldown_active = key in ALERTED_IPS and (now - ALERTED_IPS[key]).total_seconds() < ALERT_COOLDOWN_SECONDS
        out.append({
            "key": key,
            "src_ip": src_ip,
            "session_id": session_id,
            "n_events": len(events),
            "rate_rps": round(rps, 2),
            "ratio_4xx": round(ratio_4xx, 2),
            "first_seen": first.timestamp.isoformat(),
            "last_seen": last.timestamp.isoformat(),
            "last_path": last.path or "—",
            "last_method": last.method or "—",
            "last_status": last.status_code or 0,
            "last_ua": last.raw.split('"')[-2] if '"' in last.raw else "—",
            "flagged": cooldown_active,
        })
    # Most recent first
    out.sort(key=lambda f: f["last_seen"], reverse=True)
    return out


@app.get("/stats")
async def cascade_stats() -> dict:
    """Real counters per cascade tier, feeds the Detection page.

    Returns:
      counters     : raw values bumped on each ingested event
      percentages  : relative weight of each tier over events_total
      tiers        : display-ready aggregation (eliminated/escalated/triggered)
    """
    total = max(STATS["events_total"], 1)  # avoid division by zero
    pct = {k: round(100.0 * v / total, 1) for k, v in STATS.items() if k != "events_total"}

    # Cascade re-aggregation: who saw each event?
    t0_visible = total                                  # T0 sees everything
    t1_visible = STATS["t1_evaluations"]
    t2_visible = STATS["t2_evaluations"]

    t2_processed_at = STATS["t2_evaluations"]   # reaches T2

    triggered_total = (STATS["t0_critical_triggered"] + STATS["t1_high_triggered"]
                       + STATS["t2_triggered"] + STATS["canary_triggered"])

    return {
        "counters": dict(STATS),
        "percentages": pct,
        "tiers": {
            "T0": {
                "visible":    t0_visible,
                "eliminated": STATS["t0_eliminated"],         # filtered out without escalation
                "triggered":  STATS["t0_critical_triggered"], # Sigma critical, direct MTD
                "pct_eliminated": round(100.0 * STATS["t0_eliminated"] / total, 1),
            },
            "T1": {
                "visible":    t1_visible,
                "eliminated": STATS["t1_benign"],
                "triggered":  STATS["t1_high_triggered"],
                "escalated":  STATS["t2_evaluations"],
                "pct_visible": round(100.0 * t1_visible / total, 1),
            },
            "T2": {
                "visible":   t2_processed_at,
                "triggered": STATS["t2_triggered"],
                "pct_visible": round(100.0 * t2_visible / total, 1),
            },
            "canary": {
                "triggered": STATS["canary_triggered"],
            },
        },
        "triggered_total": triggered_total,
        "events_total":    STATS["events_total"],
        "t2_tokens_total": classifier_mod.LLM_TOKENS_TOTAL,
        "detection_threshold": DETECTION_THRESHOLD,
        "rps_threshold":       RPS_THRESHOLD,
    }


@app.get("/tier-trace/{key}")
async def tier_trace(key: str) -> dict:
    """Return the latest DetectionVerdict emitted for this IP (or session_id).

    Lookup in priority order:
      1. tier_trace:sess:<key>   (if key = session_id)
      2. tier_trace:<key>         (if key = IP)
    """
    if _REDIS_CLIENT is None:
        return {"found": False, "reason": "redis unavailable"}
    try:
        raw = _REDIS_CLIENT.get(f"tier_trace:sess:{key}")
        if raw is None:
            raw = _REDIS_CLIENT.get(f"tier_trace:{key}")
        if raw is None:
            return {"found": False, "key": key}
        import json
        verdict = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
        return {"found": True, "key": key, "verdict": verdict}
    except Exception as exc:
        return {"found": False, "reason": str(exc)}
