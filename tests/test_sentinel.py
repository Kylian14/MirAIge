"""Characterization tests for services/sentinel/ (T0 -> T1 -> T2 cascade).

Locks in the CURRENT behavior of the detection cascade: T0 Sigma rules,
cumulative behavioral detector, T1 heuristic fallback, T2 fail-closed with no
API key, PI canary, and the observability endpoints.

Hermetic:
  - `_emit_signal` is monkeypatched (otherwise httpx to orchestrator + Redis).
  - Redis is absent (port closed via conftest), so /tier-trace reports unavailable.
  - No AI key, so T2 is fail-closed (locked-in behavior).

Isolation: /admin/reset before each test (global in-memory state) plus distinct
IPs per test to avoid the per-IP cooldown.
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import services.sentinel.main as sm
from services.sentinel import heuristics, tier0, tier1
from services.shared.models import AttackVector, WindowFeatures

RESET = "miraige-reset-2026"


# ──────────────────────────────────────────────────────────────────────
# Fixtures & helpers
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def client(monkeypatch):
    """TestClient with _emit_signal neutralized (records the emitted verdicts)."""
    emitted: list = []

    async def fake_emit(verdict):
        emitted.append(verdict)

    monkeypatch.setattr(sm, "_emit_signal", fake_emit)
    c = TestClient(sm.app)
    c.post("/admin/reset", headers={"x-mg-reset": RESET})
    return c, emitted


def _raw(ip: str, method: str, path: str, status: int, ua: str) -> str:
    """CLF-like log line (UA is the 6th segment, in quotes)."""
    return f'{ip} - - "{method} {path}" {status} 0 "-" "{ua}"'


def _events(*, n, spacing_ms, path="/", status=200, method="GET", ip="10.0.0.1",
            ua="Mozilla/5.0", session=None, paths=None):
    """Build n LogEvents ending around now (inside the 10s window)."""
    now = datetime.now(tz=timezone.utc)
    end = now - timedelta(seconds=0.5)
    out = []
    for i in range(n):
        ts = end - timedelta(milliseconds=spacing_ms * (n - 1 - i))
        p = paths[i] if paths else path
        out.append({
            "timestamp": ts.isoformat(),
            "source": "lb",
            "src_ip": ip,
            "session_id": session,
            "method": method,
            "path": p,
            "status_code": status,
            "raw": _raw(ip, method, p, status, ua),
        })
    return out


# ──────────────────────────────────────────────────────────────────────
# 1. Liveness
# ──────────────────────────────────────────────────────────────────────


def test_health(client):
    c, _ = client
    r = c.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "service": "sentinel"}


# ──────────────────────────────────────────────────────────────────────
# 2. Benign batch: no trigger
# ──────────────────────────────────────────────────────────────────────


def test_benign_batch_no_trigger(client):
    c, emitted = client
    # Arrange: 2 normal GET / (window < 3, skipped, counted as t0-eliminated)
    evts = _events(n=2, spacing_ms=3000, path="/", status=200, ip="10.0.0.2")

    # Act
    r = c.post("/logs", json=evts)

    # Assert
    assert r.status_code == 200
    assert r.json() == {"processed": 2, "triggered": 0}
    assert emitted == []
    stats = c.get("/stats").json()
    assert stats["events_total"] == 2
    assert stats["triggered_total"] == 0


# ──────────────────────────────────────────────────────────────────────
# 3. T0: Sigma critical (SQLi) triggers directly; scanner UA accumulates
# ──────────────────────────────────────────────────────────────────────


def test_t0_sqli_critical_triggers(client):
    c, emitted = client
    # Arrange: plain UNION SELECT, matches the sql_injection rule (critical level)
    evts = _events(n=1, spacing_ms=0,
                   path="/products?id=1 UNION SELECT password FROM users",
                   status=200, ip="10.0.0.3")

    # Act
    r = c.post("/logs", json=evts)

    # Assert: a single event is enough (T0 runs before the window<3 guard)
    assert r.json()["triggered"] >= 1
    stats = c.get("/stats").json()
    assert stats["counters"]["t0_critical_triggered"] >= 1
    assert len(emitted) >= 1


def test_traversal_etc_passwd_is_high_not_critical(client):
    c, emitted = client
    # locks in a debatable existing behavior: /etc/passwd is "high" (not
    # "critical"), so it does NOT fire a direct T0 trigger. A single event
    # passes under the window<3 guard and comes back out with no alert.
    evts = _events(n=1, spacing_ms=0, path="/../../etc/passwd", ip="10.0.0.4")

    r = c.post("/logs", json=evts)

    assert r.json()["triggered"] == 0
    # but the Sigma rule does match (severity high)
    from services.shared.models import LogEvent
    hit = tier0.match_event(LogEvent(**{**evts[0]}))
    severities = {h.severity for h in hit}
    assert "high" in severities and "critical" not in severities


def test_scanner_ua_medium_accumulates_without_direct_trigger(client):
    c, emitted = client
    # Arrange: "Nuclei" UA (medium scanner rule) on 2 slow events
    evts = _events(n=2, spacing_ms=4000, path="/", status=200,
                   ip="10.0.0.5", ua="Nuclei - vulnerability scanner")

    # Act
    r = c.post("/logs", json=evts)

    # Assert: medium never arms a direct trigger (window<3 and not suspicious)
    assert r.json()["triggered"] == 0
    assert c.get("/stats").json()["counters"]["t0_critical_triggered"] == 0


# ──────────────────────────────────────────────────────────────────────
# 4. T0.5: cumulative detector (OWASP recon breadth, independent of velocity)
# ──────────────────────────────────────────────────────────────────────


def test_cumulative_recon_three_families_triggers_ai_recon(client):
    c, emitted = client
    # Arrange: 3 distinct OWASP families (secrets_env / api_enum / admin) from
    # the same IP, slowly (an AI agent "thinks" between two actions).
    paths = ["/.env", "/api/v1/users", "/admin"]
    evts = _events(n=3, spacing_ms=20000, paths=paths, status=404, ip="10.0.0.6")
    # NB: 20s spacing exceeds the 10s velocity window, so T0/T1 are blind, but
    # the cumulative horizon is 300s, so the behavioral detector catches it.

    # Act
    r = c.post("/logs", json=evts)

    # Assert: cumulative AI_RECON verdict (confidence 0.86), tier "behavioral".
    # NB: fixed regression. `TierVerdict(tier="behavioral")` was rejected by the
    # Literal in models.py, the ValidationError was swallowed, so 0 signal emitted.
    assert r.json()["triggered"] >= 1
    stats = c.get("/stats").json()
    assert stats["counters"]["cumulative_recon_triggered"] == 1
    assert sm.IP_RECON["10.0.0.6"]["fired"] is True
    assert len(emitted) == 1
    assert emitted[0].vector == AttackVector.AI_RECON
    assert emitted[0].confidence == 0.86
    assert emitted[0].tier_trace[0].tier == "behavioral"


# ──────────────────────────────────────────────────────────────────────
# 5. T1 heuristic fallback: high trigger / grey zone -> T2 fail-closed
# ──────────────────────────────────────────────────────────────────────


def test_t1_high_confidence_direct_trigger(client):
    c, emitted = client
    # Arrange: fast burst (rps>50, inter<1700ms) + 100% 4xx -> score >= 0.85
    evts = _events(n=8, spacing_ms=10, path="/app", status=404, ip="10.0.0.7",
                   paths=[f"/app{i}" for i in range(8)])

    # Act
    r = c.post("/logs", json=evts)

    # Assert: T1 >= 0.85 -> direct trigger, skip T2
    assert r.json()["triggered"] >= 1
    stats = c.get("/stats").json()
    assert stats["counters"]["t1_high_triggered"] >= 1
    assert stats["counters"]["t2_evaluations"] == 0


def test_t1_grey_zone_escalates_to_t2_failclosed(client):
    c, emitted = client
    # Arrange: moderate velocity (rps~30 -> +0.25) + AI timing (+0.35) + unique UA
    # (+0.10) ~ 0.70 in [0.40, 0.85) -> escalate to T2. No API key -> fail-closed.
    evts = _events(n=6, spacing_ms=40, path="/home", status=200, ip="10.0.0.8")

    # Act
    r = c.post("/logs", json=evts)

    # Assert: T2 evaluated but fail-closed (confidence 0) -> no trigger
    assert r.json()["triggered"] == 0
    stats = c.get("/stats").json()
    assert stats["counters"]["t2_evaluations"] >= 1
    assert stats["counters"]["t2_triggered"] == 0
    assert emitted == []


# ──────────────────────────────────────────────────────────────────────
# 6. Canary PI (feedback Ghost Shell)
# ──────────────────────────────────────────────────────────────────────


def test_canary_hit_records_high_confidence(client):
    c, emitted = client
    # Act
    r = c.post("/canary-hit", json={
        "src_ip": "10.0.0.9",
        "session_id": "v1=abc.def",
        "canary_id": "pi_notice_to_admins",
    })

    # Assert
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "recorded"
    assert body["src_ip"] == "10.0.0.9"
    assert body["confidence"] == 0.97
    assert c.get("/stats").json()["counters"]["canary_triggered"] == 1
    assert len(emitted) == 1
    assert emitted[0].confidence == 0.97
    assert emitted[0].vector == AttackVector.AI_RECON


def test_canary_finds_window_by_session_then_ip(client):
    c, emitted = client
    # Arrange: fast events carrying a session_id, so the window is keyed by
    # session (cookie), NOT by IP.
    sid = "v1=sess.deadbeef"
    evts = _events(n=5, spacing_ms=50, path="/x", status=200,
                   ip="10.0.0.20", session=sid)
    c.post("/logs", json=evts)

    # Act: canary with the session_id, the lookup must find the window
    c.post("/canary-hit", json={"src_ip": "10.0.0.20", "session_id": sid})

    # Assert: rps is computed on the window found by session (> 0).
    # Before the fix, lookup by IP alone returned an empty window -> rps 0.
    assert len(emitted) == 1
    assert emitted[0].rate_rps > 0


# ──────────────────────────────────────────────────────────────────────
# 7. Observability: /flows, /state, /tier-trace
# ──────────────────────────────────────────────────────────────────────


def test_flows_and_state_structure(client):
    c, _ = client
    # Arrange: a few benign events to populate a window
    evts = _events(n=2, spacing_ms=1000, path="/dashboard", status=200, ip="10.0.0.10")
    c.post("/logs", json=evts)

    # Act
    flows = c.get("/flows").json()
    state = c.get("/state/10.0.0.10").json()

    # Assert
    assert isinstance(flows, list) and len(flows) >= 1
    f = flows[0]
    for k in ("key", "src_ip", "session_id", "n_events", "rate_rps", "flagged"):
        assert k in f
    assert state["src_ip"] == "10.0.0.10"
    assert state["events_in_window"] == 2
    assert isinstance(state["last_5"], list)


def test_tier_trace_without_redis(client):
    c, _ = client
    # locks down: with no Redis available, /tier-trace returns found=False + reason
    r = c.get("/tier-trace/10.0.0.99").json()
    assert r == {"found": False, "reason": "redis unavailable"}


# ──────────────────────────────────────────────────────────────────────
# 8. /admin/reset: header protection
# ──────────────────────────────────────────────────────────────────────


def test_admin_reset_requires_header(client):
    c, _ = client
    # No header -> 403
    assert c.post("/admin/reset").status_code == 403
    # Wrong secret -> 403
    assert c.post("/admin/reset", headers={"x-mg-reset": "wrong"}).status_code == 403


def test_admin_reset_clears_state(client):
    c, _ = client
    # Arrange: generate some state
    c.post("/logs", json=_events(n=1, spacing_ms=0,
                                 path="/x UNION SELECT y", ip="10.0.0.11"))
    assert c.get("/stats").json()["events_total"] >= 1

    # Act
    r = c.post("/admin/reset", headers={"x-mg-reset": RESET})

    # Assert
    assert r.json() == {"service": "sentinel", "reset": True}
    assert c.get("/stats").json()["events_total"] == 0


# ──────────────────────────────────────────────────────────────────────
# 9. tier0: Sigma rule loading + matching
# ──────────────────────────────────────────────────────────────────────


def test_tier0_loads_six_rules():
    rules = tier0._get_rules()
    # locks down: 6 .yml files in sigma_rules/
    assert len(rules) == 6


def test_tier0_matches_sqli_as_critical():
    from services.shared.models import LogEvent
    ev = LogEvent(
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        source="lb", src_ip="1.2.3.4",
        method="GET", path="/p?q=1 UNION SELECT pwd", status_code=200,
        raw='1.2.3.4 - - "GET /p" 200 0 "-" "x"',
    )
    hits = tier0.match_event(ev)
    assert any(h.severity == "critical" for h in hits)


def test_tier0_no_match_on_benign():
    from services.shared.models import LogEvent
    ev = LogEvent(
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        source="lb", src_ip="1.2.3.4",
        method="GET", path="/products/42", status_code=200,
        raw='1.2.3.4 - - "GET /products/42" 200 0 "-" "Mozilla/5.0"',
    )
    assert tier0.match_event(ev) == []


# ──────────────────────────────────────────────────────────────────────
# 10. tier1: feature extraction + heuristic scoring
# ──────────────────────────────────────────────────────────────────────


def _le(ts, path, status, method="GET", ua="UA"):
    from services.shared.models import LogEvent
    return LogEvent(
        timestamp=ts, source="lb", src_ip="1.2.3.4",
        method=method, path=path, status_code=status,
        raw=f'1.2.3.4 - - "{method} {path}" {status} 0 "-" "{ua}"',
    )


def test_tier1_extract_features_exact_values():
    # Arrange: 4 events 500ms apart, paths {/a,/a,/b,/c}, mixed statuses
    base = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    window = [
        _le(base, "/a", 200),
        _le(base + timedelta(milliseconds=500), "/a", 404),
        _le(base + timedelta(milliseconds=1000), "/b", 404),
        _le(base + timedelta(milliseconds=1500), "/c", 500),
    ]

    # Act
    f = tier1.extract_features(window, sigma_hits=2)

    # Assert: exact values
    assert f.n_events == 4
    assert f.n_unique_paths == 3
    assert f.unique_path_ratio == 0.75
    assert f.ratio_4xx == 0.5
    assert f.ratio_5xx == 0.25
    assert f.ratio_200 == 0.25
    assert f.inter_arrival_mean_ms == 500.0
    assert f.n_distinct_status == 3
    assert f.n_distinct_methods == 1
    assert f.sigma_hits_in_window == 2


def test_tier1_heuristic_benign_below_threshold():
    # slow window, no error, no signal -> low confidence (< 0.40)
    f = WindowFeatures(
        rate_rps=1.0, n_events=4, n_unique_paths=1, unique_path_ratio=0.1,
        ua_entropy=2.0, ratio_4xx=0.0, ratio_5xx=0.0, ratio_200=1.0,
        inter_arrival_mean_ms=5000.0, inter_arrival_p95_ms=6000.0,
        n_distinct_status=1, n_distinct_methods=1, sigma_hits_in_window=0,
        owasp_coverage=0.0,
    )
    conf, vector = tier1._heuristic_predict(f)
    assert conf == 0.0
    assert vector == AttackVector.UNKNOWN


def test_tier1_heuristic_high_confidence_ai_recon():
    # fast burst + AI timing + 4xx + sigma + OWASP coverage -> saturation
    f = WindowFeatures(
        rate_rps=120.0, n_events=10, n_unique_paths=9, unique_path_ratio=0.9,
        ua_entropy=0.1, ratio_4xx=0.9, ratio_5xx=0.0, ratio_200=0.1,
        inter_arrival_mean_ms=100.0, inter_arrival_p95_ms=200.0,
        n_distinct_status=3, n_distinct_methods=1, sigma_hits_in_window=6,
        owasp_coverage=0.8,
    )
    conf, vector = tier1._heuristic_predict(f)
    assert conf >= 0.85
    # inter_arrival < 1700ms -> AI_RECON vector
    assert vector == AttackVector.AI_RECON


@pytest.mark.parametrize("llm_label,expected", [
    ("recon", AttackVector.RECON),
    ("ai-recon", AttackVector.AI_RECON),
    ("brute_force", AttackVector.BRUTE_FORCE),   # fixed regression (was UNKNOWN)
    ("injection", AttackVector.INJECTION),
    ("traversal", AttackVector.TRAVERSAL),
    # cases that REQUIRE separator normalization (otherwise AttackVector(...) raises):
    ("brute-force", AttackVector.BRUTE_FORCE),   # hyphen -> must become brute_force
    ("ai_recon", AttackVector.AI_RECON),         # underscore -> must become ai-recon
    ("UNKNOWN", AttackVector.UNKNOWN),           # case + known value
])
def test_t2_parser_coerces_all_vectors(llm_label, expected):
    # the T2 parser must recognize the 5 vectors whatever the separator
    # convention the LLM returns (hyphen or underscore)
    from datetime import datetime, timezone
    from services.sentinel import classifier as clf
    from services.shared.models import LogEvent
    window = [LogEvent(timestamp=datetime.now(tz=timezone.utc), source="lb",
                       src_ip="1.1.1.1", raw="x")]
    verdict = clf._parse_response(
        '{"vector":"%s","confidence":0.9,"rationale":"r"}' % llm_label, window)
    assert verdict.vector == expected
    assert verdict.confidence == 0.9


def test_heuristics_compute_rps_and_dominant_vector():
    base = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    window = [_le(base + timedelta(seconds=i), "/etc/passwd", 200) for i in range(5)]
    # rps = 5 events / 4s = 1.25
    assert heuristics.compute_rps(window) == pytest.approx(1.25, abs=0.01)
    # traversal paths -> dominant vector TRAVERSAL
    assert heuristics.dominant_vector(window) == AttackVector.TRAVERSAL
