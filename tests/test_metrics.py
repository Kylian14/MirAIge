"""Characterization tests for services/mirage_metrics/.

Locks down the OPERATIONAL behavior: tiktoken (o200k_base) count of the tokens
served to the decoy, activity snapshot (active sessions + tokens served), real
LLM usage of a self-triggered agent (tokens, NO cost). No more € cost or
energy/CO₂ metrics (removed: this is a production tool, not an economics demo).

Hermetic: no network; tiktoken present.
Isolation: /admin/reset between tests (clears tokens served + agent usage).
"""

import pytest
from fastapi.testclient import TestClient

import services.mirage_metrics.main as mm
from services.mirage_metrics.attacker_cost import AttackerCostTracker

RESET = "miraige-reset-2026"

# Fixed string -> 10 tokens in o200k_base (locked count, verified)
FIXED_TEXT = "The quick brown fox jumps over the lazy dog."
FIXED_TOKENS = 10


@pytest.fixture
def client():
    c = TestClient(mm.app)
    c.post("/admin/reset", headers={"x-mg-reset": RESET})
    return c


# ──────────────────────────────────────────────────────────────────────
# 1. Health
# ──────────────────────────────────────────────────────────────────────


def test_health(client):
    assert client.get("/health").json() == {"status": "ok", "service": "mirage_metrics"}


# ──────────────────────────────────────────────────────────────────────
# 2. /events/tokens: real tiktoken count + accumulation + canary
# ──────────────────────────────────────────────────────────────────────


def test_push_tokens_counts_with_tiktoken(client):
    r = client.post("/events/tokens", json={"session_id": "s1", "text": FIXED_TEXT})
    body = r.json()
    assert body["status"] == "recorded"
    assert body["cumulative_tokens"] == FIXED_TOKENS
    assert body["total_tokens_all_sessions"] == FIXED_TOKENS


def test_push_tokens_cumulates_across_events(client):
    client.post("/events/tokens", json={"session_id": "s1", "text": FIXED_TEXT})
    r = client.post("/events/tokens", json={"session_id": "s1", "text": FIXED_TEXT})
    assert r.json()["cumulative_tokens"] == 2 * FIXED_TOKENS


def test_push_tokens_canary_flag_increments(client):
    before = mm.ATTACKER.canary_hits
    client.post("/events/tokens", json={"session_id": "x", "tokens": 0, "canary_compliance": True})
    assert mm.ATTACKER.canary_hits == before + 1


# ──────────────────────────────────────────────────────────────────────
# 3. /current: operational snapshot (active sessions + tokens served)
# ──────────────────────────────────────────────────────────────────────


def test_current_snapshot_is_operational_only(client):
    snap = client.get("/current").json()
    # locks down: the snapshot carries ONLY operational fields (no more cost/energy)
    assert set(snap.keys()) == {"timestamp", "active_sessions", "tokens_served_attacker"}


def test_current_snapshot_zero_after_reset(client):
    snap = client.get("/current").json()
    assert snap["tokens_served_attacker"] == 0
    assert snap["active_sessions"] == 0


def test_current_snapshot_after_traffic(client):
    # 100 events of 10 tokens on a single session: 1000 tokens served, 1 session
    for _ in range(100):
        client.post("/events/tokens", json={"session_id": "s1", "text": FIXED_TEXT})
    snap = client.get("/current").json()
    assert snap["tokens_served_attacker"] == 1000
    assert snap["active_sessions"] == 1


# ──────────────────────────────────────────────────────────────────────
# 4. /events/agent-usage: real LLM usage (TOKENS only, no cost)
# ──────────────────────────────────────────────────────────────────────


def test_agent_usage_tokens_only_no_cost(client):
    client.post("/events/agent-usage", json={
        "session_id": "ai-1",
        "prompt_tokens": 500_000,
        "completion_tokens": 200_000,
        "model": "Llama-3.1-8B-Instruct",
    })
    r = client.get("/agent-usage").json()
    assert r["prompt_tokens"] == 500_000
    assert r["completion_tokens"] == 200_000
    assert r["total_tokens"] == 700_000
    assert r["calls"] == 1
    assert r["model"] == "Llama-3.1-8B-Instruct"
    # locks down: no cost estimate is exposed anymore
    assert "cost_eur" not in r
    assert all("cost_eur" not in s for s in r["sessions"].values())


# ──────────────────────────────────────────────────────────────────────
# 5. attacker_cost: unit tests (counter of tokens served, tiktoken)
# ──────────────────────────────────────────────────────────────────────


def test_attacker_cost_counts_fixed_string():
    t = AttackerCostTracker()
    assert t._has_tiktoken is True
    assert t.estimate_tokens(FIXED_TEXT) == FIXED_TOKENS


def test_attacker_cost_session_tracking():
    t = AttackerCostTracker()
    t.add("a", 5)
    t.add("a", 3)
    t.add("b", 10)
    assert t.get("a") == 8
    assert t.get("b") == 10
    assert t.total_all_sessions() == 18
    assert t.session_count() == 2


# ──────────────────────────────────────────────────────────────────────
# 6. No more cost/energy modules (removed)
# ──────────────────────────────────────────────────────────────────────


def test_cost_and_energy_modules_removed():
    import importlib.util as _u
    assert _u.find_spec("services.mirage_metrics.defender_cost") is None
    assert _u.find_spec("services.mirage_metrics.pricing_oracle") is None


# ──────────────────────────────────────────────────────────────────────
# 7. /admin/reset
# ──────────────────────────────────────────────────────────────────────


def test_admin_reset_requires_header(client):
    assert client.post("/admin/reset").status_code == 403


def test_admin_reset_clears_tokens(client):
    client.post("/events/tokens", json={"session_id": "s1", "text": FIXED_TEXT})
    client.post("/admin/reset", headers={"x-mg-reset": RESET})
    snap = client.get("/current").json()
    assert snap["tokens_served_attacker"] == 0


# ──────────────────────────────────────────────────────────────────────
# 8. _spawn: strong retention of fire-and-forget tasks (anti-GC)
# ──────────────────────────────────────────────────────────────────────


async def test_spawn_tracks_then_discards_task():
    import asyncio
    ran = []

    async def _job():
        ran.append(True)

    mm._spawn(_job())
    assert len(mm._BG_TASKS) >= 1
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert ran == [True]
    assert len(mm._BG_TASKS) == 0
