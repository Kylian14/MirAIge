"""Characterization tests for services/attack_simulator/ (pure unit tests).

Pins down the attack simulator's behavior WITHOUT launching a network attack:
loot extraction, brute-force enrichment, LLM brain in scripted mode, stealth
profiles (bounds), target parsing/classification, CLI level mapping.

Self-contained: no HTTP calls (we only test pure functions plus the AgentBrain
scripted fallback when no key is configured).
"""

import pytest

from services.attack_simulator import stealth_profiles as sp
from services.attack_simulator import target_profiler as tp
from services.attack_simulator.agent_brain import AgentBrain, AttackAction
from services.attack_simulator.attack_state import AttackState


# ──────────────────────────────────────────────────────────────────────
# 1. AttackState.harvest · secret extraction
# ──────────────────────────────────────────────────────────────────────


def test_harvest_extracts_all_loot_kinds():
    st = AttackState()
    body = (
        "user_hash=$2b$12$" + "A" * 53 + "\n"
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        "aws_secret_access_key = " + "b" * 40 + "\n"
        "DB_PASSWORD=Tz7xQ2vRk9mNs4Pg\n"
        "api_key: ak_live_4c1f7e9a2d6b8053xyz\n"
        "apiVersion: v1\nkind: Config\n"
    )

    added = st.harvest("/.env", body)

    kinds = {l.kind for l in st.loot}
    assert added >= 5
    assert {"bcrypt", "aws_key", "aws_secret", "password", "token", "k8s_yaml"} <= kinds


def test_harvest_empty_body_returns_zero():
    st = AttackState()
    assert st.harvest("/x", "") == 0


# ──────────────────────────────────────────────────────────────────────
# 2. credentials_for_login · enriched by leaks
# ──────────────────────────────────────────────────────────────────────


def test_credentials_for_login_prioritizes_leaked_password():
    st = AttackState()
    st.harvest("/.env", "password=leakedpw99\n")
    combos = st.credentials_for_login()
    # the leaked password is tried FIRST
    assert combos[0] == ("admin", "leakedpw99")


def test_credentials_for_login_default_combos():
    st = AttackState()
    combos = st.credentials_for_login()
    # 6 users × 6 default passwords = 36 combinations (pinned bounds)
    assert len(combos) == 36
    assert ("admin", "admin") in combos


# ──────────────────────────────────────────────────────────────────────
# 3. AgentBrain · no scripted fallback (serious project: no LLM, no action)
# ──────────────────────────────────────────────────────────────────────


def _brain():
    return AgentBrain(base_url="", api_key="", model="x")


def test_agent_brain_disabled_without_key():
    b = _brain()
    assert b.enabled is False


def test_no_scripted_fallback_attribute():
    # the scripted fallback was removed: neither the sequence nor the method should exist
    assert not hasattr(AgentBrain, "_FALLBACK_SEQUENCE")
    assert not hasattr(AgentBrain, "_fallback_action")


async def test_next_action_returns_none_when_disabled():
    # without an endpoint/key, the agent does NOT make up an action: it returns None
    b = _brain()
    for _ in range(3):
        action = await b.next_action("GET", "/", 200, "body")
        assert action is None


def test_parse_clean_json():
    b = _brain()
    a = b._parse_llm_response('{"thought":"t","action":{"method":"post","path":"x","body":{"a":1}}}')
    assert a.method == "POST"          # normalized to uppercase
    assert a.path == "/x"              # prefixed with a /
    assert a.body == {"a": 1}


def test_parse_json_wrapped_in_prose():
    b = _brain()
    text = 'Sure, here is my plan: {"thought":"go","action":{"method":"GET","path":"/secrets"}} — done.'
    a = b._parse_llm_response(text)
    assert a.path == "/secrets"


def test_parse_invalid_returns_none():
    b = _brain()
    # unusable LLM response means None (we invent NO fallback action)
    assert b._parse_llm_response("not json at all") is None


# ──────────────────────────────────────────────────────────────────────
# 4. stealth_profiles · UA pools + timing bounds per level
# ──────────────────────────────────────────────────────────────────────


def test_ua_pools_per_level():
    # noisy: always a known scanner UA (triggers T0)
    assert sp.pick_ua("noisy") in sp.UA_SCANNERS
    # evasive: fixed browser UA (low entropy)
    assert sp.pick_ua("evasive") == sp.UA_BROWSERS_DESKTOP[0]
    # stealth: rotation of desktop/mobile browsers
    assert sp.pick_ua("stealth") in (sp.UA_BROWSERS_DESKTOP + sp.UA_BROWSERS_MOBILE)
    # apt: browsers + legitimate bots
    assert sp.pick_ua("apt") in (sp.UA_BROWSERS_DESKTOP + sp.UA_BROWSERS_MOBILE + sp.UA_LEGITIMATE_BOTS)


@pytest.mark.parametrize("fn,lo,hi", [
    (sp.timing_noisy, 0.020, 0.060),
    (sp.timing_evasive, 0.350, 0.700),
    (sp.timing_stealth, 2.0, 3.5),
    (sp.timing_ai_agent, 0.8, 4.0),
    (sp.timing_apt, 4.0, 20.0),
])
def test_timing_distributions_within_bounds(fn, lo, hi):
    # pinned bounds (RNG, so we check the interval, not an exact value)
    for _ in range(50):
        t = fn()
        assert lo <= t <= hi


# ──────────────────────────────────────────────────────────────────────
# 5. target_profiler · HTML parsing + classification (pure functions)
# ──────────────────────────────────────────────────────────────────────


def test_parse_html_extracts_title_links_and_login_form():
    html = (
        "<html><head><title>Atlas Cloud — Espace client</title></head><body>"
        '<a href="/login">Connexion</a><a href="/api/v1/users">API</a>'
        '<form action="/login" method="post">'
        '<input name="username"><input name="password" type="password"></form>'
        "</body></html>"
    )
    profile = tp.TargetProfile(base_url="http://t")
    tp._parse_html(html, "http://t", profile)

    assert profile.title == "Atlas Cloud — Espace client"
    assert "/login" in profile.links and "/api/v1/users" in profile.links
    assert profile.has_login is True
    assert profile.forms[0].method == "POST"
    assert "password" in profile.forms[0].fields


def test_classify_detects_portal_vs_ghost():
    # portal marker means kind "portal"
    kind_p, _ = tp._classify({"server": "nginx"}, "<html>bienvenue sur miraige</html>", 200)
    assert kind_p == "portal"
    # ghost marker (execution_trace) means kind "ghost"
    kind_g, _ = tp._classify({}, '{"execution_trace": "Thought: ..."}', 200)
    assert kind_g == "ghost"
    # nothing recognized means unknown
    kind_u, _ = tp._classify({}, "<html>page banale</html>", 200)
    assert kind_u == "unknown"


def test_classify_detects_technology():
    _, tech = tp._classify({"server": "uvicorn"}, "<html>FastAPI app</html>", 200)
    assert "Uvicorn" in tech and "FastAPI" in tech


# ──────────────────────────────────────────────────────────────────────
# 6. attack.py: CLI level mapping
# ──────────────────────────────────────────────────────────────────────


def test_levels_mapping_contains_core_and_aliases():
    import services.attack_simulator.attack as attack
    # 5 modern levels
    for lvl in ("noisy", "evasive", "stealth", "ai-agent", "apt"):
        assert lvl in attack.LEVELS and callable(attack.LEVELS[lvl])
    # alias historiques --pattern
    for alias in ("recon", "brute", "traversal", "ai-recon"):
        assert alias in attack.LEVELS and callable(attack.LEVELS[alias])
