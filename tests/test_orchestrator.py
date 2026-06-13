"""Characterization tests for services/orchestrator (main, state_machine, mcp_client).

These tests pin the CURRENT behavior, including its flaws. Hermetic: no real
network (the conftest outbound URLs point to a closed port, and the unit HTTP
calls go through httpx.MockTransport).
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from services.orchestrator import main
from services.orchestrator.mcp_client import McpClient, McpError, _TokenBucket
from services.orchestrator.state_machine import MorphStateMachine
from services.shared.a2a_protocol import sign_request
from services.shared.models import (
    AttackSignal,
    AttackVector,
    GhostPersona,
    MorphContext,
    MorphState,
    RerouteLbOutput,
    RouteToGhostShellOutput,
    TerminateHoneypotOutput,
)

A2A_SECRET = "dev-secret"  # value pinned by tests/conftest.py


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _make_signal(request_id: str = "req-1", confidence: float = 0.9) -> AttackSignal:
    return AttackSignal(
        request_id=request_id,
        attacker_ip="203.0.113.10",
        attacker_session="sess.abc",
        target_instance_id="vm-1",
        vector=AttackVector.BRUTE_FORCE,
        confidence=confidence,
        rate_rps=42.0,
    )


def _signed_post(client: TestClient, signal: AttackSignal) -> httpx.Response:
    """POST /signal with a valid A2A signature (shared helper)."""
    body = signal.model_dump_json().encode()
    headers = sign_request(body, secret=A2A_SECRET, agent_id="sentinel-test")
    return client.post("/signal", content=body, headers=headers)


def _patch_async_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    """Replace httpx.AsyncClient with a mock-transport client (zero network)."""
    real_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


class _FakeMcp:
    """Fake McpClient to drive the FSM in unit tests (no network)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    async def route_to_ghost_shell(self, params) -> RouteToGhostShellOutput:
        self.calls.append(("route_to_ghost_shell", params))
        return RouteToGhostShellOutput(
            ghost_session_id="ghost-123",
            persona=GhostPersona.PORTAL_OVH,
            expires_at=1_750_000_000,
        )

    async def reroute_lb(self, params) -> RerouteLbOutput:
        self.calls.append(("reroute_lb", params))
        return RerouteLbOutput(
            rule_id="rule-abc",
            applied_at=1_750_000_000,
            rollback_token="rb-xyz",
        )

    async def terminate_honeypot(self, params) -> TerminateHoneypotOutput:
        self.calls.append(("terminate_honeypot", params))
        return TerminateHoneypotOutput(
            destroyed=True,
            ttps_archive_url=None,
            tokens_burned=0,
            asymmetric_ratio=0.0,
        )


# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_active():
    """ACTIVE is a module-level dict the code never purges, so we isolate it here."""
    main.ACTIVE.clear()
    yield
    main.ACTIVE.clear()


@pytest.fixture()
def client():
    # Context manager: keeps the anyio loop alive between requests, which lets
    # the fire-and-forget tasks run.
    with TestClient(main.app) as c:
        yield c


@pytest.fixture()
def quiet_machine(monkeypatch: pytest.MonkeyPatch) -> list:
    """Neutralize MACHINE.run (fire-and-forget) for pure endpoint tests."""
    runs: list = []

    async def _stub_run(ctx, signal) -> None:
        runs.append((ctx, signal))

    monkeypatch.setattr(main.MACHINE, "run", _stub_run)
    return runs


# ──────────────────────────────────────────────────────────────────────
# GET /health
# ──────────────────────────────────────────────────────────────────────


def test_health_expose_active_morphs(client: TestClient) -> None:
    # Act
    resp = client.get("/health")

    # Assert
    assert resp.status_code == 200
    # locks in a debatable existing behavior: active_morphs is serialized as a
    # string ("0") rather than an integer.
    assert resp.json() == {
        "status": "ok",
        "service": "orchestrator",
        "active_morphs": "0",
    }


# ──────────────────────────────────────────────────────────────────────
# POST /signal: A2A signature verification
# ──────────────────────────────────────────────────────────────────────


def test_signal_sans_signature_renvoie_401(client: TestClient) -> None:
    # Arrange
    body = _make_signal().model_dump_json().encode()

    # Act: no X-Mirage-* header
    resp = client.post("/signal", content=body)

    # Assert
    assert resp.status_code == 401
    assert resp.json() == {"detail": "invalid A2A signature"}


def test_signal_signature_invalide_renvoie_401(client: TestClient) -> None:
    # Arrange: valid timestamp but bogus digest
    body = _make_signal().model_dump_json().encode()
    headers = {
        "X-Mirage-Timestamp": str(int(time.time())),
        "X-Mirage-Signature": "v1=" + "0" * 64,
    }

    # Act
    resp = client.post("/signal", content=body, headers=headers)

    # Assert
    assert resp.status_code == 401
    assert resp.json() == {"detail": "invalid A2A signature"}


def test_signal_timestamp_perime_renvoie_401(client: TestClient) -> None:
    # Arrange: mathematically correct signature but timestamp outside skew (30 s)
    body = _make_signal().model_dump_json().encode()
    stale_ts = str(int(time.time()) - 120)
    digest = hmac.new(
        A2A_SECRET.encode(), f"{stale_ts}.".encode() + body, hashlib.sha256
    ).hexdigest()
    headers = {
        "X-Mirage-Timestamp": stale_ts,
        "X-Mirage-Signature": f"v1={digest}",
    }

    # Act
    resp = client.post("/signal", content=body, headers=headers)

    # Assert
    assert resp.status_code == 401
    assert resp.json() == {"detail": "invalid A2A signature"}


def test_signal_timestamp_non_numerique_renvoie_401(client: TestClient) -> None:
    # Regression [23]: a non-numeric timestamp raised an uncaught ValueError -> 500.
    # It must now be treated as an invalid signature (401).
    body = _make_signal().model_dump_json().encode()
    headers = {
        "X-Mirage-Timestamp": "not-a-number",
        "X-Mirage-Signature": "v1=" + "0" * 64,
    }
    resp = client.post("/signal", content=body, headers=headers)
    assert resp.status_code == 401
    assert resp.json() == {"detail": "invalid A2A signature"}


# ──────────────────────────────────────────────────────────────────────
# POST /signal: happy path, idempotence, confidence gate
# ──────────────────────────────────────────────────────────────────────


def test_signal_valide_202_et_enregistre_dans_active(
    client: TestClient, quiet_machine: list
) -> None:
    # Arrange
    signal = _make_signal(request_id="req-accept")

    # Act
    resp = _signed_post(client, signal)

    # Assert
    assert resp.status_code == 202
    assert resp.json() == {"status": "accepted", "request_id": "req-accept"}
    assert "req-accept" in main.ACTIVE
    assert main.ACTIVE["req-accept"].attacker_ip == "203.0.113.10"


def test_signal_duplique_renvoie_duplicate(client: TestClient, quiet_machine: list) -> None:
    # Arrange
    signal = _make_signal(request_id="req-dup")
    first = _signed_post(client, signal)
    assert first.json()["status"] == "accepted"

    # Act: same request_id, fresh valid signature
    second = _signed_post(client, signal)

    # Assert
    # locks in a debatable existing behavior: the duplicate also returns HTTP 202
    # (only the body differs), and since ACTIVE is never purged, a processed
    # request_id stays "duplicate" forever.
    assert second.status_code == 202
    assert second.json() == {"status": "duplicate", "request_id": "req-dup"}
    assert len(main.ACTIVE) == 1


def test_signal_sous_gate_confiance_court_circuite_vers_idle(client: TestClient) -> None:
    """confidence < 0.75 -> 202 accepted, then the real FSM falls back to IDLE.

    No mock here: below the gate, MACHINE.run makes no MCP call (short-circuits
    before any network), so the test stays hermetic.
    """
    # Arrange
    signal = _make_signal(request_id="req-low", confidence=0.5)

    # Act
    resp = _signed_post(client, signal)

    # Assert: immediate response
    assert resp.status_code == 202
    assert resp.json() == {"status": "accepted", "request_id": "req-low"}

    # Assert: the background (fire-and-forget) task ends in IDLE (short poll)
    state = None
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        state = client.get("/state/req-low").json()["state"]
        if state == MorphState.IDLE.value:
            break
        time.sleep(0.02)
    assert state == MorphState.IDLE.value
    # locks in a debatable existing behavior: the context stays in ACTIVE even
    # after the FSM finishes (no purge).
    assert "req-low" in main.ACTIVE


# ──────────────────────────────────────────────────────────────────────
# GET /state et /state/{request_id}
# ──────────────────────────────────────────────────────────────────────


def test_state_liste_les_morphs_actifs(client: TestClient, quiet_machine: list) -> None:
    # Arrange
    _signed_post(client, _make_signal(request_id="req-state"))

    # Act
    resp = client.get("/state")

    # Assert
    assert resp.status_code == 200
    active = resp.json()["active"]
    assert len(active) == 1
    assert active[0]["request_id"] == "req-state"
    assert active[0]["attacker_ip"] == "203.0.113.10"
    assert active[0]["state"] == MorphState.IDLE.value  # run() stubbed: no transition


def test_state_detail_renvoie_le_contexte(client: TestClient, quiet_machine: list) -> None:
    # Arrange
    _signed_post(client, _make_signal(request_id="req-one"))

    # Act
    resp = client.get("/state/req-one")

    # Assert
    assert resp.status_code == 200
    data = resp.json()
    assert data["request_id"] == "req-one"
    assert data["attacker_session"] == "sess.abc"
    assert data["target_instance_id"] == "vm-1"


def test_state_detail_inconnu_renvoie_404(client: TestClient) -> None:
    # Act
    resp = client.get("/state/inconnu")

    # Assert
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Not Found"}


# ──────────────────────────────────────────────────────────────────────
# POST /admin/reset + FIFO cap on ACTIVE (O2/O3 fixes)
# ──────────────────────────────────────────────────────────────────────


def test_admin_reset_requires_header(client: TestClient) -> None:
    assert client.post("/admin/reset").status_code == 403
    assert client.post("/admin/reset", headers={"x-mg-reset": "wrong"}).status_code == 403


def test_admin_reset_clears_active(client: TestClient, quiet_machine: list) -> None:
    _signed_post(client, _make_signal(request_id="req-reset"))
    assert len(main.ACTIVE) == 1

    resp = client.post("/admin/reset", headers={"x-mg-reset": "miraige-reset-2026"})

    body = resp.json()
    assert body == {"service": "orchestrator", "reset": True, "morphs_cleared": 1}
    assert len(main.ACTIVE) == 0


def test_active_is_fifo_capped(client: TestClient, quiet_machine: list,
                               monkeypatch: pytest.MonkeyPatch) -> None:
    # memory bound: past the cap, the oldest morph is evicted
    monkeypatch.setattr(main, "MAX_ACTIVE", 2)
    for i in range(4):
        _signed_post(client, _make_signal(request_id=f"req-cap-{i}"))
    assert len(main.ACTIVE) == 2
    # the 2 most recent survive, the oldest are evicted
    assert set(main.ACTIVE) == {"req-cap-2", "req-cap-3"}


# ──────────────────────────────────────────────────────────────────────
# FSM unit tests: MorphStateMachine
# ──────────────────────────────────────────────────────────────────────


def _make_machine(mcp, *, ttl_seconds: int = 0) -> MorphStateMachine:
    # ttl_seconds=0: the monitoring loop (sleep 60 s per tick) is skipped
    # entirely, without monkeypatching asyncio.sleep.
    return MorphStateMachine(
        mcp=mcp, lb_id="lb-1", ghost_pool_id="pool-ghost", ttl_seconds=ttl_seconds
    )


def _spy_transitions(monkeypatch: pytest.MonkeyPatch, machine: MorphStateMachine) -> list:
    transitions: list[MorphState] = []
    original_to = machine._to

    async def spy(ctx: MorphContext, new_state: MorphState) -> None:
        transitions.append(new_state)
        await original_to(ctx, new_state)

    monkeypatch.setattr(machine, "_to", spy)
    return transitions


async def test_fsm_happy_path_sequence_et_contexte(monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    fake = _FakeMcp()
    machine = _make_machine(fake)
    ctx = MorphContext(
        request_id="req-fsm",
        attacker_ip="203.0.113.10",
        attacker_session="sess.abc",
        target_instance_id="vm-1",
    )
    transitions = _spy_transitions(monkeypatch, machine)

    # Act
    await machine.run(ctx, _make_signal(request_id="req-fsm", confidence=0.9))

    # Assert: full transition sequence
    assert transitions == [
        MorphState.DETECTING,
        MorphState.ASSIGNING,
        MorphState.REROUTING,
        MorphState.MONITORING,
        MorphState.TERMINATING,
        MorphState.IDLE,
    ]
    assert ctx.state == MorphState.IDLE

    # Assert: the context is enriched by the MCP responses
    assert ctx.ghost_session_id == "ghost-123"
    assert ctx.ghost_persona == GhostPersona.PORTAL_OVH
    assert ctx.lb_rule_id == "rule-abc"
    assert ctx.rollback_token == "rb-xyz"
    # expires_at = applied_at + ttl (ttl=0 here)
    assert ctx.expires_at is not None
    assert int(ctx.expires_at.timestamp()) > 0

    # Assert: the 3 tools are called in order, with the right arguments
    assert [name for name, _ in fake.calls] == [
        "route_to_ghost_shell", "reroute_lb", "terminate_honeypot",
    ]
    route_params = fake.calls[0][1]
    assert route_params.attacker_cidr == "203.0.113.10/32"
    assert route_params.session_id == "req-fsm"
    reroute_params = fake.calls[1][1]
    assert reroute_params.attacker_ips == ["203.0.113.10"]
    assert reroute_params.attacker_session == "sess.abc"
    terminate_params = fake.calls[2][1]
    assert terminate_params.ghost_session_id == "ghost-123"
    assert terminate_params.rollback_token == "rb-xyz"
    assert terminate_params.collect_ttps is True


async def test_fsm_sous_gate_court_circuite_sans_appel_mcp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Arrange
    fake = _FakeMcp()
    machine = _make_machine(fake)
    ctx = MorphContext(
        request_id="req-gate", attacker_ip="203.0.113.10", target_instance_id="vm-1",
    )
    transitions = _spy_transitions(monkeypatch, machine)

    # Act: confidence 0.74 < gate 0.75
    await machine.run(ctx, _make_signal(request_id="req-gate", confidence=0.74))

    # Assert: DETECTING then straight back to IDLE, zero MCP call
    assert transitions == [MorphState.DETECTING, MorphState.IDLE]
    assert ctx.state == MorphState.IDLE
    assert fake.calls == []


async def test_fsm_circuit_breaker_apres_3_echecs_consecutifs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Arrange: an MCP that always fails on the first tool
    class _BrokenMcp(_FakeMcp):
        async def route_to_ghost_shell(self, params):
            self.calls.append(("route_to_ghost_shell", params))
            raise McpError("boom")

    fake = _BrokenMcp()
    machine = _make_machine(fake)
    ctx = MorphContext(
        request_id="req-cb", attacker_ip="203.0.113.10", target_instance_id="vm-1",
    )
    transitions = _spy_transitions(monkeypatch, machine)

    # Neutralize the inter-retry backoff (2s, 4s, ...) to keep the test fast,
    # but capture the requested durations to verify the linear backoff.
    import services.orchestrator.state_machine as sm_mod

    slept: list[float] = []

    async def _no_sleep(s):
        slept.append(s)

    monkeypatch.setattr(sm_mod.asyncio, "sleep", _no_sleep)

    # Act
    await machine.run(ctx, _make_signal(request_id="req-cb", confidence=0.9))

    # bounded linear backoff between the 2 retries before the breaker fires
    assert slept == [2.0, 4.0]

    # Assert: exactly 3 attempts (MAX_CONSECUTIVE_TOOL_FAILURES) then rollback
    assert len(fake.calls) == 3
    # Each retry goes back through ASSIGNING (the step redoes the transition).
    assert transitions == [
        MorphState.DETECTING,
        MorphState.ASSIGNING,
        MorphState.ASSIGNING,
        MorphState.ASSIGNING,
        MorphState.ROLLBACK,
        MorphState.ERROR,
    ]
    # locks in a debatable existing behavior: after the circuit breaker, the FSM
    # ends in ERROR (never IDLE) and the context stays as-is. Since
    # ghost_session_id/lb_rule_id are absent, _rollback does not call
    # terminate_honeypot.
    assert ctx.state == MorphState.ERROR
    assert ctx.ghost_session_id is None
    assert [n for n, _ in fake.calls if n == "terminate_honeypot"] == []


async def test_fsm_non_mcperror_declenche_rollback(monkeypatch: pytest.MonkeyPatch) -> None:
    # Regression: a NON-McpError exception (e.g. a ValidationError from
    # model_validate) in a step was escaping rollback -> ghost session + L7 policy leak.
    class _TerminateBrokenMcp(_FakeMcp):
        async def terminate_honeypot(self, params):
            self.calls.append(("terminate_honeypot", params))
            raise ValueError("divergent schema")   # non-McpError

    fake = _TerminateBrokenMcp()
    machine = _make_machine(fake)
    ctx = MorphContext(
        request_id="req-vErr", attacker_ip="203.0.113.10", target_instance_id="vm-1",
    )

    import services.orchestrator.state_machine as sm_mod

    async def _no_sleep(_s):
        return None

    monkeypatch.setattr(sm_mod.asyncio, "sleep", _no_sleep)

    # Act: must NOT propagate the exception (before the fix: run() raised)
    await machine.run(ctx, _make_signal(request_id="req-vErr", confidence=0.9))

    # Assert: assign+reroute succeeded (ghost session allocated), then rollback
    # fired and tried to terminate the session -> final state ERROR.
    assert ctx.state == MorphState.ERROR
    assert ctx.ghost_session_id == "ghost-123"
    n_terminate = len([n for n, _ in fake.calls if n == "terminate_honeypot"])
    assert n_terminate >= 4   # 3 step retries + 1 rollback attempt


async def test_drive_rollback_sur_annulation(monkeypatch: pytest.MonkeyPatch) -> None:
    # A cancelled FSM (demo reset / service shutdown) must release its resources
    # best-effort via rollback() before propagating the cancellation.
    rolled: list[str] = []

    class _FakeMachine:
        async def run(self, ctx, signal):
            await asyncio.sleep(60)        # blocks until cancellation

        async def rollback(self, ctx):
            rolled.append(ctx.request_id)

    monkeypatch.setattr(main, "MACHINE", _FakeMachine())
    ctx = MorphContext(request_id="req-cancel", attacker_ip="1.2.3.4", target_instance_id="vm-1")

    task = asyncio.create_task(main._drive(ctx, _make_signal(request_id="req-cancel")))
    await asyncio.sleep(0)                 # let _drive enter run()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert rolled == ["req-cancel"]        # rollback fired on cancellation


async def test_lifespan_annule_les_taches_en_vol() -> None:
    # Service shutdown (lifespan shutdown) must cancel the FSMs still in flight.
    async def _long():
        await asyncio.sleep(60)

    t = asyncio.create_task(_long())
    main._BG_TASKS.add(t)
    t.add_done_callback(main._BG_TASKS.discard)

    async with main.lifespan(main.app):
        pass                               # on exit -> shutdown -> cancel + bounded gather

    assert t.cancelled()


# ──────────────────────────────────────────────────────────────────────
# McpClient unit tests: token bucket + JSON-RPC protocol
# ──────────────────────────────────────────────────────────────────────


async def test_token_bucket_respecte_le_debit_sous_charge() -> None:
    # Regression [throttle]: after the burst is drained, N acquisitions must take
    # ~N/rate (before the fix, sleep time was recounted as a "free" refill -> ~2x
    # the rate, exceeding the OVH 20 req/s quota).
    import asyncio as _asyncio
    bucket = _TokenBucket(rate=15.0)
    for _ in range(15):          # drain the initial burst
        await bucket.acquire()

    start = time.monotonic()
    await _asyncio.gather(*[bucket.acquire() for _ in range(10)])
    elapsed = time.monotonic() - start

    # 10 tokens at 15/s ~ 0.667s. We require >= 0.55s (the bug gave ~0.33s).
    assert elapsed >= 0.55


async def test_token_bucket_ne_bloque_pas_sous_la_limite() -> None:
    # Arrange: initial capacity = rate (15 tokens available immediately)
    bucket = _TokenBucket(rate=15.0)

    # Act
    start = time.monotonic()
    for _ in range(15):
        await bucket.acquire()
    elapsed = time.monotonic() - start

    # Assert: 15 acquisitions under the limit, no notable wait
    assert elapsed < 0.5
    # The bucket is (almost) empty after 15 acquisitions
    assert bucket._tokens < 1.0


async def test_mcp_client_parse_la_reponse_json_rpc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Arrange: mocked server returning the MCP format (result.content[0].text JSON)
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["envelope"] = json.loads(request.content)
        inner = {"ghost_session_id": "gs-1", "persona": "portal_ovh", "expires_at": 123}
        return httpx.Response(200, json={
            "jsonrpc": "2.0",
            "id": captured["envelope"]["id"],
            "result": {
                "content": [{"type": "text", "text": json.dumps(inner)}],
                "isError": False,
            },
        })

    _patch_async_client(monkeypatch, handler)
    client = McpClient(base_url="http://mcp.test/")

    # Act
    data = await client._call("route_to_ghost_shell", {"session_id": "s-1"})

    # Assert: the JSON embedded in the text block is decoded
    assert data == {"ghost_session_id": "gs-1", "persona": "portal_ovh", "expires_at": 123}
    # The outgoing JSON-RPC envelope is well-formed
    assert captured["envelope"]["jsonrpc"] == "2.0"
    assert captured["envelope"]["method"] == "tools/call"
    assert captured["envelope"]["params"] == {
        "name": "route_to_ghost_shell",
        "arguments": {"session_id": "s-1"},
    }


async def test_mcp_client_erreur_transport_leve_mcperror() -> None:
    # Arrange: closed port, immediate connection refusal (hermetic)
    client = McpClient(base_url="http://127.0.0.1:1", timeout=1.0)

    # Act + Assert
    with pytest.raises(McpError, match="^transport: "):
        await client._call("route_to_ghost_shell", {})


async def test_mcp_client_reponse_error_leve_mcperror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Arrange: HTTP 200 response but JSON-RPC envelope {"error": ...}
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "jsonrpc": "2.0",
            "id": "x",
            "error": {"code": -32000, "message": "boom"},
        })

    _patch_async_client(monkeypatch, handler)
    client = McpClient(base_url="http://mcp.test")

    # Act + Assert
    with pytest.raises(McpError, match="^tool error: "):
        await client._call("reroute_lb_to_honeypot", {})


async def test_mcp_client_reponse_inparsable_leve_mcperror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Arrange: result present but with no usable content blocks
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": "x", "result": {}})

    _patch_async_client(monkeypatch, handler)
    client = McpClient(base_url="http://mcp.test")

    # Act + Assert
    with pytest.raises(McpError, match="^unparseable response: "):
        await client._call("terminate_honeypot_after_ttl", {})
