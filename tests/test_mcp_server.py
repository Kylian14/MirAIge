"""Characterization tests for services/mcp_server/ (JSON-RPC wire + 3 tools).

Covers the JSON-RPC 2.0 protocol, strict Pydantic validation of arguments
(M1 fix: a missing required field gives -32602 instead of -32000), OVH mock
mode (Octavia not called), and the mapping of Ghost Shell responses.

Hermetic: REROUTE_BACKEND=mock (conftest) means no openstacksdk; Ghost Shell calls
are intercepted by httpx.MockTransport.
"""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

import services.mcp_server.server as server

RESET = "miraige-reset-2026"


@pytest.fixture
def client():
    return TestClient(server.app)


def _patch_httpx(monkeypatch, handler):
    """Inject a MockTransport into every httpx.AsyncClient (shared by the octavia backend)."""
    real = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


def _rpc(client, method, params=None, rpc_id="1"):
    envelope = {"jsonrpc": "2.0", "id": rpc_id, "method": method}
    if params is not None:
        envelope["params"] = params
    return client.post("/mcp", json=envelope).json()


def _tool_result(rpc_response):
    """Extract and parse the JSON embedded in the content block of a tools/call."""
    text = rpc_response["result"]["content"][0]["text"]
    return json.loads(text)


# ──────────────────────────────────────────────────────────────────────
# 1. Health (mock mode)
# ──────────────────────────────────────────────────────────────────────


def test_health_reports_mock_mode(client):
    r = client.get("/health").json()
    assert r["status"] == "ok"
    assert r["service"] == "mcp_server"
    assert r["reroute_backend"] == "mock"


# ──────────────────────────────────────────────────────────────────────
# 2. JSON-RPC wire: initialize / tools/list / unknown method
# ──────────────────────────────────────────────────────────────────────


def test_initialize_handshake(client):
    r = _rpc(client, "initialize")
    assert r["result"]["protocolVersion"] == "2024-11-05"
    assert r["result"]["serverInfo"]["name"] == "miraige-mcp"


def test_tools_list_catalogue(client):
    r = _rpc(client, "tools/list")
    names = {t["name"] for t in r["result"]["tools"]}
    assert names == {
        "route_to_ghost_shell",
        "reroute_lb_to_honeypot",
        "terminate_honeypot_after_ttl",
    }


def test_unknown_method_returns_minus_32601(client):
    r = _rpc(client, "does/not/exist")
    assert r["error"]["code"] == -32601
    assert "method not found" in r["error"]["message"]


def test_unknown_tool_returns_minus_32602(client):
    r = _rpc(client, "tools/call", {"name": "no_such_tool", "arguments": {}})
    # unknown tool gives ValueError, then -32602 (invalid params)
    assert r["error"]["code"] == -32602
    assert "unknown tool" in r["error"]["message"]


# ──────────────────────────────────────────────────────────────────────
# 3. Strict Pydantic validation (M1 fix)
# ──────────────────────────────────────────────────────────────────────


def test_missing_required_arg_returns_minus_32602(client):
    # request_id missing, so Pydantic validation must produce -32602
    # (before the fix: TypeError caught as -32000 "server error")
    r = _rpc(client, "tools/call", {
        "name": "reroute_lb_to_honeypot",
        "arguments": {"lb_id": "lb-1", "attacker_ips": ["9.9.9.9"], "ghost_pool_id": "pool"},
    })
    assert r["error"]["code"] == -32602
    assert "invalid arguments" in r["error"]["message"]


def test_invalid_arg_type_returns_minus_32602(client):
    # attacker_ips must be a list, so an invalid type is also rejected with -32602
    r = _rpc(client, "tools/call", {
        "name": "reroute_lb_to_honeypot",
        "arguments": {
            "lb_id": "lb-1", "attacker_ips": "pas-une-liste",
            "ghost_pool_id": "pool", "request_id": "req-1",
        },
    })
    assert r["error"]["code"] == -32602


def test_malformed_json_body_returns_minus_32700(client):
    # non-JSON body: JSON-RPC -32700 error envelope (not a raw 500)
    r = client.post("/mcp", content=b"{not valid json",
                    headers={"content-type": "application/json"})
    assert r.status_code == 200
    assert r.json()["error"]["code"] == -32700


def test_non_dict_params_returns_minus_32602(client):
    # non-object params: -32602 (JSON-RPC contract respected)
    r = client.post("/mcp", json={
        "jsonrpc": "2.0", "id": "1", "method": "tools/call", "params": [1, 2, 3],
    }).json()
    assert r["error"]["code"] == -32602


# ──────────────────────────────────────────────────────────────────────
# 4. tools/call reroute_lb_to_honeypot (mock Octavia)
# ──────────────────────────────────────────────────────────────────────


def test_reroute_lb_mock_returns_fake_ids(client):
    r = _rpc(client, "tools/call", {
        "name": "reroute_lb_to_honeypot",
        "arguments": {
            "lb_id": "lb-1", "attacker_ips": ["9.9.9.9"],
            "ghost_pool_id": "pool-ghost", "request_id": "req-1",
        },
    })
    out = _tool_result(r)
    # mock mode: fake UUIDs, no openstack call
    assert out["rule_id"].startswith("rule-")
    assert out["rollback_token"].startswith("rb-")
    assert isinstance(out["applied_at"], int)


# ──────────────────────────────────────────────────────────────────────
# 5. tools/call route_to_ghost_shell (HTTP Ghost Shell, always real)
# ──────────────────────────────────────────────────────────────────────


def test_route_to_ghost_shell_maps_response(client, monkeypatch):
    def handler(request):
        assert request.url.path == "/sessions"
        return httpx.Response(200, json={
            "ghost_session_id": "gs-42", "persona": "portal_ovh", "expires_at": 1717,
        })

    _patch_httpx(monkeypatch, handler)
    r = _rpc(client, "tools/call", {
        "name": "route_to_ghost_shell",
        "arguments": {
            "session_id": "req-1", "attacker_cidr": "9.9.9.9/32",
            "lb_id": "lb-1", "request_id": "req-1",
        },
    })
    out = _tool_result(r)
    assert out["ghost_session_id"] == "gs-42"
    assert out["persona"] == "portal_ovh"


# ──────────────────────────────────────────────────────────────────────
# 6. tools/call terminate_honeypot_after_ttl (Ghost 404 tolerated)
# ──────────────────────────────────────────────────────────────────────


def test_terminate_tolerates_ghost_404(client, monkeypatch):
    def handler(request):
        # session already expired on the ghost side: 404
        return httpx.Response(404, text="not found")

    _patch_httpx(monkeypatch, handler)
    r = _rpc(client, "tools/call", {
        "name": "terminate_honeypot_after_ttl",
        "arguments": {
            "ghost_session_id": "gs-x", "lb_rule_id": "rule-x",
            "rollback_token": "rb-x", "request_id": "req-1",
        },
    })
    out = _tool_result(r)
    # ghost 404: tear-down treated as success (the ghost enforces its own TTL)
    assert out["destroyed"] is True
    assert out["tokens_burned"] == 0


# ──────────────────────────────────────────────────────────────────────
# 7. /admin/reset
# ──────────────────────────────────────────────────────────────────────


def test_admin_reset_requires_header(client):
    assert client.post("/admin/reset").status_code == 403


def test_admin_reset_mock_mode(client):
    r = client.post("/admin/reset", headers={"x-mg-reset": RESET}).json()
    assert r["service"] == "mcp" and r["reset"] is True
    # mock mode: no real L7 policy to purge
    assert r["purged"] == 0 and r["real_ovh"] is False


def test_non_dict_envelope_returns_minus_32600(client):
    r = client.post("/mcp", json=[1, 2, 3]).json()
    assert r["error"]["code"] == -32600
    assert "invalid request" in r["error"]["message"]

