"""Characterization tests for the BFF API gateway (services/api)."""
import httpx
import pytest
from fastapi.testclient import TestClient

import services.api.main as api

# conftest leaves DASHBOARD_PASSWORD at its default -> the console password.
PASSWORD = "Miraige2025!"


@pytest.fixture
def client():
    return TestClient(api.app)


def _patch_httpx(monkeypatch, handler):
    """Route the BFF's outbound async calls through a MockTransport."""
    real = httpx.AsyncClient

    def factory(*a, **k):
        k["transport"] = httpx.MockTransport(handler)
        return real(*a, **k)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


def _login(client) -> str:
    r = client.post("/api/v1/login", json={"password": PASSWORD})
    assert r.status_code == 200
    return r.json()["token"]


def test_login_ok_and_bad(client):
    assert client.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
    assert client.post("/api/v1/login", json={"password": "nope"}).status_code == 401


def test_protected_requires_valid_bearer(client):
    assert client.get("/api/v1/stats").status_code == 401
    assert client.get("/api/v1/stats", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_stats_proxies_sentinel(client, monkeypatch):
    token = _login(client)

    def handler(request):
        assert request.url.path == "/stats"
        return httpx.Response(200, json={"counters": {"events_total": 7}})

    _patch_httpx(monkeypatch, handler)
    r = client.get("/api/v1/stats", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200 and r.json()["counters"]["events_total"] == 7


def test_metrics_proxies_metrics_service(client, monkeypatch):
    token = _login(client)
    _patch_httpx(monkeypatch, lambda req: httpx.Response(200, json={"active_sessions": 2}))
    r = client.get("/api/v1/metrics", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200 and r.json()["active_sessions"] == 2


def test_backend_down_returns_502(client, monkeypatch):
    token = _login(client)
    _patch_httpx(monkeypatch, lambda req: httpx.Response(503, text="down"))
    r = client.get("/api/v1/flows", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 502


def test_health_aggregates_backends(client, monkeypatch):
    _patch_httpx(monkeypatch, lambda req: httpx.Response(200, json={"status": "ok"}))
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert body["service"] == "api"
    assert set(body["backends"]) == {"sentinel", "orchestrator", "mcp_server", "mirage_metrics"}
    assert all(v == "ok" for v in body["backends"].values())


# ── live stream (/api/v1/stream) ───────────────────────────────────────

def test_stream_requires_auth(client):
    # the role dependency rejects before any streaming starts (no hang)
    assert client.get("/api/v1/stream").status_code == 401


async def test_gather_snapshot_combines_three_services(monkeypatch):
    def handler(request):
        path = request.url.path
        if path == "/stats":
            return httpx.Response(200, json={"counters": {"events_total": 5}})
        if path == "/current":
            return httpx.Response(200, json={"active_sessions": 2})
        if path == "/state":
            return httpx.Response(200, json={"active": []})
        return httpx.Response(404)

    _patch_httpx(monkeypatch, handler)
    snap = await api._gather_snapshot()
    assert snap["stats"]["counters"]["events_total"] == 5
    assert snap["metrics"]["active_sessions"] == 2
    assert snap["incidents"] == {"active": []}


async def test_gather_snapshot_tolerates_upstream_down(monkeypatch):
    _patch_httpx(monkeypatch, lambda req: httpx.Response(503, text="down"))
    snap = await api._gather_snapshot()
    assert snap == {"stats": None, "metrics": None, "incidents": None}
