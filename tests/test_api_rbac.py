"""RBAC tests for the BFF: token signing, role ordering, and endpoint gating."""
import json
import time

import pytest
from fastapi.testclient import TestClient

import services.api.auth as auth
import services.api.main as api


@pytest.fixture
def client():
    return TestClient(api.app)


@pytest.fixture
def users_file(tmp_path, monkeypatch):
    """Three users, one per role; point the auth store at it."""
    path = tmp_path / "users.json"
    path.write_text(
        json.dumps({"users": [
            {"username": "ada", "role": "admin", "password_hash": auth.hash_password("ada-pw")},
            {"username": "opal", "role": "operator", "password": "opal-pw"},
            {"username": "val", "role": "viewer", "password": "val-pw"},
        ]}),
        encoding="utf-8",
    )
    monkeypatch.setenv("MIRAIGE_USERS_FILE", str(path))
    return path


def _login(client, username, password):
    return client.post("/api/v1/login", json={"username": username, "password": password})


# ── units: roles, hashing, token ───────────────────────────────────────

def test_role_ordering():
    assert auth.role_at_least("admin", "viewer")
    assert auth.role_at_least("operator", "operator")
    assert not auth.role_at_least("viewer", "operator")
    assert not auth.role_at_least("nonsense", "viewer")


def test_password_hash_roundtrip():
    h = auth.hash_password("s3cret")
    assert h.startswith("pbkdf2_sha256$")
    assert auth._verify_password("s3cret", h)
    assert not auth._verify_password("nope", h)


def test_token_roundtrip_and_tamper():
    tok = auth.issue_token(auth.Identity("ada", "admin"))
    assert auth.identity_from_token(tok) == auth.Identity("ada", "admin")
    body, _, sig = tok.partition(".")
    assert auth.identity_from_token(f"{body}x.{sig}") is None  # mutated payload
    assert auth.identity_from_token(f"{body}.{sig}deadbeef") is None  # mutated sig
    assert auth.identity_from_token("garbage") is None


def test_token_expiry():
    stale = auth.issue_token(auth.Identity("val", "viewer"), now=time.time() - auth._TOKEN_TTL_S - 100)
    assert auth.identity_from_token(stale) is None


# ── integration: login + gating ────────────────────────────────────────

def test_login_returns_role(client, users_file):
    body = _login(client, "opal", "opal-pw").json()
    assert body["username"] == "opal" and body["role"] == "operator" and body["token"]


def test_bad_credentials_401(client, users_file):
    assert _login(client, "val", "wrong").status_code == 401
    assert _login(client, "ghost", "x").status_code == 401


def test_me_reports_identity(client, users_file):
    tok = _login(client, "val", "val-pw").json()["token"]
    r = client.get("/api/v1/me", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200 and r.json() == {"username": "val", "role": "viewer"}


def test_viewer_blocked_from_attacks(client, users_file):
    tok = _login(client, "val", "val-pw").json()["token"]
    h = {"Authorization": f"Bearer {tok}"}
    assert client.post("/api/v1/attacks", json={"level": "noisy"}, headers=h).status_code == 403
    assert client.get("/api/v1/attacks", headers=h).status_code == 403


def test_viewer_authorized_for_reads(client, users_file):
    tok = _login(client, "val", "val-pw").json()["token"]
    # authz passes (not 401/403); the upstream proxy then 502s in a unit env
    r = client.get("/api/v1/stats", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code not in (401, 403)


def test_operator_can_list_attacks(client, users_file):
    tok = _login(client, "opal", "opal-pw").json()["token"]
    r = client.get("/api/v1/attacks", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200 and "attacks" in r.json()


def test_operator_can_launch_attack(client, users_file, monkeypatch):
    async def fake_launch(level, duration, rps=None):
        return {"id": "x", "level": level, "running": True}

    monkeypatch.setattr(api.attacks, "launch", fake_launch)
    tok = _login(client, "opal", "opal-pw").json()["token"]
    r = client.post(
        "/api/v1/attacks",
        json={"level": "noisy", "duration": 5},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert r.status_code == 200 and r.json()["level"] == "noisy"
