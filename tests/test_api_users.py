"""Admin user-management tests for the BFF (CRUD, gating, invariants)."""
import json

import pytest
from fastapi.testclient import TestClient

import services.api.auth as auth
import services.api.main as api


@pytest.fixture
def client():
    return TestClient(api.app)


@pytest.fixture
def store(tmp_path, monkeypatch):
    """A writable users.json with one user per role."""
    path = tmp_path / "users.json"
    path.write_text(
        json.dumps({"users": [
            {"username": "boss", "role": "admin", "password_hash": auth.hash_password("boss-pw")},
            {"username": "opal", "role": "operator", "password_hash": auth.hash_password("opal-pw")},
            {"username": "val", "role": "viewer", "password_hash": auth.hash_password("val-pw")},
        ]}),
        encoding="utf-8",
    )
    monkeypatch.setenv("MIRAIGE_USERS_FILE", str(path))
    return path


def _token(client, username, password):
    r = client.post("/api/v1/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _h(tok):
    return {"Authorization": f"Bearer {tok}"}


def test_list_users_no_secrets(client, store):
    tok = _token(client, "boss", "boss-pw")
    r = client.get("/api/v1/users", headers=_h(tok))
    assert r.status_code == 200
    body = r.json()
    assert body["managed"] is True
    assert {u["username"]: u["role"] for u in body["users"]} == {
        "boss": "admin", "opal": "operator", "val": "viewer",
    }
    assert "password" not in json.dumps(body)  # never leak hashes/plaintext


def test_non_admin_forbidden(client, store):
    for user, pw in [("opal", "opal-pw"), ("val", "val-pw")]:
        tok = _token(client, user, pw)
        assert client.get("/api/v1/users", headers=_h(tok)).status_code == 403
        assert client.post(
            "/api/v1/users", json={"username": "x", "role": "viewer", "password": "p"}, headers=_h(tok)
        ).status_code == 403
        assert client.delete("/api/v1/users/val", headers=_h(tok)).status_code == 403


def test_create_then_login(client, store):
    tok = _token(client, "boss", "boss-pw")
    assert client.post(
        "/api/v1/users", json={"username": "newbie", "role": "operator", "password": "new-pw"}, headers=_h(tok)
    ).status_code == 200
    newbie = _token(client, "newbie", "new-pw")  # the new user can log in
    assert client.get("/api/v1/attacks", headers=_h(newbie)).status_code == 200  # and is an operator


def test_create_duplicate_and_bad_role(client, store):
    tok = _token(client, "boss", "boss-pw")
    assert client.post(
        "/api/v1/users", json={"username": "opal", "role": "viewer", "password": "p"}, headers=_h(tok)
    ).status_code == 400
    assert client.post(
        "/api/v1/users", json={"username": "z", "role": "superuser", "password": "p"}, headers=_h(tok)
    ).status_code == 400


def test_patch_role_and_password(client, store):
    tok = _token(client, "boss", "boss-pw")
    assert client.patch("/api/v1/users/val", json={"role": "operator"}, headers=_h(tok)).status_code == 200
    promoted = _token(client, "val", "val-pw")
    assert client.get("/api/v1/attacks", headers=_h(promoted)).status_code == 200  # viewer -> operator
    assert client.patch("/api/v1/users/opal", json={"password": "opal-new"}, headers=_h(tok)).status_code == 200
    assert client.post("/api/v1/login", json={"username": "opal", "password": "opal-new"}).status_code == 200
    assert client.post("/api/v1/login", json={"username": "opal", "password": "opal-pw"}).status_code == 401


def test_patch_unknown_user_404(client, store):
    tok = _token(client, "boss", "boss-pw")
    assert client.patch("/api/v1/users/ghost", json={"role": "viewer"}, headers=_h(tok)).status_code == 404


def test_delete_user(client, store):
    tok = _token(client, "boss", "boss-pw")
    assert client.delete("/api/v1/users/val", headers=_h(tok)).status_code == 200
    assert client.post("/api/v1/login", json={"username": "val", "password": "val-pw"}).status_code == 401


def test_last_admin_protected(client, store):
    tok = _token(client, "boss", "boss-pw")  # boss is the only admin
    assert client.patch("/api/v1/users/boss", json={"role": "operator"}, headers=_h(tok)).status_code == 400
    assert client.delete("/api/v1/users/boss", headers=_h(tok)).status_code == 400


def test_self_delete_refused(client, store):
    tok = _token(client, "boss", "boss-pw")
    client.post("/api/v1/users", json={"username": "boss2", "role": "admin", "password": "p2"}, headers=_h(tok))
    # two admins now, so this 400 is the self-delete guard, not the last-admin one
    assert client.delete("/api/v1/users/boss", headers=_h(tok)).status_code == 400


def test_unmanaged_store_409(client, monkeypatch):
    monkeypatch.delenv("MIRAIGE_USERS_FILE", raising=False)  # fallback admin, not file-backed
    tok = _token(client, "", "Miraige2025!")  # conftest default password -> admin
    r = client.get("/api/v1/users", headers=_h(tok))
    assert r.status_code == 200 and r.json()["managed"] is False
    assert client.post(
        "/api/v1/users", json={"username": "x", "role": "viewer", "password": "p"}, headers=_h(tok)
    ).status_code == 409
