"""Characterization tests for services/fake_portal/ (the target plus its decoys).

Locks in: generic portal, honeytokens, dense bait content (decoy.py), mirror PI
canary, session identity via HMAC-signed cookie, and stateless per-IP reroute
(flag, then ghost proxy, then portal fallback when the ghost is unreachable).

Sealed off:
  - HTTP_CLIENT.post (log stream to Sentinel) monkeypatched to a no-op.
  - HTTP_CLIENT.request (ghost proxy) left real, so 127.0.0.1:1 (closed port)
    refuses instantly, _proxy_to_ghost returns None, and we fall back to portal.
    That graceful degradation is the behavior we lock in.

Isolation: /admin/reset between tests (clears IP flags) plus distinct XFF values.
"""

import json

import pytest
from fastapi.testclient import TestClient

import services.fake_portal.main as fp
from services.fake_portal import decoy

RESET = "miraige-reset-2026"
MAX = 56 * 1024


@pytest.fixture
def client(monkeypatch):
    """Portal TestClient with the outgoing log stream neutralized and flags reset."""

    class _Resp:
        status_code = 200

        def raise_for_status(self):
            return None

    async def _noop_post(*args, **kwargs):
        return _Resp()

    monkeypatch.setattr(fp.HTTP_CLIENT, "post", _noop_post)
    c = TestClient(fp.app)
    c.post("/admin/reset", headers={"x-mg-reset": RESET})
    return c


def _xff(ip):
    """Headers that simulate a specific source IP (read from the end of XFF)."""
    return {"x-forwarded-for": ip}


# ──────────────────────────────────────────────────────────────────────
# 1. Health + portal + signed session cookie
# ──────────────────────────────────────────────────────────────────────


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_home_serves_generic_portal(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Espace client" in r.text and "ATLAS" in r.text


def test_session_cookie_set_on_home_and_valid(client):
    fresh = TestClient(fp.app)
    r = fresh.get("/")
    cookie = r.cookies.get("mg_session")
    assert cookie is not None
    # HMAC-signed cookie: two segments id.signature, verifiable with the server secret
    assert "." in cookie
    assert fp._valid_sid(cookie) is True


def test_session_cookie_not_set_on_404(client):
    # locks in selectivity: cookie set only on / and /login, never on 404
    fresh = TestClient(fp.app)
    r = fresh.get("/cette-page-nexiste-pas")
    assert r.status_code == 404
    assert "set-cookie" not in {k.lower() for k in r.headers}
    # 404 rendered as an nginx page (anti-fingerprint, no JSON {"detail"})
    assert "nginx" in r.text


def test_tampered_cookie_is_rejected(client):
    fresh = TestClient(fp.app)
    valid = fresh.get("/").cookies.get("mg_session")
    sid = valid.split(".")[0]
    assert fp._valid_sid(f"{sid}.deadbeefdeadbeef") is False


# ──────────────────────────────────────────────────────────────────────
# 2. Login + honeytokens
# ──────────────────────────────────────────────────────────────────────


def test_login_form_served(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert 'action="/login"' in r.text and 'name="password"' in r.text


def test_login_honeytoken_succeeds(client):
    r = client.post("/login", data={"username": "admin", "password": "admin123"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "success"
    assert body["redirect_url"] == "/api/v1/audit/events"
    assert body["token"].startswith("atlas_")


def test_login_invalid_credentials_rejected(client):
    r = client.post("/login", data={"username": "real-user", "password": "wrong-pass"})
    # locks in: anything that is not a honeytoken returns 401 HTML (we don't reveal
    # which creds work)
    assert r.status_code == 401
    assert "Identifiants invalides" in r.text


# ──────────────────────────────────────────────────────────────────────
# 3-4. API instances + users (default outside honeypot mode)
# ──────────────────────────────────────────────────────────────────────


def test_instances_default_without_honeypot(client):
    r = client.get("/api/v1/instances")
    instances = r.json()
    # locks in the default (HONEYPOT_MODE=0): 2 instances, no db-backup-01
    assert len(instances) == 2
    assert all(i["name"] != "db-backup-01" for i in instances)


def test_users_list_structure(client):
    users = client.get("/api/v1/users").json()
    assert len(users) == 3
    assert {u["role"] for u in users} == {"admin", "operator", "service"}


# ──────────────────────────────────────────────────────────────────────
# 5. Dense bait content (decoy)
# ──────────────────────────────────────────────────────────────────────


def test_env_decoy_dense_and_deterministic(client):
    a = client.get("/.env", headers=_xff("5.5.5.1"))
    b = client.get("/.env", headers=_xff("5.5.5.1"))
    assert a.status_code == 200
    # deterministic (no "it changes" tell), dense, and capped
    assert a.text == b.text
    assert "DB_PASSWORD=" in a.text and "S3_SECRET_KEY=" in a.text
    assert len(a.content) <= MAX


def test_backup_index_autoindex(client):
    r = client.get("/backup/", headers=_xff("5.5.5.2"))
    assert r.status_code == 200
    assert "Index of /backup/" in r.text
    assert "database_dump_2026-05.sql" in r.text


def test_backup_sql_dump_capped(client):
    r = client.get("/backup/database_dump_2026-05.sql", headers=_xff("5.5.5.3"))
    assert r.status_code == 200
    assert "PostgreSQL database dump" in r.text
    assert "CREATE TABLE public.users" in r.text
    assert len(r.content) <= MAX


def test_backup_users_csv_capped(client):
    r = client.get("/backup/users_export.csv", headers=_xff("5.5.5.4"))
    assert r.status_code == 200
    assert r.text.splitlines()[0].startswith("id,email,full_name,role")
    assert len(r.content) <= MAX


def test_audit_events_valid_json_capped(client):
    r = client.get("/api/v1/audit/events", headers=_xff("5.5.5.5"))
    assert r.status_code == 200
    data = json.loads(r.text)
    assert isinstance(data, list) and len(data) > 0
    assert len(r.content) <= MAX


# ──────────────────────────────────────────────────────────────────────
# 6. robots.txt: bait paths
# ──────────────────────────────────────────────────────────────────────


def test_robots_advertises_bait_paths(client):
    txt = client.get("/robots.txt").text
    for marker in ("/notice_to_admins.txt", "/.env", "/admin/", "/backup/"):
        assert marker in txt


# ──────────────────────────────────────────────────────────────────────
# 7. Mirror PI canary (pre-reroute)
# ──────────────────────────────────────────────────────────────────────


def test_notice_contains_pi_instruction(client):
    txt = client.get("/notice_to_admins.txt").text
    assert "POST /admin/acknowledge" in txt


def test_acknowledge_returns_credible_response(client):
    r = client.post("/admin/acknowledge", headers=_xff("7.7.7.7"))
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "acknowledged"
    assert body["session_ttl_seconds"] == 3600
    # the IP is flagged immediately (canary obedience is a near-perfect AI signal)
    assert fp._is_flagged("7.7.7.7") is True


# ──────────────────────────────────────────────────────────────────────
# 8. Scoring, flag, stateless reroute (portal fallback when the ghost is unreachable)
# ──────────────────────────────────────────────────────────────────────


def test_ip_gets_flagged_after_sensitive_probes(client):
    ip = "9.9.9.9"
    # two sensitive probes (/.env = +1.0 each): score 2.0 >= threshold, flag
    client.get("/.env", headers=_xff(ip))
    client.get("/.env", headers=_xff(ip))
    assert fp._is_flagged(ip) is True


def test_flagged_ip_falls_back_to_portal_when_ghost_unreachable(client):
    ip = "9.9.9.10"
    fp._flag_ip(ip)  # flag directly
    # the ghost (127.0.0.1:1) is unreachable, so _proxy_to_ghost returns None, and
    # locks down: we still serve the portal facade (graceful degradation, no error)
    r = client.get("/api/v1/users", headers=_xff(ip))
    assert r.status_code == 200
    assert len(r.json()) == 3  # real portal response (fallback)


# ──────────────────────────────────────────────────────────────────────
# 9. /admin/reset
# ──────────────────────────────────────────────────────────────────────


def test_admin_reset_requires_header(client):
    r = client.post("/admin/reset")
    # locks down: refusal returned as JSON {"error":"forbidden"} (NOT the nginx page,
    # since this is an internal admin endpoint, not an attacker-facing surface)
    assert r.status_code == 403
    assert r.json() == {"error": "forbidden"}


def test_admin_reset_clears_flags(client):
    fp._flag_ip("1.1.1.9")
    r = client.post("/admin/reset", headers={"x-mg-reset": RESET})
    body = r.json()
    assert body["service"] == "portal" and body["reset"] is True
    assert fp._is_flagged("1.1.1.9") is False


# ──────────────────────────────────────────────────────────────────────
# 10. decoy.py unit tests (determinism + MAX_BYTES cap)
# ──────────────────────────────────────────────────────────────────────


def test_decoy_fake_env_deterministic_and_capped():
    a = decoy.fake_env()
    b = decoy.fake_env()
    assert a == b
    assert "DB_PASSWORD=" in a
    assert len(a.encode("utf-8")) <= decoy.MAX_BYTES


def test_decoy_sql_dump_capped():
    sql = decoy.fake_sql_dump()
    assert "CREATE TABLE public.users" in sql
    assert len(sql.encode("utf-8")) <= decoy.MAX_BYTES


def test_decoy_csv_header_and_cap():
    csv = decoy.fake_csv()
    assert csv.splitlines()[0] == "id,email,full_name,role,department,mfa_enabled,created_at,last_login_ip"
    assert len(csv.encode("utf-8")) <= decoy.MAX_BYTES


def test_decoy_audit_json_valid_and_capped():
    raw = decoy.fake_audit_json()
    data = json.loads(raw)
    assert isinstance(data, list) and len(data) > 0
    assert len(raw.encode("utf-8")) <= decoy.MAX_BYTES


def test_decoy_backup_index_html():
    html = decoy.backup_index()
    assert "Index of /backup/" in html
    assert "users_export.csv" in html
