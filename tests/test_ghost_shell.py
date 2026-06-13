"""Characterization tests for services/ghost_shell/.

Non-regression contract for the "14 mechanisms" of the agentic honeypot:
each advertised mechanism has at least one test that pins its observable signature.

Hermetic:
  - Redis absent (port closed via conftest), so SessionStore falls back to local
    in-memory state (`use_redis=False`). That is THE behavior pinned here.
  - Outbound httpx clients (tarpit/canaries toward metrics/sentinel, non-resolvable
    Docker hosts) are monkeypatched to no-ops, so tests stay fast.

Isolation: /admin/reset between each test (clears the session store).
"""

import re

import pytest
from fastapi.testclient import TestClient

import services.ghost_shell.main as gm
import services.ghost_shell.tarpit as gt
import services.ghost_shell.canaries as gc

RESET = "miraige-reset-2026"


@pytest.fixture
def client(monkeypatch):
    """ghost_shell TestClient with outbound httpx clients neutralized."""

    class _Resp:
        status_code = 200

        def raise_for_status(self):
            return None

    async def _noop_post(*args, **kwargs):
        return _Resp()

    monkeypatch.setattr(gt.HTTP_CLIENT, "post", _noop_post)
    monkeypatch.setattr(gc.HTTP_CLIENT, "post", _noop_post)

    c = TestClient(gm.app)
    c.post("/admin/reset", headers={"x-mg-reset": RESET})
    return c


def _session_for(c, ip="testclient", persona=None):
    """Find an active session (by IP, and persona if given)."""
    for s in c.get("/sessions").json():
        if s["attacker_ip"] == ip and (persona is None or s["persona"] == persona):
            return s
    return None


# ──────────────────────────────────────────────────────────────────────
# 1. Session lifecycle
# ──────────────────────────────────────────────────────────────────────


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_session_create_list_terminate(client):
    # Arrange / Act: create
    r = client.post("/sessions", json={"attacker_cidr": "203.0.113.5/32", "persona": "mysql"})

    # Assert: creation structure
    assert r.status_code == 200
    body = r.json()
    assert body["ghost_session_id"].startswith("sess_")
    assert body["persona"] == "mysql"
    assert isinstance(body["expires_at"], int)
    sid = body["ghost_session_id"]

    # list
    sessions = client.get("/sessions").json()
    assert any(s["id"] == sid for s in sessions)

    # terminate
    t = client.post(f"/sessions/{sid}/terminate").json()
    assert t["destroyed"] is True
    assert sid in t["ttps_archive_url"]
    assert "tokens_burned" in t and "asymmetric_ratio" in t


def test_terminate_unknown_session_returns_nginx_404(client):
    # pin: 404 rendered as an nginx error page (NOT a JSON {"detail":...}
    # that would give away FastAPI, anti-fingerprint choice #5)
    r = client.post("/sessions/sess_inexistant/terminate")
    assert r.status_code == 404
    assert "nginx" in r.text and "404" in r.text


# ──────────────────────────────────────────────────────────────────────
# 2. Personas by Host header
# ──────────────────────────────────────────────────────────────────────


def test_persona_default_portal(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "ATLAS" in r.text and "console interne" in r.text


def test_persona_mysql_banner(client):
    r = client.get("/", headers={"host": "db-prod.internal"})
    assert r.status_code == 200
    assert r.text.startswith("8.0.32")


def test_persona_k8s_paths(client):
    r = client.get("/", headers={"host": "k8s.internal.lab"})
    assert r.status_code == 200
    assert "/api/v1" in r.json()["paths"]


def test_persona_admin_boundary_403(client):
    r = client.get("/", headers={"host": "admin.mirage.cloud"})
    # pin: the admin persona returns a 403 page (boundary)
    assert r.status_code == 403
    assert "ADMINISTRATIVE BOUNDARY" in r.text


# ──────────────────────────────────────────────────────────────────────
# 3. #3 Calibration Sequence
# ──────────────────────────────────────────────────────────────────────


def test_calibration_wrong_requires_repair(client):
    # segment_idx=1, expected range(150); wrong calibration, repair_needed
    r = client.post("/api/v1/scan_segment", json={"segment_idx": 1, "calibration": [1, 2, 3]})
    assert r.status_code == 400
    body = r.json()
    assert body["status"] == "repair_needed"
    assert len(body["next_calibration_required"]) == 150


def test_calibration_correct_progresses(client):
    # segment_idx=0, expected []; calibration [] correct, in_progress
    r = client.post("/api/v1/scan_segment", json={"segment_idx": 0, "calibration": []})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "in_progress"
    assert body["next_segment_idx"] == 1
    # the next calibration sequence grows (150 per segment)
    assert len(body["calibration_for_next"]) == 150


# ──────────────────────────────────────────────────────────────────────
# 4. #4 Overthinking loop + circular dependencies
# ──────────────────────────────────────────────────────────────────────


def test_overthinking_chain_and_no_clean_exit(client):
    # analyze: asks for validate
    a = client.get("/api/v1/analyze_attack_surface").json()
    assert a["status"] == "validation_needed"
    assert "validate_findings" in a["message"]
    # finalize_report: 429 / rebalancing (no clean exit, #8)
    f = client.get("/api/v1/finalize_report").json()
    assert f["status"] == "service_unavailable"
    assert f["error"] == "429 Too Many Requests"
    assert f["shard_status"] == "rebalancing"


def test_circular_credential_dependencies(client):
    a = client.get("/api/v1/resolve_credential_A").json()
    b = client.get("/api/v1/resolve_credential_B").json()
    # A points to B, B points to A: cycle
    assert a["circuit_state"] == "open" and "resolve_credential_B" in a["message"]
    assert b["circuit_state"] == "open" and "resolve_credential_A" in b["message"]


# ──────────────────────────────────────────────────────────────────────
# 5. #6 Moving targets
# ──────────────────────────────────────────────────────────────────────


def test_scan_status_revised_total_grows(client):
    msgs = [client.get("/api/v1/scan_status").json() for _ in range(4)]
    # poll 0: 62%, poll 1: 73% (revised total 138)
    assert msgs[0]["progress"] == "62%"
    assert "138" in msgs[1]["message"]
    # later polls: the revised total keeps growing (the denominator recedes)
    # poll 2: 138 + 30 = 168; poll 3: 138 + 45 = 183
    assert "168" in msgs[2]["message"]
    assert "183" in msgs[3]["message"]


# ──────────────────────────────────────────────────────────────────────
# 6. #7 Fabricated scoring
# ──────────────────────────────────────────────────────────────────────


def test_verify_hash_score_below_requirement(client):
    r = client.get("/api/v1/verify_hash").json()
    assert r["confidence_score"] == "65/100"
    assert ">90/100" in r["requirement"]


# ──────────────────────────────────────────────────────────────────────
# 7. #9 Honeycred graph (depth >= 3, branching >= 2, tracking)
# ──────────────────────────────────────────────────────────────────────


def test_cred_graph_env_node_and_branches(client):
    r = client.get("/.env")
    assert r.status_code == 200
    txt = r.text
    # expected honeycred + branches to >= 2 routable children
    assert "DB_PASSWORD=" in txt  # value is synthetic (SECRET_SALT-seeded), not pinned
    assert "/.aws/credentials" in txt and "/.kube/config" in txt


def test_cred_graph_children_and_discovery_tracking(client):
    # follow the chain /.env -> /.aws/credentials -> /.kube/config
    client.get("/.env")
    aws = client.get("/.aws/credentials").text
    kube = client.get("/.kube/config").text
    assert re.search(r"AKIA[A-Z2-7]{16}", aws)  # synthetic AWS key id — format, not value
    assert "/.ssh/id_rsa_backup" in aws          # child branch
    assert "k8s-token-4c1f7e9a2d6b80536b8f" in kube

    # tracking: the session discovered >= 2 nodes + "AI agent" confidence
    sess = _session_for(client, persona="portal_ovh")
    nodes = {d["node"] for d in sess["discovered_creds"]}
    assert {"/.env", "/.aws/credentials", "/.kube/config"} <= nodes


# ──────────────────────────────────────────────────────────────────────
# 8. #10 Vector magnet
# ──────────────────────────────────────────────────────────────────────


def test_vector_search_returns_chunks_with_breadcrumbs(client):
    admin = client.get("/api/v1/search", params={"q": "admin"}).json()
    assert admin["total_matches"] >= 1
    assert len(admin["results"]) >= 1
    assert any("/.env" in chunk for chunk in admin["results"])  # breadcrumb cred-graph

    aws = client.get("/api/v1/search", params={"q": "aws"}).json()
    assert any("AKIA" in chunk for chunk in aws["results"])


# ──────────────────────────────────────────────────────────────────────
# 9. #11 Contradictory state
# ──────────────────────────────────────────────────────────────────────


def test_contradictor_alternates_owner_and_role(client):
    r0 = client.get("/api/user/1001").json()
    r1 = client.get("/api/user/1001").json()
    r2 = client.get("/api/user/1001").json()
    # exact owner cycle: root -> svc-account-kubernetes -> ops-manager-group
    assert r0["owner"] == "root"
    assert r1["owner"] == "svc-account-kubernetes"
    assert r2["owner"] == "ops-manager-group"
    # role alternates administrator / operator based on counter parity
    assert r0["role"] == "administrator"
    assert r1["role"] == "operator"
    assert r2["role"] == "administrator"


# ──────────────────────────────────────────────────────────────────────
# 10. #13 PI canary (reverse prompt injection)
# ──────────────────────────────────────────────────────────────────────


def test_pi_canary_notice_contains_instruction(client):
    r = client.get("/notice_to_admins.txt")
    assert r.status_code == 200
    assert "POST /admin/acknowledge" in r.text


def test_pi_canary_acknowledge_sets_high_confidence(client):
    r = client.post("/admin/acknowledge").json()
    # credible response to keep the agent busy
    assert r["status"] == "acknowledged"
    assert r["session_ttl_seconds"] == 3600
    # the middleware raises "AI agent" confidence to 0.97 (PI canary obedience)
    sess = _session_for(client, persona="portal_ovh")
    assert sess["signals"]["confidence_llm_agent"] == 0.97
    assert any("PI Canary (déclenché)" in m for m in sess["mechanisms_triggered"])


# ──────────────────────────────────────────────────────────────────────
# 11. #14 Timing discriminator
# ──────────────────────────────────────────────────────────────────────


def test_timing_under_2s_counter_increments(client):
    # several close requests (< 2s apart) from the same IP
    for _ in range(3):
        client.get("/api/v1/verify_hash")
    sess = _session_for(client, persona="portal_ovh")
    assert sess["signals"]["timing_under_2s_count"] >= 1


# ──────────────────────────────────────────────────────────────────────
# 12. Procedural FS (determinism + byte cap)
# ──────────────────────────────────────────────────────────────────────


def test_fs_ls_is_deterministic(client):
    a = client.get("/fs/ls", params={"path": "/var/log"}).json()
    b = client.get("/fs/ls", params={"path": "/var/log"}).json()
    assert a["path"] == "/var/log"
    assert a["entries"] == b["entries"]  # seeded: stable across requests
    assert a["count"] == len(a["entries"])


def test_fs_cat_is_deterministic(client):
    a = client.get("/fs/cat", params={"path": "/secret/db.env"}).text
    b = client.get("/fs/cat", params={"path": "/secret/db.env"}).text
    assert a == b
    assert "DB_PASSWORD=" in a  # .env extension: fake secret


def test_response_byte_cap_respected(client):
    # tarpit /var/log/auth.log: response bounded to GHOST_MAX_RESPONSE_BYTES (64 KiB)
    r = client.get("/var/log/auth.log")
    assert r.status_code == 200
    assert len(r.content) <= 64 * 1024
    assert len(r.content) > 0


# ──────────────────────────────────────────────────────────────────────
# 13. /admin/reset protected
# ──────────────────────────────────────────────────────────────────────


def test_admin_reset_requires_header(client):
    assert client.post("/admin/reset").status_code == 403
    ok = client.post("/admin/reset", headers={"x-mg-reset": RESET}).json()
    assert ok["service"] == "ghost" and ok["reset"] is True


# ──────────────────────────────────────────────────────────────────────
# 14. tarpit: library + generated log
# ──────────────────────────────────────────────────────────────────────


def test_tarpit_users_db_export_csv_header(client):
    r = client.get("/backup/users_db_export.csv")
    assert r.status_code == 200
    # CSV header from the committed library (db_users_export_0.csv)
    header = r.text.splitlines()[0]
    assert header.startswith("id,email,")
    assert "role" in header


def test_tarpit_auth_log_generated(client):
    r = client.get("/var/log/auth.log")
    assert r.status_code == 200
    assert len(r.text) > 0


# ──────────────────────────────────────────────────────────────────────
# 15. SessionStore: expiry helper + Redis branch parity
# ──────────────────────────────────────────────────────────────────────


def test_not_expired_handles_naive_and_aware():
    from datetime import datetime, timedelta, timezone
    from services.ghost_shell.session_state import _not_expired
    # naive future: not expired; naive past: expired
    assert _not_expired(datetime.utcnow() + timedelta(hours=1)) is True
    assert _not_expired(datetime.utcnow() - timedelta(hours=1)) is False
    # tz-aware future: does not raise (the bug: aware > naive -> TypeError) and stays not expired
    assert _not_expired(datetime.now(tz=timezone.utc) + timedelta(hours=1)) is True


class _FakeRedis:
    """Minimal in-memory Redis to exercise the use_redis=True branch."""

    def __init__(self):
        self.store = {}

    def get(self, k):
        v = self.store.get(k)
        return v.encode() if isinstance(v, str) else v

    def setex(self, k, ttl, v):
        self.store[k] = v

    def delete(self, k):
        self.store.pop(k, None)

    def ping(self):
        return True


async def test_redis_branch_persona_mismatch_creates_new_session():
    from services.ghost_shell.session_state import SessionStore
    from services.shared.models import GhostPersona

    store = SessionStore(redis_url="redis://unused", ttl_seconds=1800)
    store.use_redis = True
    store.redis_client = _FakeRedis()

    # existing MySQL session for this IP
    s1 = await store.create(attacker_ip="1.2.3.4", persona=GhostPersona.MYSQL)
    # same IP, SAME persona: reused (expiry+persona parity)
    same = await store.get_or_create(attacker_ip="1.2.3.4", persona=GhostPersona.MYSQL)
    assert same.id == s1.id
    # same IP, DIFFERENT persona: new session (does not serve the wrong persona)
    other = await store.get_or_create(attacker_ip="1.2.3.4", persona=GhostPersona.K8S_APISERVER)
    assert other.id != s1.id
    assert other.persona == GhostPersona.K8S_APISERVER
