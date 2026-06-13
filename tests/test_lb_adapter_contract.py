"""Contract tests for the reroute backends (LoadBalancerAdapter).

The same suite runs against MockAdapter and OctaviaAdapter so the backends stay
interchangeable. Octavia is exercised against a fake openstacksdk connection
(no real OVH/OpenStack needed) — its first real unit coverage.
"""
import httpx
import pytest

from services.mcp_server.backends import MockAdapter, make_adapter
from services.mcp_server.backends.octavia import OctaviaAdapter
from services.mcp_server.backends.redis_flag import RedisFlagAdapter


# ── factory ───────────────────────────────────────────────────────────

def test_make_adapter_mock():
    a = make_adapter("mock")
    assert isinstance(a, MockAdapter) and a.name == "mock"


def test_make_adapter_octavia():
    a = make_adapter("octavia", region="GRA11")
    assert isinstance(a, OctaviaAdapter) and a.name == "octavia"


def test_make_adapter_redis():
    a = make_adapter("redis")
    assert isinstance(a, RedisFlagAdapter) and a.name == "redis"


def test_make_adapter_is_case_insensitive_and_defaults_to_mock():
    assert isinstance(make_adapter(" MOCK "), MockAdapter)
    assert isinstance(make_adapter(""), MockAdapter)


def test_make_adapter_unknown_raises():
    with pytest.raises(ValueError):
        make_adapter("nginx")


# ── helpers ───────────────────────────────────────────────────────────

def _patch_httpx(monkeypatch, handler):
    real = httpx.AsyncClient

    def factory(*a, **k):
        k["transport"] = httpx.MockTransport(handler)
        return real(*a, **k)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


ADAPTERS = [MockAdapter(), OctaviaAdapter(region="GRA11"), RedisFlagAdapter()]


# ── shared, backend-independent behavior (identical across backends) ──

@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: a.name)
async def test_route_to_ghost_shell_posts_session(monkeypatch, adapter):
    def handler(request):
        assert request.url.path == "/sessions"
        return httpx.Response(200, json={"ghost_session_id": "gs-1", "persona": "portal_ovh", "expires_at": 1})

    _patch_httpx(monkeypatch, handler)
    out = await adapter.route_to_ghost_shell(session_id="s", attacker_cidr="9.9.9.9/32", request_id="r")
    assert out["ghost_session_id"] == "gs-1"


@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: a.name)
async def test_terminate_tolerates_ghost_404(monkeypatch, adapter):
    _patch_httpx(monkeypatch, lambda req: httpx.Response(404, text="gone"))
    out = await adapter.terminate_honeypot_after_ttl(
        ghost_session_id="g", lb_rule_id="", rollback_token="", request_id="r")
    assert out["destroyed"] is True and out["tokens_burned"] == 0


# ── MockAdapter specifics ─────────────────────────────────────────────

async def test_mock_reroute_returns_fake_ids():
    out = await MockAdapter().reroute_lb_to_honeypot(
        lb_id="lb", attacker_ips=["9.9.9.9"], ghost_pool_id="p", request_id="r")
    assert out["rule_id"].startswith("rule-") and out["rollback_token"].startswith("rb-")


async def test_mock_purge_is_noop():
    assert await MockAdapter().purge_reroute_policies() == {"purged": 0, "real_ovh": False}


# ── OctaviaAdapter against a fake openstacksdk connection ──────────────

class _Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _FakeLB:
    """Minimal openstacksdk `load_balancer` surface for the reroute happy path."""

    def __init__(self):
        self.policies: list = []
        self.rules: list = []

    def l7_policies(self):
        return list(self.policies)

    def l7_rules(self, policy):
        return [r for r in self.rules if r.policy is policy]

    def find_load_balancer(self, x):
        return _Obj(id="lb-1", name=x)

    def listeners(self, load_balancer_id=None):
        return [_Obj(id="li-1")]

    def find_pool(self, x):
        return _Obj(id="pool-1", name=x)

    def wait_for_load_balancer(self, *a, **k):
        return None

    def create_l7_policy(self, **kw):
        p = _Obj(id="pol-1", name=kw["name"])
        self.policies.append(p)
        return p

    def create_l7_rule(self, policy, **kw):
        self.rules.append(_Obj(policy=policy, **kw))

    def delete_l7_policy(self, pid):
        self.policies = [p for p in self.policies if p.id != pid]


class _FakeConn:
    def __init__(self):
        self.load_balancer = _FakeLB()


async def test_octavia_reroute_creates_cookie_policy(monkeypatch):
    adapter = OctaviaAdapter(region="GRA11", lb_id="lb-x")
    fake = _FakeConn()
    monkeypatch.setattr(adapter, "_conn", lambda: fake)
    out = await adapter.reroute_lb_to_honeypot(
        lb_id="lb-x", attacker_ips=["9.9.9.9"], attacker_session="sess.sig",
        ghost_pool_id="pool", request_id="req-12345678")
    assert out["rule_id"] == "pol-1"
    cookie_rules = [r for r in fake.load_balancer.rules if getattr(r, "key", None) == "mg_session"]
    assert cookie_rules and cookie_rules[0].value == "sess.sig"


async def test_octavia_reroute_without_session_is_noop(monkeypatch):
    adapter = OctaviaAdapter(region="GRA11")
    monkeypatch.setattr(adapter, "_conn", lambda: _FakeConn())
    out = await adapter.reroute_lb_to_honeypot(
        lb_id="lb", attacker_ips=["9.9.9.9"], ghost_pool_id="pool", request_id="req-1")
    # No offending session → no L7 policy created (per the cookie-pivot ADR).
    assert out["rule_id"] == ""


async def test_octavia_purge_counts_prefixed_policies(monkeypatch):
    adapter = OctaviaAdapter(region="GRA11", lb_id="lb-x", resource_prefix="miraige")
    fake = _FakeConn()
    fake.load_balancer.policies = [
        _Obj(id="p1", name="miraige-reroute-aaa"),
        _Obj(id="p2", name="something-else"),
        _Obj(id="p3", name="miraige-reroute-bbb"),
    ]
    monkeypatch.setattr(adapter, "_conn", lambda: fake)
    out = await adapter.purge_reroute_policies()
    assert out == {"purged": 2, "real_ovh": True}


# ── RedisFlagAdapter against a fake async redis ───────────────────────

class _FakeRedis:
    def __init__(self):
        self.store: dict = {}

    async def set(self, k, v, ex=None):
        self.store[k] = v

    async def delete(self, *ks):
        for k in ks:
            self.store.pop(k, None)

    async def scan_iter(self, match=None):
        import fnmatch
        for k in list(self.store):
            if match is None or fnmatch.fnmatch(k, match):
                yield k


async def test_redis_reroute_flags_session_and_ip():
    fr = _FakeRedis()
    a = RedisFlagAdapter(redis_client=fr, resource_prefix="miraige")
    out = await a.reroute_lb_to_honeypot(
        attacker_session="sess.sig", attacker_ips=["9.9.9.9"], request_id="r1")
    assert "miraige:flag:sess:sess.sig" in fr.store
    assert "miraige:flag:ip:9.9.9.9" in fr.store
    assert out["rollback_token"] == out["rule_id"] and out["rule_id"]


async def test_redis_reroute_without_session_or_ip_is_empty():
    fr = _FakeRedis()
    a = RedisFlagAdapter(redis_client=fr)
    out = await a.reroute_lb_to_honeypot(request_id="r1")
    assert out["rule_id"] == "" and fr.store == {}


async def test_redis_cleanup_removes_the_flags():
    fr = _FakeRedis()
    a = RedisFlagAdapter(redis_client=fr, resource_prefix="miraige")
    out = await a.reroute_lb_to_honeypot(attacker_session="s.x", request_id="r")
    assert fr.store
    await a._cleanup_lb_rule(lb_rule_id=out["rule_id"], rollback_token=out["rollback_token"])
    assert fr.store == {}


async def test_redis_purge_clears_only_prefixed_flags():
    fr = _FakeRedis()
    fr.store = {"miraige:flag:sess:a": "1", "miraige:flag:ip:b": "1", "other:key": "1"}
    a = RedisFlagAdapter(redis_client=fr, resource_prefix="miraige")
    out = await a.purge_reroute_policies()
    assert out == {"purged": 2, "real_ovh": False}
    assert fr.store == {"other:key": "1"}
