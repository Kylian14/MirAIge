"""MorphStore tests: in-memory + redis backends, FIFO eviction, backend selection."""
from services.orchestrator.store import (
    InMemoryMorphStore,
    RedisMorphStore,
    make_morph_store,
)
from services.shared.models import MorphContext, MorphState


def _ctx(rid: str, state: MorphState = MorphState.IDLE) -> MorphContext:
    return MorphContext(
        request_id=rid, attacker_ip="203.0.113.1", target_instance_id="vm-1", state=state,
    )


# ── a minimal async fake of the redis hash + list ops we use ───────────
class _FakeRedis:
    def __init__(self) -> None:
        self.h: dict[str, dict[str, str]] = {}
        self.l: dict[str, list[str]] = {}

    async def hset(self, key, field, value):
        self.h.setdefault(key, {})[field] = value

    async def hget(self, key, field):
        return self.h.get(key, {}).get(field)

    async def hexists(self, key, field):
        return field in self.h.get(key, {})

    async def hvals(self, key):
        return list(self.h.get(key, {}).values())

    async def hlen(self, key):
        return len(self.h.get(key, {}))

    async def hdel(self, key, *fields):
        for f in fields:
            self.h.get(key, {}).pop(f, None)

    async def rpush(self, key, *vals):
        self.l.setdefault(key, []).extend(vals)

    async def lrange(self, key, start, stop):
        lst = self.l.get(key, [])
        return lst[start:] if stop == -1 else lst[start : stop + 1]

    async def lrem(self, key, count, value):
        self.l[key] = [x for x in self.l.get(key, []) if x != value]

    async def delete(self, *keys):
        for k in keys:
            self.h.pop(k, None)
            self.l.pop(k, None)


# ── in-memory ──────────────────────────────────────────────────────────

async def test_inmemory_crud_roundtrip():
    s = InMemoryMorphStore()
    await s.add(_ctx("a"))
    assert await s.contains("a")
    assert (await s.get("a")).request_id == "a"
    assert await s.count() == 1
    await s.save(_ctx("a", MorphState.MONITORING))
    assert (await s.get("a")).state == MorphState.MONITORING
    assert [c.request_id for c in await s.all()] == ["a"]
    assert await s.get("missing") is None
    assert await s.clear() == 1
    assert await s.count() == 0


async def test_inmemory_wraps_passed_dict():
    backing: dict = {}
    s = InMemoryMorphStore(backing)
    await s.add(_ctx("a"))
    assert "a" in backing  # same object → the back-compat bridge for main.ACTIVE


async def test_inmemory_evict_spares_in_flight():
    s = InMemoryMorphStore()
    for rid, st in [("old1", MorphState.IDLE), ("busy", MorphState.MONITORING),
                    ("old2", MorphState.ERROR), ("new", MorphState.IDLE)]:
        await s.add(_ctx(rid, st))
    await s.evict_terminal(2)
    assert {c.request_id for c in await s.all()} == {"busy", "new"}


# ── redis ───────────────────────────────────────────────────────────────

async def test_redis_crud_and_transition_persist():
    s = RedisMorphStore(redis_client=_FakeRedis(), key_prefix="t:orch")
    await s.add(_ctx("a"))
    assert await s.contains("a") and await s.count() == 1
    assert (await s.get("a")).request_id == "a"
    await s.save(_ctx("a", MorphState.MONITORING))  # a transition
    assert (await s.get("a")).state == MorphState.MONITORING
    assert [c.request_id for c in await s.all()] == ["a"]
    assert await s.clear() == 1 and await s.count() == 0
    assert await s.contains("a") is False


async def test_redis_evict_spares_in_flight():
    s = RedisMorphStore(redis_client=_FakeRedis(), key_prefix="t:orch")
    for rid, st in [("old1", MorphState.IDLE), ("busy", MorphState.MONITORING),
                    ("old2", MorphState.ERROR), ("new", MorphState.IDLE)]:
        await s.add(_ctx(rid, st))
    await s.evict_terminal(2)
    assert {c.request_id for c in await s.all()} == {"busy", "new"}


# ── factory ─────────────────────────────────────────────────────────────

def test_make_store_selects_backend(monkeypatch):
    monkeypatch.delenv("ORCHESTRATOR_STATE_BACKEND", raising=False)
    assert isinstance(make_morph_store({}), InMemoryMorphStore)
    monkeypatch.setenv("ORCHESTRATOR_STATE_BACKEND", "redis")
    assert isinstance(make_morph_store({}), RedisMorphStore)
