"""Active-morph state store for the orchestrator.

`ACTIVE` used to be an in-memory dict: lost on restart and invisible to any other
instance. This abstracts it behind a small async interface with two backends,
selected by ORCHESTRATOR_STATE_BACKEND (mirrors REROUTE_BACKEND):

  · memory (default) — a plain dict; fine for a single instance and for tests.
  · redis            — JSON in Redis: crash-safe and shared across instances.

The FSM persists on every transition (orchestrator wires `on_transition` to
`save`), so a redis-backed /state reflects MONITORING in near real time.

Note: this gives shared, crash-safe *state*. Resuming an FSM that was interrupted
mid-flight (re-driving a MONITORING morph after a restart) is a further step and
is intentionally out of scope here.
"""
from __future__ import annotations

import os
from typing import Any, Protocol

from services.shared.models import MorphContext, MorphState

_TERMINAL = (MorphState.IDLE, MorphState.ERROR)


class MorphStore(Protocol):
    async def add(self, ctx: MorphContext) -> None: ...
    async def save(self, ctx: MorphContext) -> None: ...
    async def get(self, request_id: str) -> MorphContext | None: ...
    async def contains(self, request_id: str) -> bool: ...
    async def all(self) -> list[MorphContext]: ...
    async def count(self) -> int: ...
    async def clear(self) -> int: ...
    async def evict_terminal(self, max_active: int) -> None: ...


class InMemoryMorphStore:
    """Dict-backed store. `items` is exposed for introspection (tests)."""

    def __init__(self, items: dict[str, MorphContext] | None = None) -> None:
        self.items: dict[str, MorphContext] = {} if items is None else items

    async def add(self, ctx: MorphContext) -> None:
        self.items[ctx.request_id] = ctx

    async def save(self, ctx: MorphContext) -> None:
        self.items[ctx.request_id] = ctx

    async def get(self, request_id: str) -> MorphContext | None:
        return self.items.get(request_id)

    async def contains(self, request_id: str) -> bool:
        return request_id in self.items

    async def all(self) -> list[MorphContext]:
        return list(self.items.values())

    async def count(self) -> int:
        return len(self.items)

    async def clear(self) -> int:
        n = len(self.items)
        self.items.clear()
        return n

    async def evict_terminal(self, max_active: int) -> None:
        # FIFO over insertion order; never evict an in-flight morph.
        for k in list(self.items):
            if len(self.items) <= max_active:
                break
            if self.items[k].state in _TERMINAL:
                self.items.pop(k, None)


class RedisMorphStore:
    """JSON in Redis — a hash `<prefix>:morphs` plus an insertion-order list `<prefix>:order`."""

    def __init__(
        self,
        *,
        redis_url: str = "redis://redis:6379/0",
        key_prefix: str = "miraige:orch",
        redis_client: Any = None,  # injectable for tests; else lazy-connect
    ) -> None:
        self.redis_url = redis_url
        self._h = f"{key_prefix}:morphs"
        self._order = f"{key_prefix}:order"
        self._redis = redis_client

    def _r(self) -> Any:
        if self._redis is None:
            import redis.asyncio as aioredis  # lazy: only the redis backend needs it
            self._redis = aioredis.from_url(self.redis_url, decode_responses=True)
        return self._redis

    async def add(self, ctx: MorphContext) -> None:
        r = self._r()
        await r.hset(self._h, ctx.request_id, ctx.model_dump_json())
        await r.rpush(self._order, ctx.request_id)

    async def save(self, ctx: MorphContext) -> None:
        await self._r().hset(self._h, ctx.request_id, ctx.model_dump_json())

    async def get(self, request_id: str) -> MorphContext | None:
        raw = await self._r().hget(self._h, request_id)
        return MorphContext.model_validate_json(raw) if raw else None

    async def contains(self, request_id: str) -> bool:
        return bool(await self._r().hexists(self._h, request_id))

    async def all(self) -> list[MorphContext]:
        raw = await self._r().hvals(self._h)
        return [MorphContext.model_validate_json(v) for v in raw]

    async def count(self) -> int:
        return int(await self._r().hlen(self._h))

    async def clear(self) -> int:
        r = self._r()
        n = int(await r.hlen(self._h))
        await r.delete(self._h, self._order)
        return n

    async def evict_terminal(self, max_active: int) -> None:
        r = self._r()
        if int(await r.hlen(self._h)) <= max_active:
            return
        for rid in await r.lrange(self._order, 0, -1):
            if int(await r.hlen(self._h)) <= max_active:
                break
            raw = await r.hget(self._h, rid)
            if raw is None:
                await r.lrem(self._order, 0, rid)  # stale order entry
                continue
            if MorphContext.model_validate_json(raw).state in _TERMINAL:
                await r.hdel(self._h, rid)
                await r.lrem(self._order, 0, rid)


def make_morph_store(active: dict[str, MorphContext] | None = None) -> MorphStore:
    """memory (default) wraps `active`; redis is selected by ORCHESTRATOR_STATE_BACKEND."""
    if os.environ.get("ORCHESTRATOR_STATE_BACKEND", "memory").lower() == "redis":
        return RedisMorphStore(
            redis_url=os.environ.get("REDIS_URL", "redis://redis:6379/0"),
            key_prefix=os.environ.get("ORCHESTRATOR_REDIS_PREFIX", "miraige:orch"),
        )
    return InMemoryMorphStore(active)
