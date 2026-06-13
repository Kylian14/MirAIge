"""Cloud-free reroute backend: flag offending sessions / IPs in Redis.

The inline reverse-proxy (deploy/proxy/inline) reads these flags on every
request and routes flagged traffic to the Ghost Shell — no load-balancer API,
runs on any host. This adapter only writes and clears the flags.

Keys (TTL'd): <prefix>:flag:sess:<mg_session>  and  <prefix>:flag:ip:<ip>
"""
from __future__ import annotations

import time
from typing import Any

from .base import LoadBalancerAdapter


class RedisFlagAdapter(LoadBalancerAdapter):
    name = "redis"

    def __init__(
        self,
        *,
        redis_url: str = "redis://redis:6379/0",
        flag_ttl_seconds: int = 7200,
        redis_client: Any = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.redis_url = redis_url
        self.flag_ttl_seconds = flag_ttl_seconds
        self._redis = redis_client  # injectable for tests; else lazy-connect

    def _r(self) -> Any:
        if self._redis is None:
            import redis.asyncio as aioredis  # lazy: only this backend needs redis
            self._redis = aioredis.from_url(self.redis_url, decode_responses=True)
        return self._redis

    def _sess_key(self, session: str) -> str:
        return f"{self.resource_prefix}:flag:sess:{session}"

    def _ip_key(self, ip: str) -> str:
        return f"{self.resource_prefix}:flag:ip:{ip}"

    async def reroute_lb_to_honeypot(
        self,
        *,
        lb_id: str = "",
        attacker_ips: list[str] | None = None,
        attacker_session: str | None = None,
        ghost_pool_id: str = "",
        persistence_seconds: int = 7200,
        request_id: str,
        **_: Any,
    ) -> dict[str, Any]:
        """Flag the offending session (and any IPs) in Redis with a TTL."""
        r = self._r()
        ttl = persistence_seconds or self.flag_ttl_seconds
        keys: list[str] = []
        if attacker_session:
            k = self._sess_key(attacker_session)
            await r.set(k, request_id, ex=ttl)
            keys.append(k)
        for ip in attacker_ips or []:
            k = self._ip_key(ip)
            await r.set(k, request_id, ex=ttl)
            keys.append(k)
        token = "|".join(keys)
        return {"rule_id": token, "applied_at": int(time.time()), "rollback_token": token}

    async def purge_reroute_policies(self) -> dict[str, Any]:
        """Demo reset: clear every flag."""
        r = self._r()
        n = 0
        async for k in r.scan_iter(match=f"{self.resource_prefix}:flag:*"):
            await r.delete(k)
            n += 1
        return {"purged": n, "real_ovh": False}

    async def _cleanup_lb_rule(self, *, lb_rule_id: str, rollback_token: str) -> None:
        token = rollback_token or lb_rule_id
        if not token:
            return
        r = self._r()
        for k in token.split("|"):
            if k:
                await r.delete(k)
