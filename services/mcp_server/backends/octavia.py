"""OVH / OpenStack (Octavia) reroute backend — the reference cloud adapter.

Only used when REROUTE_BACKEND=octavia; the stack runs without it via the mock.
Octavia auth: openstacksdk via the standard OS_* env vars (any OpenStack).

The reroute is an L7 policy: COOKIE mg_session EQUAL_TO <session> -> REDIRECT_TO_POOL
(targeted revocation by signed session; cookieless fallback when no session).
"""
from __future__ import annotations

import asyncio
import threading
import time
from typing import Any

from .base import LoadBalancerAdapter


class OctaviaAdapter(LoadBalancerAdapter):
    name = "octavia"

    def __init__(self, *, project_id: str = "", region: str = "GRA11", **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.project_id = project_id
        self.region = region
        self._os_conn: Any = None  # lazy-init on first real call
        # THREAD lock (not asyncio): _conn() runs in the executor threads
        # (run_in_executor), not on the asyncio loop.
        self._conn_lock = threading.Lock()

    # ─── OpenStack helpers ────────────────────────────────────────────

    def _conn(self) -> Any:
        """Lazy-init openstacksdk connection: reads all OS_* env vars directly.

        Guard against the check-then-act race: TOOLS is a shared singleton
        and the _sync_* methods run on the multi-thread executor, so two
        concurrent requests could open 2 connections.
        """
        if self._os_conn is None:
            with self._conn_lock:
                if self._os_conn is None:
                    import openstack  # type: ignore[import]
                    self._os_conn = openstack.connect(region_name=self.region)
        return self._os_conn

    def _wait_active(self, lb_id: str) -> None:
        """Block until the LB is ACTIVE (Octavia serialises all writes)."""
        self._conn().load_balancer.wait_for_load_balancer(
            lb_id, status="ACTIVE", failures=["ERROR"], interval=2, wait=120,
        )

    def _sync_reroute(
        self, lb_id: str, attacker_ips: list[str], ghost_pool_id: str, request_id: str,
        attacker_session: str | None = None,
    ) -> dict[str, Any]:
        """Synchronous Octavia L7 reroute, runs in a thread via executor."""
        conn = self._conn()
        policy_name = f"{self.resource_prefix}-reroute-{request_id[:8]}"

        # Idempotence: return existing policy if already created for this request
        existing = next(
            (p for p in conn.load_balancer.l7_policies() if p.name == policy_name),
            None,
        )
        if existing:
            # Creation is not atomic (policy then rules, 4 calls): a failure could
            # leave a policy with NO rule. We only reuse it if it actually carries
            # its rules; otherwise we delete the orphan and recreate. When in doubt
            # (read error), we keep the previous behavior.
            has_rules = True
            try:
                has_rules = any(True for _ in conn.load_balancer.l7_rules(existing))
            except Exception:
                has_rules = True
            if has_rules:
                return {"rule_id": existing.id, "applied_at": int(time.time()), "rollback_token": existing.id}
            try:
                conn.load_balancer.delete_l7_policy(existing.id)
                self._wait_active(lb_id)
            except Exception:
                pass

        # L7 reroute = PER-SESSION (signed cookie) ONLY. Stateless attackers (no cookie)
        # are handled by the APPLICATION-level per-IP reroute on the portal side (seamless + fallback).
        # Creating a cookieless L7 fallback here would route the first legitimate contact (/login
        # without cookie) -> ghost -> 404 and break the facade (observed bug). So: no-op when no
        # offending session is known.
        if not attacker_session:
            return {"rule_id": "", "applied_at": int(time.time()), "rollback_token": ""}

        # Resolve LB: try UUID first, then by the prefixed name as fallback
        lb = conn.load_balancer.find_load_balancer(lb_id)
        if lb is None:
            lb = conn.load_balancer.find_load_balancer(f"{self.resource_prefix}-lb")
        if lb is None:
            lbs = list(conn.load_balancer.load_balancers())
            raise ValueError(f"LB {lb_id!r} not found. Available: {[l.name for l in lbs]}")
        # Find the HTTP listener (there is exactly one in the miraige setup)
        listener = next(iter(conn.load_balancer.listeners(load_balancer_id=lb.id)), None)
        if listener is None:
            raise ValueError(f"No listener found on LB {lb_id}")

        # Resolve ghost pool: UUID first, then by the prefixed name
        pool = conn.load_balancer.find_pool(ghost_pool_id)
        if pool is None:
            pool = conn.load_balancer.find_pool(f"{self.resource_prefix}-pool-ghost")
        if pool is None:
            raise ValueError(f"Ghost pool {ghost_pool_id!r} not found")

        # Create L7 policy → ghost pool
        policy = conn.load_balancer.create_l7_policy(
            name=policy_name,
            listener_id=listener.id,
            action="REDIRECT_TO_POOL",
            redirect_pool_id=pool.id,
            position=1,
        )
        # Octavia serialises: policy must be ACTIVE before adding the rule (409 otherwise)
        self._wait_active(lb_id)

        # Targeted behavioral revocation. The mg_session cookie is a unique session IDENTITY
        # signed by the portal (non-forgeable), NOT a static free pass.
        if attacker_session:
            # Reroutes the exact offending session -> ghost (including its landing). Performing
            # legitimate actions to obtain a cookie does not protect you: attacking with that
            # session reroutes it. Continuous and revocable trust, not binary/permanent.
            conn.load_balancer.create_l7_rule(
                policy, type="COOKIE", key="mg_session",
                compare_type="EQUAL_TO", value=attacker_session,
            )
            self._wait_active(lb_id)
        else:
            # Fallback (attacker without cookie or unsigned cookie): (no valid cookie)
            # AND (path != landing) -> ghost. Portal-signed sessions contain a ".".
            conn.load_balancer.create_l7_rule(
                policy, type="COOKIE", key="mg_session",
                compare_type="CONTAINS", value=".", invert=True,
            )
            self._wait_active(lb_id)
            conn.load_balancer.create_l7_rule(
                policy, type="PATH", compare_type="EQUAL_TO", value="/", invert=True,
            )
            self._wait_active(lb_id)

        return {"rule_id": policy.id, "applied_at": int(time.time()), "rollback_token": policy.id}

    def _sync_delete_policy(self, policy_id: str, lb_id: str) -> None:
        """Best-effort L7 policy deletion, runs in a thread via executor."""
        try:
            conn = self._conn()
            conn.load_balancer.delete_l7_policy(policy_id)
            self._wait_active(lb_id)
        except Exception:
            pass

    def _sync_purge_reroutes(self) -> int:
        """Delete all '<prefix>-reroute-*' L7 policies (demo reset)."""
        conn = self._conn()
        lb = conn.load_balancer.find_load_balancer(self.lb_id) if self.lb_id else None
        if lb is None:
            lb = conn.load_balancer.find_load_balancer(f"{self.resource_prefix}-lb")
        n = 0
        for p in list(conn.load_balancer.l7_policies()):
            if (p.name or "").startswith(f"{self.resource_prefix}-reroute-"):
                try:
                    conn.load_balancer.delete_l7_policy(p.id)
                    if lb is not None:
                        conn.load_balancer.wait_for_load_balancer(
                            lb.id, status="ACTIVE", failures=["ERROR"], interval=2, wait=60)
                    n += 1
                except Exception:
                    pass
        return n

    # ─── LoadBalancerAdapter API ─────────────────────────────────────────

    async def reroute_lb_to_honeypot(
        self,
        *,
        lb_id: str,
        attacker_ips: list[str],
        attacker_session: str | None = None,
        ghost_pool_id: str,
        persistence_seconds: int = 7200,
        request_id: str,
        **_: Any,
    ) -> dict[str, Any]:
        """L7 PATCH Octavia · COOKIE mg_session == <offending session> → REDIRECT_TO_POOL=ghost."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._sync_reroute, lb_id, attacker_ips, ghost_pool_id, request_id, attacker_session
        )

    async def purge_reroute_policies(self) -> dict[str, Any]:
        loop = asyncio.get_running_loop()
        n = await loop.run_in_executor(None, self._sync_purge_reroutes)
        return {"purged": n, "real_ovh": True}

    async def _cleanup_lb_rule(self, *, lb_rule_id: str, rollback_token: str) -> None:
        if lb_rule_id and self.lb_id:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._sync_delete_policy, lb_rule_id, self.lb_id)
