"""Pluggable reroute backend interface.

A backend exposes the 3 MCP tools + the demo purge. Allocating a Ghost Shell
session and tearing it down are backend-INDEPENDENT (plain HTTP to the Ghost
Shell), so they live here once; only the load-balancer reroute / rollback /
purge are backend-specific and left abstract.
"""
from __future__ import annotations

import abc
from typing import Any

import httpx


class LoadBalancerAdapter(abc.ABC):
    """Base class for reroute backends (mock, octavia, …)."""

    name: str = "base"

    def __init__(
        self,
        *,
        ghost_shell_url: str = "http://ghost_shell:8080",
        lb_id: str = "",
        resource_prefix: str = "miraige",
        **_: Any,
    ) -> None:
        self.ghost_shell_url = ghost_shell_url.rstrip("/")
        self.lb_id = lb_id
        self.resource_prefix = resource_prefix

    # ─── Tool 1 · Ghost Shell session (backend-independent HTTP) ──────────

    async def route_to_ghost_shell(
        self,
        *,
        session_id: str,
        attacker_cidr: str,
        persona: str = "portal_ovh",
        ttl_seconds: int = 1800,
        lb_id: str = "",
        request_id: str,
        **_: Any,
    ) -> dict[str, Any]:
        """Allocate a Ghost Shell session: POST ghost_shell:/sessions."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{self.ghost_shell_url}/sessions",
                json={
                    "attacker_cidr": attacker_cidr,
                    "persona": persona,
                    "ttl_seconds": ttl_seconds,
                    "request_id": request_id,
                },
            )
            resp.raise_for_status()
            return resp.json()

    # ─── Tool 3 · teardown (shared HTTP + backend-specific LB rollback) ───

    async def terminate_honeypot_after_ttl(
        self,
        *,
        ghost_session_id: str,
        lb_rule_id: str,
        rollback_token: str,
        collect_ttps: bool = True,
        request_id: str,
        **_: Any,
    ) -> dict[str, Any]:
        """Tear down: terminate the Ghost Shell session, then roll back the reroute."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{self.ghost_shell_url}/sessions/{ghost_session_id}/terminate",
            )
            if resp.status_code == 404:
                # Session already expired — Ghost Shell enforces its own TTL.
                result = {"destroyed": True, "ttps_archive_url": None, "tokens_burned": 0, "asymmetric_ratio": 0.0}
            else:
                resp.raise_for_status()
                result = resp.json()

        await self._cleanup_lb_rule(lb_rule_id=lb_rule_id, rollback_token=rollback_token)
        return result

    # ─── Backend-specific ────────────────────────────────────────────────

    @abc.abstractmethod
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
        """Reroute the offending session/traffic to the Ghost Shell."""

    @abc.abstractmethod
    async def purge_reroute_policies(self) -> dict[str, Any]:
        """Demo reset: remove every reroute rule pointing at the Ghost Shell."""

    async def _cleanup_lb_rule(self, *, lb_rule_id: str, rollback_token: str) -> None:
        """Roll back a single reroute rule. Default: nothing to undo."""
        return None
