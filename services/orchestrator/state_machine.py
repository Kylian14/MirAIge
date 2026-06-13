"""
Orchestrator state machine · transitions IDLE → DETECTING → ASSIGNING → REROUTING → MONITORING → TERMINATING.

Hard caps (anti self-DoS, see Claude Code #15909, docs/technical-paper.html §5):
  - 15 thought steps max per investigation
  - Circuit breaker on 3 consecutive tool failures (plus bounded backoff)
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

from services.shared import logging_config
from services.shared.models import (
    AttackSignal,
    GhostPersona,
    MorphContext,
    MorphState,
    RerouteLbInput,
    RouteToGhostShellInput,
    TerminateHoneypotInput,
)

from .mcp_client import McpClient

log = logging_config.setup("orchestrator.fsm")

# Hard caps, see docs/technical-paper.html §5
CONFIDENCE_GATE = 0.75
MAX_THOUGHT_STEPS = 15
MAX_CONSECUTIVE_TOOL_FAILURES = 3
# Linear backoff between two attempts of the same step after an MCP error
# (2s, 4s...), avoids the tight retry loop that was hammering the MCP server.
# (Replaces the old CIRCUIT_BREAKER_BACKOFF_SECONDS=60 that was never used.)
RETRY_BACKOFF_BASE_SECONDS = 2.0


class MorphStateMachine:
    """Drive one morph through its lifecycle."""

    def __init__(
        self,
        *,
        mcp: McpClient,
        lb_id: str,
        ghost_pool_id: str,
        ttl_seconds: int,
        on_transition: Callable[[MorphContext], Awaitable[None]] | None = None,
    ) -> None:
        self.mcp = mcp
        self.lb_id = lb_id
        self.ghost_pool_id = ghost_pool_id
        self.ttl_seconds = ttl_seconds
        # Persist ctx after every transition (the orchestrator wires this to its
        # store.save, so a redis-backed /state reflects the live state).
        self.on_transition = on_transition

    async def run(self, ctx: MorphContext, signal: AttackSignal) -> None:
        """Drive ctx through the full morph lifecycle."""
        await self._to(ctx, MorphState.DETECTING)

        if signal.confidence < CONFIDENCE_GATE:
            log.info(json.dumps({
                "event": "fsm.below_gate",
                "request_id": ctx.request_id,
                "confidence": signal.confidence,
            }))
            await self._to(ctx, MorphState.IDLE)
            return

        thought_steps = 0
        consecutive_failures = 0

        steps = [
            lambda: self._assigning(ctx, signal),
            lambda: self._rerouting(ctx, signal),
            lambda: self._monitoring(ctx),
            lambda: self._terminating(ctx),
        ]

        for step in steps:
            while True:
                if thought_steps >= MAX_THOUGHT_STEPS:
                    log.error(json.dumps({
                        "event": "fsm.max_steps",
                        "request_id": ctx.request_id,
                        "steps": thought_steps,
                    }))
                    await self._rollback(ctx)
                    return
                thought_steps += 1
                try:
                    await step()
                    consecutive_failures = 0
                    break
                except Exception as e:
                    # We catch EVERY exception (not just McpError): a
                    # ValidationError from model_validate on the mcp_client side was
                    # escaping rollback → ghost session + L7 policy leaked. CancelledError
                    # (BaseException) is NOT caught → clean cancellation goes through.
                    consecutive_failures += 1
                    log.warning(json.dumps({
                        "event": "fsm.step_error",
                        "request_id": ctx.request_id,
                        "error": f"{type(e).__name__}: {e}",
                        "consecutive_failures": consecutive_failures,
                    }))
                    if consecutive_failures >= MAX_CONSECUTIVE_TOOL_FAILURES:
                        log.error(json.dumps({
                            "event": "fsm.circuit_breaker",
                            "request_id": ctx.request_id,
                        }))
                        await self._rollback(ctx)
                        return
                    # Bounded backoff before retrying the same step (anti MCP hammering).
                    await asyncio.sleep(RETRY_BACKOFF_BASE_SECONDS * consecutive_failures)

    async def _assigning(self, ctx: MorphContext, signal: AttackSignal) -> None:
        """Call MCP `route_to_ghost_shell`, store ghost_session_id in ctx."""
        await self._to(ctx, MorphState.ASSIGNING)
        result = await self.mcp.route_to_ghost_shell(RouteToGhostShellInput(
            session_id=ctx.request_id,
            attacker_cidr=f"{signal.attacker_ip}/32",
            persona=GhostPersona.PORTAL_OVH,
            ttl_seconds=self.ttl_seconds,
            lb_id=self.lb_id,
            request_id=signal.request_id,
        ))
        ctx.ghost_session_id = result.ghost_session_id
        ctx.ghost_persona = result.persona

    async def _rerouting(self, ctx: MorphContext, signal: AttackSignal) -> None:
        """Call MCP `reroute_lb_to_honeypot`, store lb_rule_id + rollback_token."""
        await self._to(ctx, MorphState.REROUTING)
        result = await self.mcp.reroute_lb(RerouteLbInput(
            lb_id=self.lb_id,
            attacker_ips=[signal.attacker_ip],
            attacker_session=signal.attacker_session,
            ghost_pool_id=self.ghost_pool_id,
            persistence_seconds=self.ttl_seconds,
            request_id=signal.request_id,
        ))
        ctx.lb_rule_id = result.rule_id
        ctx.rollback_token = result.rollback_token
        ctx.expires_at = datetime.fromtimestamp(
            result.applied_at + self.ttl_seconds, tz=timezone.utc
        ).replace(tzinfo=None)

    async def _monitoring(self, ctx: MorphContext) -> None:
        """Wait until TTL expiry with periodic heartbeat logs."""
        await self._to(ctx, MorphState.MONITORING)
        elapsed = 0
        tick = 60
        while elapsed < self.ttl_seconds:
            sleep_for = min(tick, self.ttl_seconds - elapsed)
            await asyncio.sleep(sleep_for)
            elapsed += sleep_for
            log.info(json.dumps({
                "event": "fsm.monitoring_tick",
                "request_id": ctx.request_id,
                "elapsed_s": elapsed,
                "ttl_s": self.ttl_seconds,
            }))

    async def _terminating(self, ctx: MorphContext) -> None:
        """Call MCP `terminate_honeypot_after_ttl`, transition to IDLE."""
        await self._to(ctx, MorphState.TERMINATING)
        await self.mcp.terminate_honeypot(TerminateHoneypotInput(
            ghost_session_id=ctx.ghost_session_id,
            lb_rule_id=ctx.lb_rule_id,
            rollback_token=ctx.rollback_token,
            collect_ttps=True,
            request_id=ctx.request_id,
        ))
        await self._to(ctx, MorphState.IDLE)

    async def rollback(self, ctx: MorphContext) -> None:
        """Public cleanup (terminate ghost + L7), best-effort.

        Exposed so the orchestrator can free resources when a
        morph is CANCELLED (demo reset / service shutdown), not only on error.
        """
        await self._rollback(ctx)

    async def _rollback(self, ctx: MorphContext) -> None:
        """Best-effort cleanup on error."""
        await self._to(ctx, MorphState.ROLLBACK)
        # We terminate as soon as a ghost session has been allocated, EVEN if the
        # cookieless reroute returned empty rule_id/rollback_token, otherwise the
        # ghost session was never freed. Tool 3 only deletes the L7 policy if
        # lb_rule_id is non-empty, so passing "" is safe.
        if ctx.ghost_session_id:
            try:
                await self.mcp.terminate_honeypot(TerminateHoneypotInput(
                    ghost_session_id=ctx.ghost_session_id,
                    lb_rule_id=ctx.lb_rule_id or "",
                    rollback_token=ctx.rollback_token or "",
                    collect_ttps=False,
                    request_id=ctx.request_id,
                ))
            except Exception as e:
                log.error(json.dumps({
                    "event": "fsm.rollback_failed",
                    "request_id": ctx.request_id,
                    "error": str(e),
                }))
        await self._to(ctx, MorphState.ERROR)

    # ─── Helper · functional for transition logging ─────────

    async def _to(self, ctx: MorphContext, new_state: MorphState) -> None:
        """Atomic state transition + structured log."""
        old = ctx.state.value
        ctx.state = new_state
        ctx.last_transition_at = datetime.utcnow()
        log.info(json.dumps({
            "event": "fsm.transition",
            "request_id": ctx.request_id,
            "from": old,
            "to": new_state.value,
        }))
        if self.on_transition is not None:
            await self.on_transition(ctx)
