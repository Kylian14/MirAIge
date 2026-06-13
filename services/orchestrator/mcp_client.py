"""
MCP client: JSON-RPC 2.0 over HTTP to the MCP Server.

Status: WORKING. Token bucket rate limiter at 15 req/s is in place (stays under the
OVH 20 req/s quota). Hardening roadmap (not blocking for the demo):
  - retry with exponential backoff on transient errors
  - traceparent propagation (W3C Trace Context)
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from uuid import uuid4

import httpx


class _TokenBucket:
    """Async token bucket that enforces a maximum request rate."""

    def __init__(self, rate: float) -> None:
        self._rate = rate
        self._tokens = rate
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            # Re-credit since the last refill, capped at capacity.
            now = time.monotonic()
            self._tokens = min(self._rate, self._tokens + (now - self._last) * self._rate)
            self._last = now
            # If there aren't enough tokens, sleep then RE-refill from a FRESH
            # clock by resetting _last. Otherwise the next acquire would count the
            # time already slept as "free" refill, giving ~2x the target rate
            # (the limiter went over the OVH 20 req/s quota under concurrent load).
            while self._tokens < 1.0:
                await asyncio.sleep((1.0 - self._tokens) / self._rate)
                now = time.monotonic()
                self._tokens = min(self._rate, self._tokens + (now - self._last) * self._rate)
                self._last = now
            self._tokens -= 1.0

from services.shared.models import (
    RouteToGhostShellInput,
    RouteToGhostShellOutput,
    RerouteLbInput,
    RerouteLbOutput,
    TerminateHoneypotInput,
    TerminateHoneypotOutput,
)


class McpError(Exception):
    """Raised when a tool returns an error or transport fails."""


class McpClient:
    def __init__(self, *, base_url: str, timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._limiter = _TokenBucket(rate=15.0)

    async def _call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        await self._limiter.acquire()
        envelope = {
            "jsonrpc": "2.0",
            "id": str(uuid4()),
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.post(f"{self.base_url}/mcp", json=envelope)
                r.raise_for_status()
                payload = r.json()
        except httpx.HTTPError as e:
            raise McpError(f"transport: {e}") from e

        if "error" in payload:
            raise McpError(f"tool error: {json.dumps(payload['error'])[:200]}")

        try:
            content_blocks = payload["result"]["content"]
            text = next(b["text"] for b in content_blocks if b.get("type") == "text")
            return json.loads(text)
        except (KeyError, StopIteration, json.JSONDecodeError) as e:
            raise McpError(f"unparseable response: {e}") from e

    async def route_to_ghost_shell(self, params: RouteToGhostShellInput) -> RouteToGhostShellOutput:
        data = await self._call("route_to_ghost_shell", params.model_dump(mode="json"))
        return RouteToGhostShellOutput.model_validate(data)

    async def reroute_lb(self, params: RerouteLbInput) -> RerouteLbOutput:
        data = await self._call("reroute_lb_to_honeypot", params.model_dump(mode="json"))
        return RerouteLbOutput.model_validate(data)

    async def terminate_honeypot(self, params: TerminateHoneypotInput) -> TerminateHoneypotOutput:
        data = await self._call("terminate_honeypot_after_ttl", params.model_dump(mode="json"))
        return TerminateHoneypotOutput.model_validate(data)
