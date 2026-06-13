"""
Mir[AI]ge MCP Server, JSON-RPC 2.0 wire format.

Exposes 3 security-scoped tools (allowlisted, static):
  - route_to_ghost_shell
  - reroute_lb_to_honeypot
  - terminate_honeypot_after_ttl

Status: WORKING. The JSON-RPC wire protocol is complete and the 3 tools run real
logic (see backends/octavia.py): real Octavia L7 when REROUTE_BACKEND=octavia, mock fallback otherwise
(tool 1 `route_to_ghost_shell` is ALWAYS real, POST ghost_shell:/sessions).

Wire methods supported:
  - initialize  (handshake)
  - tools/list  (catalog with JSON Schema)
  - tools/call  (invocation by name)

Security, see technical-paper §5:
  - Allowlisted tool descriptions, no dynamic registration
  - No credential pass-through
  - Strict Pydantic validation on arguments
"""
from __future__ import annotations

import json
import os
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import ValidationError

from services.shared import logging_config
from services.shared.models import (
    RerouteLbInput,
    RouteToGhostShellInput,
    TerminateHoneypotInput,
)
from services.shared.secrets import check_reset_secret, resolve_secret

from .backends import make_adapter

log = logging_config.setup("mcp_server")
app = FastAPI(title="Mir[AI]ge · MCP Server", version="0.1.0")

REROUTE_BACKEND = os.environ.get("REROUTE_BACKEND", "mock").strip().lower()

TOOLS = make_adapter(
    REROUTE_BACKEND,
    project_id=os.environ.get("OVH_PROJECT_ID", ""),
    region=os.environ.get("OVH_REGION", "GRA11"),
    ghost_shell_url=os.environ.get("GHOST_SHELL_URL", "http://ghost_shell:8080"),
    lb_id=os.environ.get("LB_ID", ""),
    resource_prefix=os.environ.get("RESOURCE_PREFIX", "miraige"),
    redis_url=os.environ.get("REDIS_URL", "redis://redis:6379/0"),
)

# ─── MCP catalog: JSON Schema for the 3 tools (static allowlist) ───
TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "route_to_ghost_shell",
        "description": (
            "Initialise une session attaquant sur le Ghost Shell. "
            "Alloue session_id, persona, expires_at. Pas de clonage VM."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["session_id", "attacker_cidr", "lb_id", "request_id"],
            "properties": {
                "session_id": {"type": "string"},
                "attacker_cidr": {"type": "string"},
                "persona": {"type": "string", "default": "portal_ovh"},
                "ttl_seconds": {"type": "integer", "default": 1800},
                "lb_id": {"type": "string"},
                "request_id": {"type": "string"},
            },
        },
    },
    {
        "name": "reroute_lb_to_honeypot",
        "description": (
            "PATCH Octavia : ajoute une L7 policy avec rule "
            "COOKIE mg_session EQUAL_TO <attacker_session> "
            "-> REDIRECT_TO_POOL=ghost_pool (révocation comportementale ciblée par session "
            "signée, non-spoofable ; Octavia n'a pas de règle SOURCE_IP native). Atomique."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["lb_id", "attacker_ips", "ghost_pool_id", "request_id"],
            "properties": {
                "lb_id": {"type": "string"},
                "attacker_ips": {"type": "array", "items": {"type": "string"}},
                "attacker_session": {"type": "string", "description": "cookie mg_session signé de la session fautive (clé du reroute L7)"},
                "ghost_pool_id": {"type": "string"},
                "persistence_seconds": {"type": "integer", "default": 7200},
                "request_id": {"type": "string"},
            },
        },
    },
    {
        "name": "terminate_honeypot_after_ttl",
        "description": (
            "Dump TTPs vers Object Storage, DELETE la l7policy, "
            "libère la session Ghost Shell."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["ghost_session_id", "lb_rule_id", "rollback_token", "request_id"],
            "properties": {
                "ghost_session_id": {"type": "string"},
                "lb_rule_id": {"type": "string"},
                "rollback_token": {"type": "string"},
                "collect_ttps": {"type": "boolean", "default": True},
                "request_id": {"type": "string"},
            },
        },
    },
]


@app.get("/health")
async def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "mcp_server",
        "reroute_backend": REROUTE_BACKEND,
    }


# Per-tool Pydantic input models, strict validation of JSON-RPC arguments
# (the docstring promised this without doing it: a missing field raised a
# TypeError caught as -32000 instead of -32602 "invalid params").
_TOOL_INPUT_MODELS = {
    "route_to_ghost_shell": RouteToGhostShellInput,
    "reroute_lb_to_honeypot": RerouteLbInput,
    "terminate_honeypot_after_ttl": TerminateHoneypotInput,
}

RESET_SECRET = resolve_secret("MG_RESET_SECRET", "miraige-reset-2026")


@app.post("/admin/reset")
async def admin_reset(request: Request) -> dict[str, Any]:
    """Demo reset: purge the L7 reroute policies (cookie → ghost). Protected by X-Mg-Reset."""
    if not check_reset_secret(request.headers.get("x-mg-reset"), RESET_SECRET):
        raise HTTPException(status_code=403, detail="forbidden")
    res = await TOOLS.purge_reroute_policies()
    return {"service": "mcp", "reset": True, **res}


@app.post("/mcp")
async def jsonrpc(request: Request) -> dict[str, Any]:
    """Single JSON-RPC 2.0 endpoint (MCP-compatible)."""
    # Parsing/extraction OUTSIDE the dispatch try → a malformed body returned
    # a raw 500 instead of the expected JSON-RPC error envelope.
    try:
        envelope = await request.json()
    except Exception:
        return _error(None, -32700, "parse error")
    if not isinstance(envelope, dict):
        return _error(None, -32600, "invalid request")
    rpc_id = envelope.get("id")
    method = envelope.get("method", "")
    params = envelope.get("params", {})
    if not isinstance(params, dict):
        return _error(rpc_id, -32602, "params must be an object")

    try:
        if method == "initialize":
            result: Any = {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "miraige-mcp", "version": "0.1.0"},
            }
        elif method == "tools/list":
            result = {"tools": TOOL_SCHEMAS}
        elif method == "tools/call":
            result = await _dispatch_tool(params.get("name", ""), params.get("arguments", {}))
        else:
            return _error(rpc_id, -32601, f"method not found: {method}")
    except ValueError as e:
        return _error(rpc_id, -32602, str(e))
    except Exception as e:  # noqa: BLE001
        log.exception(json.dumps({"event": "mcp.unhandled", "error": str(e)}))
        return _error(rpc_id, -32000, f"server error: {e}")

    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


async def _dispatch_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    log.info(json.dumps({"event": "tool.call", "tool": name, "request_id": args.get("request_id")}))

    model_cls = _TOOL_INPUT_MODELS.get(name)
    if model_cls is None:
        raise ValueError(f"unknown tool: {name}")

    # Strict Pydantic validation → ValueError (→ -32602) if arguments are invalid.
    try:
        validated = model_cls.model_validate(args)
    except ValidationError as e:
        raise ValueError(f"invalid arguments for {name}: {e.errors()}") from e
    kwargs = validated.model_dump(mode="json")

    if name == "route_to_ghost_shell":
        out = await TOOLS.route_to_ghost_shell(**kwargs)
    elif name == "reroute_lb_to_honeypot":
        out = await TOOLS.reroute_lb_to_honeypot(**kwargs)
    else:
        out = await TOOLS.terminate_honeypot_after_ttl(**kwargs)

    # MCP returns content blocks; we embed the JSON in a text block
    return {"content": [{"type": "text", "text": json.dumps(out)}], "isError": False}


def _error(rpc_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}
