"""Mir[AI]ge BFF · the single authenticated API gateway (/api/v1/*).

Consolidates the read surface of the internal services (sentinel, orchestrator,
mirage_metrics) behind one authenticated API, so a UI / SIEM / automation has a
single place to talk to and the internal services need not be exposed.
"""
from __future__ import annotations

import asyncio
import json
import os
from typing import Any
from urllib.parse import quote

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

from services.shared import logging_config
from services.shared.secrets import resolve_secret

from . import attacks, auth, ratelimit

log = logging_config.setup("api")
app = FastAPI(title="Mir[AI]ge · API", version="0.1.0")

# CORS: a single origin (the SPA). Defaults to "*" for the demo.
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("API_CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

SENTINEL_URL = os.environ.get("SENTINEL_URL", "http://sentinel:8001")
ORCHESTRATOR_URL = os.environ.get("ORCHESTRATOR_URL", "http://orchestrator:8002")
MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://mcp_server:8003")
MIRAGE_METRICS_URL = os.environ.get("MIRAGE_METRICS_URL", "http://mirage_metrics:8004")
RESET_SECRET = resolve_secret("MG_RESET_SECRET", "miraige-reset-2026")
STREAM_INTERVAL_S = float(os.environ.get("API_STREAM_INTERVAL_S", "2.0"))

_BACKENDS = {
    "sentinel": SENTINEL_URL,
    "orchestrator": ORCHESTRATOR_URL,
    "mcp_server": MCP_SERVER_URL,
    "mirage_metrics": MIRAGE_METRICS_URL,
}


# ─── helpers ──────────────────────────────────────────────────────────

async def _get(url: str) -> Any:
    """Proxy a GET to an internal service; 502 if it's unreachable."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(url)
            r.raise_for_status()
            return r.json()
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"backend unavailable: {e}") from e


async def current_identity(authorization: str = Header(default="")) -> auth.Identity:
    identity = auth.identity_from_request(authorization)
    if identity is None:
        raise HTTPException(status_code=401, detail="unauthorized")
    return identity


def require_role(minimum: str):
    """Dependency: 401 if unauthenticated, 403 if the role is below `minimum`."""
    async def _dep(identity: auth.Identity = Depends(current_identity)) -> auth.Identity:
        if not auth.role_at_least(identity.role, minimum):
            raise HTTPException(status_code=403, detail=f"requires role: {minimum}")
        return identity

    return _dep


_VIEWER = [Depends(require_role("viewer"))]      # any authenticated user
_OPERATOR = [Depends(require_role("operator"))]  # may run attacks / reset
_ADMIN = [Depends(require_role("admin"))]        # may manage users


# ─── auth ─────────────────────────────────────────────────────────────

class LoginIn(BaseModel):
    username: str = ""   # blank → admin (back-compat with the password-only login)
    password: str


def _client_ip(request: Request) -> str:
    """Best-effort client IP: first hop of X-Forwarded-For, else the socket peer."""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        first = fwd.split(",", 1)[0].strip()
        if first:
            return first
    return request.client.host if request.client else "unknown"


@app.post("/api/v1/login")
async def login(request: Request, body: LoginIn) -> dict[str, str]:
    if not ratelimit.check_and_record(_client_ip(request)):
        raise HTTPException(status_code=429, detail="too many login attempts; slow down")
    if not auth.login_enabled():
        raise HTTPException(status_code=501, detail="login is handled by the identity provider")
    identity = auth.authenticate(body.username, body.password)
    if identity is None:
        raise HTTPException(status_code=401, detail="bad credentials")
    return {"token": auth.issue_token(identity), "username": identity.username, "role": identity.role}


@app.get("/api/v1/me")
async def me(identity: auth.Identity = Depends(require_role("viewer"))) -> dict[str, str]:
    return {"username": identity.username, "role": identity.role}


# ─── public ───────────────────────────────────────────────────────────

@app.get("/api/v1/health")
async def health() -> dict[str, Any]:
    async def ping(name: str, url: str) -> tuple[str, str]:
        try:
            async with httpx.AsyncClient(timeout=3.0) as c:
                r = await c.get(f"{url}/health")
                return name, ("ok" if r.status_code == 200 else f"http {r.status_code}")
        except Exception:  # noqa: BLE001
            return name, "unreachable"

    results = await asyncio.gather(*[ping(n, u) for n, u in _BACKENDS.items()])
    return {"status": "ok", "service": "api", "backends": dict(results)}


# ─── read surface (authenticated) ─────────────────────────────────────

@app.get("/api/v1/stats", dependencies=_VIEWER)
async def stats() -> Any:
    return await _get(f"{SENTINEL_URL}/stats")


@app.get("/api/v1/flows", dependencies=_VIEWER)
async def flows() -> Any:
    return await _get(f"{SENTINEL_URL}/flows")


@app.get("/api/v1/sessions/{src_ip}", dependencies=_VIEWER)
async def session(src_ip: str) -> Any:
    return await _get(f"{SENTINEL_URL}/state/{quote(src_ip, safe='')}")


@app.get("/api/v1/tier-trace/{key}", dependencies=_VIEWER)
async def tier_trace(key: str) -> Any:
    return await _get(f"{SENTINEL_URL}/tier-trace/{quote(key, safe='')}")


@app.get("/api/v1/incidents", dependencies=_VIEWER)
async def incidents() -> Any:
    return await _get(f"{ORCHESTRATOR_URL}/state")


@app.get("/api/v1/incidents/{request_id}", dependencies=_VIEWER)
async def incident(request_id: str) -> Any:
    return await _get(f"{ORCHESTRATOR_URL}/state/{quote(request_id, safe='')}")


@app.get("/api/v1/metrics", dependencies=_VIEWER)
async def metrics() -> Any:
    return await _get(f"{MIRAGE_METRICS_URL}/current")


@app.get("/api/v1/metrics/agents", dependencies=_VIEWER)
async def agents() -> Any:
    return await _get(f"{MIRAGE_METRICS_URL}/agent-usage")


# ─── admin (authenticated) ────────────────────────────────────────────

@app.post("/api/v1/admin/reset", dependencies=_OPERATOR)
async def reset() -> dict[str, Any]:
    async def one(name: str, url: str) -> tuple[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=5.0) as c:
                r = await c.post(f"{url}/admin/reset", headers={"x-mg-reset": RESET_SECRET})
                return name, r.json()
        except Exception as e:  # noqa: BLE001
            return name, {"error": str(e)}

    results = await asyncio.gather(*[one(n, u) for n, u in _BACKENDS.items()])
    return {"reset": dict(results)}


# ─── red team · launch / track / stop the attack simulator ────────────
# Registered before the SPA catch-all below so GET /api/v1/attacks wins.

class LaunchIn(BaseModel):
    level: str
    duration: int = 30
    rps: int | None = None


@app.post("/api/v1/attacks", dependencies=_OPERATOR)
async def launch_attack(body: LaunchIn) -> dict[str, Any]:
    try:
        return await attacks.launch(body.level, body.duration, body.rps)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except RuntimeError as e:
        raise HTTPException(status_code=429, detail=str(e)) from e


@app.get("/api/v1/attacks", dependencies=_OPERATOR)
async def running_attacks() -> dict[str, Any]:
    return {"attacks": attacks.list_runs()}


@app.post("/api/v1/attacks/{run_id}/stop", dependencies=_OPERATOR)
async def stop_attack(run_id: str) -> dict[str, Any]:
    if not attacks.stop(run_id):
        raise HTTPException(status_code=404, detail="unknown attack")
    return {"ok": True}


@app.get("/api/v1/attacks/{run_id}/logs", dependencies=_OPERATOR)
async def attack_logs(run_id: str) -> dict[str, Any]:
    lines = attacks.logs(run_id)
    if lines is None:
        raise HTTPException(status_code=404, detail="unknown attack")
    return {"lines": lines}


# ─── user management (admin) ──────────────────────────────────────────

class UserIn(BaseModel):
    username: str
    role: str
    password: str


class UserPatch(BaseModel):
    role: str | None = None
    password: str | None = None


def _require_managed() -> None:
    if not auth.is_managed():
        raise HTTPException(
            status_code=409,
            detail="user store is not file-backed — set MIRAIGE_USERS_FILE to manage users",
        )


@app.get("/api/v1/users", dependencies=_ADMIN)
async def users_list() -> dict[str, Any]:
    return {"users": auth.list_users(), "managed": auth.is_managed()}


@app.post("/api/v1/users", dependencies=_ADMIN)
async def users_create(body: UserIn) -> dict[str, bool]:
    _require_managed()
    try:
        auth.create_user(body.username, body.role, body.password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"ok": True}


@app.patch("/api/v1/users/{username}", dependencies=_ADMIN)
async def users_patch(username: str, body: UserPatch) -> dict[str, bool]:
    _require_managed()
    try:
        if body.role is not None:
            auth.set_role(username, body.role)
        if body.password:
            auth.set_password(username, body.password)
    except KeyError as e:
        raise HTTPException(status_code=404, detail="unknown user") from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"ok": True}


@app.delete("/api/v1/users/{username}")
async def users_delete(
    username: str,
    identity: auth.Identity = Depends(require_role("admin")),
) -> dict[str, bool]:
    _require_managed()
    if username == identity.username:
        raise HTTPException(status_code=400, detail="refuse to delete your own account")
    try:
        auth.delete_user(username)
    except KeyError as e:
        raise HTTPException(status_code=404, detail="unknown user") from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"ok": True}


# ─── live stream · push state to the console (replaces fast polling) ──

async def _safe_get(url: str) -> Any:
    try:
        return await _get(url)
    except Exception:  # noqa: BLE001
        return None


async def _gather_snapshot() -> dict[str, Any]:
    """One combined snapshot of the live console data; upstream failures → None."""
    stats, metrics, incidents = await asyncio.gather(
        _safe_get(f"{SENTINEL_URL}/stats"),
        _safe_get(f"{MIRAGE_METRICS_URL}/current"),
        _safe_get(f"{ORCHESTRATOR_URL}/state"),
    )
    return {"stats": stats, "metrics": metrics, "incidents": incidents}


@app.get("/api/v1/stream", dependencies=_VIEWER)
async def stream(request: Request) -> StreamingResponse:
    """NDJSON: one {stats, metrics, incidents} snapshot per interval until the
    client disconnects. The SPA feeds these into its query cache, so a slow
    fallback poll is all that's needed on top."""
    async def gen():
        while not await request.is_disconnected():
            yield json.dumps(await _gather_snapshot()) + "\n"
            await asyncio.sleep(STREAM_INTERVAL_S)

    return StreamingResponse(gen(), media_type="application/x-ndjson")


# ─── SPA · serve the built console (production) ────────────────────────
# When WEB_DIR points at a built SPA (web/dist baked into the image), the BFF is
# the single public surface: the /api/v1/* routes above win, the console is
# served below, and unknown client-side routes fall back to index.html.
WEB_DIR = os.path.normpath(os.environ["WEB_DIR"]) if os.environ.get("WEB_DIR") else ""

if WEB_DIR and os.path.isdir(WEB_DIR):
    _INDEX = os.path.join(WEB_DIR, "index.html")

    @app.get("/{full_path:path}")
    async def spa(full_path: str) -> FileResponse:
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="not found")
        candidate = os.path.normpath(os.path.join(WEB_DIR, full_path))
        # serve a real built asset, else the SPA shell (guard path traversal)
        if full_path and candidate.startswith(WEB_DIR + os.sep) and os.path.isfile(candidate):
            return FileResponse(candidate)
        return FileResponse(_INDEX)
