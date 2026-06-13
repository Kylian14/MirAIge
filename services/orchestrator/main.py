"""
Orchestrator · receives A2A signals -> drives the state machine.

Status: WORKING. A2A HMAC verification, full FSM (`MorphStateMachine.run`),
real MCP calls (Octavia L7 if REROUTE_BACKEND=octavia). Engagement state lives in a
store (`store.py`): in-memory by default, Redis — crash-safe and shared across
instances — when ORCHESTRATOR_STATE_BACKEND=redis.

Endpoints:
  POST /signal     · receives signed AttackSignal from Sentinel
  GET  /health     · liveness + count
  GET  /state      · lists all active MorphContext entries
  GET  /state/{id} · detail of one morph
"""
from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status

from services.shared import logging_config
from services.shared.a2a_protocol import A2AVerificationError, verify_request
from services.shared.models import AttackSignal, MorphContext
from services.shared.secrets import check_reset_secret, resolve_secret

from .mcp_client import McpClient
from .state_machine import MorphStateMachine
from .store import make_morph_store

log = logging_config.setup("orchestrator")

# Strong references to in-flight FSM tasks (keeps fire-and-forget tasks from being GC'd).
_BG_TASKS: set[asyncio.Task] = set()


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    # Service shutdown: cancel any in-flight FSMs and wait (bounded) for their
    # cleanup, otherwise they get killed abruptly, leaving the ghost session
    # and L7 policy unreleased. _drive catches the cancellation to roll back.
    tasks = list(_BG_TASKS)
    for t in tasks:
        t.cancel()
    if tasks:
        try:
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True), timeout=10.0
            )
        except Exception:
            pass


app = FastAPI(title="Mir[AI]ge · Orchestrator", version="0.1.0", lifespan=lifespan)

A2A_SECRET = resolve_secret("A2A_SHARED_SECRET", "dev-secret")
RESET_SECRET = resolve_secret("MG_RESET_SECRET", "miraige-reset-2026")
MCP_URL = os.environ.get("MCP_SERVER_URL", "http://mcp_server:8003")
RESOURCE_PREFIX = os.environ.get("RESOURCE_PREFIX", "miraige")
LB_ID = os.environ.get("LB_ID", f"{RESOURCE_PREFIX}-lb")
GHOST_POOL_ID = os.environ.get("GHOST_POOL_ID", f"{RESOURCE_PREFIX}-pool-ghost")
TTL = int(os.environ.get("HONEYPOT_TTL_SECONDS", "1800"))

# ─── Active morph contexts ────────────────────────────────────────
# State lives behind a store: memory by default, Redis when
# ORCHESTRATOR_STATE_BACKEND=redis (crash-safe + shared across instances).
# ACTIVE is the in-memory backend's backing dict (also handy for introspection).
ACTIVE: dict[str, MorphContext] = {}
STORE = make_morph_store(ACTIVE)
# Memory bound: cap with FIFO eviction of the oldest TERMINAL morph — recent
# request_id idempotence is preserved, unbounded growth over a campaign is cut.
MAX_ACTIVE = int(os.environ.get("ORCHESTRATOR_MAX_ACTIVE", "10000"))

MCP = McpClient(base_url=MCP_URL)
MACHINE = MorphStateMachine(
    mcp=MCP, lb_id=LB_ID, ghost_pool_id=GHOST_POOL_ID, ttl_seconds=TTL,
    on_transition=STORE.save,  # persist ctx on every FSM transition
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "orchestrator",
        "active_morphs": str(await STORE.count()),
    }


@app.post("/signal", status_code=status.HTTP_202_ACCEPTED)
async def receive_signal(request: Request) -> dict[str, str]:
    """Receive a signed A2A signal from a Sentinel.

    Full (working) chain:
      1. Read raw body
      2. Verify HMAC-SHA256 signature
      3. Parse AttackSignal
      4. Idempotence check (by request_id)
      5. Register in the store
      6. Fire-and-forget MACHINE.run(), full FSM (assign → reroute → monitor → terminate)
    """
    body = await request.body()
    try:
        verify_request(body, request.headers, secret=A2A_SECRET)
    except A2AVerificationError as e:
        log.warning(json.dumps({"event": "signal.signature_invalid", "error": str(e)}))
        raise HTTPException(status_code=401, detail="invalid A2A signature") from e

    signal = AttackSignal.model_validate_json(body)
    log.info(json.dumps({
        "event": "signal.received",
        "request_id": signal.request_id,
        "attacker_ip": signal.attacker_ip,
        "confidence": signal.confidence,
    }))

    if await STORE.contains(signal.request_id):
        return {"status": "duplicate", "request_id": signal.request_id}

    ctx = MorphContext(
        request_id=signal.request_id,
        attacker_ip=signal.attacker_ip,
        attacker_session=signal.attacker_session,
        target_instance_id=signal.target_instance_id,
    )
    await STORE.add(ctx)
    if await STORE.count() > MAX_ACTIVE:
        # Evict the oldest TERMINAL morphs only — never an in-flight one (that
        # would break its /state tracking and idempotence while it runs).
        await STORE.evict_terminal(MAX_ACTIVE)

    # Fire-and-forget · drive the full FSM as a background task. We keep a strong
    # reference to the task (otherwise the GC may destroy it before it finishes).
    task = asyncio.create_task(_drive(ctx, signal))
    _BG_TASKS.add(task)
    task.add_done_callback(_BG_TASKS.discard)

    return {"status": "accepted", "request_id": signal.request_id}


async def _drive(ctx: MorphContext, signal: AttackSignal) -> None:
    try:
        await MACHINE.run(ctx, signal)
    except asyncio.CancelledError:
        # Cancellation (demo reset or service shutdown): best-effort release of
        # the ghost session and L7 policy already allocated, with a bounded delay
        # so shutdown is not blocked, then re-raise the cancellation.
        try:
            await asyncio.wait_for(MACHINE.rollback(ctx), timeout=5.0)
        except Exception:
            pass
        raise
    except Exception as e:  # noqa: BLE001
        log.exception(json.dumps({
            "event": "morph.fatal",
            "request_id": ctx.request_id,
            "error": str(e),
        }))


@app.post("/admin/reset")
async def admin_reset(request: Request) -> dict:
    """Demo reset: purge active MorphContext entries. Protected by X-Mg-Reset.

    Closes a gap: every other service exposed /admin/reset, but not the
    orchestrator, so a demo reset left its morphs (and their "duplicate"
    request_id values) as zombies.
    """
    if not check_reset_secret(request.headers.get("x-mg-reset"), RESET_SECRET):
        raise HTTPException(status_code=403, detail="forbidden")
    n = await STORE.clear()
    # Cancel in-flight FSMs (otherwise they run to completion as zombies after a
    # demo reset; the ghost session then falls back on its own TTL).
    for t in list(_BG_TASKS):
        t.cancel()
    return {"service": "orchestrator", "reset": True, "morphs_cleared": n}


@app.get("/state")
async def list_active() -> dict[str, list[dict]]:
    return {"active": [ctx.model_dump(mode="json") for ctx in await STORE.all()]}


@app.get("/state/{request_id}")
async def get_one(request_id: str) -> MorphContext:
    ctx = await STORE.get(request_id)
    if ctx is None:
        raise HTTPException(404)
    return ctx
