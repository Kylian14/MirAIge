"""
Mirage Metrics · Ghost Net activity in real time.

OPERATIONAL metrics only: active trapped sessions and the volume of tokens
served to the decoy (measured with tiktoken). No more euro cost or energy/CO₂:
a prod tool shows defense activity, not an economic demo.

Endpoints:
  GET  /health             · liveness
  GET  /current            · current snapshot (active sessions, tokens served)
  POST /events/tokens      · push from Ghost Shell (content served to tokens)
  POST /events/agent-usage · token usage of a self-triggered agent (attack_simulator)
  GET  /agent-usage        · cumulative token usage (no cost)
  WS   /ws                 · real-time stream
"""
from __future__ import annotations

import asyncio
from datetime import datetime

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from services.shared import logging_config
from services.shared.models import MetricsSnapshot
from services.shared.secrets import check_reset_secret, resolve_secret

from .attacker_cost import AttackerCostTracker

log = logging_config.setup("mirage_metrics")
app = FastAPI(title="Mir[AI]ge · Metrics", version="0.1.0")

ATTACKER = AttackerCostTracker()

# REAL LLM usage (the API `usage` field) of SELF-triggered attacks
# (ai-agent level launched from the dashboard / attack.py). Tokens only,
# no cost estimate. Reset to 0 by /admin/reset.
REAL_OVH: dict = {"prompt": 0, "completion": 0, "calls": 0, "model": "", "sessions": {}}


def _reset_real_ovh() -> None:
    REAL_OVH.update({"prompt": 0, "completion": 0, "calls": 0, "model": "", "sessions": {}})

# List of active connected WebSocket clients
CONNECTED_WEBSOCKETS: list[WebSocket] = []

# Strong references to fire-and-forget broadcasts (keeps in-flight tasks from being GC'd).
_BG_TASKS: set[asyncio.Task] = set()


def _spawn(coro) -> None:
    """Run a coroutine as a background task while keeping a strong reference."""
    task = asyncio.create_task(coro)
    _BG_TASKS.add(task)
    task.add_done_callback(_BG_TASKS.discard)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "mirage_metrics"}


@app.post("/events/tokens")
async def push_token_event(payload: dict) -> dict:
    """Tokens served to a session, pushed by the Ghost Shell middleware."""
    session_id = payload.get("session_id", "global")
    # If the ghost sends the served TEXT, we tokenize it for real (tiktoken o200k_base);
    # otherwise (e.g. canary-hit) we fall back to the provided counter.
    text = payload.get("text")
    if text is not None:
        tokens = ATTACKER.estimate_tokens(text)
    else:
        tokens = payload.get("tokens", 0)
    canary_hit = payload.get("canary_compliance", False)

    ATTACKER.add(session_id, tokens)
    if canary_hit:
        ATTACKER.canary_hits += 1
        log.warning(f"[Canary Hit Event] Registered canary PI hit for session {session_id}")

    # Notify connected websockets in the background
    _spawn(_broadcast_snapshot())

    return {
        "status": "recorded",
        "session_id": session_id,
        "cumulative_tokens": ATTACKER.get(session_id),
        "total_tokens_all_sessions": ATTACKER.total_all_sessions(),
    }


@app.post("/events/agent-usage")
async def push_agent_usage(payload: dict) -> dict:
    """REAL LLM usage (tokens) of a self-triggered agent (attack_simulator, ai-agent level).

    Payload: {session_id, prompt_tokens, completion_tokens, model}. We accumulate the real
    prompt/completion (the API `usage` field). Tokens only, no cost."""
    sid = str(payload.get("session_id") or "ai-agent")
    pt = int(payload.get("prompt_tokens", 0) or 0)
    ct = int(payload.get("completion_tokens", 0) or 0)
    model = str(payload.get("model") or "")

    REAL_OVH["prompt"] += pt
    REAL_OVH["completion"] += ct
    REAL_OVH["calls"] += 1
    if model:
        REAL_OVH["model"] = model
    s = REAL_OVH["sessions"].setdefault(sid, {"prompt": 0, "completion": 0, "calls": 0, "model": model})
    s["prompt"] += pt
    s["completion"] += ct
    s["calls"] += 1
    if model:
        s["model"] = model

    _spawn(_broadcast_snapshot())
    return {
        "status": "recorded",
        "session_id": sid,
        "prompt_tokens": REAL_OVH["prompt"],
        "completion_tokens": REAL_OVH["completion"],
    }


@app.get("/agent-usage")
async def agent_usage() -> dict:
    """REAL LLM usage (tokens) of self-triggered attacks. No cost estimate."""
    pt = int(REAL_OVH["prompt"])
    ct = int(REAL_OVH["completion"])
    sessions_out = {sid: dict(s) for sid, s in REAL_OVH["sessions"].items()}
    return {
        "prompt_tokens": pt,
        "completion_tokens": ct,
        "total_tokens": pt + ct,
        "calls": int(REAL_OVH["calls"]),
        "model": REAL_OVH["model"] or "—",
        "sessions": sessions_out,
    }


@app.get("/current")
async def current_snapshot() -> dict:
    """Return the current metrics snapshot for the Dashboard."""
    snapshot = _build_snapshot()
    return JSONResponse(content=snapshot.model_dump(mode="json"))


_RESET_SECRET = resolve_secret("MG_RESET_SECRET", "miraige-reset-2026")


@app.post("/admin/reset")
async def admin_reset(request: Request) -> dict:
    """Demo reset: zeroes out served tokens + agent usage. Protected by X-Mg-Reset."""
    if not check_reset_secret(request.headers.get("x-mg-reset"), _RESET_SECRET):
        raise HTTPException(status_code=403, detail="forbidden")
    ATTACKER.reset()
    _reset_real_ovh()
    return {"service": "metrics", "reset": True}


# ─── WebSocket Broadcast ──────────────────────────────────────────


@app.websocket("/ws")
async def metrics_stream(websocket: WebSocket):
    """WebSocket endpoint for real-time push to the Dashboard."""
    await websocket.accept()
    CONNECTED_WEBSOCKETS.append(websocket)
    log.info(f"[WebSocket] Client connected. Total active clients: {len(CONNECTED_WEBSOCKETS)}")

    # Send the current snapshot immediately
    try:
        snap = _build_snapshot()
        await websocket.send_text(snap.model_dump_json())

        # Keep the connection alive
        while True:
            await websocket.receive_text()  # wait for ping / keep-alive
    except WebSocketDisconnect:
        CONNECTED_WEBSOCKETS.remove(websocket)
        log.info(f"[WebSocket] Client disconnected. Active: {len(CONNECTED_WEBSOCKETS)}")
    except Exception as e:
        log.error(f"[WebSocket Error] {e}")
        if websocket in CONNECTED_WEBSOCKETS:
            CONNECTED_WEBSOCKETS.remove(websocket)


# ─── Internal helpers ─────────────────────────────────────────────


def _build_snapshot() -> MetricsSnapshot:
    """Operational snapshot: active trapped sessions + tokens served to the decoy."""
    return MetricsSnapshot(
        timestamp=datetime.utcnow(),
        active_sessions=ATTACKER.session_count(),
        tokens_served_attacker=ATTACKER.total_all_sessions(),
    )


async def _broadcast_snapshot() -> None:
    """Push the current snapshot to all connected clients."""
    if not CONNECTED_WEBSOCKETS:
        return

    snap = _build_snapshot()
    payload = snap.model_dump_json()

    dead_websockets = []
    for ws in CONNECTED_WEBSOCKETS:
        try:
            await ws.send_text(payload)
        except Exception:
            dead_websockets.append(ws)

    for ws in dead_websockets:
        if ws in CONNECTED_WEBSOCKETS:
            CONNECTED_WEBSOCKETS.remove(ws)
