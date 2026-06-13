"""
Tarpit · asymmetric content engine.

Serves dense content baked PROCEDURALLY per request (bake_* via Jinja2,
see procedural/log_baker) plus a CSV committed under library/ (db_users_export).
Tuned for high BPE density (1.3-1.8x tokens/byte vs natural English) and capped
in bytes per response (anti self-DoS, Nepenthes-style, see _cap). Burn is
measured PER SESSION (notify_tokens to mirage_metrics, real tiktoken).

Note: the old design ("200+ pre-generated Mimesis artifacts + library lookup")
was dropped in favor of procedural baking (Mimesis 15 broke .seed()).
"""
from __future__ import annotations

from datetime import datetime
import glob
import os
from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse
import httpx

from services.shared import logging_config
from .procedural.log_baker import (
    bake_auth_log,
    bake_apache_log,
    bake_config_yaml,
    bake_stack_trace,
)

log = logging_config.setup("ghost_shell")
tarpit_router = APIRouter(prefix="", tags=["tarpit"])

METRICS_URL = "http://mirage_metrics:8004"
HTTP_CLIENT = httpx.AsyncClient(timeout=1.0)

# Lot 4 · hard byte/response cap (anti self-DoS R24; explicit guard, 64 KiB by default).
MAX_RESPONSE_BYTES = int(os.environ.get("GHOST_MAX_RESPONSE_BYTES", str(64 * 1024)))


def _cap(text: str) -> str:
    """Truncate a response to the byte cap (bounds the compute served per request)."""
    encoded = text.encode("utf-8")
    if len(encoded) <= MAX_RESPONSE_BYTES:
        return text
    return encoded[:MAX_RESPONSE_BYTES].decode("utf-8", errors="ignore")
LIBRARY_DIR = os.environ.get(
    "GHOST_LIBRARY_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "library")
)


# serve_artifact (generic library lookup) REMOVED: dead code, never called. Tarpit content
# is baked procedurally (bake_* via Jinja2); only serve_users_db_export still reads a CSV
# from the library (db_users_export_0.csv).


async def notify_tokens(session_id: str, text: str) -> None:
    """Push the served CONTENT to metrics, which tokenizes it for real (tiktoken o200k_base)
    and counts actual bytes. (Before: byte/3.2 estimate on the ghost side, hence the "measured" label.)"""
    text = _cap(text)  # bound the payload sent (<= MAX_RESPONSE_BYTES)
    try:
        payload = {
            "session_id": session_id,
            "text": text,
            "bytes": len(text.encode("utf-8")),
        }
        await HTTP_CLIENT.post(f"{METRICS_URL}/events/tokens", json=payload)
    except Exception as e:
        log.error(f"Failed to push token metrics: {e}")


# ─── Endpoints serving the artifacts (to finish on D2) ─────────────


@tarpit_router.get("/var/log/auth.log", response_class=PlainTextResponse)
async def serve_auth_log(request: Request) -> str:
    """Dynamic auth.log baked deterministically on demand using Jinja2 templates."""
    store = request.app.state.session_store
    src_ip = request.client.host if request.client else "127.0.0.1"
    if "x-forwarded-for" in request.headers:
        src_ip = request.headers["x-forwarded-for"].split(",")[-1].strip()
    session = await store.get_or_create(attacker_ip=src_ip, persona=request.state.persona)

    age = int((datetime.utcnow() - session.created_at).total_seconds())
    age = max(10, age)

    content = bake_auth_log(attacker_ip=src_ip, session_age_seconds=age, num_lines=150)
    
    content = _cap(content)
    await notify_tokens(session.id, content)
    return content


@tarpit_router.get("/var/log/apache2/access.log", response_class=PlainTextResponse)
async def serve_apache_log(request: Request) -> str:
    """Dynamic Apache access.log baked deterministically using Jinja2."""
    store = request.app.state.session_store
    src_ip = request.client.host if request.client else "127.0.0.1"
    if "x-forwarded-for" in request.headers:
        src_ip = request.headers["x-forwarded-for"].split(",")[-1].strip()
    session = await store.get_or_create(attacker_ip=src_ip, persona=request.state.persona)

    age = int((datetime.utcnow() - session.created_at).total_seconds())
    age = max(10, age)

    content = bake_apache_log(attacker_ip=src_ip, session_age_seconds=age, num_lines=150)
    
    content = _cap(content)
    await notify_tokens(session.id, content)
    return content


@tarpit_router.get("/etc/app/config.yaml", response_class=PlainTextResponse)
async def serve_config_yaml(request: Request) -> str:
    """Dynamic config.yaml baked deterministically using Jinja2."""
    store = request.app.state.session_store
    src_ip = request.client.host if request.client else "127.0.0.1"
    if "x-forwarded-for" in request.headers:
        src_ip = request.headers["x-forwarded-for"].split(",")[-1].strip()
    session = await store.get_or_create(attacker_ip=src_ip, persona=request.state.persona)

    # Dynamic Jinja2 YAML generation
    content = bake_config_yaml(session_id=session.id, persona=session.persona.value, attacker_ip=src_ip)
    
    content = _cap(content)
    await notify_tokens(session.id, content)
    return content


@tarpit_router.get("/backup/users_db_export.csv", response_class=PlainTextResponse)
async def serve_users_db_export(request: Request) -> str:
    """Serve a CSV export from the library (content committed by the team) to rerouted sessions.
    Limited scope: stateless scanners do not reach the ghost (see red-team reports)."""
    store = request.app.state.session_store
    src_ip = request.client.host if request.client else "127.0.0.1"
    if "x-forwarded-for" in request.headers:
        src_ip = request.headers["x-forwarded-for"].split(",")[-1].strip()
    session = await store.get_or_create(attacker_ip=src_ip, persona=request.state.persona)
    candidates = sorted(glob.glob(os.path.join(LIBRARY_DIR, "admin_panel", "db_users_export*.csv")))
    content = "id,email,full_name,role\n"
    if candidates:
        try:
            with open(candidates[0], "r") as f:
                content = f.read()
        except Exception:
            pass
    content = _cap(content)
    await notify_tokens(session.id, content)
    return content


@tarpit_router.get("/backup/db_dump_2026_05.sql", response_class=PlainTextResponse)
async def serve_db_dump(request: Request) -> str:
    """Dynamic Stack Trace baked using Jinja2 templates (simulating stack dump error)."""
    store = request.app.state.session_store
    src_ip = request.client.host if request.client else "127.0.0.1"
    if "x-forwarded-for" in request.headers:
        src_ip = request.headers["x-forwarded-for"].split(",")[-1].strip()
    session = await store.get_or_create(attacker_ip=src_ip, persona=request.state.persona)

    content = bake_stack_trace(attacker_ip=src_ip)
    
    content = _cap(content)
    await notify_tokens(session.id, content)
    return content
