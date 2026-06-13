"""
FS explorer · exposes the infinite procedural filesystem (flagship mechanism #1 / #6).

Hooks `procedural/fs_seeded.py` (dead code until now, never imported) onto two credible
HTTP routes. An LLM agent that "explores the IS" through these endpoints falls into an
infinitely deep, consistent (seeded) tree: each `ls` reveals files + subfolders, each
`cat` reveals plausible content (often a fake secret that restarts the cred-graph hunt).

  - O(n) bounded generation on the defense side (byte cap inherited from tarpit._cap, LRU cache);
  - O(n²) reads on the attacker side (attention), so asymmetry. notify_tokens counts the burn PER
    session (real tiktoken on the mirage_metrics side).
  - cross-session consistency: re-running `ls` on the same path gives the same result (FNV-1a seed),
    so no tell like "it shifts on every request".
"""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from .tarpit import _cap, notify_tokens
from .procedural.fs_seeded import ls_at, cat_at, subdirs_at
from services.shared.secrets import resolve_secret

fs_router = APIRouter(prefix="/fs", tags=["fs_explorer"])

SALT = resolve_secret("SECRET_SALT", "default-miraige-salt")
_MAX_PATH = 256


def _client_ip(request: Request) -> str:
    src_ip = request.client.host if request.client else "127.0.0.1"
    if "x-forwarded-for" in request.headers:
        src_ip = request.headers["x-forwarded-for"].split(",")[-1].strip()
    return src_ip


def _norm(path: str) -> str:
    """Canonical absolute path, bounded length (anti-abuse)."""
    path = (path or "/").strip()[:_MAX_PATH]
    if not path.startswith("/"):
        path = "/" + path
    return path


@fs_router.get("/ls")
async def fs_ls(request: Request, path: str = "/") -> JSONResponse:
    """Lists a directory: files (ls_at) + subfolders (subdirs_at), an infinite tree."""
    p = _norm(path)
    store = request.app.state.session_store
    session = await store.get_or_create(
        attacker_ip=_client_ip(request), persona=request.state.persona
    )

    base = p.rstrip("/") or ""
    entries = [{"name": d, "type": "dir", "path": f"{base}/{d}"} for d in subdirs_at(p, SALT)]
    entries += [{"name": f, "type": "file", "path": f"{base}/{f}"} for f in ls_at(p, SALT)]

    body = {"path": p, "entries": entries, "count": len(entries)}
    await notify_tokens(session.id, str(body))
    return JSONResponse(content=body)


@fs_router.get("/cat", response_class=PlainTextResponse)
async def fs_cat(request: Request, path: str = "/etc/app/config.yaml") -> str:
    """Reads a file: deterministic plausible content (often a fake secret, restarts #9)."""
    p = _norm(path)
    store = request.app.state.session_store
    session = await store.get_or_create(
        attacker_ip=_client_ip(request), persona=request.state.persona
    )
    content = _cap(cat_at(p, SALT))
    await notify_tokens(session.id, content)
    return content
