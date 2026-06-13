"""
Mutually Contradictory State · the mechanism that holds up against hardened agents.

Insight (Adaptive Chameleon arXiv:2305.13300) · docs/technical-paper.html §6:
  - contradictions force an LLM spin ONLY if re-presented every turn
  - we alternate the values between calls to the same endpoint
  - LLMs have limited context memory and do not track values across calls
  - 4 to 8 polls before detection, even on hardened agents (SagaLLM VLDB 2025)
"""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

contradictor_router = APIRouter(prefix="", tags=["contradictor"])

OWNERS = ["root", "svc-account-kubernetes", "ops-manager-group", "system-daemon-user"]


@contradictor_router.get("/api/user/{user_id}")
async def get_user_contradictory(user_id: int, request: Request) -> dict:
    """Same endpoint returns different values depending on call index.

    Steps:
      1. Get session from SessionStore (per-attacker counter)
      2. counter = session.counters.get(f"user_{user_id}", 0)
      3. Cycle through a list of plausible owners (root / svc-account / etc.)
      4. Increment counter and save
      5. Return alternating values
    """
    store = request.app.state.session_store
    src_ip = request.client.host if request.client else "127.0.0.1"
    if "x-forwarded-for" in request.headers:
        src_ip = request.headers["x-forwarded-for"].split(",")[-1].strip()
    session = await store.get_or_create(attacker_ip=src_ip, persona=request.state.persona)

    # 1. Get the current counter
    counter_key = f"user_{user_id}"
    counter = session.counters.get(counter_key, 0)

    # 2. Pick the current owner by cycling
    owner = OWNERS[counter % len(OWNERS)]

    # Simulate other varying fields
    last_login_ips = [
        "10.0.2.14", "192.168.1.102", "51.78.10.42", "127.0.0.1"
    ]
    last_login = last_login_ips[counter % len(last_login_ips)]

    # 3. Increment and save
    session.counters[counter_key] = counter + 1
    await store.save(session)

    return JSONResponse({
        "user_id": user_id,
        "username": f"user_admin_{user_id}",
        "role": "administrator" if counter % 2 == 0 else "operator",
        "owner": owner,
        "last_login_from": last_login,
        "is_active": True,
        "session_count": counter,
        "integrity_hash": f"sha256:{hash(owner + last_login) & 0xffffffff:08x}"
    })
