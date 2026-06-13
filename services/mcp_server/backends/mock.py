"""In-process mock reroute backend (the default — no cloud, no credentials).

Ghost Shell session allocation and teardown still happen for real (HTTP); only
the load-balancer reroute is faked, so the whole demo runs offline.
"""
from __future__ import annotations

import time
import uuid
from typing import Any

from .base import LoadBalancerAdapter


class MockAdapter(LoadBalancerAdapter):
    name = "mock"

    async def reroute_lb_to_honeypot(self, *, request_id: str, **_: Any) -> dict[str, Any]:
        return {
            "rule_id": f"rule-{uuid.uuid4().hex[:8]}",
            "applied_at": int(time.time()),
            "rollback_token": f"rb-{uuid.uuid4().hex[:12]}",
        }

    async def purge_reroute_policies(self) -> dict[str, Any]:
        return {"purged": 0, "real_ovh": False}
