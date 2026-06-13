"""Shared config for the characterization tests (Phase 3).

These tests pin the CURRENT behavior of the code, including its known
flaws. They run outside Docker: outbound URLs point to a closed port
(fast failure), Redis is absent (the in-memory fallbacks are the pinned
behavior), and the optional heavy imports (xgboost, codecarbon) are
absent (the heuristic fallbacks are the pinned behavior).

IMPORTANT: env vars are read when the service modules are imported, so
this file must stay the first import in the suite.
"""

import os

_DEFAULTS = {
    # Outbound URLs to a closed port: fire-and-forget calls fail immediately.
    "ORCHESTRATOR_URL": "http://127.0.0.1:1",
    "SENTINEL_URL": "http://127.0.0.1:1",
    "METRICS_URL": "http://127.0.0.1:1",
    "MIRAGE_METRICS_URL": "http://127.0.0.1:1",
    "GHOST_SHELL_URL": "http://127.0.0.1:1",
    "MCP_SERVER_URL": "http://127.0.0.1:1",
    "LB_TARGET": "http://127.0.0.1:1",
    "REDIS_URL": "redis://127.0.0.1:1/0",
    # Secrets: pin the current default values from the code.
    "A2A_SHARED_SECRET": "dev-secret",
    "MG_RESET_SECRET": "miraige-reset-2026",
    # No real LLM calls in the tests.
    "AI_ENDPOINTS_BASE_URL": "",
    "AI_ENDPOINTS_API_KEY": "",
    # Mock reroute backend for mcp_server.
    "REROUTE_BACKEND": "mock",
}

for _k, _v in _DEFAULTS.items():
    os.environ.setdefault(_k, _v)
