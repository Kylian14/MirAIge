"""Reroute backends for the MCP server, selected by REROUTE_BACKEND."""
from __future__ import annotations

from typing import Any

from .base import LoadBalancerAdapter
from .mock import MockAdapter

__all__ = ["LoadBalancerAdapter", "MockAdapter", "make_adapter"]


def make_adapter(backend: str, **cfg: Any) -> LoadBalancerAdapter:
    """Build the reroute backend for REROUTE_BACKEND (mock | octavia | redis)."""
    backend = (backend or "mock").strip().lower()
    if backend == "mock":
        return MockAdapter(**cfg)
    if backend == "octavia":
        # Lazy import: openstacksdk is only needed for the octavia backend.
        from .octavia import OctaviaAdapter
        return OctaviaAdapter(**cfg)
    if backend == "redis":
        # Lazy import: redis is only needed for the inline-proxy backend.
        from .redis_flag import RedisFlagAdapter
        return RedisFlagAdapter(**cfg)
    raise ValueError(f"unknown REROUTE_BACKEND={backend!r} (expected 'mock', 'octavia' or 'redis')")
