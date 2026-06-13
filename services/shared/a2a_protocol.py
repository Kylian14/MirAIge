"""HMAC-SHA256 signing for Agent-to-Agent calls.

Compatible with the spirit of Google A2A (signed messages between agents),
without requiring full protocol implementation.

Usage (sender)::

    headers = sign_request(payload_bytes, secret=os.environ["A2A_SHARED_SECRET"])
    httpx.post(url, content=payload_bytes, headers=headers)

Usage (receiver)::

    body = await request.body()
    verify_request(body, request.headers, secret=os.environ["A2A_SHARED_SECRET"])
"""
from __future__ import annotations

import hashlib
import hmac
import time
from typing import Mapping

CLOCK_SKEW_SECONDS = 30


class A2AVerificationError(Exception):
    """Signature failed, timestamp drifted, or header missing."""


def sign_request(body: bytes, *, secret: str, agent_id: str = "mirage") -> dict[str, str]:
    """Return the headers to attach to a signed A2A request."""
    timestamp = str(int(time.time()))
    message = f"{timestamp}.".encode() + body
    digest = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    return {
        "X-Mirage-Agent": agent_id,
        "X-Mirage-Timestamp": timestamp,
        "X-Mirage-Signature": f"v1={digest}",
    }


def verify_request(body: bytes, headers: Mapping[str, str], *, secret: str) -> None:
    """Raise A2AVerificationError on any signature/timestamp issue."""
    try:
        ts = headers["X-Mirage-Timestamp"]
        sig = headers["X-Mirage-Signature"]
    except KeyError as e:
        raise A2AVerificationError(f"missing header: {e.args[0]}") from None

    try:
        drift = abs(int(time.time()) - int(ts))
    except (ValueError, TypeError):
        raise A2AVerificationError("timestamp not numeric") from None
    if drift > CLOCK_SKEW_SECONDS:
        raise A2AVerificationError("timestamp drift exceeds allowed skew")

    if not sig.startswith("v1="):
        raise A2AVerificationError("unsupported signature scheme")

    expected = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig.removeprefix("v1=")):
        raise A2AVerificationError("signature mismatch")
