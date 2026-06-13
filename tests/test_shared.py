"""Characterization tests for services/shared/ (a2a_protocol + models).

Locks in the CURRENT behavior of A2A HMAC signing and the shared Pydantic
contracts. Hermetic: no network dependency, no mocked clock beyond
monkeypatch.time.
"""

import time

import pytest
from pydantic import ValidationError

from services.shared import a2a_protocol as a2a
from services.shared.a2a_protocol import (
    A2AVerificationError,
    sign_request,
    verify_request,
)
from services.shared.models import (
    AttackSignal,
    AttackVector,
    DetectionVerdict,
    LogEvent,
)

SECRET = "dev-secret"


# ──────────────────────────────────────────────────────────────────────
# a2a_protocol: sign / verify
# ──────────────────────────────────────────────────────────────────────


def test_sign_verify_roundtrip_ok():
    # Arrange
    body = b'{"hello":"world"}'

    # Act
    headers = sign_request(body, secret=SECRET, agent_id="sentinel")

    # Assert: roundtrip does not raise
    verify_request(body, headers, secret=SECRET)
    assert headers["X-Mirage-Agent"] == "sentinel"
    assert headers["X-Mirage-Signature"].startswith("v1=")
    assert "X-Mirage-Timestamp" in headers


def test_verify_rejects_tampered_body():
    # Arrange
    headers = sign_request(b"original", secret=SECRET)

    # Act / Assert: tampered body, signature no longer matches
    with pytest.raises(A2AVerificationError, match="signature mismatch"):
        verify_request(b"tampered", headers, secret=SECRET)


def test_verify_rejects_wrong_secret():
    # Arrange
    headers = sign_request(b"payload", secret=SECRET)

    # Act / Assert
    with pytest.raises(A2AVerificationError, match="signature mismatch"):
        verify_request(b"payload", headers, secret="autre-secret")


def test_verify_rejects_timestamp_outside_skew(monkeypatch):
    # Arrange: sign at T, verify at T + (skew + 5)s
    body = b"payload"
    headers = sign_request(body, secret=SECRET)
    drift = a2a.CLOCK_SKEW_SECONDS + 5
    real_now = int(headers["X-Mirage-Timestamp"])
    monkeypatch.setattr(a2a.time, "time", lambda: real_now + drift)

    # Act / Assert
    with pytest.raises(A2AVerificationError, match="timestamp drift"):
        verify_request(body, headers, secret=SECRET)


def test_verify_accepts_timestamp_within_skew(monkeypatch):
    # Arrange: drift just under the limit, tolerated
    body = b"payload"
    headers = sign_request(body, secret=SECRET)
    real_now = int(headers["X-Mirage-Timestamp"])
    monkeypatch.setattr(a2a.time, "time", lambda: real_now + a2a.CLOCK_SKEW_SECONDS - 1)

    # Act / Assert: does not raise
    verify_request(body, headers, secret=SECRET)


def test_verify_rejects_non_v1_scheme():
    # Arrange: signature with an unsupported scheme
    body = b"payload"
    headers = sign_request(body, secret=SECRET)
    headers["X-Mirage-Signature"] = "v2=" + headers["X-Mirage-Signature"].removeprefix("v1=")

    # Act / Assert
    with pytest.raises(A2AVerificationError, match="unsupported signature scheme"):
        verify_request(body, headers, secret=SECRET)


def test_verify_rejects_missing_timestamp_header():
    # Arrange
    headers = sign_request(b"payload", secret=SECRET)
    del headers["X-Mirage-Timestamp"]

    # Act / Assert
    with pytest.raises(A2AVerificationError, match="missing header"):
        verify_request(b"payload", headers, secret=SECRET)


def test_verify_rejects_missing_signature_header():
    # Arrange
    headers = sign_request(b"payload", secret=SECRET)
    del headers["X-Mirage-Signature"]

    # Act / Assert
    with pytest.raises(A2AVerificationError, match="missing header"):
        verify_request(b"payload", headers, secret=SECRET)


def test_sign_default_agent_id_is_mirage():
    # locks down the default agent_id
    headers = sign_request(b"x", secret=SECRET)
    assert headers["X-Mirage-Agent"] == "mirage"


# ──────────────────────────────────────────────────────────────────────
# models: Pydantic contracts
# ──────────────────────────────────────────────────────────────────────


def test_logevent_requires_core_fields():
    # Arrange / Act
    ev = LogEvent(
        timestamp="2026-06-01T12:00:00",
        source="lb",
        src_ip="1.2.3.4",
        raw="GET / HTTP/1.1",
    )

    # Assert: optional field defaults
    assert ev.session_id is None
    assert ev.method is None
    assert ev.path is None
    assert ev.status_code is None


def test_logevent_rejects_unknown_source():
    # source is a restricted Literal
    with pytest.raises(ValidationError):
        LogEvent(
            timestamp="2026-06-01T12:00:00",
            source="nginx",  # outside {lb,vm,auth,syslog}
            src_ip="1.2.3.4",
            raw="x",
        )


def test_logevent_missing_raw_fails():
    with pytest.raises(ValidationError):
        LogEvent(timestamp="2026-06-01T12:00:00", source="lb", src_ip="1.2.3.4")


def test_attacksignal_defaults_and_required():
    # Arrange / Act: emitted_at has a default, attacker_session is optional
    sig = AttackSignal(
        request_id="r1",
        attacker_ip="9.9.9.9",
        target_instance_id="vm-1",
        vector=AttackVector.AI_RECON,
        confidence=0.9,
        rate_rps=12.5,
    )

    # Assert
    assert sig.attacker_session is None
    assert sig.emitted_at is not None
    assert sig.vector is AttackVector.AI_RECON


def test_attacksignal_vector_accepts_enum_value_string():
    # locks down: a str Enum accepts the raw value "ai-recon"
    sig = AttackSignal(
        request_id="r1",
        attacker_ip="9.9.9.9",
        target_instance_id="vm-1",
        vector="ai-recon",
        confidence=0.5,
        rate_rps=1.0,
    )
    assert sig.vector is AttackVector.AI_RECON


def test_detectionverdict_confidence_bounds():
    # confidence is bounded [0,1], locks down the validation
    with pytest.raises(ValidationError):
        DetectionVerdict(
            attacker_ip="1.1.1.1",
            vector=AttackVector.RECON,
            confidence=1.5,  # out of bounds
            rationale="x",
            rate_rps=1.0,
            window_start="2026-06-01T12:00:00",
            window_end="2026-06-01T12:00:10",
        )


def _secrets():
    from services.shared import secrets
    return secrets


def test_resolve_secret_returns_env_value_when_set(monkeypatch):
    s = _secrets()
    monkeypatch.setenv("MY_SECRET_X", "real-value")
    assert s.resolve_secret("MY_SECRET_X", "default") == "real-value"


def test_resolve_secret_warns_once_on_default(monkeypatch):
    s = _secrets()
    monkeypatch.delenv("MY_SECRET_Y", raising=False)
    monkeypatch.delenv("MG_STRICT_SECRETS", raising=False)
    s._WARNED.discard("MY_SECRET_Y")
    # returns the default and marks the variable as warned (dedup)
    assert s.resolve_secret("MY_SECRET_Y", "dev-default") == "dev-default"
    assert "MY_SECRET_Y" in s._WARNED
    # second call: no re-warning (already deduped), same value
    assert s.resolve_secret("MY_SECRET_Y", "dev-default") == "dev-default"


def test_resolve_secret_strict_mode_raises(monkeypatch):
    s = _secrets()
    monkeypatch.delenv("MY_SECRET_Z", raising=False)
    monkeypatch.setenv("MG_STRICT_SECRETS", "1")
    with pytest.raises(RuntimeError, match="non sûre"):
        s.resolve_secret("MY_SECRET_Z", "dev-default")


def test_resolve_secret_warns_on_change_me_placeholder(monkeypatch):
    s = _secrets()
    # a "change-me" placeholder from .env.example is NOT equal to the code default
    # but must still trigger the warning (the cp .env.example case)
    monkeypatch.setenv("MY_SECRET_CM", "change-me-in-production-please")
    monkeypatch.delenv("MG_STRICT_SECRETS", raising=False)
    s._WARNED.discard("MY_SECRET_CM")
    assert s.resolve_secret("MY_SECRET_CM", "un-autre-defaut") == "change-me-in-production-please"
    assert "MY_SECRET_CM" in s._WARNED


def test_check_reset_secret():
    s = _secrets()
    assert s.check_reset_secret("good", "good") is True
    assert s.check_reset_secret("bad", "good") is False
    assert s.check_reset_secret(None, "good") is False
    assert s.check_reset_secret("", "good") is False


def test_detectionverdict_autogenerates_request_id():
    # request_id has a default (uuid4); tier_trace defaults to empty
    v = DetectionVerdict(
        attacker_ip="1.1.1.1",
        vector=AttackVector.RECON,
        confidence=0.5,
        rationale="x",
        rate_rps=1.0,
        window_start="2026-06-01T12:00:00",
        window_end="2026-06-01T12:00:10",
    )
    assert v.request_id
    assert v.tier_trace == []
