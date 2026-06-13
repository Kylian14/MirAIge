"""Unit tests for the BFF login rate limiter and client IP helper."""
import time
import pytest
from collections import deque
from fastapi import Request
from fastapi.datastructures import Headers

import services.api.ratelimit as ratelimit
import services.api.main as api_main


@pytest.fixture(autouse=True)
def reset_ratelimiter():
    ratelimit.reset()
    yield
    ratelimit.reset()


def test_ratelimit_allowed_within_limit(monkeypatch):
    monkeypatch.setattr(ratelimit, "LIMIT", 3)
    monkeypatch.setattr(ratelimit, "WINDOW_S", 60.0)

    # 3 hits should be allowed
    assert ratelimit.check_and_record("1.2.3.4") is True
    assert ratelimit.check_and_record("1.2.3.4") is True
    assert ratelimit.check_and_record("1.2.3.4") is True


def test_ratelimit_blocked_after_limit(monkeypatch):
    monkeypatch.setattr(ratelimit, "LIMIT", 2)
    monkeypatch.setattr(ratelimit, "WINDOW_S", 60.0)

    assert ratelimit.check_and_record("1.2.3.4") is True
    assert ratelimit.check_and_record("1.2.3.4") is True
    # 3rd hit should be blocked
    assert ratelimit.check_and_record("1.2.3.4") is False


def test_ratelimit_different_ips_independent(monkeypatch):
    monkeypatch.setattr(ratelimit, "LIMIT", 1)

    assert ratelimit.check_and_record("1.2.3.4") is True
    assert ratelimit.check_and_record("1.2.3.4") is False
    # A different IP should not be blocked
    assert ratelimit.check_and_record("5.6.7.8") is True


def test_ratelimit_prunes_stale_hits(monkeypatch):
    monkeypatch.setattr(ratelimit, "LIMIT", 2)
    monkeypatch.setattr(ratelimit, "WINDOW_S", 2.0)

    now = time.monotonic()
    fake_time = now

    def mock_monotonic():
        return fake_time

    monkeypatch.setattr(time, "monotonic", mock_monotonic)

    assert ratelimit.check_and_record("1.2.3.4") is True
    assert ratelimit.check_and_record("1.2.3.4") is True
    assert ratelimit.check_and_record("1.2.3.4") is False  # limit hit

    # Advance time past window (2.1s)
    fake_time += 2.1

    # Should be allowed again
    assert ratelimit.check_and_record("1.2.3.4") is True


def test_ratelimit_max_keys_enforcement(monkeypatch):
    monkeypatch.setattr(ratelimit, "_MAX_KEYS", 2)
    monkeypatch.setattr(ratelimit, "WINDOW_S", 1.0)

    now = time.monotonic()
    fake_time = now

    def mock_monotonic():
        return fake_time

    monkeypatch.setattr(time, "monotonic", mock_monotonic)

    # Insert two keys
    assert ratelimit.check_and_record("1.1.1.1") is True
    assert ratelimit.check_and_record("2.2.2.2") is True

    # Advance time to make the first two keys stale
    fake_time += 1.5

    # Inserting a third key should trigger pruning of the first two
    assert ratelimit.check_and_record("3.3.3.3") is True
    assert "1.1.1.1" not in ratelimit._hits
    assert "2.2.2.2" not in ratelimit._hits
    assert "3.3.3.3" in ratelimit._hits


def test_client_ip_helper_extraction():
    # Helper dummy class for Request
    class FakeRequest:
        def __init__(self, headers_dict, host="127.0.0.1"):
            self.headers = Headers(headers_dict)
            class Client:
                host = "127.0.0.1"
            self.client = Client()
            self.client.host = host

    # Test when X-Forwarded-For header is present with a single IP
    req1 = FakeRequest({"x-forwarded-for": "192.168.1.10"})
    assert api_main._client_ip(req1) == "192.168.1.10"

    # Test when X-Forwarded-For header is present with multiple IPs (comma-separated)
    req2 = FakeRequest({"x-forwarded-for": "192.168.1.10, 10.0.0.1, 127.0.0.1"})
    assert api_main._client_ip(req2) == "192.168.1.10"

    # Test when X-Forwarded-For header is absent (should fallback to request.client.host)
    req3 = FakeRequest({}, host="203.0.113.5")
    assert api_main._client_ip(req3) == "203.0.113.5"

    # Test when socket client is completely missing
    class MissingClientRequest:
        headers = Headers({})
        client = None
    assert api_main._client_ip(MissingClientRequest()) == "unknown"
