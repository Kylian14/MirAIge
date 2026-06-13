"""
Session state · Redis-backed per-attacker isolation.
"""
from __future__ import annotations

from datetime import datetime, timedelta
import json
import uuid

import redis

from services.shared.models import GhostPersona, SessionState, SessionSignals


def _not_expired(expires_at: datetime) -> bool:
    """Compare against now, tolerating a tz-aware expires_at (Redis round-trip),
    otherwise `aware > naive` raises a TypeError."""
    if expires_at.tzinfo is not None:
        expires_at = expires_at.replace(tzinfo=None)
    return expires_at > datetime.utcnow()


class SessionStore:
    """Per-attacker session store. Backed by Redis in prod, in-memory in POC."""

    def __init__(self, *, redis_url: str, ttl_seconds: int) -> None:
        self.redis_url = redis_url
        self.ttl_seconds = ttl_seconds
        self.use_redis = False
        self._local_store: dict[str, SessionState] = {}
        
        # Test Redis connection
        try:
            self.redis_client = redis.from_url(redis_url, socket_timeout=1.0)
            self.redis_client.ping()
            self.use_redis = True
        except Exception:
            # Silent fallback to local mode
            pass

    async def get_or_create(self, *, attacker_ip: str, persona: GhostPersona) -> SessionState:
        """Lookup session by IP and active persona or create a new one."""
        if self.use_redis:
            # Look up by IP in Redis (IP index -> session_id)
            session_id_bytes = self.redis_client.get(f"ip_map:{attacker_ip}")
            if session_id_bytes:
                session_id = session_id_bytes.decode()
                session_bytes = self.redis_client.get(f"session:{session_id}")
                if session_bytes:
                    data = json.loads(session_bytes.decode())
                    sess = SessionState.model_validate(data)
                    # Parity with the in-memory branch: only reuse if the
                    # persona matches AND the session is not expired, otherwise
                    # create a fresh one (avoids serving the wrong persona for
                    # the same IP, or a stale session).
                    if sess.persona == persona and _not_expired(sess.expires_at):
                        return sess

        else:
            # Local lookup
            for session in self._local_store.values():
                if session.attacker_ip == attacker_ip and session.persona == persona:
                    # Expiration check (robust tz-aware/naive)
                    if _not_expired(session.expires_at):
                        return session
                    else:
                        break

        # Not found or expired -> create
        return await self.create(attacker_ip=attacker_ip, persona=persona)

    async def create(self, *, attacker_ip: str, persona: GhostPersona) -> SessionState:
        """Alloc fresh session, store with TTL."""
        session_id = f"sess_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow()
        expires = now + timedelta(seconds=self.ttl_seconds)

        session = SessionState(
            id=session_id,
            attacker_ip=attacker_ip,
            persona=persona,
            created_at=now,
            expires_at=expires,
            counters={},
            discovered_creds=[],
            signals=SessionSignals(),
            tokens_burned=0
        )

        await self.save(session)
        return session

    async def save(self, session: SessionState) -> None:
        """Write-through after mutation."""
        if self.use_redis:
            data = session.model_dump_json()
            # Store the session
            self.redis_client.setex(
                f"session:{session.id}",
                self.ttl_seconds,
                data
            )
            # Store the IP -> ID mapping
            self.redis_client.setex(
                f"ip_map:{session.attacker_ip}",
                self.ttl_seconds,
                session.id
            )
        else:
            self._local_store[session.id] = session

    async def list_all(self) -> list[SessionState]:
        """Return all non-expired sessions (for monitoring dashboard)."""
        sessions: list[SessionState] = []
        if self.use_redis:
            for key in self.redis_client.scan_iter("session:*"):
                try:
                    data = self.redis_client.get(key)
                    if data:
                        sessions.append(SessionState.model_validate(json.loads(data.decode())))
                except Exception:
                    pass
        else:
            now = datetime.utcnow()
            sessions = [s for s in self._local_store.values() if s.expires_at > now]
        return sessions

    async def terminate(self, session_id: str) -> None:
        """DEL session key from database."""
        if self.use_redis:
            session_bytes = self.redis_client.get(f"session:{session_id}")
            if session_bytes:
                data = json.loads(session_bytes.decode())
                attacker_ip = data.get("attacker_ip")
                self.redis_client.delete(f"session:{session_id}")
                if attacker_ip:
                    self.redis_client.delete(f"ip_map:{attacker_ip}")
        else:
            if session_id in self._local_store:
                del self._local_store[session_id]

    async def clear_all(self) -> int:
        """Delete ALL sessions (demo reset). Returns the number deleted."""
        n = 0
        if self.use_redis:
            for pat in ("session:*", "ip_map:*"):
                for key in self.redis_client.scan_iter(pat):
                    self.redis_client.delete(key)
                    n += 1
        else:
            n = len(self._local_store)
            self._local_store.clear()
        return n
