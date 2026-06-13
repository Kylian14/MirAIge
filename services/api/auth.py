"""Auth + RBAC for the BFF.

A client logs in (username + password) and gets a signed bearer token carrying
their identity and role. Protected endpoints require a minimum role:

    viewer  <  operator  <  admin

  · viewer    — read-only (stats, flows, sessions, incidents, metrics)
  · operator  — viewer + run/stop attacks, reset demo state
  · admin     — operator + (future) user management

Identity backends are pluggable via AUTH_BACKEND (mirrors REROUTE_BACKEND):
  · local (default) — users from MIRAIGE_USERS_FILE (JSON); if absent, a single
    `admin` is synthesized from DASHBOARD_PASSWORD (zero-config, back-compatible
    with the old single-password console — and no more permissive than it was).
  · oidc            — reserved seam: validate the IdP's JWT and map a claim to a
    role. Not implemented yet; selecting it denies all requests (fail closed).

Token = base64url(payload) "." hmac_sha256_hex(payload).  payload = {sub, role,
exp}.  Signing key: DASHBOARD_TOKEN_SECRET if set, else derived from a real
SECRET_SALT, else a random per-process key (tokens die on restart — fine for a
local demo).

    Generate a password hash for users.json:
        python -m services.api.auth hash 'the-password'
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import tempfile
import threading
import time
from dataclasses import dataclass

from services.shared.secrets import resolve_secret

log = logging.getLogger("api.auth")

# ── roles ─────────────────────────────────────────────────────────────
ROLES = ("viewer", "operator", "admin")
_RANK = {r: i for i, r in enumerate(ROLES)}


def role_at_least(role: str, minimum: str) -> bool:
    """True if `role` is at or above `minimum` in the viewer<operator<admin order."""
    return _RANK.get(role, -1) >= _RANK.get(minimum, len(ROLES))


@dataclass(frozen=True)
class Identity:
    username: str
    role: str


# ── password hashing (stdlib pbkdf2, salted) ──────────────────────────
_PBKDF2_ITER = 200_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITER)
    return f"pbkdf2_sha256${_PBKDF2_ITER}${salt.hex()}${dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


# ── user store ────────────────────────────────────────────────────────
@dataclass(frozen=True)
class _User:
    username: str
    role: str
    password_hash: str = ""   # pbkdf2_sha256$... (preferred)
    password: str = ""        # plaintext (demo only, warned at load)

    def check(self, candidate: str) -> bool:
        if self.password_hash:
            return _verify_password(candidate, self.password_hash)
        if self.password:
            return hmac.compare_digest(candidate.encode("utf-8"), self.password.encode("utf-8"))
        return False


def _load_users() -> dict[str, _User]:
    """username -> _User, from MIRAIGE_USERS_FILE (JSON) or a synthesized admin."""
    path = os.environ.get("MIRAIGE_USERS_FILE", "")
    if path and os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as fh:
                raw = json.load(fh)
            entries = raw.get("users", []) if isinstance(raw, dict) else raw
            users: dict[str, _User] = {}
            for e in entries:
                name, role = e.get("username"), e.get("role", "viewer")
                if not name:
                    continue
                if role not in _RANK:
                    log.warning("user %r has unknown role %r — skipped", name, role)
                    continue
                if e.get("password") and not e.get("password_hash"):
                    log.warning("user %r uses a plaintext password — prefer password_hash", name)
                users[name] = _User(name, role, e.get("password_hash", ""), e.get("password", ""))
            if users:
                return users
            log.warning("MIRAIGE_USERS_FILE %s has no usable users — using the fallback admin", path)
        except Exception as exc:  # noqa: BLE001
            log.error("cannot read MIRAIGE_USERS_FILE %s: %s — using the fallback admin", path, exc)
    # Zero-config fallback: one admin from DASHBOARD_PASSWORD. Same reach as the
    # old single-password console (everyone-with-the-password was already admin),
    # so an existing deploy is not silently made more permissive.
    pw = resolve_secret("DASHBOARD_PASSWORD", "Miraige2025!")
    return {"admin": _User("admin", "admin", password=pw)}


def authenticate(username: str, password: str) -> Identity | None:
    """Validate credentials. A blank username maps to `admin` (back-compat with
    the old password-only login)."""
    user = _load_users().get(username or "admin")
    if user is None or not user.check(password or ""):
        return None
    return Identity(user.username, user.role)


# ── store administration (admin-only, file-backed) ────────────────────
# The console can CRUD users only when MIRAIGE_USERS_FILE points at a writable
# file. The zero-config fallback admin is read-only — there is nothing to persist.
_STORE_LOCK = threading.Lock()


def is_managed() -> bool:
    """True when users live in a writable file we can edit (not the fallback admin)."""
    path = os.environ.get("MIRAIGE_USERS_FILE", "")
    return bool(path) and os.path.isfile(path) and os.access(path, os.W_OK)


def list_users() -> list[dict]:
    """Public view — [{username, role}], never secrets. Sorted admin-first."""
    users = _load_users().values()
    order = {"admin": 0, "operator": 1, "viewer": 2}
    return [
        {"username": u.username, "role": u.role}
        for u in sorted(users, key=lambda u: (order.get(u.role, 9), u.username))
    ]


def _read_entries() -> list[dict]:
    path = os.environ.get("MIRAIGE_USERS_FILE", "")
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    return raw.get("users", []) if isinstance(raw, dict) else (raw or [])


def _write_entries(entries: list[dict]) -> None:
    path = os.environ["MIRAIGE_USERS_FILE"]
    payload = json.dumps({"users": entries}, indent=2) + "\n"
    folder = os.path.dirname(path) or "."
    # Prefer an atomic temp-file + rename. A single-file bind mount puts the temp
    # file on a different device, so os.replace raises EXDEV — fall back to an
    # in-place write (is_managed() already confirmed the path is writable).
    try:
        fd, tmp = tempfile.mkstemp(dir=folder, prefix=".users.", suffix=".json")
    except OSError:
        tmp = None
    if tmp is not None:
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.replace(tmp, path)  # atomic when tmp shares the target's filesystem
            return
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(payload)


def _find(entries: list[dict], username: str) -> dict | None:
    return next((e for e in entries if e.get("username") == username), None)


def _admin_count(entries: list[dict]) -> int:
    return sum(1 for e in entries if e.get("role") == "admin")


def create_user(username: str, role: str, password: str) -> None:
    username = (username or "").strip()
    if not username:
        raise ValueError("username is required")
    if role not in _RANK:
        raise ValueError(f"invalid role: {role!r}")
    if not password:
        raise ValueError("password is required")
    with _STORE_LOCK:
        entries = _read_entries()
        if _find(entries, username) is not None:
            raise ValueError(f"user already exists: {username!r}")
        entries.append({"username": username, "role": role, "password_hash": hash_password(password)})
        _write_entries(entries)


def set_role(username: str, role: str) -> None:
    if role not in _RANK:
        raise ValueError(f"invalid role: {role!r}")
    with _STORE_LOCK:
        entries = _read_entries()
        target = _find(entries, username)
        if target is None:
            raise KeyError(username)
        if target.get("role") == "admin" and role != "admin" and _admin_count(entries) <= 1:
            raise ValueError("cannot demote the last admin")
        target["role"] = role
        _write_entries(entries)


def set_password(username: str, password: str) -> None:
    if not password:
        raise ValueError("password is required")
    with _STORE_LOCK:
        entries = _read_entries()
        target = _find(entries, username)
        if target is None:
            raise KeyError(username)
        target.pop("password", None)  # drop any plaintext, store a hash
        target["password_hash"] = hash_password(password)
        _write_entries(entries)


def delete_user(username: str) -> None:
    with _STORE_LOCK:
        entries = _read_entries()
        target = _find(entries, username)
        if target is None:
            raise KeyError(username)
        if target.get("role") == "admin" and _admin_count(entries) <= 1:
            raise ValueError("cannot delete the last admin")
        _write_entries([e for e in entries if e.get("username") != username])


# ── token signing ─────────────────────────────────────────────────────
_RANDOM_PROCESS_KEY = secrets.token_bytes(32)
_TOKEN_TTL_S = int(os.environ.get("MIRAIGE_TOKEN_TTL_S", str(12 * 3600)))


def _is_default_secret(value: str) -> bool:
    return not value or "change-me" in value.lower() or value == "Miraige2025!"


def _resolve_signing_key() -> bytes:
    explicit = os.environ.get("DASHBOARD_TOKEN_SECRET", "")
    if explicit:
        return explicit.encode("utf-8")
    salt = resolve_secret("SECRET_SALT", "change-me-ghost-shell")
    if not _is_default_secret(salt):
        return hashlib.sha256(b"miraige-api-token-key|" + salt.encode("utf-8")).digest()
    return _RANDOM_PROCESS_KEY


_SIGNING_KEY = _resolve_signing_key()


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign(payload_b64: str) -> str:
    return hmac.new(_SIGNING_KEY, payload_b64.encode("ascii"), hashlib.sha256).hexdigest()


def issue_token(identity: Identity, now: float | None = None) -> str:
    exp = int(time.time() if now is None else now) + _TOKEN_TTL_S
    payload = {"sub": identity.username, "role": identity.role, "exp": exp}
    body = _b64(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{body}.{_sign(body)}"


def identity_from_token(token: str, now: float | None = None) -> Identity | None:
    if not token or "." not in token:
        return None
    body, _, sig = token.partition(".")
    if not hmac.compare_digest(sig, _sign(body)):
        return None
    try:
        payload = json.loads(_unb64(body))
    except (ValueError, json.JSONDecodeError):
        return None
    if int(payload.get("exp", 0)) < (time.time() if now is None else now):
        return None
    role, sub = payload.get("role", ""), payload.get("sub", "")
    if role not in _RANK or not sub:
        return None
    return Identity(sub, role)


# ── backend seam (local | oidc) ───────────────────────────────────────
BACKEND = os.environ.get("AUTH_BACKEND", "local").lower()

if BACKEND not in ("local", "oidc"):
    log.warning("unknown AUTH_BACKEND=%r — treating as 'local'", BACKEND)
    BACKEND = "local"
if BACKEND == "oidc":
    log.warning("AUTH_BACKEND=oidc is a reserved seam and not implemented — all requests will be denied")


def login_enabled() -> bool:
    """The local backend issues tokens; under oidc, login is the IdP's job."""
    return BACKEND == "local"


def identity_from_request(authorization: str) -> Identity | None:
    """Resolve the caller's identity from the Authorization header, per backend."""
    token = (authorization or "").removeprefix("Bearer ").strip()
    if not token:
        return None
    if BACKEND == "oidc":
        # Seam: validate the IdP's JWT (signature, iss, aud, exp) and map a
        # configured claim/group to a role here. Until then: deny (fail closed).
        return None
    return identity_from_token(token)


if __name__ == "__main__":  # `python -m services.api.auth hash <password>`
    import sys

    if len(sys.argv) == 3 and sys.argv[1] == "hash":
        print(hash_password(sys.argv[2]))
    else:
        print("usage: python -m services.api.auth hash <password>", file=sys.stderr)
        sys.exit(2)
