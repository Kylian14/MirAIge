"""
AttackState: shared state that tracks the kill-chain of an attack session.

Lets each phase (recon, enum, exploit) reuse what the previous one found:
credentials, paths that return 200, session cookies, hints left in HTML
pages, and so on.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from .target_profiler import TargetProfile

# Common leak patterns found in bodies
_RE_BCRYPT = re.compile(r"\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}")
_RE_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
_RE_AWS_SECRET = re.compile(r"(?i)aws_secret_access_key\s*=\s*([A-Za-z0-9/+=]{32,})")
_RE_EMAIL = re.compile(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9-.]+")
_RE_URL_HINT = re.compile(r"(/[a-zA-Z0-9_./\-]{4,80})")
_RE_K8S = re.compile(r"(?:apiVersion|kind|namespace)\s*:")
_RE_PASSWORD_KV = re.compile(r"""(?i)(password|passwd|pwd)\s*[:=]\s*["']?([^\s"']{4,40})""")
_RE_TOKEN = re.compile(r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{16,})")


@dataclass
class Loot:
    """A secret extracted from a response."""
    kind: str           # bcrypt, aws_key, password, token, k8s, email
    value: str
    source_path: str    # where it came from
    found_at: float = field(default_factory=time.time)


@dataclass
class AttackState:
    """Live state of an attack session, visible across phases."""
    target_profile: TargetProfile | None = None
    phase: str = "init"
    started_at: float = field(default_factory=time.time)

    # Discoveries
    discovered_paths: set[str] = field(default_factory=set)   # every path tried
    working_paths: set[str] = field(default_factory=set)      # those that returned 2xx
    forbidden_paths: set[str] = field(default_factory=set)    # 401/403
    loot: list[Loot] = field(default_factory=list)

    # Auth state
    cookies: dict[str, str] = field(default_factory=dict)
    bearer: str | None = None
    last_csrf: str | None = None

    # Counters (for the end banner)
    requests_sent: int = 0
    bytes_in: int = 0
    by_status: dict[int, int] = field(default_factory=dict)
    by_phase: dict[str, int] = field(default_factory=dict)

    def record_request(self, path: str, status: int, body_len: int) -> None:
        self.requests_sent += 1
        self.bytes_in += body_len
        self.by_status[status] = self.by_status.get(status, 0) + 1
        self.by_phase[self.phase] = self.by_phase.get(self.phase, 0) + 1
        self.discovered_paths.add(path)
        if 200 <= status < 300:
            self.working_paths.add(path)
        elif status in (401, 403):
            self.forbidden_paths.add(path)

    def harvest(self, path: str, body: str) -> int:
        """Look for secrets/hints in the body, return how many loot items were added."""
        if not body:
            return 0
        added = 0

        for m in _RE_BCRYPT.findall(body)[:3]:
            self.loot.append(Loot(kind="bcrypt", value=m, source_path=path))
            added += 1
        for m in _RE_AWS_KEY.findall(body)[:2]:
            self.loot.append(Loot(kind="aws_key", value=m, source_path=path))
            added += 1
        for val in _RE_AWS_SECRET.findall(body)[:1]:
            self.loot.append(Loot(kind="aws_secret", value=val[:40], source_path=path))
            added += 1
        for label, val in _RE_PASSWORD_KV.findall(body)[:3]:
            self.loot.append(Loot(kind="password", value=f"{label}={val}", source_path=path))
            added += 1
        for label, val in _RE_TOKEN.findall(body)[:3]:
            self.loot.append(Loot(kind="token", value=f"{label[:8]}={val[:24]}", source_path=path))
            added += 1
        if _RE_K8S.search(body):
            self.loot.append(Loot(kind="k8s_yaml", value="kubeconfig fragment", source_path=path))
            added += 1

        # Pull out "interesting" URLs/paths mentioned in the response
        # (the agent follows these breadcrumbs in later phases)
        for m in set(_RE_URL_HINT.findall(body)[:30]):
            if m.endswith((".css", ".js", ".png", ".jpg", ".woff2", ".ico", ".svg")):
                continue
            if m not in self.discovered_paths:
                self.discovered_paths.add(m)
        return added

    def harvest_cookies(self, set_cookie_header: str) -> None:
        """Parse Set-Cookie and store the cookies for the session."""
        if not set_cookie_header:
            return
        for c in re.split(r",\s*(?=[A-Za-z0-9_\-]+=)", set_cookie_header):
            kv = c.split(";", 1)[0].strip()
            if "=" in kv:
                k, v = kv.split("=", 1)
                self.cookies[k.strip()] = v.strip()

    def credentials_for_login(self) -> list[tuple[str, str]]:
        """Combinations to try in brute-force, enriched with the leaks."""
        users = ["admin", "root", "administrator", "ovh", "operator", "sysadmin"]
        passwords = ["admin", "password", "admin123", "ovh2025", "P@ssw0rd!", "letmein"]

        # Enrich with the emails found (extract the user part)
        emails = [l for l in self.loot if l.kind == "email"]
        for e in emails[:3]:
            user = e.value.split("@", 1)[0]
            if user not in users:
                users.append(user)

        # If a leaked password exists, try it first
        leaked_pw = [l.value.split("=", 1)[-1] for l in self.loot if l.kind == "password"]
        passwords = leaked_pw + passwords

        # Reasonable cap for the demo
        combos: list[tuple[str, str]] = []
        for u in users[:6]:
            for p in passwords[:8]:
                combos.append((u, p))
        return combos

    def summary_dict(self) -> dict:
        return {
            "duration_s": round(time.time() - self.started_at, 1),
            "requests_sent": self.requests_sent,
            "bytes_in": self.bytes_in,
            "phases": dict(self.by_phase),
            "status_codes": dict(self.by_status),
            "working_paths": len(self.working_paths),
            "loot_count": len(self.loot),
            "loot_kinds": sorted({l.kind for l in self.loot}),
        }
