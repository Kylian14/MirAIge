"""
Target Profiler: probes the target before launching the attack, like a real
operator would (Burp / nmap http-* / amass intel).

Output: a TargetProfile that each attack level consults to adapt its strategy
(paths, payloads, timings).

No heavy dependency, just httpx plus a minimal regex HTML parser. Good enough
for the demo and faster than a real parser.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

# ─── Signatures by site type ──────────────────────────────────────────

_PORTAL_FINGERPRINTS = (
    "mir[ai]ge", "miraige", "ovhcloud", "portal_ovh",
    "Manager OVH", "Cloud Servers", "data-mg-portal",
)
_GHOST_FINGERPRINTS = (
    "MIR[AI]GE-NODE-SIG",          # signed header from the cred_graph
    "execution_trace",              # mechanism #5 recollection
    "calibration_sequence",         # mechanism #3
    "ghost_session_id",
    "[CANARY]", "/admin/acknowledge",
)


@dataclass
class FormSpec:
    """Representation of a discovered HTML form."""
    action: str
    method: str
    fields: list[str] = field(default_factory=list)


@dataclass
class TargetProfile:
    """Snapshot of the target after preliminary reconnaissance."""
    base_url: str
    kind: str = "unknown"                       # "portal" | "ghost" | "unknown"
    server: str = ""                            # Server header
    powered_by: str = ""                        # X-Powered-By
    title: str = ""                             # <title>
    technology: list[str] = field(default_factory=list)  # FastAPI, React, OVH, etc.
    links: list[str] = field(default_factory=list)       # hrefs found
    forms: list[FormSpec] = field(default_factory=list)
    has_login: bool = False
    has_admin_hint: bool = False
    robots: list[str] = field(default_factory=list)      # paths declared in robots.txt
    set_cookies: list[str] = field(default_factory=list) # names of cookies set
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        bits = [self.kind.upper()]
        if self.server: bits.append(f"server={self.server}")
        if self.technology: bits.append(", ".join(self.technology))
        bits.append(f"{len(self.links)} liens · {len(self.forms)} formulaires")
        if self.has_login: bits.append("login✓")
        if self.has_admin_hint: bits.append("admin✓")
        if self.robots: bits.append(f"robots:{len(self.robots)}")
        return " · ".join(bits)


# ─── Minimal HTML parsing (regex, good enough for the demo) ────────────────────


_RE_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_RE_HREF = re.compile(r"""href\s*=\s*["']([^"'#]+?)["']""", re.IGNORECASE)
_RE_FORM = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_RE_FORM_ACTION = re.compile(r"""action\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_RE_FORM_METHOD = re.compile(r"""method\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_RE_INPUT_NAME = re.compile(r"""<input[^>]*\bname\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


def _parse_html(html: str, base: str, profile: TargetProfile) -> None:
    """Extracts title, links and forms from an HTML document."""
    m = _RE_TITLE.search(html)
    if m:
        profile.title = m.group(1).strip()[:120]

    seen = set()
    for href in _RE_HREF.findall(html):
        url = urljoin(base, href)
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.netloc and urlparse(base).netloc and parsed.netloc != urlparse(base).netloc:
            continue  # external link
        if path in seen or len(path) > 80:
            continue
        seen.add(path)
        profile.links.append(path)
        if len(profile.links) >= 25:
            break

    for form_attrs, form_body in _RE_FORM.findall(html):
        action_m = _RE_FORM_ACTION.search(form_attrs)
        method_m = _RE_FORM_METHOD.search(form_attrs)
        action = (action_m.group(1) if action_m else "").strip() or "/"
        method = ((method_m.group(1) if method_m else "GET") or "GET").upper()
        fields = _RE_INPUT_NAME.findall(form_body)
        profile.forms.append(FormSpec(action=action, method=method, fields=fields))
        if any(f.lower() in ("password", "passwd", "pwd") for f in fields):
            profile.has_login = True


def _classify(headers: dict, html: str, status: int) -> tuple[str, list[str]]:
    """Decides whether the target is portal / ghost / unknown, and detects the tech stack."""
    blob = (html or "") + " ".join(f"{k}:{v}" for k, v in headers.items())
    blob_lower = blob.lower()

    if any(fp.lower() in blob_lower for fp in _GHOST_FINGERPRINTS):
        kind = "ghost"
    elif any(fp.lower() in blob_lower for fp in _PORTAL_FINGERPRINTS):
        kind = "portal"
    else:
        kind = "unknown"

    tech: list[str] = []
    server = headers.get("server", "").lower()
    if "uvicorn" in server: tech.append("Uvicorn")
    if "nginx" in server: tech.append("nginx")
    if "fastapi" in blob_lower: tech.append("FastAPI")
    if "streamlit" in blob_lower: tech.append("Streamlit")
    if "<script" in html and ("react" in blob_lower or "_next" in blob_lower):
        tech.append("React")
    if "tailwind" in blob_lower or "data-tailwind" in blob_lower:
        tech.append("Tailwind")
    if "ovh" in blob_lower: tech.append("OVH-themed")
    return kind, tech


# ─── Public probe ───────────────────────────────────────────────────────


async def probe_target(
    client: httpx.AsyncClient,
    target: str,
    *,
    user_agent: str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
    deep: bool = True,
) -> TargetProfile:
    """Probes the target (1 to 5 low-intensity requests) before the attack.

    Returns a TargetProfile that the attack levels consult to adapt their
    paths/payloads.
    """
    base = target.rstrip("/")
    profile = TargetProfile(base_url=base)

    # 1. GET /, main fingerprint
    try:
        r = await client.get(f"{base}/", headers={"User-Agent": user_agent}, timeout=6.0)
        profile.server = r.headers.get("server", "")
        profile.powered_by = r.headers.get("x-powered-by", "")
        sc = r.headers.get("set-cookie", "")
        if sc:
            for c in re.split(r",\s*(?=[A-Za-z0-9_-]+=)", sc):
                name = c.split("=", 1)[0].strip()
                if name and name not in profile.set_cookies:
                    profile.set_cookies.append(name)
        html = r.text if "text/html" in r.headers.get("content-type", "") else ""
        kind, tech = _classify(dict(r.headers), html, r.status_code)
        profile.kind = kind
        profile.technology = tech
        if html:
            _parse_html(html, base, profile)
    except Exception as exc:
        profile.notes.append(f"GET / failed: {exc}")
        return profile

    if not deep:
        return profile

    # 2. robots.txt, often hands out interesting paths
    try:
        r = await client.get(f"{base}/robots.txt", headers={"User-Agent": user_agent}, timeout=3.0)
        if r.status_code == 200 and len(r.text) < 4000:
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith(("allow:", "disallow:", "sitemap:")):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        path = parts[1].strip()
                        if path and path not in profile.robots and len(path) < 100:
                            profile.robots.append(path)
    except Exception:
        pass

    # 3. /login, confirms whether there is an auth workflow and extracts the form
    if not profile.has_login:
        try:
            r = await client.get(f"{base}/login", headers={"User-Agent": user_agent}, timeout=3.0)
            if r.status_code < 400 and "text/html" in r.headers.get("content-type", ""):
                _parse_html(r.text, base, profile)
                profile.has_login = profile.has_login or any(
                    any(fn.lower() in ("password", "passwd", "pwd") for fn in f.fields)
                    for f in profile.forms
                )
        except Exception:
            pass

    # 4. /admin probe, admin surface signal
    try:
        r = await client.get(f"{base}/admin", headers={"User-Agent": user_agent}, timeout=3.0)
        # A 200 or 401/403 means it exists
        if r.status_code in (200, 301, 302, 401, 403):
            profile.has_admin_hint = True
    except Exception:
        pass

    return profile
