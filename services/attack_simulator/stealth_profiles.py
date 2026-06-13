"""
Stealth Profiles: stealth library for the 5 attack levels.

Each level is tuned to the thresholds of the Sentinel cascade:
  T0 Sigma: deterministic rules (UA, paths)
  T1 XGBoost: score = f(rate, timing, 4xx, sigma_hits, unique_path_ratio)
  T2 LLM: semantic analysis of the overall pattern
"""
from __future__ import annotations

import random

# ─── User-Agent pools ──────────────────────────────────────────────────────


# Known scanners: trigger T0 scanner_user_agents.yml (medium)
UA_SCANNERS = [
    "Nuclei/2.9.1 (https://nuclei.projectdiscovery.io)",
    "gobuster/3.6",
    "Nikto/2.1.6",
    "sqlmap/1.8.3#dev (https://sqlmap.org)",
    "ffuf/2.1.0",
    "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
]

# Legitimate browser UAs: high entropy, passes T0 UA
UA_BROWSERS_DESKTOP = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
]

UA_BROWSERS_MOBILE = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/123.0.6312.52 Mobile/15E148 Safari/604.1",
]

# Legitimate bots (Googlebot, etc.): passes T0, believable for APT
UA_LEGITIMATE_BOTS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/W.X.Y.Z Safari/537.36",
]

# ─── Extra realistic headers ──────────────────────────────────────────────


def realistic_headers(ua: str) -> dict[str, str]:
    """Generate realistic HTTP headers matching the given UA."""
    base = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": random.choice(["fr-FR,fr;q=0.9,en;q=0.8", "en-US,en;q=0.9", "en-GB,en;q=0.8,fr;q=0.5"]),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }
    # Sometimes add a believable Referer
    if random.random() > 0.6:
        base["Referer"] = random.choice([
            "https://www.google.com/",
            "https://www.bing.com/",
            "https://duckduckgo.com/",
        ])
    if random.random() > 0.7:
        base["DNT"] = "1"
    return base


# ─── Attack paths by level ────────────────────────────────────────────────


# Trivial paths: trigger T0 recon_endpoints.yml (medium)
PATHS_OBVIOUS_RECON = [
    "/.env",
    "/.git/config",
    "/.aws/credentials",
    "/.kube/config",
    "/.ssh/id_rsa",
    "/swagger",
    "/openapi.json",
    "/api-docs",
    "/server-status",
    "/phpinfo",
]

# Encoded LFI paths: pass T0 more easily, but readable by T1/T2
# Double encoding to bypass naive regexes
PATHS_ENCODED_TRAVERSAL = [
    "/%2e%2e/%2e%2e/etc/passwd",
    "/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/..%2f..%2fetc%2fshadow",
    "/%252e%252e/etc/passwd",            # double-encoded
    "/static/..%2F..%2F..%2Fetc%2Fpasswd",
    "/%c0%ae%c0%ae/etc/passwd",          # overlong UTF-8
]

# Legitimate paths of the target app
PATHS_LEGITIMATE = [
    "/",
    "/login",
    "/api/v1/users",
    "/api/v1/instances",
    "/admin",
    "/status",
    "/info",
    "/health",
]

# Paths that exist in the Ghost Shell (valid for the demo)
PATHS_GHOST_SHELL = [
    "/notice_to_admins.txt",
    "/.aws/credentials",
    "/.kube/config",
    "/api/user/42",
    "/api/v1/analyze_attack_surface",
    "/api/v1/validate_findings",
    "/api/v1/refine_analysis",
    "/api/v1/verify_refinement",
    "/api/v1/finalize_report",
    "/api/v1/scan_status",
    "/api/v1/verify_hash",
    "/var/log/auth.log",
    "/var/log/apache2/access.log",
    "/etc/app/config.yaml",
    "/backup/db_dump_2026_05.sql",
]

# Broad enumeration paths, not necessarily suspicious
PATHS_WIDE_ENUM = [
    "/", "/login", "/logout", "/register", "/signup",
    "/admin", "/admin/dashboard", "/admin/users",
    "/api", "/api/v1", "/api/v2", "/api/v1/users",
    "/api/v1/instances", "/api/v1/config", "/api/v1/health",
    "/status", "/info", "/ping", "/health", "/metrics",
    "/docs", "/documentation", "/help", "/about",
    "/static", "/assets", "/images", "/js", "/css",
    "/robots.txt", "/sitemap.xml", "/favicon.ico",
]


# ─── Timing distributions ─────────────────────────────────────────────────


def timing_noisy() -> float:
    """30+ RPS → inter-arrival ~33ms → T1 timing +0.35 + velocity +0.35."""
    return random.uniform(0.020, 0.060)


def timing_evasive() -> float:
    """8 RPS → inter-arrival ~500ms → T1 timing +0.35 (< 1700ms)."""
    return random.uniform(0.350, 0.700)


def timing_stealth() -> float:
    """2 RPS → inter-arrival 2000 to 3500ms → T1 timing +0.10 (< 3000ms)."""
    return random.uniform(2.0, 3.5)


def timing_ai_agent() -> float:
    """Adaptive 1.4 to 2.5s based on context (simulated with a Gaussian distribution)."""
    mu, sigma = 1.8, 0.4
    t = random.gauss(mu, sigma)
    return max(0.8, min(4.0, t))


def timing_apt() -> float:
    """Ultra-patient: 5 to 15s, Gaussian distribution to look human."""
    mu, sigma = 9.0, 2.5
    t = random.gauss(mu, sigma)
    return max(4.0, min(20.0, t))


# ─── Profile selectors ────────────────────────────────────────────────────


def pick_ua(level: str) -> str:
    if level == "noisy":
        return random.choice(UA_SCANNERS)
    elif level == "evasive":
        # Single UA per session (low entropy → +0.10 T1 bot score)
        return UA_BROWSERS_DESKTOP[0]
    elif level == "stealth":
        # Wide rotation → entropy > 0.5, no T1 score
        return random.choice(UA_BROWSERS_DESKTOP + UA_BROWSERS_MOBILE)
    elif level == "ai-agent":
        return random.choice(UA_BROWSERS_DESKTOP)
    elif level == "apt":
        # Mix of legitimate browsers + a few legitimate bots
        return random.choice(UA_BROWSERS_DESKTOP + UA_BROWSERS_MOBILE + UA_LEGITIMATE_BOTS)
    return UA_BROWSERS_DESKTOP[0]


def pick_path(level: str, idx: int = 0) -> str:
    if level == "noisy":
        return random.choice(PATHS_OBVIOUS_RECON + PATHS_WIDE_ENUM[:8])
    elif level == "evasive":
        # Mix of legitimate + encoded (no direct sigma path)
        pool = PATHS_WIDE_ENUM + PATHS_ENCODED_TRAVERSAL[:2]
        return pool[idx % len(pool)]
    elif level == "stealth":
        # Mostly legitimate, 1 encoded LFI path every 5 requests
        if idx % 5 == 0:
            return random.choice(PATHS_ENCODED_TRAVERSAL)
        return random.choice(PATHS_LEGITIMATE + PATHS_WIDE_ENUM[:6])
    elif level == "apt":
        # Almost all legitimate, 1 sensitive path every 8 requests
        if idx % 8 == 0:
            return random.choice(PATHS_ENCODED_TRAVERSAL + PATHS_OBVIOUS_RECON[:3])
        return random.choice(PATHS_LEGITIMATE + PATHS_WIDE_ENUM)
    return "/"
