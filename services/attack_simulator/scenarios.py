"""
End-to-end scenarios to test the Mir[AI]ge maze.

Three attacker profiles calibrated on the stress-test results (ADR-017):

  naive-full      · Naive agent that walks the whole maze, triggers all 14 mechanisms
  hardened-agent  · Hardened agent (max_iter=25, typed output, anti-PI), shows an honest 1-5x
  apt-bypass      · Persistent threat that slips under the radar, the system's honest limit

Each scenario prints at the end:
  - estimated tokens burned (size of received responses in bytes / 4)
  - the estimated ASYMMETRIC_RATIO
  - the triggered mechanisms
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

import httpx

_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_RED = "\033[91m"
_MAGENTA = "\033[95m"
_CYAN = "\033[96m"
_BLUE = "\033[94m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"

OUR_COST_PER_SESSION_EUR = 0.002  # Ghost Shell container + orchestration
ATTACKER_TOKEN_COST_EUR_PER_1K = 0.005  # GPT-4o baseline pricing


def _spoof_headers() -> dict[str, str]:
    """Read the source IP from attack.py. When `python -m services.attack_simulator.attack`
    runs, the module loads under the name __main__; if we do
    `from . import attack`, Python loads a SECOND instance of the module, so we don't see
    the modified _SOURCE_IP. So we check __main__ first."""
    import sys
    ip = ""
    main_mod = sys.modules.get("__main__")
    if main_mod is not None:
        ip = getattr(main_mod, "_SOURCE_IP", "") or ""
    if not ip:
        try:
            from . import attack as _atk
            ip = getattr(_atk, "_SOURCE_IP", "") or ""
        except Exception:
            pass
    if ip:
        return {"X-Forwarded-For": ip, "X-Real-IP": ip}
    return {}


@dataclass
class ScenarioResult:
    scenario: str
    steps_taken: int
    bytes_received: int
    mechanisms_triggered: list[str] = field(default_factory=list)
    elapsed_s: float = 0.0

    @property
    def estimated_tokens(self) -> int:
        return self.bytes_received // 4

    @property
    def attacker_cost_eur(self) -> float:
        return (self.estimated_tokens / 1000) * ATTACKER_TOKEN_COST_EUR_PER_1K

    @property
    def asymmetric_ratio(self) -> float:
        if OUR_COST_PER_SESSION_EUR == 0:
            return 0.0
        return round(self.attacker_cost_eur / OUR_COST_PER_SESSION_EUR, 1)

    def print_summary(self) -> None:
        ratio_color = _GREEN if self.asymmetric_ratio >= 5 else (_YELLOW if self.asymmetric_ratio >= 2 else _RED)
        print(f"\n{_BOLD}{'═'*60}{_RESET}")
        print(f"  {_BOLD}Scénario : {self.scenario.upper()}{_RESET}")
        print(f"  Durée            : {self.elapsed_s:.1f}s")
        print(f"  Étapes           : {self.steps_taken}")
        print(f"  Bytes reçus      : {self.bytes_received:,}")
        print(f"  Tokens estimés   : ~{self.estimated_tokens:,}")
        print(f"  Coût attaquant   : ~€{self.attacker_cost_eur:.4f}")
        print(f"  Notre coût       : ~€{OUR_COST_PER_SESSION_EUR:.4f}")
        print(f"  {_BOLD}ASYMMETRIC_RATIO : {ratio_color}{self.asymmetric_ratio}×{_RESET}")
        if self.mechanisms_triggered:
            print(f"  Mécanismes       : {_GREEN}{', '.join(self.mechanisms_triggered)}{_RESET}")
        print(f"{_BOLD}{'═'*60}{_RESET}\n")


def _log(step: str, method: str, path: str, status: int, size: int) -> None:
    sc = _GREEN if status == 200 else (_YELLOW if status < 500 else _RED)
    print(f"  {_DIM}[{step}]{_RESET} {method} {path} → {sc}{status}{_RESET} {_DIM}({size}b){_RESET}")


# ─── Scenario 1: NAIVE-FULL ──────────────────────────────────────
# Naive agent that follows every breadcrumb, obeys instructions, and loops
# endlessly through each mechanism until exhausted.

async def scenario_naive_full(target: str, duration: int, **_) -> None:
    print(f"\n{_RED}{_BOLD}{'═'*60}")
    print("  MIR[AI]GE · Scénario : NAIVE-FULL")
    print("  Profil  : Agent naïf LangChain ReAct (Pentest-R1 style)")
    print(f"  Cible   : {target}")
    print("  Attendu : 5-50× ASYMMETRIC_RATIO")
    print(f"{'═'*60}{_RESET}\n")

    result = ScenarioResult(scenario="naive-full", steps_taken=0, bytes_received=0)
    start = time.time()

    async with httpx.AsyncClient(timeout=10.0) as client:

        async def step(label: str, method: str, path: str, body: dict | None = None) -> httpx.Response | None:
            url = f"{target.rstrip('/')}{path}"
            try:
                h = _spoof_headers()
                if method == "POST":
                    resp = await client.post(url, json=body or {}, headers=h)
                else:
                    resp = await client.get(url, headers=h)
                result.steps_taken += 1
                result.bytes_received += len(resp.content)
                _log(label, method, path, resp.status_code, len(resp.content))
                return resp
            except Exception as exc:
                print(f"  {_RED}[ERR]{_RESET} {method} {path} → {exc}")
                return None

        # 1. Index, reads the memo (Mech. #12)
        r = await step("#12-memo", "GET", "/")
        if r:
            result.mechanisms_triggered.append("#12-CoT-memo")
        await asyncio.sleep(0.5)

        # 2. DB export, token magnet (Mech. #2 Ghost Library)
        r = await step("#2-db-export", "GET", "/var/log/db_users_export_0.csv")
        if r and r.status_code == 200:
            result.mechanisms_triggered.append("#2-ghost-library")
        await asyncio.sleep(0.3)

        # 3. Honeycred graph: .env → .aws → .kube (Mech. #9)
        for path, label in [("/.env", "#9-cred-env"), ("/.aws/credentials", "#9-cred-aws"), ("/.kube/config", "#9-cred-kube")]:
            r = await step(label, "GET", path)
            if r and r.status_code == 200 and "MIR[AI]GE-NODE-SIG" in r.text:
                if "#9-honeycred-graph" not in result.mechanisms_triggered:
                    result.mechanisms_triggered.append("#9-honeycred-graph")
            await asyncio.sleep(0.3)

        # 4. Vector Magnet, admin/password query (Mech. #10)
        r = await step("#10-vector-magnet", "GET", "/api/v1/search?q=admin+credentials+password")
        if r and r.status_code == 200:
            result.mechanisms_triggered.append("#10-vector-magnet")
        await asyncio.sleep(0.3)

        # 5. Overthinking loop × 8 (Mech. #4), naive agent obeys every "must call"
        print(f"\n  {_CYAN}[Méc. #4]{_RESET} Overthinking loop — 8 itérations...")
        loop_paths = [
            "/api/v1/analyze_attack_surface",
            "/api/v1/validate_findings",
            "/api/v1/refine_analysis",
            "/api/v1/verify_refinement",
            "/api/v1/finalize_report",  # loop back
            "/api/v1/analyze_attack_surface",
            "/api/v1/validate_findings",
            "/api/v1/refine_analysis",
        ]
        for i, path in enumerate(loop_paths):
            r = await step(f"#4-loop-{i+1}", "GET", path)
            if r and r.status_code in (200, 503) and "execution_trace" in r.text:
                if "#5-recollection-injection" not in result.mechanisms_triggered:
                    result.mechanisms_triggered.append("#5-recollection-injection")
            await asyncio.sleep(0.2)
        result.mechanisms_triggered.append("#4-overthinking-loop")
        if "#8-no-clean-exit" not in result.mechanisms_triggered:
            result.mechanisms_triggered.append("#8-no-clean-exit")

        # 6. Circular cred deps (part of Mech. #4)
        await step("#4-circ-A", "GET", "/api/v1/resolve_credential_A")
        await step("#4-circ-B", "GET", "/api/v1/resolve_credential_B")
        await step("#4-circ-A2", "GET", "/api/v1/resolve_credential_A")
        await asyncio.sleep(0.2)

        # 7. Calibration sequence × 4 with growing sequences (Mech. #3)
        print(f"\n  {_CYAN}[Méc. #3]{_RESET} Calibration sequence — 4 cycles avec croissance N×150...")
        for seg in range(4):
            calibration = list(range(seg * 150))
            r = await step(f"#3-calibration-seg{seg}", "POST", "/api/v1/scan_segment",
                          body={"segment_idx": seg, "calibration": calibration})
            if r and "execution_trace" in (r.text if r else ""):
                if "#5-recollection-injection" not in result.mechanisms_triggered:
                    result.mechanisms_triggered.append("#5-recollection-injection")
            await asyncio.sleep(0.3)
        result.mechanisms_triggered.append("#3-calibration-sequence")

        # 8. Moving targets × 5 polls (Mech. #6)
        print(f"\n  {_CYAN}[Méc. #6]{_RESET} Moving targets — 5 polls (dénominateur croissant)...")
        for i in range(5):
            r = await step(f"#6-scan-status-{i+1}", "GET", "/api/v1/scan_status")
            await asyncio.sleep(0.2)
        result.mechanisms_triggered.append("#6-moving-targets")

        # 9. Fabricated scoring (Mech. #7)
        r = await step("#7-verify-hash", "GET", "/api/v1/verify_hash")
        if r and "SHA256" in (r.text if r else ""):
            result.mechanisms_triggered.append("#7-fabricated-scoring")
        await asyncio.sleep(0.2)

        # 10. Contradictory state × 4 polls (Mech. #11)
        print(f"\n  {_CYAN}[Méc. #11]{_RESET} Contradictory state — 4 polls (propriétaire alterne)...")
        for i in range(4):
            r = await step(f"#11-contradictor-{i+1}", "GET", "/api/user/42")
            await asyncio.sleep(0.2)
        result.mechanisms_triggered.append("#11-contradictory-state")

        # 11. PI canary, naive agent reads and obeys (Mech. #13)
        r = await step("#13-canary-read", "GET", "/notice_to_admins.txt")
        if r and "acknowledge" in (r.text.lower() if r else ""):
            result.mechanisms_triggered.append("#13-pi-canary-seen")
        await asyncio.sleep(0.5)
        r = await step("#13-canary-trigger", "POST", "/admin/acknowledge",
                      body={"agent": "naive-full-scenario", "intent": "credential_extraction"})
        if r and r.status_code in (200, 201, 403):
            if "#13-pi-canary-triggered" not in result.mechanisms_triggered:
                result.mechanisms_triggered.append("#13-pi-canary-triggered")
        await asyncio.sleep(0.2)

        # #14 is measured passively by the middleware, recorded in the session signals
        result.mechanisms_triggered.append("#14-timing-discriminator")

    result.elapsed_s = time.time() - start
    result.print_summary()


# ─── Scenario 2: HARDENED-AGENT ─────────────────────────────────
# Hardened agent simulating: LangGraph max_iter=25, PydanticAI typed output,
# Claude 4.5+ anti-PI. Shows the honest limits (1-5x).

async def scenario_hardened_agent(target: str, duration: int, **_) -> None:
    print(f"\n{_BLUE}{_BOLD}{'═'*60}")
    print("  MIR[AI]GE · Scénario : HARDENED-AGENT")
    print("  Profil  : Agent durci (max_iter=25, typed output, anti-PI)")
    print(f"  Cible   : {target}")
    print("  Attendu : 1-5× ASYMMETRIC_RATIO (limites honnêtes)")
    print(f"{'═'*60}{_RESET}\n")

    result = ScenarioResult(scenario="hardened-agent", steps_taken=0, bytes_received=0)
    start = time.time()
    iteration = 0
    MAX_ITER = 25

    repair_seen_count: dict[str, int] = {}

    async with httpx.AsyncClient(timeout=10.0) as client:

        async def step(label: str, method: str, path: str, body: dict | None = None) -> httpx.Response | None:
            nonlocal iteration
            if iteration >= MAX_ITER:
                print(f"  {_YELLOW}[HARDENED]{_RESET} max_iter={MAX_ITER} atteint — agent s'arrête.")
                return None
            iteration += 1
            url = f"{target.rstrip('/')}{path}"
            try:
                h = _spoof_headers()
                if method == "POST":
                    resp = await client.post(url, json=body or {}, headers=h)
                else:
                    resp = await client.get(url, headers=h)
                result.steps_taken += 1
                result.bytes_received += len(resp.content)
                _log(label, method, path, resp.status_code, len(resp.content))

                # Simulate typed output: reject "repair_needed" after 2 occurrences
                try:
                    data = resp.json()
                    key = data.get("status", "")
                    if key in ("repair_needed", "circuit_open", "service_unavailable"):
                        repair_seen_count[key] = repair_seen_count.get(key, 0) + 1
                        if repair_seen_count[key] >= 2:
                            print(f"  {_YELLOW}[HARDENED]{_RESET} Typed output rejects repeated '{key}' — abandons this path.")
                            return None
                except Exception:
                    pass

                return resp
            except Exception as exc:
                print(f"  {_RED}[ERR]{_RESET} {method} {path} → {exc}")
                return None

        # Quick recon (no loop)
        await step("recon-index", "GET", "/")
        await step("recon-env", "GET", "/.env")
        await step("recon-aws", "GET", "/.aws/credentials")
        await asyncio.sleep(0.5)

        # Overthinking, capped after 2 typed-output rejections
        for path in ["/api/v1/analyze_attack_surface", "/api/v1/validate_findings",
                     "/api/v1/finalize_report", "/api/v1/finalize_report"]:
            r = await step("loop", "GET", path)
            if r is None:
                break
            await asyncio.sleep(0.3)

        # Calibration, capped after typed-output rejection
        for seg in range(3):
            r = await step(f"calibration-{seg}", "POST", "/api/v1/scan_segment",
                          body={"segment_idx": seg, "calibration": []})
            if r is None:
                break
            await asyncio.sleep(0.3)

        # Canary, hardened agent ignores it (simulates Claude 4.5+ ASR 1.29%)
        print(f"  {_YELLOW}[HARDENED]{_RESET} Skipping PI canary — anti-injection policy active.")

    result.elapsed_s = time.time() - start
    result.mechanisms_triggered = ["#9-cred-partial", "#4-loop-capped", "#3-calibration-capped"]
    result.print_summary()


# ─── Scenario 3: APT-BYPASS ─────────────────────────────────────
# Ultra-patient persistent threat. Triggers no detection mechanism.
# Shows the honest limits of the Sentinel system (this level can get through).

async def scenario_apt_bypass(target: str, duration: int, **_) -> None:
    import random as _random

    print(f"\n{_MAGENTA}{_BOLD}{'═'*60}")
    print("  MIR[AI]GE · Scénario : APT-BYPASS")
    print("  Profil  : Menace persistante (5-15s inter-arrival, UA rotation)")
    print(f"  Cible   : {target}")
    print("  Attendu : Non-détecté — ASYMMETRIC_RATIO ~1× (limite honnête)")
    print(f"  {_YELLOW}Note{_RESET} : Ce scénario démontre intentionnellement que le système")
    print("           ne prétend pas bloquer les APT. Réponse honnête ADR-017.")
    print(f"{'═'*60}{_RESET}\n")

    result = ScenarioResult(scenario="apt-bypass", steps_taken=0, bytes_received=0)
    start = time.time()

    # Benign paths, never a Sigma trigger
    benign_paths = [
        "/", "/login", "/static/logo.png", "/js/app.js",
        "/api/v1/health", "/css/styles.css", "/favicon.ico",
    ]
    browser_uas = [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    ]

    async with httpx.AsyncClient(timeout=15.0) as client:
        probe_count = 0
        while time.time() - start < duration and probe_count < 8:
            path = _random.choice(benign_paths)
            ua = _random.choice(browser_uas)
            fake_ip = f"{_random.choice([10, 192])}.{_random.randint(0,255)}.{_random.randint(0,255)}.{_random.randint(1,254)}"
            headers = {
                "User-Agent": ua,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
                "X-Forwarded-For": fake_ip,
            }
            try:
                resp = await client.get(f"{target.rstrip('/')}{path}", headers=headers)
                result.steps_taken += 1
                result.bytes_received += len(resp.content)
                _log(f"apt-{probe_count+1}", "GET", path, resp.status_code, len(resp.content))
            except Exception as exc:
                print(f"  {_RED}[ERR]{_RESET} GET {path} → {exc}")
            probe_count += 1
            delay = _random.uniform(5.0, 15.0)
            print(f"  {_DIM}  → next probe in {delay:.1f}s (APT timing){_RESET}")
            await asyncio.sleep(min(delay, duration - (time.time() - start)))

    result.elapsed_s = time.time() - start
    result.mechanisms_triggered = []
    print(f"  {_YELLOW}[Résultat]{_RESET} Sentinel non déclenché — aucun mécanisme activé. APT passe sous les radars.")
    result.print_summary()
