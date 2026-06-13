<div align="center">

# Mir[AI]ge

**Defense by attrition. Their LLM, their bill.**

An autonomous agentic defense that traps AI-driven attackers in a fake reality
built to drain their compute budget.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/Kylian14/miraige/actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-3776AB.svg)
![Runs offline](https://img.shields.io/badge/runs-offline%20%C2%B7%20no%20cloud%20required-success.svg)

</div>

---

## What is this?

Attackers now use AI. They scan faster, write payloads on the fly, and adapt mid-attack,
so static defenses like WAFs and blocklists struggle to keep up. Mir[AI]ge turns the
economics around: we generate decoy content cheaply in **O(n)** from templates, while the
attacker's model pays **O(n²)** to read it back through attention.

When it detects a machine-speed attack, it quietly reroutes that traffic to a single
procedural honeypot called the **Ghost Shell**. The Ghost Shell fakes a whole
infrastructure: 14 compute-wasting mechanisms, a procedural filesystem, a honeycredential
graph, shifting contradictory state, and reverse prompt-injection canaries. The attacker's
agent keeps running its kill-chain against nothing while the real user stays on the real
service, untouched. A naive attacker session typically costs them 5 to 50 times more
compute than it costs us, decided automatically in about three seconds with no human in
the loop.

> **It runs fully offline.** No cloud account, no API key, no GPU. `docker compose up`
> starts the whole stack with heuristic detection and a mocked load-balancer reroute.
> The cloud parts (LLM tier and real reroute) are opt-in.

**📖 Full reference:** the [handbook](docs/guide/) covers
[architecture](docs/guide/architecture.md),
[configuration](docs/guide/configuration.md) and the
[API](docs/guide/api.md).

---

## Quickstart

```bash
git clone https://github.com/Kylian14/miraige.git
cd miraige
cp .env.example .env          # works as-is for a local run, no secrets required
docker compose up --build -d  # or: make up
```

Then open:

| URL | What |
|---|---|
| http://localhost:8000 | **Console** (the SPA, served by the API). Set `DASHBOARD_PASSWORD` in `.env`; the default is a `change-me` placeholder the services warn about at startup. |
| http://localhost:8090 | The protected demo portal (the "victim") |
| http://localhost:8080 | The Ghost Shell decoy (inspect the 14 mechanisms directly) |

The control-plane services (sentinel, orchestrator, …) are network-internal by
default — the console aggregates all of their data under `/api/v1`. To reach them
directly while debugging, add `-f docker-compose.dev.yml`.

Launch an attack and watch the asymmetry build up:

```bash
python3 -m services.attack_simulator.attack \
  --target http://localhost:8080 --level naive-full --duration 120
```

---

## Install on your own server

`docker compose up --build` works on any Docker host. For a real deployment, use the guided
installer — it checks Docker, generates strong secrets into `.env`, turns on
`MG_STRICT_SECRETS=1`, and starts the stack:

```bash
sh deploy/install.sh
```

Harden it with the production overlay — internal services are no longer published, the
the console is bound to loopback, `MG_STRICT_SECRETS=1`, restart policies on:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

Then put a reverse proxy in front for TLS. Either point your **existing** nginx / Traefik /
Caddy / HAProxy at `127.0.0.1:8000` (drop-in configs in
[`deploy/proxy/snippets/`](deploy/proxy/snippets/)), or add **one bundled** proxy overlay:

```bash
BASE="-f docker-compose.yml -f docker-compose.prod.yml"
docker compose $BASE -f deploy/proxy/caddy.yml   up -d   # auto-HTTPS, also on localhost
docker compose $BASE -f deploy/proxy/nginx.yml   up -d   # HTTP; mount certs for TLS
MIRAIGE_DOMAIN=app.example.com \
  docker compose $BASE -f deploy/proxy/traefik.yml up -d # auto-HTTPS (public domain)
```

To bootstrap a fresh VM on any cloud (AWS, GCP, Azure, OVH, Hetzner…), paste
[`deploy/cloud-init.example.yaml`](deploy/cloud-init.example.yaml) as the instance's
user-data.

For Kubernetes, a Helm chart lives in [`deploy/helm/miraige`](deploy/helm/miraige) — the
console is the only service exposed (via an Ingress), everything else stays in-cluster:

```bash
helm install miraige deploy/helm/miraige \
  --set image.registry=ghcr.io/you \
  --set secrets.DASHBOARD_PASSWORD=$(openssl rand -hex 24) \
  --set ingress.host=miraige.example.com
```

---

## Architecture

The stack is fully containerized: 8 services plus Redis.

| Service | Port | Role |
|---|---|---|
| `fake_portal_prod` | 8090 | The legitimate target. Streams its HTTP logs to Sentinel. |
| `ghost_shell` | 8080 | The active decoy. One procedural container that fakes a whole infrastructure and hosts the 14 compute-wasting mechanisms. |
| `sentinel` | 8001 | Detection. Three-tier cascade: **T0** Sigma rules, then **T1** calibrated heuristic scoring, then an optional **T2** LLM. |
| `orchestrator` | 8002 | Decision. Runs the incident state machine and signs agent-to-agent calls (HMAC-SHA256). |
| `mcp_server` | 8003 | Action. Security-scoped MCP server that patches traffic routes. Mocked by default; can drive a real OpenStack/Octavia LB. |
| `mirage_metrics` | 8004 | Attrition audit. Counts attacker BPE tokens (tiktoken) and defender energy (CodeCarbon). |
| `api` | 8000 | BFF + SOC console. The single authenticated surface: the SPA at `/`, the API under `/api/v1`. |
| `attack_simulator` | n/a | Red team. Multiple stealth levels calibrated against the Sentinel cascade. |
| `redis` | 6379 | Shared session/state store. |

```
attacker ──▶ fake_portal_prod ──logs──▶ sentinel ──A2A──▶ orchestrator ──MCP──▶ mcp_server
                   │                       (T0/T1/T2)                              │ reroute
                   └────────────── legitimate user stays here ──────────┐         ▼
                                                                        attacker ▶ ghost_shell (decoy)
```

**Network model.** By default only the user-facing surfaces are published to the
host: the console/API (`:8000`), the protected portal (`:8090`), and the decoy
(`:8080`). The control-plane — `sentinel`, `orchestrator`, `mcp_server`,
`mirage_metrics`, `redis` — is network-internal (the console aggregates all of it
under `/api/v1`, so you never need to hit those ports directly). Re-open them for
debugging with `-f docker-compose.dev.yml`; lock everything except the API down
to loopback (for a reverse proxy) with `-f docker-compose.prod.yml`.

---

## Running without a cloud (default)

Out of the box the stack is provider-agnostic:

- `SENTINEL_STUB=1`: Sentinel runs T0 (Sigma) and T1 (heuristics) only, with no LLM call.
- `REROUTE_BACKEND=mock`: the load-balancer reroute is mocked in-process.

That covers the whole demo: detection, rerouting, the Ghost Shell decoy, the metrics, and
the dashboard, with zero external dependencies.

### Bring your own LLM (optional T2 tier)

The LLM tier speaks the OpenAI-compatible Chat Completions API, so any provider works,
including OpenAI, OVH AI Endpoints, Together, Groq, or a local vLLM or Ollama. In `.env`:

```bash
SENTINEL_STUB=0
AI_ENDPOINTS_BASE_URL=https://api.openai.com/v1   # or your provider's /v1 URL
AI_ENDPOINTS_API_KEY=sk-...
AI_MODEL_CLASSIFIER=gpt-4o-mini                   # any chat model
```

The attack simulator's `ai-agent` level takes the same config via `--ai-endpoint`,
`--ai-key`, and `--ai-model`. Without a key it falls back to a scripted attack.

### Cloud-free reroute on any host (inline proxy)

For a real reroute with **no cloud at all**, set `REROUTE_BACKEND=redis`: the orchestrator
flags the offending `mg_session` / IP in Redis, and a small OpenResty proxy in front of your
app ([`deploy/proxy/inline/`](deploy/proxy/inline/)) routes flagged traffic to the Ghost
Shell while everything else passes through. It fails open (never breaks your app if Redis is
down) and runs anywhere Docker does. The proxy also mirrors each request to Sentinel, so
detection works in front of your own app — set `SENTINEL_URL=` (empty) to disable it if your
app already streams its logs. It also serves always-on decoy traps in front of your app —
bait paths and a reverse prompt-injection canary
([`deploy/proxy/inline/canary_manifest.json`](deploy/proxy/inline/canary_manifest.json)) — so
an AI scanner trips a high-confidence signal before it even reaches you.

```bash
REROUTE_BACKEND=redis UPSTREAM_URL=http://your-app:8080 \
  docker compose -f docker-compose.yml -f deploy/proxy/inline.yml up -d
# send traffic through the proxy (default :8088)
```

### Optional: real infrastructure reroute (OVH / OpenStack)

To drive a real Octavia load balancer instead of the mock, set `REROUTE_BACKEND=octavia` and fill
in the `OVH_*` / `OS_*` credentials plus `LB_ID` and `GHOST_POOL_ID` in `.env`. The Octavia adapter
([`services/mcp_server/backends/octavia.py`](services/mcp_server/backends/octavia.py)) is the only
OVH-specific code and nothing else depends on it. Provisioning the load balancer and the hosts is
your infrastructure's concern — any OpenStack works, and other reroute backends are on the roadmap.

---

## Origins: an OVH hackathon project, reworked to be provider-agnostic

Mir[AI]ge was born at the **OVHcloud Cybersecurity Hackathon (2026 edition)**. The first
build was wired straight into OVH Public Cloud: the optional detection LLM ran on OVH AI
Endpoints, the decoy and control plane ran on OpenStack VMs, and the live reroute drove a
real **Octavia** L7 load balancer. The `OVH_*` / `OS_*` settings and the Octavia adapter
(`backends/octavia.py`) are the direct descendants of that build.

Since then, the OVH-specific parts have been deliberately separated from the core so the
project runs anywhere:

- **Offline by default.** Detection, the Ghost Shell decoy, the metrics and the dashboard
  need no cloud account, no API key and no GPU. `docker compose up` is the whole demo.
- **The cloud is opt-in.** The Octavia reroute sits behind a single boundary
  ([`services/mcp_server/backends/octavia.py`](services/mcp_server/backends/octavia.py)) and is mocked
  in-process unless you set `REROUTE_BACKEND=octavia`. Nothing else in the stack imports it, so
  Octavia is the *reference* backend rather than a hard dependency — it is also the
  boundary other load balancers (nginx, Traefik, Envoy, a managed cloud LB) plug into.
- **Bring your own LLM.** The detection LLM speaks the OpenAI-compatible Chat Completions
  API, so OVH AI Endpoints, OpenAI, Together, Groq, a local vLLM or Ollama all work with a
  single URL and key.

OVH remains the best-supported path because that is where the project grew up; the
architecture no longer requires it.

---

## The attack simulator

Each level is calibrated to pass (or trigger) a specific detection tier.

```bash
python3 -m services.attack_simulator.attack --target http://localhost:8090 --level <LEVEL> --duration 60
```

| Level | Triggers | Behaviour |
|---|---|---|
| `noisy` | T0 Sigma | Scanner UA (Nuclei/gobuster), high RPS, `/.env` `/.aws` paths |
| `evasive` | T1 heuristics | Fixed browser UA (low entropy), ~500 ms timing, ~45% 4xx |
| `stealth` | T2 only | High UA rotation, 2 to 3.5 s timing, encoded LFI (`%2e%2e`) |
| `ai-agent` | variable | Real ReAct LLM brain; remembers discovered credentials |
| `apt` | honest limit | Ultra-patient 5 to 15 s, multi-IP; may go undetected |
| `naive-full` | end-to-end | Walks the whole Ghost Shell through every mechanism |
| `hardened-agent` | end-to-end | Same walk with a capped/typed agent, to show the honest 1 to 5 times floor |
| `apt-bypass` | end-to-end | Stops before the Sigma paths, which confirms we do not claim to block everything |

---

## Project layout

```
miraige/
├── docker-compose.yml          # the whole stack
├── Makefile                    # up / down / attack / site / …
├── .env.example                # config template (works as-is)
└── services/
    ├── sentinel/               # detection cascade (T0, T1, T2)
    ├── orchestrator/           # decision + state machine (A2A signed)
    ├── mcp_server/             # action: mock LB by default, Octavia optional
    ├── ghost_shell/            # the procedural decoy + 14 mechanisms
    ├── mirage_metrics/         # ASYMMETRIC_RATIO telemetry
    ├── api/                    # BFF gateway + serves the SPA console (web/)
    ├── attack_simulator/       # red team
    ├── fake_portal/            # the protected target
    └── shared/                 # A2A signing, Pydantic models, helpers
```

---

## Access control (roles)

The console is role-based — **viewer < operator < admin**:

| Role | Can |
|------|-----|
| `viewer` | read the console: Overview, Detection, Engagements |
| `operator` | + launch / stop red-team runs, reset the demo state |
| `admin` | + (reserved) user management |

Out of the box there is nothing to manage: the BFF synthesizes a single `admin`
from `DASHBOARD_PASSWORD`, so the old single-password login keeps working — and
is no more permissive than before. For real multi-user RBAC, drop a `users.json`
(see [users.example.json](users.example.json)), mount it, and point
`MIRAIGE_USERS_FILE` at it:

```bash
python -m services.api.auth hash 'the-password'   # -> pbkdf2_sha256$... for users.json
```

Once `MIRAIGE_USERS_FILE` is set, an admin adds/removes users, changes roles and
resets passwords from the console's **Users** page — no hand-editing required.

`AUTH_BACKEND=local` (default) uses that store. `AUTH_BACKEND=oidc` is a reserved
seam for delegating to an identity provider (validate its JWT, map a group to a
role) — not implemented yet, and selecting it currently denies all requests.

## Security & responsible use

Mir[AI]ge is a defensive security research project. Everything the Ghost Shell leaks
(credentials, API keys, database dumps) is fake honeytokens generated at runtime, and none
of it grants real access. Deploy it only against traffic you are authorized to defend. See
[SECURITY.md](SECURITY.md).

## Contributing

Issues and PRs are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

[Apache-2.0](LICENSE) © The Mir[AI]ge Authors.

> Originally built for the OVHcloud Cybersecurity Hackathon, 2026 edition.
