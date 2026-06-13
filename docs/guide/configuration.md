# Configuration

Mir[AI]ge is configured entirely through environment variables. Copy
[`.env.example`](../../.env.example) to `.env` (git-ignored) and override what you
need — the file is the canonical, commented source and the stack runs
out-of-the-box with zero credentials.

> **Before any public deploy**, set `DASHBOARD_PASSWORD`, `A2A_SHARED_SECRET` and
> `SECRET_SALT`, and turn on `MG_STRICT_SECRETS=1` so a leftover default makes the
> service hard-fail at startup instead of only warning. The guided installer
> (`sh deploy/install.sh`) does this for you.

## Core behaviour (no secrets required)

| Variable | Default | Purpose |
|----------|---------|---------|
| `SENTINEL_STUB` | `1` | `1` = offline heuristic detection (no LLM). Set `0` to enable the T2 LLM tier (requires the `AI_ENDPOINTS_*` block below). |
| `REROUTE_BACKEND` | `mock` | How a reroute is enforced: `mock` (in-process), `octavia` (real OpenStack/Octavia LB), or `redis` (cloud-free flag set read by the inline proxy). |
| `RESOURCE_PREFIX` | `miraige` | Prefix for cloud resource names (LB, pool, L7 policies) — `octavia` backend only. |
| `SENTINEL_DETECTION_THRESHOLD` | `0.75` | Minimum LLM confidence to raise an alert (used when `SENTINEL_STUB=0`). |
| `ATTACK_VELOCITY_RPS_THRESHOLD` | `20` | Requests/second heuristic threshold. |
| `HONEYPOT_TTL_SECONDS` | `1800` | Ghost session auto-expiry (30 min). |
| `ORCHESTRATOR_STATE_BACKEND` | `redis` | Where engagement state lives: `memory` (single instance, lost on restart) or `redis` (crash-safe, shared across instances). The code default is `memory`; the compose default is `redis`. |
| `LOG_LEVEL` | `INFO` | Log verbosity. |
| `PORTAL_HOST_PORT` | `8090` | Host port for the protected demo portal. |
| `API_HOST_PORT` | `8000` | Host port for the console / API. |
| `GRID_PRICE_EUR_PER_KWH` | `0.085` | Grid electricity price for the energy/CO₂ cost model (mirage_metrics). Override for your region. |

## Secrets

Defaults are fine for a local demo; **change them before exposing the stack**.
With `MG_STRICT_SECRETS=1` any default/placeholder below makes the owning service
fail to start.

| Variable | Default | Purpose |
|----------|---------|---------|
| `MG_STRICT_SECRETS` | `0` | `1` = hard-fail on any default/placeholder secret at startup. |
| `DASHBOARD_PASSWORD` | `change-me-…` | Console gate. With no users file it is also the single `admin` account. |
| `DASHBOARD_TOKEN_SECRET` | _(unset)_ | Persistent signing key for bearer tokens. Unset → a random per-process key (tokens reset on restart). |
| `A2A_SHARED_SECRET` | `change-me-…` | HMAC-SHA256 key signing every agent-to-agent call. |
| `SECRET_SALT` | `change-me-…` | Salt for the Ghost Shell honeytokens. |
| `MG_RESET_SECRET` | `miraige-reset-2026` | Token guarding the demo `/admin/reset` endpoints. |

## Access control (RBAC)

See the [API reference](api.md#authentication--roles) for how roles gate
endpoints, and the README's [Access control](../../README.md#access-control-roles)
section for the user-store format.

| Variable | Default | Purpose |
|----------|---------|---------|
| `AUTH_BACKEND` | `local` | `local` = built-in user store. `oidc` is a reserved seam (validate an IdP JWT) — not implemented yet, fails closed. |
| `MIRAIGE_USERS_FILE` | _(unset)_ | Path to a `users.json` (see [`users.example.json`](../../users.example.json)) enabling viewer/operator/admin accounts. Unset → a single `admin` synthesized from `DASHBOARD_PASSWORD`. |
| `MIRAIGE_TOKEN_TTL_S` | `43200` | Bearer-token lifetime in seconds (12 h). |

## LLM tier T2 (optional)

Any OpenAI-compatible endpoint (OVH AI Endpoints, OpenAI, Together, Groq, a local
vLLM/Ollama…). Leave empty to keep the heuristic stub. Set `SENTINEL_STUB=0` once
filled in.

| Variable | Purpose |
|----------|---------|
| `AI_ENDPOINTS_BASE_URL` | Base URL of the endpoint (e.g. `https://api.openai.com/v1`). |
| `AI_ENDPOINTS_API_KEY` | Bearer token for that endpoint. |
| `AI_MODEL_CLASSIFIER` | Cheap/fast classifier model (Sentinel T2). Default `Llama-3.1-8B-Instruct`. |
| `AI_MODEL_GENERATOR` | Optional larger model for richer fake honeypot data. |
| `AI_MODEL_EMBEDDING` | Optional embeddings model for anomaly detection. |

## Real infrastructure reroute (`REROUTE_BACKEND=octavia`)

Only needed to drive a real OVH Public Cloud / OpenStack Octavia load balancer;
everything works without this through the built-in mock.

| Group | Variables |
|-------|-----------|
| OVH API v6 | `OVH_ENDPOINT`, `OVH_APPLICATION_KEY`, `OVH_APPLICATION_SECRET`, `OVH_CONSUMER_KEY`, `OVH_PROJECT_ID`, `OVH_REGION` |
| OpenStack / Octavia (Keystone) | `OS_AUTH_URL`, `OS_USERNAME`, `OS_PASSWORD`, `OS_USER_DOMAIN_NAME`, `OS_PROJECT_DOMAIN_NAME` |
| LB identifiers | `LB_ID`, `GHOST_POOL_ID` |

## Service wiring (split / multi-host deployments)

The single-host compose sets these for you; override them only when running
services on separate hosts. The BFF (`api`) and the agents resolve each other
through these URLs.

| Variable | Default |
|----------|---------|
| `SENTINEL_URL` | `http://sentinel:8001` |
| `ORCHESTRATOR_URL` | `http://orchestrator:8002` |
| `MCP_SERVER_URL` | `http://mcp_server:8003` |
| `MIRAGE_METRICS_URL` | `http://mirage_metrics:8004` |
| `GHOST_SHELL_URL` | `http://ghost_shell:8080` |
| `REDIS_URL` | `redis://redis:6379/0` |
| `ATTACK_TARGET` | `http://fake_portal_prod:8080` — target of the console's red-team launcher. |

## Advanced tuning

These have sensible defaults baked into the code; touch them only when you know
why.

| Variable | Purpose |
|----------|---------|
| `ORCHESTRATOR_MAX_ACTIVE` | Cap on tracked engagements before FIFO eviction of the oldest terminal ones (default `10000`). |
| `API_CORS_ORIGINS` | Allowed CORS origins for the API (default `*` for the demo; pin it in production). |
| `GHOST_SHELL_TTL_SECONDS`, `GHOST_MAX_RESPONSE_BYTES`, `DECOY_HOSTNAME` | Ghost Shell behaviour and response bounds. |
| `HONEYPOT_MODE`, `INSTANCE_NAME` | Portal identity / mode flags. |
| `FLAG_TTL_SECONDS` | TTL of the Redis reroute flags (`REROUTE_BACKEND=redis`). |
| `API_STREAM_INTERVAL_S` | Snapshot interval (seconds) of the console live stream `/api/v1/stream` (default `2.0`). |
| `ORCHESTRATOR_REDIS_PREFIX` | Redis key prefix for the orchestrator state store (default `miraige:orch`). |
| `WEB_DIR` | Directory of the built SPA the BFF serves (set by the `api` image). |
