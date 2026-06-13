# Architecture

Mir[AI]ge protects a real service by *watching* its traffic and, when it is
confident a request is an attacker, transparently **rerouting that attacker to a
decoy** while legitimate users stay on the real service. The decoy then wastes
the attacker's time and compute.

## The flow

```
attacker ──▶ fake_portal_prod ──logs──▶ sentinel ──A2A──▶ orchestrator ──MCP──▶ mcp_server
                  │                    (T0 / T1 / T2)        (state machine)       │ reroute
                  └──────────── legitimate user stays here ──────────┐            ▼
                                                                attacker ────▶ ghost_shell (decoy)
```

1. **fake_portal_prod** is the protected service in the demo. Every request it
   serves is streamed to the Sentinel for classification — the app is
   *instrumented*, not proxied, so detection adds no latency to real users.
2. **sentinel** runs the detection cascade and, on a confident verdict, sends a
   signed `AttackSignal` to the orchestrator.
3. **orchestrator** drives a per-incident state machine: allocate a decoy
   session, flip the route, monitor, then tear down.
4. **mcp_server** is the only component that touches infrastructure. It exposes
   three security-scoped MCP tools (route to ghost, reroute the LB, terminate)
   and applies them through the configured reroute backend.
5. **ghost_shell** is the decoy: one procedural container that fabricates a whole
   infrastructure and hosts the compute-wasting mechanisms.

Two supporting services: **mirage_metrics** audits the attrition (attacker tokens
burned vs. defender energy), and **redis** is the shared session/flag store.

## Detection — a three-tier cascade

Most traffic is judged for free; only the genuinely ambiguous reaches the LLM.

- **T0 — Sigma rules.** Cheap signature matching (scanner UAs, obvious recon
  paths). Eliminates the noisy majority instantly.
- **T1 — calibrated heuristics.** A scored model over timing, error-rate bursts,
  UA rotation and request velocity (`ATTACK_VELOCITY_RPS_THRESHOLD`).
- **T2 — LLM (optional).** Any OpenAI-compatible model judges the semantic
  pattern of what survived T0/T1. Off by default (`SENTINEL_STUB=1`); enable with
  the `AI_ENDPOINTS_*` block. The alert threshold is `SENTINEL_DETECTION_THRESHOLD`.

The full per-key trace is available at `GET /api/v1/tier-trace/{key}`.

## Decision — the orchestrator state machine

Each incident runs one `MorphContext` through a state machine
(`services/orchestrator/state_machine.py`):

```
IDLE → DETECTING → ASSIGNING → REROUTING → MONITORING → TERMINATING → IDLE
                          └──────── on error ───────▶ ROLLBACK → ERROR
```

- A confidence gate (0.75) short-circuits low-confidence signals straight back to
  `IDLE` — no decoy is spun up for a maybe.
- `ASSIGNING` allocates a Ghost Shell session; `REROUTING` flips the attacker's
  route; `MONITORING` holds it until the TTL (`HONEYPOT_TTL_SECONDS`);
  `TERMINATING` frees everything.
- Hard caps keep the agent honest: a bounded number of thought steps and a
  circuit breaker after consecutive tool failures, so a misbehaving step rolls
  back cleanly rather than leaking a decoy session or an LB rule.

Agent-to-agent calls are signed with HMAC-SHA256 (`A2A_SHARED_SECRET`); an unsigned
or stale signal is rejected.

**State persistence.** Engagement state lives behind a store
(`ORCHESTRATOR_STATE_BACKEND`): an in-memory dict for a single instance, or Redis
— crash-safe and shared — so a restart no longer drops live engagements and more
than one orchestrator can run. The state machine persists on every transition, so
a Redis-backed `/api/v1/incidents` reflects the live state.

## Action — pluggable reroute backends

The reroute is abstracted behind one interface (`LoadBalancerAdapter`), selected
by `REROUTE_BACKEND`:

| Backend | What it does | Needs |
|---------|--------------|-------|
| `mock` | Reroute simulated in-process. | nothing — the default |
| `octavia` | Drives a real OpenStack/Octavia L7 load balancer. | OVH/OpenStack credentials |
| `redis` | Flags the offending session/IP in a Redis set that an inline reverse proxy reads on every request. | nothing cloud-side — runs on any host |

The `redis` backend + the bundled OpenResty proxy
([`deploy/proxy/inline/`](../../deploy/proxy/inline)) give cloud-free enforcement
in front of any unmodified upstream: flagged traffic is routed to the Ghost Shell,
mirrored to the Sentinel, and met with always-on canary traps.

## Why the economics favour the defender

The decoy serves *fabricated* data — fake credentials, API keys, database dumps —
that grant no real access, and the compute-wasting mechanisms make every step the
attacker takes cost them more than it costs the defender. An attacker running an
LLM agent against the decoy pays for the tokens; the defender's side stays cheap.
`mirage_metrics` quantifies this asymmetry, surfaced in the console.

## The console

The **api** service is a BFF that serves the React SPA and exposes `/api/v1/*`
behind bearer-token auth and [RBAC](api.md#authentication--roles). It is the only
surface an operator touches; the agents (sentinel, orchestrator, mcp_server,
mirage_metrics) stay internal. The SPA stays live through a single push stream
(`/api/v1/stream`) rather than polling. See the [API reference](api.md) for the
endpoints and the README's [Architecture](../../README.md#architecture) table for
ports.

**Network model.** Only the console (`api`), the protected portal and the decoy
are published to the host; the agents and Redis are network-internal. The
production overlay (`docker-compose.prod.yml`) further binds the console to
loopback for a TLS reverse proxy, while `docker-compose.dev.yml` re-opens the
internal ports for debugging. See [Operations](operations.md) for deployment.
