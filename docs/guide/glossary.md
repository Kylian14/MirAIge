# Glossary

Terms used across Mir[AI]ge and this handbook.

| Term | Meaning |
|------|---------|
| **Mir[AI]ge** | The whole system: detection + decision + a deception decoy that drains an attacker's compute. |
| **Sentinel** | The detection service. Runs the three-tier cascade and emits a signed signal when confident. |
| **Detection cascade (T0/T1/T2)** | The tiered classifier: **T0** Sigma rules, **T1** calibrated heuristics, **T2** an optional LLM — cheapest first. |
| **Orchestrator** | The decision service. Runs one state machine per incident (allocate decoy → reroute → monitor → terminate). |
| **MCP server** | The action service: a security-scoped MCP server exposing the three tools that touch infrastructure (route to ghost, reroute the LB, terminate). |
| **Reroute backend** | How a reroute is enforced — `mock`, `octavia` (real LB), or `redis` (flag set + inline proxy). Selected by `REROUTE_BACKEND`. |
| **Ghost Shell** | The decoy: one container that fakes a whole infrastructure and hosts the compute-wasting [mechanisms](mechanisms.md). |
| **Engagement / morph** | One active incident — an attacker currently rerouted to the Ghost Shell. Internally a `MorphContext` moving through the orchestrator's state machine; surfaced at `/api/v1/incidents`. |
| **Persona** | A distinct decoy "identity" the Ghost Shell presents, selected by the `Host` header (different TLS/DNS/content per persona). |
| **Honeycredential graph** | Fake credentials that branch ≥ 2 — following one leads to more, never to anything real. |
| **Tarpit** | The pre-generated decoy content layer (the "Ghost Library") served to slow and cost the attacker. |
| **Canary (reverse prompt injection)** | Bait that a human ignores but an LLM agent trips, yielding a high-confidence "this is a machine" signal. |
| **A2A** | Agent-to-agent: the HMAC-SHA256-signed calls between Sentinel and Orchestrator (`A2A_SHARED_SECRET`). |
| **BFF / console** | The `api` service — Backend-For-Frontend that serves the SPA and the authenticated `/api/v1`. The single public surface. |
| **Role** | `viewer` < `operator` < `admin` — the [RBAC](api.md#authentication--roles) level a token carries. |
| **Attrition / asymmetry** | The economics: a decoy session costs the attacker many times more compute than the defender. Quantified by `mirage_metrics`. |
| **Attack level** | A calibrated red-team profile (`noisy`, `evasive`, `stealth`, `ai-agent`, `apt`, `naive-full`, …) tuned against a detection tier. |
