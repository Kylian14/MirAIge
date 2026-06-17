# Mir[AI]ge handbook

The reference documentation for running and operating Mir[AI]ge. For a one-page
overview and the quickstart, start with the [project README](../../README.md);
this handbook is the deeper reference.

## Contents

| Page | What it covers |
|------|----------------|
| [Architecture](architecture.md) | How a request flows through the detection cascade, the orchestrator, and the Ghost Shell, and why the economics favour the defender. |
| [Ghost Shell mechanisms](mechanisms.md) | The compute-wasting mechanisms the decoy runs, as implemented in the code. |
| [Configuration](configuration.md) | Every environment variable: defaults, what it changes, and which ones you must set before exposing the stack. |
| [Operations](operations.md) | Deploy, harden, scale, and run it: compose overlays, reverse proxies, secrets, multi-instance, Kubernetes. |
| [Using the console](usage.md) | Sign in, read the pages, launch red-team runs, manage users. |
| [API reference](api.md) | The BFF (`/api/v1/*`): authentication, roles, and every endpoint. |
| [Troubleshooting](troubleshooting.md) | Common symptoms (401/403/409/502, strict secrets, isolation, the live stream, Helm) and fixes. |
| [Development & testing](development.md) | Dev environment, the test suite, and CI (the contribution workflow is in CONTRIBUTING.md). |
| [Supply chain](supply-chain.md) | The secure release pipeline and how to verify signed images, SBOMs, and build provenance. |
| [Glossary](glossary.md) | The project's terms in one place. |

## At a glance

Mir[AI]ge is an **agentic deception / moving-target-defense** system. It watches
the traffic to a service it protects, and when it is confident a request is an
attacker it transparently **reroutes that attacker to a procedural decoy** (the
Ghost Shell) while legitimate users stay on the real service. The decoy then
spends the attacker's time and tokens on fabricated, never-ending infrastructure.

- **Detection** is a three-tier cascade. Cheap Sigma rules run first, a
  calibrated heuristic next, and an optional LLM last, so most traffic is judged
  for free.
- **Decision** is a small state machine per incident, signed agent-to-agent.
- **Action** is a reroute, abstracted behind a backend interface: an in-process
  mock, a real OpenStack/Octavia load balancer, or a cloud-free Redis-flag +
  inline reverse proxy that runs on any host.
- **The console** (a single authenticated BFF + SPA) is the only surface an
  operator needs; everything else stays internal.

It began as an entry to the OVHcloud Cybersecurity Hackathon 2026 and was then
reworked to be provider-agnostic and installable anywhere. See the README's
[Origins](../../README.md#origins-an-ovh-hackathon-project-reworked-to-be-provider-agnostic)
section for that history.
