# Ghost Shell mechanisms

The Ghost Shell is the decoy an attacker lands on after a reroute. A **single
container** presents the illusion of a whole information system, and every layer
of that illusion is built to cost the attacker (especially an LLM-driven one)
more than it costs the defender.

> **The asymmetry.** Decoy content is generated in **O(n)** from templates and
> seeds; an attacking model pays **O(n²)** to read it back through attention.
> Everything served is fabricated honeytokens (salted with `SECRET_SALT`) that
> grant no real access.

This page documents the mechanisms **as implemented** (in `services/ghost_shell/`).
They realise the design's "14 compute-wasting mechanisms" themed in the project's
research. Here they are grouped by what they do.

## Procedural illusion: one container, a whole "infrastructure"

| Mechanism | Module | What it does |
|-----------|--------|--------------|
| **Persona routing** | `persona_router` | The `Host` header selects a distinct decoy personality, so the same container looks like many different systems. |
| **Pre-generated Ghost Library** | `tarpit` + `library/` | Serves a deep catalog of plausible fake artifacts (admin panels, DB exports, a k8s API server, MySQL dumps, an OVH-style portal, stack traces, logs) looked up rather than computed. |
| **Procedural filesystem** | `fs_explorer`, `procedural/fs_seeded` | An endless, self-consistent fake filesystem generated from path-seeded RNG (Mimesis), so exploration never reaches a bottom. |
| **Synthetic logs** | `procedural/log_baker` | Fabricated log/memo content baked on demand. |

## Cost asymmetry

The content engine is the foundation. Artifacts are **templated/seeded** (cheap to
produce) but dense and high-entropy to read, so an attacker's model burns
disproportionate compute parsing them. `mirage_metrics` quantifies the resulting
attacker-token vs. defender-energy ratio.

## Honeytoken graph

| Mechanism | Module | What it does |
|-----------|--------|--------------|
| **Honeycredential graph** | `cred_graph` | Fake credentials that **branch ≥ 2**: every leaked secret points to two or more further fake systems/secrets, so following the trail expands instead of converging. The result is an exponential rabbit hole that never reaches anything real. |

## Reasoning traps: keep the model busy and wrong

| Mechanism | Module | What it does |
|-----------|--------|--------------|
| **Mutually contradictory state** | `contradictor` | The "truth" the decoy presents contradicts itself across turns, so a reasoning agent keeps trying to reconcile facts that can't be reconciled. |
| **Per-attacker session isolation** | `session_state` (Redis) | Each attacker gets an isolated, self-consistent world keyed to their session, so the lie stays coherent *within* a session (and so two attackers never see the same state). |

## Detection (the secondary payoff)

| Mechanism | Module | What it does |
|-----------|--------|--------------|
| **Reverse prompt-injection canaries** | `canaries` | Bait content (e.g. an `/admin/acknowledge` trap) that a *human* ignores but an LLM agent following instructions will trip. Tripping it is a high-confidence "this is a machine" signal fed back to the Sentinel. |

## Network mimicry (optional, `mimicry/`)

When enabled, each persona is backed by its own TLS certificate, CoreDNS zone and
TTL behaviour (and optionally a separate network namespace), so even TLS- and
DNS-level fingerprinting sees a coherent, distinct system rather than one decoy.

## In short

One container, many faces, all fake, tuned so that the deeper an automated
attacker digs, the more it pays, while the real service stays untouched and the
defender's cost stays flat. See [Architecture](architecture.md) for how traffic
reaches the Ghost Shell, and the README's
[Origins](../../README.md#what-is-this) for the research thesis behind it.
