"""
Mimicry · the Ghost Shell's 3 P0 mitigations.

Without them, the container is detectable in < 2 min via nmap + JARM + dig.
With them, it holds for 30 min against an LLM agent (see dossier-lundi §7).

P0.1: netns per persona (defeats identical TCP stack fingerprint)
P0.2: distinct TLS per persona (defeats identical JA3S/JARM)
P0.3: distinct DNS per persona (defeats CERTainty SOA/TTL profiling)

To implement on D3 if there's time. For the POC demo, these mitigations are
documented but not applied (Docker compose runs on a single netns).
"""
