# Security Policy

## A note on the fake credentials

Mir[AI]ge is a **deception** tool. The Ghost Shell deliberately serves credentials, API
keys, SSH keys, database dumps and configuration files. **All of these are fake
honeytokens generated at runtime** — they are bait and grant access to nothing. Security
scanners flagging "leaked secrets" in `services/ghost_shell/` are seeing intended decoy
content, not a real exposure.

These honeytokens are **synthetic**: they are not redacted real secrets, they are not tied
to any account, host or service, and they unlock nothing. Any secret-like string you find
in `services/ghost_shell` (hard-coded samples, templates, or values produced at runtime) is
a deliberate decoy. Treat such matches as expected, and do not file them as leaked-credential
findings.

The only *real* secrets are the operational ones you configure via environment variables
(`DASHBOARD_PASSWORD`, `A2A_SHARED_SECRET`, `AI_ENDPOINTS_API_KEY`, the `OVH_*` / `OS_*`
credentials). These are never committed: `.env` is git-ignored and the services print a
startup warning when a built-in default secret is still in use.

## Responsible use

Deploy Mir[AI]ge only in front of infrastructure and traffic you are authorized to defend.
It is designed for defensive security research, blue-team exercises, and honeypot
deployments — not for targeting systems you do not own or operate.

## Reporting a vulnerability

If you find a security issue **in Mir[AI]ge itself** (not in the intentional decoy
content), please report it privately rather than opening a public issue:

1. Use GitHub's **"Report a vulnerability"** (Security → Advisories) on this repository, or
2. Email the maintainers listed in the repository profile.

Please include reproduction steps and the affected version/commit. We aim to acknowledge
reports within a few days. Thank you for disclosing responsibly.

## Supported versions

This is a research project; security fixes are applied to the `main` branch. There is no
long-term-support guarantee.
