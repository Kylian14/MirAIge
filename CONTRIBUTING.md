# Contributing to Mir[AI]ge

Thanks for your interest! Mir[AI]ge is a defensive security research project and we
welcome bug reports, mechanism ideas, detection improvements, and documentation fixes.

## Ground rules

- **Defensive use only.** Contributions must serve detection, deception, or analysis of
  authorized traffic. We don't accept offensive tooling aimed at real third-party systems.
- Be respectful — see the [Code of Conduct](CODE_OF_CONDUCT.md).
- Found a vulnerability in Mir[AI]ge itself? Please follow [SECURITY.md](SECURITY.md)
  instead of opening a public issue.

## Getting set up

```bash
git clone https://github.com/Kylian14/miraige.git
cd miraige
cp .env.example .env
docker compose up --build -d   # runs fully offline, no credentials needed
```

No cloud account or API key is required for development — the stack defaults to
`SENTINEL_STUB=1` (heuristic detection) and `REROUTE_BACKEND=mock` (mocked reroute).

## Making a change

1. Fork and create a branch: `git checkout -b feat/short-description`.
2. Keep changes focused. Match the style of the surrounding code.
3. Run a smoke test before opening a PR:
   ```bash
   docker compose up --build -d
   curl -sf localhost:8000/api/v1/health   # the console reports every internal agent's health
   python3 -m services.attack_simulator.attack --target http://localhost:8080 --level naive-full --duration 30
   ```
4. Run the linter if you have it: `ruff check services/`.
5. Open a PR describing **what** changed and **why**. Link any related issue.

## Adding a compute-wasting mechanism

Mechanisms live in `services/ghost_shell/`. A new one should:

- Cost the attacker's LLM far more than it costs us to serve (keep generation O(n)).
- Be tracked so it shows up in the dashboard's mechanism view.
- Be documented in the PR with the asymmetry rationale.

## Commit messages

Short imperative subject lines (`ghost: add vector-magnet endpoint`). Reference issues
where relevant.
