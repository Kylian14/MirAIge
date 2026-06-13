# Development & testing

The contribution workflow (fork, branch, smoke test, PR, commit style, adding a
mechanism) lives in [CONTRIBUTING.md](../../CONTRIBUTING.md). This page is the
reference for the **dev environment and the test suite**.

## Run the stack for development

```bash
cp .env.example .env
docker compose up --build -d        # fully offline: SENTINEL_STUB=1, REROUTE_BACKEND=mock
```

No cloud account or API key is needed. Reach the control-plane agents (internal
by default) for debugging by adding `-f docker-compose.dev.yml`, or just read
everything through the console at `:8000`.

## Run the test suite

The suite is pure-Python and offline, with no Docker, no network, and no cloud:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest                    # pytest.ini sets testpaths=tests, asyncio_mode=auto
```

It is **hermetic by design**: outbound URLs point nowhere, Redis is faked, and no
LLM key is used, so the same run is reproducible anywhere and must stay green on
every change. A few tests self-skip when an optional tool is absent (for example,
the Helm render/lint tests skip without the `helm` binary).

What the suites cover (`tests/`):

| Area | Example suites |
|------|----------------|
| Detection & flows | `test_sentinel*`, classifier/cascade behaviour |
| Orchestrator | `test_orchestrator`, `test_orchestrator_store` (memory + redis backends) |
| Reroute backends | `test_lb_adapter_contract` (mock / octavia / redis) |
| Ghost Shell | `test_ghost_shell` and the mechanism modules |
| BFF / API | `test_bff_api`, `test_api_rbac`, `test_api_users` |
| CLI & attacker | `test_cli`, `test_attack_simulator` |
| Packaging | `test_helm_chart` (structure always; render/lint when `helm` is present) |

## Continuous integration

[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) runs on every push and
pull request:

1. **Lint**: `ruff check services/` (advisory for now).
2. **Test**: the pytest suite on Python 3.12.
3. **Stack smoke**: builds and starts the stack, waits for health, and runs an
   end-to-end attack in offline stub mode.

## Code style

- Many small, focused files; match the surrounding style.
- Keep new deception content generation **O(n)**: the whole point is that the
  attacker, not the defender, pays. See
  [CONTRIBUTING → Adding a compute-wasting mechanism](../../CONTRIBUTING.md#adding-a-compute-wasting-mechanism)
  and the [mechanisms catalog](mechanisms.md).
