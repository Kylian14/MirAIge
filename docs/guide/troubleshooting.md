# Troubleshooting

Common symptoms and what they usually mean. For the variables mentioned see
[Configuration](configuration.md).

## A service won't start (exits immediately)

Almost always `MG_STRICT_SECRETS=1` plus a leftover default/placeholder secret:
the service refuses to run with an unsafe secret. The log names the variable. Set
a real value for `DASHBOARD_PASSWORD`, `A2A_SHARED_SECRET`, `SECRET_SALT` (and
`MG_RESET_SECRET` if you set it). `sh deploy/install.sh` generates them for you.

## `http://localhost:8001…8004` refuses the connection

**By design.** The control-plane (sentinel, orchestrator, mcp_server,
mirage_metrics, Redis) is network-internal; only the console (`:8000`), portal
(`:8090`) and decoy (`:8080`) are published. Read everything through the console's
`/api/v1`, or re-open the ports for debugging with
`-f docker-compose.dev.yml`.

## API calls fail

| Status | Meaning | Fix |
|--------|---------|-----|
| **401** | No/invalid/expired bearer token. | Log in again (`POST /api/v1/login`); tokens expire after `MIRAIGE_TOKEN_TTL_S`. |
| **403** | Your role is below what the endpoint needs. | Use an account with the right role (viewer < operator < admin). |
| **409** on `/users` | The user store isn't file-backed. | Set `MIRAIGE_USERS_FILE` to a mounted, writable `users.json`. |
| **429** on `/attacks` | Too many concurrent runs. | Wait or stop a run. |
| **502** | A backend agent is unreachable. | `docker compose ps` / `logs <service>`; the agent is down or still starting. |

## I launched an attack but no engagement appears

- Low-signal levels (e.g. `apt`) may stay **below the confidence gate** (0.75) on
  purpose: no decoy is spun up for a maybe. Watch the **Detection** page to see
  what each tier did, and try a louder level (`noisy`) to confirm the pipeline.
- In stub mode (`SENTINEL_STUB=1`) only T0/T1 run; that's expected and still
  enough for the full demo.

## The console doesn't update live

The SPA reads `GET /api/v1/stream`; if the stream drops it falls back to a ~20 s
poll, so data still refreshes, just slower. Check the stream is reachable and the
token is valid. A reverse proxy in front must allow streaming responses
(disable response buffering for `/api/v1/stream`).

## Helm pods stay in `ImagePullBackOff`

The images aren't on a public registry yet. Build and push
`services/<name>/Dockerfile` as `<registry>/miraige-<name>:<tag>`, then
`--set image.registry=<your-registry>`. See the
[chart README](../../deploy/helm/miraige/README.md).

## Reset between runs

`POST /api/v1/admin/reset` (operator) clears engagements and detection state
across all agents.
