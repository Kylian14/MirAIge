# API reference

The BFF (`api` service) is the single authenticated surface. It serves the SPA at
`/` and the JSON API under `/api/v1`, and proxies the read surface of the internal
agents so they never need to be exposed. Base URL in the default compose:
`http://localhost:8000`.

## Authentication & roles

Log in with a username and password to receive a bearer token, then send it as
`Authorization: Bearer <token>` on every protected call.

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"…"}' | jq -r .token)

curl -s http://localhost:8000/api/v1/stats -H "Authorization: Bearer $TOKEN"
```

`POST /api/v1/login` accepts `{username, password}`; a blank/omitted username maps
to `admin` (back-compatible with the old single-password login). It returns
`{token, username, role}`. Tokens are signed (HMAC) and carry the role + an
expiry (`MIRAIGE_TOKEN_TTL_S`, default 12 h).

Three roles, ordered **viewer < operator < admin**:

| Role | Can |
|------|-----|
| `viewer` | read everything in the console |
| `operator` | + launch/stop red-team runs, reset demo state |
| `admin` | + manage users |

A call below the required role returns **403**; a missing/invalid token returns
**401**.

## Endpoints

### Public

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/login` | Exchange credentials for a bearer token. |
| `GET` | `/api/v1/health` | Liveness + reachability of each backend agent. |

### Read surface: `viewer`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/me` | The caller's `{username, role}`. |
| `GET` | `/api/v1/stats` | Sentinel detection counters. |
| `GET` | `/api/v1/flows` | Recent classified flows. |
| `GET` | `/api/v1/sessions/{src_ip}` | Per-source-IP detection state. |
| `GET` | `/api/v1/tier-trace/{key}` | The cascade trace (T0→T1→T2) for one key. |
| `GET` | `/api/v1/incidents` | Active engagements (orchestrator state). |
| `GET` | `/api/v1/incidents/{request_id}` | One engagement in detail. |
| `GET` | `/api/v1/metrics` | Current attrition metrics (tokens burned, sessions…). |
| `GET` | `/api/v1/metrics/agents` | Per-agent token usage. |
| `GET` | `/api/v1/stream` | Live stream. NDJSON, one `{stats, metrics, incidents}` snapshot per interval (`API_STREAM_INTERVAL_S`) until the client disconnects. The SPA consumes it instead of polling. |

### Red team: `operator`

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/attacks` | Launch a calibrated run: `{level, duration, rps?}`. |
| `GET` | `/api/v1/attacks` | List runs (live + recently finished). |
| `POST` | `/api/v1/attacks/{run_id}/stop` | Stop a running run (SIGTERM). |
| `GET` | `/api/v1/attacks/{run_id}/logs` | Tail a run's output. |
| `POST` | `/api/v1/admin/reset` | Reset demo state across all agents. |

`level` is one of the calibrated levels: `noisy`, `evasive`, `stealth`,
`ai-agent`, `apt`, `naive-full`, `hardened-agent`, `apt-bypass`. See
[The attack simulator](../../README.md#the-attack-simulator).

### User management: `admin`

Available only when a file-backed user store is configured (`MIRAIGE_USERS_FILE`);
otherwise these return **409**.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/users` | List users `{username, role}` (never secrets) + whether the store is editable. |
| `POST` | `/api/v1/users` | Create `{username, role, password}`. |
| `PATCH` | `/api/v1/users/{username}` | Change `{role?, password?}`. |
| `DELETE` | `/api/v1/users/{username}` | Remove a user. |

Guard rails: the last `admin` cannot be demoted or deleted, and an admin cannot
delete their own account.

## Errors

Standard HTTP status codes; the body is `{"detail": "<message>"}`. Notable cases:
**401** (unauthenticated / bad token), **403** (role too low), **404** (unknown
resource), **409** (user store not file-backed), **429** (too many concurrent
attacks), **502** (a backend agent is unreachable).
