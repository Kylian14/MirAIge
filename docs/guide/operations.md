# Operations

How to deploy, harden, and run Mir[AI]ge. For the variables referenced here see
[Configuration](configuration.md).

## Single host (Docker Compose)

The fastest path is the guided installer. It checks Docker, generates strong
secrets into `.env`, turns on `MG_STRICT_SECRETS=1`, and starts the stack:

```bash
sh deploy/install.sh
```

Or do it by hand:

```bash
cp .env.example .env          # runs as-is; edit secrets before exposing
docker compose up --build -d
```

The console is then at `http://localhost:8000`.

## Network model & overlays

By default only the user-facing surfaces are published to the host: the console
(`:8000`), the protected portal (`:8090`), and the decoy (`:8080`). The
control-plane (`sentinel`, `orchestrator`, `mcp_server`, `mirage_metrics`,
`redis`) is network-internal; the console aggregates all of it under `/api/v1`.

| Overlay | Effect |
|---------|--------|
| _(base)_ `docker-compose.yml` | Public surfaces published; control-plane internal. |
| `docker-compose.prod.yml` | Hardening: every service except the API closed, console bound to `127.0.0.1`, `MG_STRICT_SECRETS=1`, restart policies. Put a TLS proxy in front. |
| `docker-compose.dev.yml` | Re-publishes the internal control-plane ports (`:8001` to `:8004`, Redis) for low-level debugging. |

```bash
# production hardening
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
# debugging (re-open internal ports)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

## TLS / reverse proxy

The console listens on plain HTTP; terminate TLS in front of it. Either point an
existing proxy at `127.0.0.1:8000` (drop-in configs for nginx, Caddy, Traefik
and HAProxy in [`deploy/proxy/snippets/`](../../deploy/proxy/snippets)), or add a
bundled overlay:

```bash
BASE="-f docker-compose.yml -f docker-compose.prod.yml"
docker compose $BASE -f deploy/proxy/caddy.yml   up -d   # auto-HTTPS (also localhost)
docker compose $BASE -f deploy/proxy/nginx.yml   up -d   # HTTP; mount certs for TLS
MIRAIGE_DOMAIN=app.example.com \
  docker compose $BASE -f deploy/proxy/traefik.yml up -d # auto-HTTPS (public domain)
```

## Secrets

Set these before any public deploy (the installer does it for you):
`DASHBOARD_PASSWORD`, `A2A_SHARED_SECRET`, `SECRET_SALT`, optionally
`DASHBOARD_TOKEN_SECRET` and `MG_RESET_SECRET`. Turn on `MG_STRICT_SECRETS=1` so a
leftover default makes the owning service fail to start. A default value (or any
`change-me…` placeholder) is detected and rejected.

```bash
openssl rand -hex 24    # generate one
```

## Scaling & resilience

With `ORCHESTRATOR_STATE_BACKEND=redis` (the compose default) engagement state
lives in Redis, so the orchestrator is crash-safe (a restart keeps live
engagements) and you can run more than one instance behind the BFF. Resuming an
FSM that was interrupted mid-flight is not yet automatic. See
[Architecture → State persistence](architecture.md#decision-the-orchestrator-state-machine).

## Cloud-free enforcement (no LB API)

To protect an **unmodified** upstream without any cloud load balancer, use the
Redis-flag backend plus the bundled inline reverse proxy:

```bash
REROUTE_BACKEND=redis
# then run the proxy in deploy/proxy/inline/ in front of your upstream
```

Flagged sessions/IPs are routed to the Ghost Shell, mirrored to the Sentinel, and
met with always-on canary traps. See the README's
[inline-proxy section](../../README.md#cloud-free-reroute-on-any-host-inline-proxy).

## Kubernetes (Helm)

A chart lives in [`deploy/helm/miraige`](../../deploy/helm/miraige); the console
is the only service exposed (an Ingress), everything else is a ClusterIP Service.
The images are not on a public registry yet: publish them and set
`image.registry`. See the [chart README](../../deploy/helm/miraige/README.md).

```bash
helm install miraige deploy/helm/miraige \
  --set image.registry=ghcr.io/you \
  --set secrets.DASHBOARD_PASSWORD=$(openssl rand -hex 24) \
  --set ingress.host=miraige.example.com
```

## Maintenance

- Reset demo state across all agents with `POST /api/v1/admin/reset` (operator
  role).
- Tail logs with `docker compose logs -f <service>`.
- Stop the stack with `docker compose down` (add `-v` to drop the Redis volume).
