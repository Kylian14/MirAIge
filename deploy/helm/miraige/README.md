# Mir[AI]ge Helm chart

Deploys the full stack on Kubernetes. The console (BFF) is the **only** public
surface — via an Ingress; every other service stays in-cluster.

> ⚠ The images aren't on a public registry yet. Publish each
> `services/<name>/Dockerfile` as `<registry>/miraige-<name>:<tag>` first, then
> point `image.registry` at it.

```bash
helm install miraige deploy/helm/miraige \
  --set image.registry=ghcr.io/you \
  --set secrets.DASHBOARD_PASSWORD=$(openssl rand -hex 24) \
  --set secrets.A2A_SHARED_SECRET=$(openssl rand -hex 24) \
  --set secrets.SECRET_SALT=$(openssl rand -hex 24) \
  --set ingress.host=miraige.example.com
```

Render it locally without a cluster: `helm template rel deploy/helm/miraige`.

## Key values

| Key | Default | Notes |
|---|---|---|
| `image.registry` / `image.tag` | `ghcr.io/kylian14` / `0.1.0` | where the images live |
| `config.REROUTE_BACKEND` | `mock` | `mock` \| `octavia` \| `redis` |
| `config.ORCHESTRATOR_STATE_BACKEND` | `redis` | engagement-state backend |
| `config.AUTH_BACKEND` | `local` | console auth (`oidc` reserved) |
| `secrets.*` | `change-me-*` | **override before exposing** |
| `redis.enabled` | `true` | bundled Redis (disable + set `config.REDIS_URL` to BYO) |
| `ingress.enabled` / `ingress.host` | `true` / `miraige.local` | the public console |

Each compose service maps to one Deployment + ClusterIP Service; underscored names
become hyphenated (`mcp_server` → `mcp-server`), and the in-cluster URLs in
`config` already account for that.
