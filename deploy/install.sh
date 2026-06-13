#!/bin/sh
# Mir[AI]ge — guided single-host installer (provider-agnostic).
#
# Brings the whole stack up on ANY Docker host: checks prerequisites, generates
# strong secrets into .env (and turns on MG_STRICT_SECRETS=1), then starts it.
# No cloud account required — REROUTE_BACKEND defaults to "mock".
#
#   sh deploy/install.sh                       # interactive
#   MG_NONINTERACTIVE=1 sh deploy/install.sh   # no prompts (cloud-init / CI)
#
set -eu

# ── locate the repo root (this script lives in deploy/) ──────────────
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$ROOT"

COMPOSE_FILE=${MG_COMPOSE_FILE:-docker-compose.yml}

say()  { printf '\033[1;34m[miraige]\033[0m %s\n' "$1"; }
die()  { printf '\033[1;31m[miraige]\033[0m %s\n' "$1" >&2; exit 1; }

# ── 1. prerequisites ─────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 \
  || die "Docker not found. Install it: https://docs.docker.com/engine/install/"
if docker compose version >/dev/null 2>&1; then
  DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DC="docker-compose"
else
  die "Docker Compose v2 not found (need the 'docker compose' plugin)."
fi
docker info >/dev/null 2>&1 \
  || die "Docker daemon unreachable (running? need sudo / the 'docker' group?)."
say "Docker OK ($DC)."

# ── 2. strong secret generation ──────────────────────────────────────
gen_secret() {
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex 24
  else head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'; fi
}

# set KEY=VALUE in a .env file: rewrite an existing (or commented) line, else append.
set_kv() {
  _f=$1; _k=$2; _v=$3
  if grep -qE "^#? *${_k}=" "$_f" 2>/dev/null; then
    _tmp=$(mktemp)
    sed "s|^#\{0,1\} *${_k}=.*|${_k}=${_v}|" "$_f" > "$_tmp" && mv "$_tmp" "$_f"
  else
    printf '%s=%s\n' "$_k" "$_v" >> "$_f"
  fi
}

# ── 3. .env (generated once) ─────────────────────────────────────────
if [ -f .env ]; then
  say ".env already exists — keeping it (delete it to regenerate secrets)."
else
  [ -f .env.example ] || die ".env.example missing — run this from the repo root."
  cp .env.example .env
  say "Generating strong secrets into .env ..."
  for k in DASHBOARD_PASSWORD A2A_SHARED_SECRET SECRET_SALT MG_RESET_SECRET DASHBOARD_TOKEN_SECRET; do
    set_kv .env "$k" "$(gen_secret)"
  done
  set_kv .env MG_STRICT_SECRETS 1
  say "Secrets written; MG_STRICT_SECRETS=1 (services hard-fail on a default secret)."
fi

# ── 4. bring up the stack ────────────────────────────────────────────
say "Building and starting the stack (the first run compiles the images) ..."
# shellcheck disable=SC2086
$DC -f "$COMPOSE_FILE" up --build -d

# ── 5. summary ───────────────────────────────────────────────────────
DASH_PW=$(grep -E '^DASHBOARD_PASSWORD=' .env | head -1 | cut -d= -f2-)
PORTAL_PORT=$(grep -E '^PORTAL_HOST_PORT=' .env 2>/dev/null | head -1 | cut -d= -f2- || true)
PORTAL_PORT=${PORTAL_PORT:-8090}
say "Stack is up."
cat <<EOF

  Console (SOC)           : http://localhost:8000   password: ${DASH_PW}
  Protected demo portal   : http://localhost:${PORTAL_PORT}
  Ghost Shell decoy       : http://localhost:8080

  Reroute backend : mock  (set REROUTE_BACKEND=octavia in .env for a real Octavia LB)
  Production      : docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
  + TLS proxy     : append -f deploy/proxy/caddy.yml  (or nginx.yml / traefik.yml)
  Stop everything : ${DC} down

  Save the console password above — it lives in .env (git-ignored).
EOF
