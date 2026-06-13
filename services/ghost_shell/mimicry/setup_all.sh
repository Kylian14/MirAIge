#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# Orchestrateur des mitigations P0 du Ghost Shell
# ─────────────────────────────────────────────────────────────────────
# Enchaîne, dans l'ordre, les 4 défenses anti-fingerprint à déployer sur
# l'instance miraige-ghost-vm :
#   P0.1  netns par persona      (netns_setup.sh)
#   --    TTL cohérent par IP     (ttl_mangler.sh)
#   P0.2  certs TLS distincts     (tls_personas.py)
#   P0.3  zones DNS distinctes    (coredns_zones/, si coredns présent)
# Idempotent. Requiert root / CAP_NET_ADMIN. Réf : README.md, ADR-018.
#
# Usage : sudo ./setup_all.sh up | down | check
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PYTHON:-python3}"

need_root() { [ "$(id -u)" -eq 0 ] || { echo "!! root / CAP_NET_ADMIN requis" >&2; exit 1; }; }

check_prereq() {
  local ok=1
  for bin in ip iptables openssl "$PY"; do
    command -v "$bin" >/dev/null 2>&1 || { echo "  ✗ manque: $bin"; ok=0; }
  done
  modprobe xt_HL 2>/dev/null || true
  command -v coredns >/dev/null 2>&1 || echo "  ⚠ coredns absent — P0.3 (DNS) à lancer séparément"
  [ "$ok" -eq 1 ] || { echo "!! prérequis manquants" >&2; exit 1; }
}

up() {
  need_root; check_prereq
  echo "[1/4] P0.1 netns…";  bash "$HERE/netns_setup.sh" up
  echo "[2/4] TTL…";          bash "$HERE/ttl_mangler.sh" up
  echo "[3/4] P0.2 certs TLS…"; "$PY" "$HERE/tls_personas.py"
  echo "[4/4] P0.3 CoreDNS…"
  if command -v coredns >/dev/null 2>&1; then
    ( cd "$HERE/coredns_zones" && coredns -conf Corefile >/tmp/miraige-coredns.log 2>&1 & )
    echo "  coredns lancé (log: /tmp/miraige-coredns.log)"
  else
    echo "  (skip — coredns non installé)"
  fi
  echo "✅ stack P0 up. Vérif : sudo ./setup_all.sh check"
}

down() {
  need_root
  bash "$HERE/ttl_mangler.sh" down || true
  bash "$HERE/netns_setup.sh" down || true
  pkill -f "coredns -conf Corefile" 2>/dev/null || true
  echo "✅ stack P0 down."
}

check() {
  echo "── netns ──"; ip netns list 2>/dev/null || echo "  (aucun)"
  echo "── TTL (mangle POSTROUTING) ──"; iptables -t mangle -S POSTROUTING 2>/dev/null | grep -i ttl || echo "  (aucune règle)"
  echo "── certs TLS ──"; ls -1 "$HERE"/certs/*.crt 2>/dev/null || echo "  (aucun cert)"
  echo "── DNS (SOA distincts ?) ──"
  for z in portal.miraige.lab k8s.miraige.lab; do
    printf "  %s : " "$z"; dig @127.0.0.1 "$z" SOA +short 2>/dev/null | head -1 || echo "n/a"
  done
}

case "${1:-check}" in
  up) up ;; down) down ;; check) check ;;
  *) echo "usage: $0 up|down|check" >&2; exit 1 ;;
esac
