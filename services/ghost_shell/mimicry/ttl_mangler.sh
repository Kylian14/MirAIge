#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# Anti « Time-to-Lie » · force le TTL sortant par persona
# ─────────────────────────────────────────────────────────────────────
# Le TTL ICMP/IP révèle le nombre de hops réels => trahit un honeypot
# (Time-to-Lie, arXiv 2410.17731 : 8000+ honeypots ICS détectés via TTL).
# On fixe un TTL cohérent avec l'OS revendiqué (Linux = 64) pour chaque IP
# persona, indépendamment du routage interne du conteneur. Réf : ADR-014/018.
#
# Requiert CAP_NET_ADMIN + module noyau xt_HL. Idempotent.
# Usage : sudo ./ttl_mangler.sh up | down
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

# ip ttl  (toutes les personas = Linux => 64 ; cohérence + masque les hops réels)
ROWS=(
  "10.42.0.11 64"
  "10.42.0.12 64"
  "10.42.0.13 64"
  "10.42.0.14 64"
)

need_root() { [ "$(id -u)" -eq 0 ] || { echo "!! root / CAP_NET_ADMIN requis" >&2; exit 1; }; }

add_rule() {
  iptables -t mangle -C POSTROUTING -s "$1" -j TTL --ttl-set "$2" 2>/dev/null \
    || iptables -t mangle -A POSTROUTING -s "$1" -j TTL --ttl-set "$2"
}
del_rule() {
  iptables -t mangle -D POSTROUTING -s "$1" -j TTL --ttl-set "$2" 2>/dev/null || true
}

case "${1:-up}" in
  up)   need_root; for r in "${ROWS[@]}"; do add_rule $r; echo "TTL set $r"; done ;;
  down) need_root; for r in "${ROWS[@]}"; do del_rule $r; done; echo "règles TTL retirées" ;;
  *) echo "usage: $0 up|down" >&2; exit 1 ;;
esac
