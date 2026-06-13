#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# P0.1 · un network namespace par persona => stack TCP/IP indépendante
# ─────────────────────────────────────────────────────────────────────
# (ISN, pool de ports source, ARP, sysctls). Sans ça, toutes les personas
# partagent le même kernel => MÊME signature Nmap -O et MÊME allocation de
# ports source observable en <2 min. Réf : ADR-018, stress-test-findings.md §2.
#
# Topologie : un bridge miraige-br0 (10.42.0.1/24) ; chaque persona vit dans
# son netns avec son IP (10.42.0.11-14), reliée au bridge par une paire veth.
# On varie tcp_timestamps / window_scaling / rmem_max par persona => les
# fingerprints passifs (p0f) et actifs (Nmap -O) diffèrent réellement.
#
# Requiert CAP_NET_ADMIN (root, ou conteneur lancé --cap-add=NET_ADMIN).
# Usage : sudo ./netns_setup.sh up | down | status
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

BR=miraige-br0
GW=10.42.0.1

# persona | netns | ip | veth_host | tcp_timestamps | tcp_window_scaling | rmem_max
PERSONAS=(
  "portal miraige-ns-portal 10.42.0.11 vth-portal 1 1 6291456"
  "mysql  miraige-ns-mysql  10.42.0.12 vth-mysql  1 0 4194304"
  "k8s    miraige-ns-k8s    10.42.0.13 vth-k8s    0 1 8388608"
  "admin  miraige-ns-admin  10.42.0.14 vth-admin  1 1 3145728"
)

need_root() { [ "$(id -u)" -eq 0 ] || { echo "!! root / CAP_NET_ADMIN requis" >&2; exit 1; }; }

ensure_bridge() {
  if ! ip link show "$BR" >/dev/null 2>&1; then
    ip link add "$BR" type bridge
    ip addr add "${GW}/24" dev "$BR"
    ip link set "$BR" up
    echo "+ bridge $BR (${GW}/24)"
  fi
}

up_one() {
  local p=$1 ns=$2 ip=$3 vh=$4 ts=$5 ws=$6 rmem=$7
  local vn="${vh}-ns"
  if ip netns list 2>/dev/null | grep -qw "$ns"; then echo "= $ns déjà présent"; return; fi
  ip netns add "$ns"
  ip link add "$vh" type veth peer name "$vn"
  ip link set "$vh" master "$BR"; ip link set "$vh" up
  ip link set "$vn" netns "$ns"
  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip addr add "${ip}/24" dev "$vn"
  ip netns exec "$ns" ip link set "$vn" up
  ip netns exec "$ns" ip route add default via "$GW"
  # Stack TCP distincte par persona :
  ip netns exec "$ns" sysctl -qw net.ipv4.ip_default_ttl=64        >/dev/null
  ip netns exec "$ns" sysctl -qw net.ipv4.tcp_timestamps="$ts"     >/dev/null
  ip netns exec "$ns" sysctl -qw net.ipv4.tcp_window_scaling="$ws" >/dev/null
  ip netns exec "$ns" sysctl -qw net.core.rmem_max="$rmem"         >/dev/null
  echo "+ $ns ($ip) ts=$ts ws=$ws rmem=$rmem"
}

down_all() {
  for row in "${PERSONAS[@]}"; do
    set -- $row
    ip netns del "$2" 2>/dev/null || true
    ip link  del "$4" 2>/dev/null || true
  done
  ip link del "$BR" 2>/dev/null || true
  echo "netns + bridge supprimés"
}

case "${1:-status}" in
  up)     need_root; ensure_bridge; for row in "${PERSONAS[@]}"; do up_one $row; done ;;
  down)   need_root; down_all ;;
  status) echo "netns:"; ip netns list 2>/dev/null || echo "  (aucun)" ;;
  *) echo "usage: $0 up|down|status" >&2; exit 1 ;;
esac
