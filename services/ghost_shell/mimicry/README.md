# Ghost Shell · mimicry P0 (anti-fingerprint)

> Sans ces mitigations, le Ghost Shell single-container est **détectable en
> <2 min** par un LLM agent basique faisant `nmap -O + JARM + dig`.
> Réfs : Bitter Harvest (WOOT'18), Time-to-Lie (arXiv 2410.17731).

Les 4 personas (`portal_ovh`, `mysql`, `k8s_apiserver`, `admin_panel`) sont
définies dans [`persona_catalog.yaml`](persona_catalog.yaml) — **source de
vérité** (IP, netns, TTL, profil TLS, zone DNS cohérents par persona).

## Les mitigations

| Fichier | Vecteur défendu | Mécanisme |
|---|---|---|
| `netns_setup.sh` | **P0.1** — stack TCP identique (Nmap -O, source-ports) | 1 netns + veth par persona, sysctls TCP variés |
| `tls_personas.py` | **P0.2** — JARM/JA3S identique sur tous les vhosts | versions TLS + ordre suites + ALPN + émetteur distincts |
| `coredns_zones/` | **P0.3** — SOA/TTL/NS identiques (`dig`) | une zone CoreDNS par persona, serials/NS/TTL distincts |
| `ttl_mangler.sh` | TTL ICMP révèle les hops réels (Time-to-Lie) | iptables MANGLE, TTL=64 cohérent par IP persona |

## Prérequis

- `CAP_NET_ADMIN` (root, ou conteneur `--cap-add=NET_ADMIN`) pour netns + iptables
- module noyau `xt_HL` (cible iptables `TTL`)
- `openssl` (génération des certs), `coredns` (zones DNS)

## Ordre de mise en place

```sh
sudo ./netns_setup.sh up          # P0.1 : namespaces + bridge miraige-br0
sudo ./ttl_mangler.sh up          # TTL cohérent par persona
python tls_personas.py            # P0.2 : génère les certs dans certs/
coredns -conf coredns_zones/Corefile   # P0.3 : DNS autoritatif par persona
./netns_setup.sh status           # vérif
```

## Validation (le spike Dev A)

```sh
# P0.1 — stacks distinctes :
sudo ip netns exec miraige-ns-portal nmap -O 10.42.0.13   # doit voir un "autre host"
# P0.2 — JARM distincts (jarm.py / fingerprintls) entre :11 / :13 / :14
# P0.3 — SOA distincts :
dig @127.0.0.1 portal.miraige.lab SOA +short
dig @127.0.0.1 k8s.miraige.lab SOA +short
```

## Teardown

```sh
sudo ./ttl_mangler.sh down
sudo ./netns_setup.sh down
```

> ⚠️ Ces scripts sont la **recette** validée ; certains ajustements selon
> l'hôte/conteneur (capabilities, `xt_HL` dispo) sont à confirmer sur votre
> instance cible.
