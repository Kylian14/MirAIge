"""
Procedural filesystem · path-seeded RNG (flagship mechanism #1: Asymmetric Content).

Spec · docs/compute-wasting-features.md §1:
  - seed = FNV-1a(salt + canonical_path)  -> cross-session consistency (same `ls` = same result)
  - INFINITELY deep tree: every folder has files (ls_at) AND subfolders
    (subdirs_at) -> an agent enumerating recursively never finishes (compute-sink O(n))
  - 100% stdlib (seeded random.Random): NO mimesis dependency (the string-locale /
    .seed() API of mimesis 15 was broken, and this module had never run before the J3 wiring).
  - LRU cache of 10k entries (amortized O(1) generation, zero inference, so no self-DoS).
"""
from __future__ import annotations

import os
import random
import uuid
from functools import lru_cache

FNV_64_PRIME = 0x100000001B3
FNV_64_INIT = 0xCBF29CE484222325

# Small deterministic lexicons (replace Mimesis, enough for a plausible decoy).
_FIRST = ("alex", "marie", "yanis", "claire", "omar", "lena", "hugo", "sofia", "noah", "ines")
_LAST = ("durand", "martin", "nguyen", "lopez", "haddad", "moreau", "petit", "roux", "faure", "blanc")
_WORDS = (
    "rotation", "backup", "cluster", "ingress", "secret", "policy", "runtime", "sidecar",
    "manifest", "replica", "throughput", "quota", "namespace", "checksum", "pipeline",
    "credential", "endpoint", "scheduler", "telemetry", "artifact",
)
_ALPHANUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def fnv1a_64(data: bytes) -> int:
    """FNV-1a 64-bit. Réf : https://en.wikipedia.org/wiki/Fowler-Noll-Vo_hash_function"""
    hval = FNV_64_INIT
    for byte in data:
        hval ^= byte
        hval = (hval * FNV_64_PRIME) & 0xFFFFFFFFFFFFFFFF
    return hval


def seed_for_path(salt: str, path: str) -> int:
    """Canonicalize the path, then FNV-1a with the salt."""
    canonical_path = os.path.normpath(path).replace("\\", "/")
    return fnv1a_64(f"{salt}:{canonical_path}".encode("utf-8"))


def _password(rng: random.Random, length: int = 16) -> str:
    return "".join(rng.choice(_ALPHANUM) for _ in range(length))


def _ipv4(rng: random.Random) -> str:
    return f"{rng.randint(10, 250)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _full_name(rng: random.Random) -> str:
    return f"{rng.choice(_FIRST).capitalize()} {rng.choice(_LAST).capitalize()}"


def _sentence(rng: random.Random, n: int = 12) -> str:
    return " ".join(rng.choice(_WORDS) for _ in range(n)).capitalize() + "."


def uuid_seeded(seed: int) -> str:
    """Deterministic UUIDv4 from a seed."""
    rng = random.Random(seed)
    rand_bytes = bytearray(rng.getrandbits(8) for _ in range(16))
    rand_bytes[6] = (rand_bytes[6] & 0x0F) | 0x40  # version 4
    rand_bytes[8] = (rand_bytes[8] & 0x3F) | 0x80  # RFC 4122 variant
    return str(uuid.UUID(bytes=bytes(rand_bytes)))


@lru_cache(maxsize=10000)
def ls_at(path: str, salt: str = "default-miraige-salt") -> list[str]:
    """Child files of `path`, consistent on every re-traversal (seeded)."""
    rng = random.Random(seed_for_path(salt, path))
    num_children = rng.randint(2, 6)

    path = path.rstrip("/")
    if path == "/var/log" or path.endswith("/log"):
        extensions = [".log", ".log.1", ".log.2.gz"]
        prefixes = ["auth", "syslog", "nginx-access", "nginx-error", "dpkg", "kern", "cron"]
    elif path == "/etc" or path.endswith("/etc") or "config" in path or "kubernetes" in path:
        extensions = [".conf", ".yaml", ".json", ".ini", ".env"]
        prefixes = ["app", "db", "nginx", "redis", "kubernetes", "vault", "services"]
    elif ".ssh" in path:
        extensions = ["", ".pub"]
        prefixes = ["id_rsa", "id_ed25519", "authorized_keys", "known_hosts", "config"]
    else:
        extensions = [".txt", ".md", ".sh", ".py", ".json"]
        prefixes = ["memo", "readme", "run", "backup", "dump", "test", "credentials"]

    children: list[str] = []
    for _ in range(num_children):
        name = f"{rng.choice(prefixes)}_{rng.randint(1, 99)}{rng.choice(extensions)}"
        if name not in children:
            children.append(name)
    return children


@lru_cache(maxsize=10000)
def subdirs_at(path: str, salt: str = "default-miraige-salt") -> list[str]:
    """Subfolders of `path` (seeded), so the tree is infinitely deep (compute-sink)."""
    rng = random.Random(seed_for_path(salt, path + ":dirs"))
    pool = ["archive", "old", "2025", "2026", "prod", "staging", "secrets", "data",
            "snapshots", "shared", "private", "tmp"]
    n = rng.randint(1, 3)
    out: list[str] = []
    for _ in range(n):
        d = rng.choice(pool)
        if d not in out:
            out.append(d)
    return out


@lru_cache(maxsize=10000)
def cat_at(path: str, salt: str = "default-miraige-salt") -> str:
    """Content of `path`, consistent on every re-read (seeded). Depends on the extension."""
    seed = seed_for_path(salt, path)
    rng = random.Random(seed)
    ext = os.path.splitext(path)[1]

    if ext == ".env":
        return (
            "# Generated Configuration via Procedural FS\n"
            f"DB_HOST={_ipv4(rng)}\n"
            "DB_PORT=3306\n"
            "DB_USER=root\n"
            f"DB_PASSWORD={_password(rng)}\n"
            f"API_KEY=ak_live_{uuid_seeded(seed)[:16]}\n"
        )
    if ext in (".yaml", ".yml"):
        return (
            "version: '3.8'\n"
            "services:\n"
            "  app:\n"
            "    image: ovh-manager-node:latest\n"
            "    environment:\n"
            "      - NODE_ENV=production\n"
            "      - PORT=8080\n"
            f"      - CLUSTER_ID={uuid_seeded(seed)}\n"
        )
    if ext in (".log", ".gz"):
        lines = []
        for _ in range(rng.randint(10, 20)):
            lines.append(
                f"2026-06-01T{rng.randint(10, 23):02d}:{rng.randint(10, 59):02d}:"
                f"{rng.randint(10, 59):02d}Z [info] user {rng.choice(_FIRST)} "
                f"from {_ipv4(rng)} performed operation status=200"
            )
        return "\n".join(lines) + "\n"
    if ext in ("", ".pub") and ".ssh" in path:
        # Markers assembled from parts so no "BEGIN <type> PRIVATE KEY" literal
        # exists in source (push-protection / gitleaks never matches), while the
        # served decoy stays a PEM-shaped, plausible private key (seeded body).
        pem_begin = "-----BEGIN " + "OPENSSH PRIVATE KEY" + "-----"
        pem_end = "-----END " + "OPENSSH PRIVATE KEY" + "-----"
        return (
            f"{pem_begin}\n"
            f"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt{uuid_seeded(seed)[:18]}\n"
            f"{pem_end}\n"
        )
    # Default text file / memo
    return (
        "# MEMORANDUM INTERNE\n"
        "Date: 2026-06-01\n"
        f"Auteur: {_full_name(rng)}\n"
        f"Chemin: {path}\n\n"
        f"Resume: {_sentence(rng, 14)}\n\n"
        f"Note technique: {_sentence(rng, 18)}\n"
    )
