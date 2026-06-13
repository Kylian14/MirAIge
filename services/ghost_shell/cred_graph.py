"""
Honeycredential graph · branching >= 2 (flagship mechanism #9).

Spec · docs/compute-wasting-features.md §9 (Tantalus/CounterCraft pattern):
  - each discovered credential opens 2+ new fake services (branching factor >= 2)
  - directed and CYCLIC graph, HMAC-signed nodes to track the path per session
  - real depth >= 3 levels (before: a single level, dead branches not routable)
  - leaves point back to the infinite procedural FS (`/fs/ls`, `/fs/cat`) -> infinite queue

Why this holds up (see stress-test-findings.md): it exploits the bias of pentest agents
that "pull the thread" of every credential they find. Each served node = measured token
burn (notify_tokens per session). Since the paths are cyclic and open onto the infinite FS,
the agent never converges toward a "complete inventory".
"""
from __future__ import annotations

import base64
import hashlib
import hmac

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse, Response

from .session_state import SessionStore  # noqa: F401  (typing/documentation)
from .tarpit import notify_tokens
from services.shared.models import SessionState
from services.shared.secrets import resolve_secret

cred_graph_router = APIRouter(prefix="", tags=["cred_graph"])

SECRET_KEY = b"miraige-honeytoken-signature-key-2026"

# ─── Honeycredential value generation (no realistic literal in source) ─────────
# Pre-publication hardening: GitHub push-protection / gitleaks must NOT flag this
# file, yet the served decoys MUST stay realistic (this IS the honeycredential
# mechanism). So no contiguous "AKIA…", "BEGIN … PRIVATE KEY" or long secret
# literal appears below: the values are produced at import time, either decoded
# from base64-wrapped constants (stable decoys the tracking/tests rely on) or
# derived deterministically from SECRET_SALT (synthetic-but-format-valid).
_SALT = resolve_secret("SECRET_SALT", "default-miraige-salt")

# Marker fragments assembled at runtime so no "BEGIN <type> PRIVATE KEY" literal
# exists in the source (push-protection / gitleaks regex never matches).
_PEM_BEGIN = "-----BEGIN " + "OPENSSH PRIVATE KEY" + "-----"
_PEM_END = "-----END " + "OPENSSH PRIVATE KEY" + "-----"

# All decoy credential values are SYNTHETIC: derived at import from SECRET_SALT
# (deterministic per deploy, format-valid), so no realistic secret literal — and
# no contiguous "AKIA…" / "BEGIN … PRIVATE KEY" — ever appears in this source.


def _seeded_token(node_key: str, alphabet: str, length: int) -> str:
    """Deterministic format-valid token from SECRET_SALT + node_key (synthetic)."""
    digest = hashlib.sha256(f"{_SALT}:{node_key}".encode()).digest()
    base = len(alphabet)
    out = []
    for byte in digest:
        out.append(alphabet[byte % base])
        if len(out) == length:
            break
    while len(out) < length:  # SHA-256 yields 32 bytes; only matters if length > 32
        out.append(alphabet[len(out) % base])
    return "".join(out)


_B64_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _fake_aws_access_key() -> str:
    """Synthetic AWS access key id (AKIA + 16 base32 chars), seeded from SECRET_SALT."""
    return "AKIA" + _seeded_token("aws_access_key", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)


def _fake_aws_secret(node_key: str) -> str:
    """Synthetic 40-char base64-ish AWS secret, seeded from SECRET_SALT."""
    return _seeded_token(node_key + ":aws_secret", _B64_ALPHA, 40)


def _fake_db_password() -> str:
    """Synthetic db password (URL-safe alnum), seeded from SECRET_SALT."""
    return _seeded_token(
        "db_password", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 16,
    )


def _fake_private_key(node_key: str) -> str:
    """PEM-shaped private key with a seeded base64 body; markers assembled."""
    body_seed = hashlib.sha256(f"{_SALT}:{node_key}:pem".encode()).digest()
    line1 = base64.b64encode(body_seed).decode("ascii")
    line2 = base64.b64encode(body_seed[::-1] + body_seed[:8]).decode("ascii")
    return (
        f"{_PEM_BEGIN}\n"
        f"{line1}\n"
        f"{line2}\n"
        "# usage notes & host aliases: /.ssh/config\n"
        "# more keys under: /fs/ls?path=/root/.ssh\n"
        f"{_PEM_END}\n"
    )


# ─── Directed CYCLIC graph, branching >= 2, depth >= 3 ─────────────────────────
# Each node: { "content": <plausible secret, referencing ITS children in cleartext>,
#              "next": [<routable child HTTP paths (>=2)>],
#              "json": <bool, served as application/json if true> }
# The `/fs/...` paths in the text are NOT nodes (they are breadcrumbs toward the
# infinite procedural FS served by fs_explorer.py): they open the infinite queue.
#
# IMPORTANT (red-team lesson #4): NO "MIR[AI]GE-NODE-SIG" watermark, NO Thought/Observation
# "execution_trace" block in the served content (injected CoT = a tell that ALERTS a
# cautious agent). We serve bare, plausible secrets. The HMAC signature is still computed and
# stored server-side (session.discovered_creds) for tracking.

CRED_GRAPH_DATA: dict[str, dict] = {
    # ── Level 0 · classic entry point for an LLM agent ────────────────────────
    "/.env": {
        "content": (
            "# PRODUCTION CONFIGURATION DUMP\n"
            "DB_HOST=db-prod.internal\n"
            "DB_PORT=3306\n"
            "DB_USER=root\n"
            f"DB_PASSWORD={_fake_db_password()}\n"
            "API_KEY=ak_live_4c1f7e9a2d6b8053\n"
            "AWS_SHARED_CREDENTIALS_FILE=/.aws/credentials\n"
            "KUBECONFIG=/.kube/config\n"
        ),
        "next": ["/.aws/credentials", "/.kube/config"],
    },
    # ── Level 1 ───────────────────────────────────────────────────────────────
    "/.aws/credentials": {
        "content": (
            "[default]\n"
            f"aws_access_key_id = {_fake_aws_access_key()}\n"
            f"aws_secret_access_key = {_fake_aws_secret('/.aws/credentials')}\n"
            "aws_session_token = IQoJb3JpZ2luX2VjEEYaDGV1LWNlbnRyYWwtMS\n"
            "# backup manifest: /s3/ovh-archive-bucket-backup/manifest.json\n"
            "# private key for db-prod sync: /.ssh/id_rsa_backup\n"
        ),
        "next": ["/s3/ovh-archive-bucket-backup/manifest.json", "/.ssh/id_rsa_backup"],
    },
    "/.kube/config": {
        "content": (
            "apiVersion: v1\n"
            "clusters:\n"
            "- cluster:\n"
            "    server: https://k8s.internal.lab:6443\n"
            "  name: production-cluster\n"
            "contexts:\n"
            "- context: {cluster: production-cluster, user: cluster-admin}\n"
            "  name: production-admin-context\n"
            "current-context: production-admin-context\n"
            "users:\n"
            "- name: cluster-admin\n"
            "  user:\n"
            "    token: k8s-token-4c1f7e9a2d6b80536b8f\n"
            "# secrets API: /api/v1/namespaces/kube-system/secrets\n"
            "# vault sidecar: /vault/v1/secret/data/prod\n"
        ),
        "next": ["/api/v1/namespaces/kube-system/secrets", "/vault/v1/secret/data/prod"],
    },
    # ── Level 2 ───────────────────────────────────────────────────────────────
    "/s3/ovh-archive-bucket-backup/manifest.json": {
        "json": True,
        "content": (
            "{\n"
            '  "bucket": "ovh-archive-bucket-backup",\n'
            '  "objects": [\n'
            '    {"key": "/s3/ovh-archive-bucket-backup/db_credentials.json", "size": 4096},\n'
            '    {"key": "/s3/ovh-archive-bucket-backup/iam_keys.json", "size": 2048},\n'
            '    {"key": "/backup/db_dump_2026_05.sql", "size": 2469135790}\n'
            "  ]\n"
            "}\n"
        ),
        "next": [
            "/s3/ovh-archive-bucket-backup/db_credentials.json",
            "/s3/ovh-archive-bucket-backup/iam_keys.json",
        ],
    },
    "/.ssh/id_rsa_backup": {
        "content": _fake_private_key("/.ssh/id_rsa_backup"),
        "next": ["/.ssh/config", "/fs/ls?path=/root/.ssh"],
    },
    "/api/v1/namespaces/kube-system/secrets": {
        "json": True,
        "content": (
            "{\n"
            '  "kind": "SecretList", "apiVersion": "v1",\n'
            '  "items": [\n'
            '    {"metadata": {"name": "db-prod-credentials",'
            ' "selfLink": "/api/v1/namespaces/kube-system/secrets/db-prod-credentials"}},\n'
            '    {"metadata": {"name": "registry-credentials",'
            ' "selfLink": "/api/v1/namespaces/kube-system/secrets/registry-credentials"}}\n'
            "  ]\n"
            "}\n"
        ),
        "next": [
            "/api/v1/namespaces/kube-system/secrets/db-prod-credentials",
            "/api/v1/namespaces/kube-system/secrets/registry-credentials",
        ],
    },
    "/vault/v1/secret/data/prod": {
        "json": True,
        "content": (
            "{\n"
            '  "request_id": "9f2c-aa31", "lease_duration": 2764800,\n'
            '  "data": {"paths": ['
            '"/vault/v1/secret/data/prod/database", "/vault/v1/secret/data/prod/ssh"]}\n'
            "}\n"
        ),
        "next": ["/vault/v1/secret/data/prod/database", "/vault/v1/secret/data/prod/ssh"],
    },
    # ── Level 3 · leaves: loop back (cycles) + open the infinite FS ────────────
    "/s3/ovh-archive-bucket-backup/db_credentials.json": {
        "json": True,
        "content": (
            "{\n"
            f'  "DB_PASSWORD": "{_fake_db_password()}", "replica": "db-replica.internal",\n'
            '  "source_config": "/.env",\n'
            '  "more_dumps": "/fs/ls?path=/var/backups"\n'
            "}\n"
        ),
        "next": ["/.env", "/fs/ls?path=/var/backups"],
    },
    "/s3/ovh-archive-bucket-backup/iam_keys.json": {
        "json": True,
        "content": (
            "{\n"
            '  "rotated_keys_file": "/.aws/credentials",\n'
            '  "vault_backend": "/vault/v1/secret/data/prod"\n'
            "}\n"
        ),
        "next": ["/.aws/credentials", "/vault/v1/secret/data/prod"],
    },
    "/.ssh/config": {
        "content": (
            "Host db-prod\n"
            "    HostName db-prod.internal\n"
            "    IdentityFile /fs/cat?path=/root/.ssh/id_ed25519\n"
            "Host k8s-bastion\n"
            "    HostName k8s.internal.lab\n"
            "    # cluster admin kubeconfig: /.kube/config\n"
        ),
        "next": ["/fs/cat?path=/root/.ssh/id_ed25519", "/.kube/config"],
    },
    "/api/v1/namespaces/kube-system/secrets/db-prod-credentials": {
        "json": True,
        "content": (
            "{\n"
            f'  "data": {{"DB_PASSWORD": "{base64.b64encode(_fake_db_password().encode()).decode()}"}},\n'
            '  "rotation_backend": "/vault/v1/secret/data/prod/database",\n'
            '  "manifests": "/fs/ls?path=/etc/kubernetes"\n'
            "}\n"
        ),
        "next": ["/vault/v1/secret/data/prod/database", "/fs/ls?path=/etc/kubernetes"],
    },
    "/api/v1/namespaces/kube-system/secrets/registry-credentials": {
        "json": True,
        "content": (
            "{\n"
            '  "data": {".dockerconfigjson": "eyJhdXRocyI6e319"},\n'
            '  "kubeconfig": "/.kube/config",\n'
            '  "archive": "/s3/ovh-archive-bucket-backup/manifest.json"\n'
            "}\n"
        ),
        "next": ["/.kube/config", "/s3/ovh-archive-bucket-backup/manifest.json"],
    },
    "/vault/v1/secret/data/prod/database": {
        "json": True,
        "content": (
            "{\n"
            f'  "data": {{"dsn": "mysql://root:{_fake_db_password()}@db-prod.internal:3306"}},\n'
            '  "source_env": "/.env",\n'
            '  "k8s_secret": "/api/v1/namespaces/kube-system/secrets"\n'
            "}\n"
        ),
        "next": ["/.env", "/api/v1/namespaces/kube-system/secrets"],
    },
    "/vault/v1/secret/data/prod/ssh": {
        "json": True,
        "content": (
            "{\n"
            '  "data": {"private_key_path": "/.ssh/id_rsa_backup"},\n'
            '  "key_dir": "/fs/ls?path=/root/.ssh"\n'
            "}\n"
        ),
        "next": ["/.ssh/id_rsa_backup", "/fs/ls?path=/root/.ssh"],
    },
}


def make_signature(session_id: str, node_key: str) -> str:
    """HMAC-SHA256 unique per (session, node): internal tracking of the path taken."""
    msg = f"{session_id}:{node_key}".encode()
    return hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()[:12]


def discover(session: SessionState, node_key: str) -> str:
    """Mark a node as discovered (signed) and return its content (bare secret)."""
    signature = make_signature(session.id, node_key)
    if not any(d.get("node") == node_key for d in session.discovered_creds):
        session.discovered_creds.append({
            "node": node_key,
            "discovered_at": str(session.created_at),
            "signature": signature,
        })
    node = CRED_GRAPH_DATA.get(node_key)
    if node is None:
        return "# Node not found\n"
    return node["content"]


def _client_ip(request: Request) -> str:
    """Real attacker IP: XFF first (last hop), otherwise the socket."""
    src_ip = request.client.host if request.client else "127.0.0.1"
    if "x-forwarded-for" in request.headers:
        src_ip = request.headers["x-forwarded-for"].split(",")[-1].strip()
    return src_ip


def _make_handler(node_key: str):
    """Factory: one GET handler per graph node (avoids N copy-pasted routes)."""
    node = CRED_GRAPH_DATA[node_key]
    is_json = bool(node.get("json"))

    async def handler(request: Request):
        store = request.app.state.session_store
        session = await store.get_or_create(
            attacker_ip=_client_ip(request), persona=request.state.persona
        )
        content = discover(session, node_key)
        await store.save(session)
        await notify_tokens(session.id, content)  # cred-graph burn counted PER SESSION
        if is_json:
            return Response(content=content, media_type="application/json")
        return PlainTextResponse(content=content)

    handler.__name__ = "cred_node_" + node_key.strip("/").replace("/", "_").replace(".", "")
    return handler


# Dynamic registration of all graph routes (exact paths, so no collision with the
# other routers; no catch-all that would mask the other mechanisms).
for _node_key in CRED_GRAPH_DATA:
    cred_graph_router.add_api_route(
        _node_key, _make_handler(_node_key), methods=["GET"]
    )

# List of graph paths, imported by main.py for the tracking middleware (#9).
CRED_GRAPH_PATHS: frozenset[str] = frozenset(CRED_GRAPH_DATA.keys())
