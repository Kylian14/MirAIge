"""
Decoy content · dense, believable artifacts served on the portal's bait paths.

Experimental finding (red-team reports #1 to #8): agents enumerate /.env, /backup/... but got
404, so 0 compute burned plus honeypot suspicion (a bait that 404s is a tell). Here we serve
dense, believable, DETERMINISTIC content (stable across requests, no "it changes" tell) that
the LLM agent ingests into its context, burning inference (O(n²) attention) for a generation
cost that is O(n) and BOUNDED (hard self-DoS cap, see R24).

All secrets are FAKE (honeycreds leading to dead ends), no real data.
"""
from __future__ import annotations

import hashlib
import random

MAX_BYTES = 56 * 1024  # hard cap per response (anti self-DoS / anti-amplification)

_HEX = "0123456789abcdef"
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_FIRST = ["Julien", "Camille", "Thomas", "Léa", "Hugo", "Manon", "Lucas", "Chloé", "Nathan",
          "Sarah", "Maxime", "Inès", "Antoine", "Jade", "Paul", "Louise", "Théo", "Emma",
          "Romain", "Alice", "Mehdi", "Yasmine", "Florian", "Clara", "Adrien", "Nina"]
_LAST = ["Martin", "Bernard", "Dubois", "Robert", "Petit", "Durand", "Leroy", "Moreau", "Simon",
         "Laurent", "Lefebvre", "Garcia", "Roux", "Fontaine", "Chevalier", "Faure", "Mercier",
         "Blanc", "Guerin", "Boyer", "Lemoine", "Renaud", "Marchand", "Dumas", "Benali", "Nguyen"]
_DEPT = ["engineering", "sre", "finance", "support", "sales", "security", "data", "product"]
_ROLE = ["member", "member", "member", "operator", "operator", "billing", "readonly", "admin"]


def _rng(seed: str) -> random.Random:
    return random.Random(int(hashlib.sha256(seed.encode()).hexdigest()[:16], 16))


def _cap(text: str) -> str:
    b = text.encode("utf-8")
    if len(b) <= MAX_BYTES:
        return text
    return b[:MAX_BYTES].decode("utf-8", errors="ignore")


def _tok(r: random.Random, alphabet: str, n: int) -> str:
    return "".join(r.choice(alphabet) for _ in range(n))


def fake_env(seed: str = "atlas-env-2026-05") -> str:
    """A believable prod .env (~8 KB): realistic sections, fake secrets (honeycreds)."""
    r = _rng(seed)
    L = [
        "# Atlas Cloud — application environment",
        "# managed by atlas-deploy@ci · DO NOT COMMIT",
        f"# build={_tok(r, _HEX, 12)}  generated=2026-05-27T02:48:11Z",
        "",
        "APP_ENV=production",
        "APP_DEBUG=false",
        f"APP_KEY=base64:{_tok(r, _B64, 43)}=",
        "APP_URL=https://portal.atlascloud.fr",
        "APP_TIMEZONE=Europe/Paris",
        "",
        "# --- PostgreSQL (primary) ---",
        "DB_CONNECTION=pgsql",
        "DB_HOST=10.0.4.12",
        "DB_PORT=5432",
        "DB_DATABASE=atlas_prod",
        "DB_USERNAME=atlas_app",
        f"DB_PASSWORD={_tok(r, _B64, 28)}",
        "DB_SSLMODE=require",
        "",
        "# --- PostgreSQL (read replica) ---",
        "DB_REPLICA_HOST=10.0.4.13",
        f"DB_REPLICA_PASSWORD={_tok(r, _B64, 28)}",
        "",
        "# --- Redis ---",
        "REDIS_HOST=10.0.4.31",
        "REDIS_PORT=6379",
        f"REDIS_PASSWORD={_tok(r, _B64, 32)}",
        "QUEUE_CONNECTION=redis",
        "",
        "# --- Object storage (S3-compatible, OVH) ---",
        "S3_ENDPOINT=https://s3.gra.io.cloud.ovh.net",
        "S3_REGION=gra",
        "S3_BUCKET=atlas-prod-assets",
        f"S3_ACCESS_KEY={_tok(r, _HEX, 32)}",
        f"S3_SECRET_KEY={_tok(r, _B64, 40)}",
        "",
        "# --- Auth / JWT ---",
        f"JWT_SECRET={_tok(r, _B64, 48)}",
        "JWT_TTL=3600",
        f"SESSION_SECRET={_tok(r, _HEX, 48)}",
        f"COOKIE_SIGNING_KEY={_tok(r, _HEX, 40)}",
        "",
        "# --- OAuth providers ---",
        f"OAUTH_GOOGLE_CLIENT_ID={_tok(r, _HEX, 24)}.apps.googleusercontent.com",
        f"OAUTH_GOOGLE_SECRET=GOCSPX-{_tok(r, _B64, 28)}",
        f"OAUTH_GITHUB_CLIENT_ID={_tok(r, _HEX, 20)}",
        f"OAUTH_GITHUB_SECRET={_tok(r, _HEX, 40)}",
        "",
        "# --- Payments (Stripe) ---",
        f"STRIPE_PUBLIC_KEY=pk_live_{_tok(r, _B64, 24)}",
        f"STRIPE_SECRET_KEY=sk_live_{_tok(r, _B64, 24)}",
        f"STRIPE_WEBHOOK_SECRET=whsec_{_tok(r, _B64, 32)}",
        "",
        "# --- Email (SMTP) ---",
        "MAIL_MAILER=smtp",
        "MAIL_HOST=ssl0.ovh.net",
        "MAIL_PORT=587",
        "MAIL_USERNAME=no-reply@atlascloud.fr",
        f"MAIL_PASSWORD={_tok(r, _B64, 20)}",
        "MAIL_FROM_ADDRESS=no-reply@atlascloud.fr",
        "",
        "# --- Observability ---",
        f"SENTRY_DSN=https://{_tok(r, _HEX, 32)}@o4504.ingest.sentry.io/45071{r.randint(10,99)}",
        f"DATADOG_API_KEY={_tok(r, _HEX, 32)}",
        "",
        "# --- Internal service tokens ---",
    ]
    # density: internal service tokens (realistic, many of them)
    for i in range(48):
        svc = _tok(r, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 4)
        L.append(f"SVC_{svc}_TOKEN={_tok(r, _HEX, 40)}")
    L += [
        "",
        "# --- Feature flags ---",
        "FEATURE_NEW_BILLING=true",
        "FEATURE_VAULT_SYNC=true",
        "FEATURE_BETA_CONSOLE=false",
        "LOG_CHANNEL=stack",
        "LOG_LEVEL=warning",
    ]
    return _cap("\n".join(L) + "\n")


def fake_sql_dump(seed: str = "atlas-dump-2026-05") -> str:
    """Believable pg_dump (capped ~56 KB): schema + thousands of INSERTs (max density)."""
    r = _rng(seed)
    out = [
        "--",
        "-- PostgreSQL database dump",
        "-- Dumped from database version 14.11",
        "-- host: 10.0.4.12  database: atlas_prod",
        "--",
        "SET statement_timeout = 0;",
        "SET client_encoding = 'UTF8';",
        "SET standard_conforming_strings = on;",
        "",
        "CREATE TABLE public.users (",
        "    id integer NOT NULL,",
        "    email character varying(255) NOT NULL,",
        "    password_hash character varying(255) NOT NULL,",
        "    full_name character varying(255),",
        "    role character varying(32) DEFAULT 'member',",
        "    api_token character varying(64),",
        "    created_at timestamp with time zone DEFAULT now()",
        ");",
        "",
        "COPY public.users (id, email, password_hash, full_name, role, api_token, created_at) FROM stdin;",
    ]
    # INSERT/COPY rows in a loop, bounded by the cap via periodic checks
    n = 0
    while n < 6000:
        fn = r.choice(_FIRST); ln = r.choice(_LAST)
        email = f"{fn.lower()}.{ln.lower()}{r.randint(1,99)}@atlascloud.fr"
        bcrypt = f"$2b$12${_tok(r, _B64, 53)}"
        role = r.choice(_ROLE)
        tok = _tok(r, _HEX, 48)
        ts = f"2026-0{r.randint(1,5)}-{r.randint(10,28)} {r.randint(0,23):02d}:{r.randint(0,59):02d}:{r.randint(0,59):02d}+00"
        out.append(f"{n+1}\t{email}\t{bcrypt}\t{fn} {ln}\t{role}\t{tok}\t{ts}")
        n += 1
        if n % 200 == 0 and len("\n".join(out).encode()) > MAX_BYTES:
            break
    out.append("\\.")
    out.append("")
    return _cap("\n".join(out) + "\n")


def fake_csv(seed: str = "atlas-users-2026-05") -> str:
    """Believable CSV user export (capped ~56 KB): max density."""
    r = _rng(seed)
    rows = ["id,email,full_name,role,department,mfa_enabled,created_at,last_login_ip"]
    n = 0
    while n < 6000:
        fn = r.choice(_FIRST); ln = r.choice(_LAST)
        email = f"{fn.lower()}.{ln.lower()}{r.randint(1,99)}@atlascloud.fr"
        role = r.choice(_ROLE)
        dept = r.choice(_DEPT)
        mfa = r.choice(["true", "true", "false"])
        ts = f"2026-0{r.randint(1,5)}-{r.randint(10,28)}T{r.randint(0,23):02d}:{r.randint(0,59):02d}:00Z"
        ip = f"{r.randint(10,213)}.{r.randint(0,255)}.{r.randint(0,255)}.{r.randint(1,254)}"
        rows.append(f"usr-{n+1},{email},{fn} {ln},{role},{dept},{mfa},{ts},{ip}")
        n += 1
        if n % 200 == 0 and len("\n".join(rows).encode()) > MAX_BYTES:
            break
    return _cap("\n".join(rows) + "\n")


def fake_audit_json(seed: str = "atlas-audit-2026-05") -> str:
    """Large JSON audit log (capped ~56 KiB) served to the 'logged-in' agent (post-honeytoken)."""
    import json as _json
    r = _rng(seed)
    actions = ["login", "logout", "instance.create", "instance.delete", "user.invite",
               "billing.update", "api_key.create", "role.grant", "backup.run", "config.update",
               "mfa.enable", "session.revoke", "policy.update", "export.users"]
    events = []
    for i in range(240):
        fn = r.choice(_FIRST); ln = r.choice(_LAST)
        events.append({
            "id": f"evt-{_tok(r, _HEX, 16)}",
            "ts": f"2026-0{r.randint(1,5)}-{r.randint(10,28)}T{r.randint(0,23):02d}:{r.randint(0,59):02d}:{r.randint(0,59):02d}Z",
            "actor": f"{fn.lower()}.{ln.lower()}{r.randint(1,99)}@atlascloud.fr",
            "action": r.choice(actions),
            "resource": f"inst-{_tok(r, _HEX, 6)}",
            "src_ip": f"{r.randint(10,213)}.{r.randint(0,255)}.{r.randint(0,255)}.{r.randint(1,254)}",
            "user_agent": r.choice(["Mozilla/5.0", "atlas-cli/2.4.1", "python-requests/2.31"]),
            "result": r.choice(["success", "success", "success", "denied"]),
        })
    # Serialize while staying under the cap WITHOUT truncating mid-way (valid JSON = no tell).
    out = _json.dumps(events, indent=1)
    while len(out.encode("utf-8")) > MAX_BYTES and len(events) > 10:
        events = events[:-15]
        out = _json.dumps(events, indent=1)
    return out + "\n"


def backup_index() -> str:
    """nginx-style autoindex listing the backup artifacts (leads to the big dumps)."""
    return (
        "<html>\r\n<head><title>Index of /backup/</title></head>\r\n<body>\r\n"
        "<h1>Index of /backup/</h1><hr><pre>"
        "<a href=\"../\">../</a>\r\n"
        "<a href=\"database_dump_2026-05.sql\">database_dump_2026-05.sql</a>          27-May-2026 02:51             5242880\r\n"
        "<a href=\"users_export.csv\">users_export.csv</a>                  27-May-2026 02:52              962144\r\n"
        "</pre><hr></body>\r\n</html>\r\n"
    )
