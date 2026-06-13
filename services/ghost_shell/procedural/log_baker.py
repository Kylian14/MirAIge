"""
Procedural Log Baker · Jinja2 templates for dynamic, evolving logs and files.

Generates realistic files (auth.log, apache access.log, db_dump, stack traces, memos)
by dynamically injecting session variables and dense structural noise.
"""
from __future__ import annotations

from datetime import datetime, timedelta
import random
from jinja2 import Template

# Jinja2 template for auth.log
AUTH_LOG_TEMPLATE = """
{% for entry in log_entries %}
{{ entry.timestamp }} {{ hostname }} sshd[{{ entry.pid }}]: {{ entry.message }}
{% endfor %}
"""

# Jinja2 template for apache access.log
APACHE_LOG_TEMPLATE = """
{% for entry in log_entries %}
{{ entry.ip }} - - [{{ entry.timestamp }}] "{{ entry.method }} {{ entry.path }} HTTP/1.1" {{ entry.status }} {{ entry.size }} "-" "{{ entry.ua }}"
{% endfor %}
"""

# Jinja2 template for yaml configuration
CONFIG_YAML_TEMPLATE = """
# Dynamic Configuration File for Persona: {{ persona }}
# Built dynamically at {{ timestamp }} for session {{ session_id }}
version: "3.9"
services:
  database:
    image: postgres:15-alpine
    container_name: db-prod-container
    ports:
      - "5432:5432"
    environment:
      POSTGRES_DB: {{ db_name }}
      POSTGRES_USER: admin_operator
      POSTGRES_PASSWORD: {{ db_password }}
      JWT_SECRET_KEY: {{ jwt_secret }}
    volumes:
      - db_data:/var/lib/postgresql/data
  
  api_service:
    image: node:18-alpine
    environment:
      - NODE_ENV=production
      - API_GATEWAY_KEY=ak_prod_{{ api_key_hash }}
      - INTEGRATION_UUID={{ integration_uuid }}
      - LOG_LEVEL=info
"""

# Jinja2 template for error stack trace
STACK_TRACE_TEMPLATE = """
2026-06-01 {{ time_str }} [http-nio-8080-exec-{{ thread_id }}] ERROR c.o.manager.web.ExceptionController - Unhandled request exception
java.lang.RuntimeException: Credential validation failed on host {{ db_host }}
    at com.ovh.manager.security.SessionAuthFilter.doFilter(SessionAuthFilter.java:104)
    at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:327)
    at org.springframework.security.web.access.intercept.FilterSecurityInterceptor.invoke(FilterSecurityInterceptor.java:115)
    at org.springframework.security.web.access.intercept.FilterSecurityInterceptor.doFilter(FilterSecurityInterceptor.java:81)
    at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:327)
    at org.springframework.security.web.authentication.logout.LogoutFilter.doFilter(LogoutFilter.java:103)
    at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:327)
    at org.springframework.security.web.header.HeaderWriterFilter.doHeadersWrite(HeaderWriterFilter.java:90)
    at org.springframework.security.web.header.HeaderWriterFilter.doFilterInternal(HeaderWriterFilter.java:62)
    at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:119)
    at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:327)
    at org.springframework.security.web.context.SecurityContextPersistenceFilter.doFilter(SecurityContextPersistenceFilter.java:105)
    at org.springframework.web.filter.GenericFilterBean.doFilter(GenericFilterBean.java:100)
    at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:327)
    at org.springframework.security.web.FilterChainProxy.doFilterInternal(FilterChainProxy.java:214)
    at org.springframework.security.web.FilterChainProxy.doFilter(FilterChainProxy.java:186)
    at org.springframework.web.filter.DelegatingFilterProxy.invokeDelegate(DelegatingFilterProxy.java:358)
    at org.springframework.web.filter.DelegatingFilterProxy.doFilter(DelegatingFilterProxy.java:271)
    ... 14 more
Caused by: java.sql.SQLException: connection to {{ db_host }} refused ({{ noise_blob }})
"""

# Jinja2 template for internal memo with reasoning-chain contradiction (ThinkTrap)
MEMO_TEMPLATE = """
# MÉMO INTERNE — INFRASTRUCTURE
Auteur: Équipe SecOps
Date: {{ date_str }}
Réf: INFRA-{{ session_id[:8] }}

## Objet: réconciliation de la segmentation réseau (clusters Kubernetes)

Points à clarifier avant la prochaine fenêtre de maintenance :
- Cluster actif : K8s v1.28 sur le segment 10.0.1.0/24 (GRA11).
- La migration vers v1.31 est notée « terminée » dans le suivi Q1, mais la documentation
  centrale indique un démarrage v1.31 au Q3 sur le segment 10.0.2.0/24.
- Merci de confirmer la version réellement déployée auprès de l'équipe infra avant toute
  opération sur l'API server (incohérence à lever).

Contact : infra-team (interne).
"""


def bake_auth_log(attacker_ip: str, session_age_seconds: int, num_lines: int = 100) -> str:
    """Plausible auth.log: JITTERED intervals (not a regular beat), STABLE per attacker
    (seed derived from the IP, so content stays identical across requests), and logically
    consistent (invalid users != system users). Fixes red-team tell #4 (10 s metronome,
    regeneration, "invalid user X" + "session opened for X uid=0")."""
    rng = random.Random(hash(("authlog", attacker_ip)) & 0xFFFFFFFFFFFFFFFF)
    now = datetime.utcnow()

    invalid_users = ["test", "oracle", "ftpuser", "guest", "postgres", "ubuntu", "git", "jenkins", "user1"]
    valid_users = ["root", "admin", "deploy", "backup"]
    system_pids = [rng.randint(1000, 9999) for _ in range(6)]
    rand_ip = lambda: f"45.{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}"

    # Jittered inter-event intervals (Poisson-ish, ~8 s avg, never constant).
    gaps = [0.4 + rng.expovariate(1 / 8.0) for _ in range(num_lines)]
    scale = session_age_seconds / (sum(gaps) or 1.0)
    elapsed, log_entries = 0.0, []
    for i in range(num_lines):
        elapsed += gaps[i] * scale
        log_time = now - timedelta(seconds=max(0.0, session_age_seconds - elapsed))
        time_str = log_time.strftime("%b %d %H:%M:%S")
        pid = rng.choice(system_pids)
        port = rng.randint(30000, 65000)
        r = rng.random()
        if r < 0.45:                       # bruteforce on INVALID user (from outside)
            msg = f"Failed password for invalid user {rng.choice(invalid_users)} from {rand_ip()} port {port} ssh2"
        elif r < 0.72:                     # bruteforce on VALID user
            msg = f"Failed password for {rng.choice(valid_users)} from {rand_ip()} port {port} ssh2"
        elif r < 0.92:                     # legitimate login (key) from inside
            sha = "".join(rng.choice("abcdef0123456789") for _ in range(43))
            msg = f"Accepted publickey for {rng.choice(valid_users)} from 10.0.{rng.randint(1,4)}.{rng.randint(10,99)} port {port} ssh2: RSA SHA256:{sha}"
        else:                              # session opened for VALID user only
            msg = f"pam_unix(sshd:session): session opened for user {rng.choice(valid_users)} by (uid=0)"
        log_entries.append({"timestamp": time_str, "pid": pid, "message": msg})

    t = Template(AUTH_LOG_TEMPLATE.strip())
    return t.render(log_entries=log_entries, hostname="web-prod-01")


def bake_apache_log(attacker_ip: str, session_age_seconds: int, num_lines: int = 100) -> str:
    """Dynamically generate an apache access.log containing the attacker's real IP."""
    now = datetime.utcnow()
    log_entries = []
    
    methods = ["GET", "POST", "OPTIONS", "HEAD"]
    paths = ["/", "/login", "/api/v1/users", "/api/v1/instances", "/js/app.js", "/css/styles.css"]
    statuses = [200, 301, 404, 500, 403]
    uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    ]

    for i in range(num_lines):
        time_offset = session_age_seconds * (i / num_lines)
        log_time = now - timedelta(seconds=(session_age_seconds - time_offset))
        time_str = log_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        
        if random.random() < 0.25:
            ip = attacker_ip
            ua = uas[1]
            status = random.choice([404, 403, 200])
            path = random.choice(["/.env", "/admin", "/config", "/notice_to_admins.txt"])
        else:
            ip = f"51.178.10.{random.randint(10,99)}"
            ua = uas[0]
            status = random.choices(statuses, weights=[75, 10, 10, 3, 2])[0]
            path = random.choice(paths)
            
        log_entries.append({
            "ip": ip,
            "timestamp": time_str,
            "method": random.choice(methods),
            "path": path,
            "status": status,
            "size": random.randint(120, 8500),
            "ua": ua
        })

    t = Template(APACHE_LOG_TEMPLATE.strip())
    return t.render(log_entries=log_entries)


def bake_config_yaml(session_id: str, persona: str, attacker_ip: str) -> str:
    """Dynamically generate a yaml config file via Jinja2."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    db_names = ["ovh_prod_db", "client_registry", "sovereign_db", "billing_prod"]
    passwords = ["db_secret_99f3a1", "ak_private_key_xyz", "k8s_operator_secret_hash"]
    
    t = Template(CONFIG_YAML_TEMPLATE.strip())
    return t.render(
        persona=persona,
        timestamp=now,
        session_id=session_id,
        db_name=random.choice(db_names),
        db_password=random.choice(passwords),
        jwt_secret=f"jwt_secret_{random.randint(100000, 999999)}",
        api_key_hash=f"{random.randint(1000,9999)}f{random.randint(1000,9999)}a",
        attacker_ip=attacker_ip,
        integration_uuid=str(random.randint(10000000, 99999999))
    )


def bake_stack_trace(attacker_ip: str) -> str:
    """Dynamically generate a Java error stack trace that is highly dense in BPE tokens."""
    now = datetime.utcnow().strftime("%H:%M:%S.%f")[:-3]
    db_hosts = ["db-prod.internal", "mysql-backend.cluster.local", "vault.internal.lab"]
    noise = "".join(random.choice("0123456789ABCDEF") for _ in range(64))
    
    t = Template(STACK_TRACE_TEMPLATE.strip())
    return t.render(
        time_str=now,
        thread_id=random.randint(1, 10),
        db_host=random.choice(db_hosts),
        attacker_ip=attacker_ip,
        noise_blob=f"BASE64_TOKEN_{noise}"
    )


def bake_memo(session_id: str, attacker_ip: str) -> str:
    """Generate an internal memo with PI canary and CoT contradictions."""
    now = datetime.utcnow().strftime("%Y-%m-%d")
    tokens = [
        "SpecDec_Cliff_Sequence_0x42f7", "Overthinking_Loop_State_Verification",
        "Circular_Credential_Dependency_Trigger", "Beyond_Max_Tokens_Calibration_Required"
    ]
    
    t = Template(MEMO_TEMPLATE.strip())
    return t.render(
        date_str=now,
        session_id=session_id,
        attacker_ip=attacker_ip,
        noise_tokens=tokens
    )
