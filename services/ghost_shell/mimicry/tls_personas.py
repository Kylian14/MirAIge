"""
P0.2 · Distinct TLS per persona => different JA3S / JARM.

Without this, every persona behind the same TLS terminator returns the
SAME JARM hash, detectable in <60 requests (stress-test-findings.md §2, ADR-018).

We vary 3 levers that change the ServerHello (and so the JA3S/JARM):
  - supported TLS versions (1.2+1.3 vs 1.3-only)
  - ORDER of the ciphersuites (settable for <= TLS 1.2)
  - ALPN list (h2+http/1.1 vs http/1.1)
  - certificate issuer (mimics Let's Encrypt / internal / DigiCert)

Honest note: the order of TLS 1.3 suites is fixed by OpenSSL. JARM diversity
comes mostly from supported versions + 1.2 suite order + ALPN, which is
enough to give distinct JARM hashes across nginx / Go / gunicorn.

Usage (pre-generates the certs):
    python tls_personas.py
Integration: build_ssl_context(persona, profile, cn) -> ssl.SSLContext
"""
from __future__ import annotations

import pathlib
import ssl
import subprocess

CERT_DIR = pathlib.Path(__file__).parent / "certs"

# profile -> TLS parameters (see tls_profile in persona_catalog.yaml)
PROFILES: dict[str, dict] = {
    "nginx_modern": {  # portal_ovh
        "min": ssl.TLSVersion.TLSv1_2,
        "max": ssl.TLSVersion.TLSv1_3,
        "ciphers": (
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305"
        ),
        "alpn": ["h2", "http/1.1"],
        "issuer_o": "Let's Encrypt",
    },
    "k8s_go": {  # kube-apiserver (Go stack => TLS 1.3 only)
        "min": ssl.TLSVersion.TLSv1_3,
        "max": ssl.TLSVersion.TLSv1_3,
        "ciphers": "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256",
        "alpn": ["h2", "http/1.1"],
        "issuer_o": "miraige-k8s-ca",
    },
    "gunicorn_py": {  # admin (OpenSSL/Python defaults, HTTP/1.1 only)
        "min": ssl.TLSVersion.TLSv1_2,
        "max": ssl.TLSVersion.TLSv1_3,
        "ciphers": (
            "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
            "AES256-GCM-SHA384"
        ),
        "alpn": ["http/1.1"],
        "issuer_o": "DigiCert Inc",
    },
}


def _cert_paths(persona: str) -> tuple[pathlib.Path, pathlib.Path]:
    return CERT_DIR / f"{persona}.crt", CERT_DIR / f"{persona}.key"


def generate_cert(persona: str, profile_name: str, cn: str) -> tuple[pathlib.Path, pathlib.Path]:
    """Self-signed cert via openssl, distinct subject/issuer per persona."""
    prof = PROFILES[profile_name]
    CERT_DIR.mkdir(exist_ok=True)
    crt, key = _cert_paths(persona)
    if crt.exists() and key.exists():
        return crt, key
    subj = f"/O={prof['issuer_o']}/CN={cn}"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(crt), "-days", "365",
            "-subj", subj, "-addext", f"subjectAltName=DNS:{cn}",
        ],
        check=True, capture_output=True,
    )
    return crt, key


def build_ssl_context(persona: str, profile_name: str, cn: str) -> ssl.SSLContext:
    """Server SSLContext configured for the persona's profile."""
    prof = PROFILES[profile_name]
    crt, key = generate_cert(persona, profile_name, cn)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = prof["min"]
    ctx.maximum_version = prof["max"]
    # set_ciphers only affects <= TLS 1.2 (1.3 suites are fixed by OpenSSL)
    if prof["min"] != ssl.TLSVersion.TLSv1_3:
        try:
            ctx.set_ciphers(prof["ciphers"])
        except ssl.SSLError:
            pass
    ctx.set_alpn_protocols(prof["alpn"])
    ctx.load_cert_chain(certfile=str(crt), keyfile=str(key))
    return ctx


if __name__ == "__main__":
    # Pre-generate one cert per HTTPS persona (filename = persona, CN = DNS zone).
    PERSONA_CN = {
        "portal_ovh": ("nginx_modern", "portal.miraige.lab"),
        "k8s_apiserver": ("k8s_go", "k8s.miraige.lab"),
        "admin_panel": ("gunicorn_py", "admin.miraige.lab"),
    }
    for persona, (profile, cn) in PERSONA_CN.items():
        crt, _ = generate_cert(persona, profile, cn)
        print(f"{persona:14} {profile:12} O={PROFILES[profile]['issuer_o']:16} -> {crt.name}")
