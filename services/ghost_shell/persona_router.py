"""
Persona router · Host header -> personality.

Several OVH VIPs all terminate in THIS container: this is where
we decide which persona to serve based on the Host header.
"""
from __future__ import annotations

from services.shared.models import GhostPersona


def resolve_persona(host_header: str) -> GhostPersona:
    """Return the persona for this Host header.

    Maps the demo hostnames to the GhostPersona enums.
    Default = PORTAL_OVH.
    """
    host = host_header.split(":")[0].lower().strip()

    if "db-prod" in host or "mysql" in host:
        return GhostPersona.MYSQL
    elif "k8s" in host or "kubernetes" in host:
        return GhostPersona.K8S_APISERVER
    elif "admin" in host:
        return GhostPersona.ADMIN_PANEL
    
    # By default, present the standard OVH portal
    return GhostPersona.PORTAL_OVH
