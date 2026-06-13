"""Secret resolution with a default-value safeguard.

Services read their secrets (A2A HMAC, admin reset, session salt) from env
variables with a hardcoded default: handy in a demo, dangerous if deployed
as-is (forgeable A2A signatures, guessable /admin/reset).

`resolve_secret` returns the resolved value and, if it still equals the unsafe
default, emits ONE warning (deduplicated per variable). Setting
`MG_STRICT_SECRETS=1` turns the use of a default into a fatal error at
startup: enable it in production.
"""
from __future__ import annotations

import hmac
import os

from services.shared import logging_config

log = logging_config.setup("secrets")

_WARNED: set[str] = set()


def check_reset_secret(provided: str | None, expected: str) -> bool:
    """Timing-safe comparison of the X-Mg-Reset header (anti timing attack)."""
    return hmac.compare_digest(provided or "", expected)


def resolve_secret(env_name: str, default: str) -> str:
    """Return the secret from the env; warn (or fail) if it isn't safe.

    Unsafe = equals the hardcoded default, OR contains a « change-me » placeholder
    (the case of an unedited `cp .env.example .env`: the .env.example placeholders
    are not equal to the code defaults, hence the double detection).
    """
    value = os.environ.get(env_name, default)
    if value == default or "change-me" in value.lower():
        strict = os.environ.get("MG_STRICT_SECRETS") == "1"
        msg = (
            f"{env_name} utilise une valeur par défaut/placeholder non sûre — "
            f"à surcharger via l'environnement avant tout déploiement exposé"
        )
        if strict:
            raise RuntimeError(f"[secret] {msg} (MG_STRICT_SECRETS=1)")
        if env_name not in _WARNED:
            _WARNED.add(env_name)
            log.warning("[secret] %s", msg)
    return value
