"""Mir[AI]ge control CLI — a thin, dependency-free wrapper over docker compose,
the BFF API, and the attack simulator.

  miraige up [--build]      build/start the stack
  miraige down              stop the stack
  miraige status            aggregate health via the API (else: compose ps)
  miraige logs [service]    follow logs
  miraige attack ...        run the attack simulator
  miraige reset             reset all services (via the authenticated API)
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

API = os.environ.get("MIRAIGE_API", "http://localhost:8000")


# ─── helpers ──────────────────────────────────────────────────────────

def _compose(*args: str) -> int:
    return subprocess.call(["docker", "compose", *args])


def _http(method: str, path: str, token: str | None = None, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 (trusted local API)
        return json.loads(resp.read() or "{}")


# ─── commands ─────────────────────────────────────────────────────────

def cmd_up(a) -> int:
    args = ["up", "-d"] + (["--build"] if a.build else [])
    return _compose(*args)


def cmd_down(a) -> int:
    return _compose("down")


def cmd_logs(a) -> int:
    return _compose("logs", "-f", *([a.service] if a.service else []))


def cmd_status(a) -> int:
    try:
        print(json.dumps(_http("GET", "/api/v1/health"), indent=2))
        return 0
    except (urllib.error.URLError, OSError) as e:
        print(f"API unreachable ({e}); falling back to `docker compose ps`", file=sys.stderr)
        return _compose("ps")


def cmd_attack(a) -> int:
    return subprocess.call([
        sys.executable, "-m", "services.attack_simulator.attack",
        "--target", a.target, "--level", a.level, "--duration", str(a.duration),
    ])


def cmd_reset(a) -> int:
    password = a.password or os.environ.get("DASHBOARD_PASSWORD")
    if not password:
        print("error: need --password or DASHBOARD_PASSWORD", file=sys.stderr)
        return 1
    try:
        token = _http("POST", "/api/v1/login", body={"password": password}).get("token")
    except (urllib.error.URLError, OSError) as e:
        print(f"error: API unreachable ({e})", file=sys.stderr)
        return 1
    if not token:
        print("error: login failed", file=sys.stderr)
        return 1
    print(json.dumps(_http("POST", "/api/v1/admin/reset", token=token), indent=2))
    return 0


# ─── parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="miraige", description="Mir[AI]ge control CLI")
    sub = p.add_subparsers(dest="command", required=True)

    up = sub.add_parser("up", help="build/start the stack")
    up.add_argument("--build", action="store_true", help="rebuild images first")
    up.set_defaults(func=cmd_up)

    sub.add_parser("down", help="stop the stack").set_defaults(func=cmd_down)

    lg = sub.add_parser("logs", help="follow logs")
    lg.add_argument("service", nargs="?", help="a single service (default: all)")
    lg.set_defaults(func=cmd_logs)

    sub.add_parser("status", help="aggregate health via the API").set_defaults(func=cmd_status)

    at = sub.add_parser("attack", help="run the attack simulator")
    at.add_argument("--target", default="http://localhost:8090")
    at.add_argument("--level", default="noisy")
    at.add_argument("--duration", type=int, default=60)
    at.set_defaults(func=cmd_attack)

    rs = sub.add_parser("reset", help="reset all services (authenticated)")
    rs.add_argument("--password", help="console password (else $DASHBOARD_PASSWORD)")
    rs.set_defaults(func=cmd_reset)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
