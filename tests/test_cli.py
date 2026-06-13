"""Tests for the miraige CLI (stdlib-only, no Docker/network)."""
import json

import miraige_cli.cli as cli


def test_up_invokes_compose_up(monkeypatch):
    seen = {}

    def rec(*a):
        seen["args"] = a
        return 0

    monkeypatch.setattr(cli, "_compose", rec)
    assert cli.main(["up", "--build"]) == 0
    assert seen["args"] == ("up", "-d", "--build")


def test_up_without_build(monkeypatch):
    seen = {}
    monkeypatch.setattr(cli, "_compose", lambda *a: seen.update(args=a) or 0)
    cli.main(["up"])
    assert seen["args"] == ("up", "-d")


def test_down_invokes_compose_down(monkeypatch):
    seen = {}
    monkeypatch.setattr(cli, "_compose", lambda *a: seen.update(args=a) or 0)
    cli.main(["down"])
    assert seen["args"] == ("down",)


def test_status_prints_health(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_http", lambda m, p, **k: {"status": "ok", "backends": {"sentinel": "ok"}})
    assert cli.main(["status"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "ok"


def test_status_falls_back_to_compose_ps(monkeypatch):
    def boom(*a, **k):
        raise OSError("nope")

    seen = {}
    monkeypatch.setattr(cli, "_http", boom)
    monkeypatch.setattr(cli, "_compose", lambda *a: seen.update(args=a) or 7)
    assert cli.main(["status"]) == 7
    assert seen["args"] == ("ps",)


def test_attack_builds_command(monkeypatch):
    seen = {}
    monkeypatch.setattr(cli.subprocess, "call", lambda cmd: seen.update(cmd=cmd) or 0)
    cli.main(["attack", "--level", "stealth", "--duration", "30"])
    cmd = seen["cmd"]
    assert "services.attack_simulator.attack" in cmd
    assert cmd[cmd.index("--level") + 1] == "stealth"
    assert cmd[cmd.index("--duration") + 1] == "30"


def test_reset_needs_password(monkeypatch, capsys):
    monkeypatch.delenv("DASHBOARD_PASSWORD", raising=False)
    assert cli.main(["reset"]) == 1
    assert "need --password" in capsys.readouterr().err


def test_reset_logs_in_then_posts(monkeypatch, capsys):
    calls = []

    def fake_http(method, path, token=None, body=None):
        calls.append((method, path, token, body))
        return {"token": "T0K"} if path == "/api/v1/login" else {"reset": {"sentinel": {"reset": True}}}

    monkeypatch.setattr(cli, "_http", fake_http)
    assert cli.main(["reset", "--password", "pw"]) == 0
    assert calls[0] == ("POST", "/api/v1/login", None, {"password": "pw"})
    assert calls[1][:3] == ("POST", "/api/v1/admin/reset", "T0K")
    assert "reset" in capsys.readouterr().out


def test_logs_invokes_compose_logs(monkeypatch):
    seen = {}
    monkeypatch.setattr(cli, "_compose", lambda *a: seen.update(args=a) or 0)
    
    # logs with no service
    assert cli.main(["logs"]) == 0
    assert seen["args"] == ("logs", "-f")
    
    # logs with a service
    assert cli.main(["logs", "sentinel"]) == 0
    assert seen["args"] == ("logs", "-f", "sentinel")


def test_reset_api_unreachable(monkeypatch, capsys):
    def fake_http(method, path, token=None, body=None):
        import urllib.error
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(cli, "_http", fake_http)
    assert cli.main(["reset", "--password", "pw"]) == 1
    assert "error: API unreachable" in capsys.readouterr().err


def test_reset_login_failed(monkeypatch, capsys):
    # API reachable but token missing in response
    monkeypatch.setattr(cli, "_http", lambda m, p, **k: {})
    assert cli.main(["reset", "--password", "pw"]) == 1
    assert "error: login failed" in capsys.readouterr().err

