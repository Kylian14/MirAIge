"""Helm chart structure tests (+ a full render/lint when helm is available)."""
import pathlib
import shutil
import subprocess

import pytest
import yaml

CHART = pathlib.Path(__file__).resolve().parents[1] / "deploy" / "helm" / "miraige"
SERVICES = {"sentinel", "orchestrator", "mcp_server", "mirage_metrics",
            "ghost_shell", "fake_portal_prod", "api"}


def test_chart_metadata():
    meta = yaml.safe_load((CHART / "Chart.yaml").read_text())
    assert meta["name"] == "miraige"
    assert meta["version"] and meta["appVersion"]


def test_values_cover_services_and_only_api_public():
    vals = yaml.safe_load((CHART / "values.yaml").read_text())
    assert set(vals["services"]) == SERVICES
    public = [s for s, c in vals["services"].items() if c.get("public")]
    assert public == ["api"]  # the console/API is the only public surface
    assert set(vals["secrets"]) >= {
        "DASHBOARD_PASSWORD", "A2A_SHARED_SECRET", "SECRET_SALT", "MG_RESET_SECRET",
    }
    # underscored compose names must be hyphenated in the in-cluster URLs (DNS-1035)
    assert vals["config"]["MCP_SERVER_URL"] == "http://mcp-server:8003"


def test_templates_present():
    names = {p.name for p in (CHART / "templates").iterdir()}
    assert {"_helpers.tpl", "configmap.yaml", "secret.yaml", "services.yaml",
            "redis.yaml", "ingress.yaml", "NOTES.txt"} <= names


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")
def test_helm_template_renders():
    out = subprocess.run(
        ["helm", "template", "rel", str(CHART)], capture_output=True, text=True,
    )
    assert out.returncode == 0, out.stderr
    docs = [d for d in yaml.safe_load_all(out.stdout) if d]
    kinds = [d["kind"] for d in docs]
    assert kinds.count("Deployment") == len(SERVICES) + 1  # services + redis
    assert kinds.count("Service") == len(SERVICES) + 1
    assert kinds.count("Ingress") == 1
    services = {d["metadata"]["name"] for d in docs if d["kind"] == "Service"}
    assert {"api", "sentinel", "mcp-server", "redis"} <= services


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")
def test_helm_lint_passes():
    out = subprocess.run(["helm", "lint", str(CHART)], capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr
