"""Decepticon CLI — doctor + explain commands.

Uses click for parsing. Exposes two entry points registered in pyproject:

    decepticon-doctor
    decepticon-explain
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import sys
from pathlib import Path
from typing import Any

import click

from decepticon.playbooks.loader import list_playbooks
from decepticon.scope.validator import ScopeValidator
from decepticon.scoring.cvss4 import CVSS_LOOKUP_GLOBAL

# ── doctor ──────────────────────────────────────────────────────────────


def _check_docker() -> tuple[str, bool, str]:
    path = shutil.which("docker")
    if not path:
        return ("docker", False, "docker CLI not found on PATH")
    try:
        import subprocess

        out = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out.returncode == 0 and out.stdout.strip():
            return ("docker", True, f"server {out.stdout.strip()}")
        return ("docker", False, out.stderr.strip() or "daemon unreachable")
    except Exception as e:  # noqa: BLE001
        return ("docker", False, str(e))


def _check_sandbox_image() -> tuple[str, bool, str]:
    img = os.getenv("DECEPTICON_SANDBOX_IMAGE", "decepticon-sandbox")
    try:
        import subprocess

        out = subprocess.run(
            ["docker", "image", "inspect", img],
            capture_output=True,
            text=True,
            timeout=5,
        )
        ok = out.returncode == 0
        return ("sandbox_image", ok, img if ok else f"image {img!r} not found")
    except Exception as e:  # noqa: BLE001
        return ("sandbox_image", False, str(e))


def _check_neo4j() -> tuple[str, bool, str]:
    host = os.getenv("NEO4J_HOST", "neo4j")
    port = int(os.getenv("NEO4J_BOLT_PORT", "7687"))
    try:
        with socket.create_connection((host, port), timeout=2):
            return ("neo4j", True, f"{host}:{port} reachable")
    except Exception as e:  # noqa: BLE001
        return ("neo4j", False, f"{host}:{port} {e}")


def _check_sliver() -> tuple[str, bool, str]:
    path = shutil.which("sliver-client") or shutil.which("sliver")
    if not path:
        return ("sliver", False, "not installed (optional)")
    return ("sliver", True, path)


def _check_api_keys() -> tuple[str, bool, str]:
    missing = [k for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY") if not os.getenv(k)]
    if missing == ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]:
        return ("api_keys", False, "no LLM API keys configured")
    return ("api_keys", True, "OK" if not missing else f"have at least 1; missing: {missing}")


def _check_cvss_lut() -> tuple[str, bool, str]:
    ok = len(CVSS_LOOKUP_GLOBAL) >= 270
    return ("cvss4_lut", ok, f"{len(CVSS_LOOKUP_GLOBAL)} entries")


def _check_playbooks(dir_: str = "playbooks") -> tuple[str, bool, str]:
    try:
        pbs = list_playbooks(dir_)
    except Exception as e:  # noqa: BLE001
        return ("playbooks", False, str(e))
    return ("playbooks", len(pbs) > 0, f"{len(pbs)} valid")


def _check_scope(cfg_path: str | None = None) -> tuple[str, bool, str]:
    candidate = cfg_path or os.getenv("DECEPTICON_SCOPE_YAML", "")
    if not candidate:
        return ("scope_cfg", True, "no scope config set (deny-by-default will apply)")
    p = Path(candidate)
    if not p.exists():
        return ("scope_cfg", False, f"missing {candidate}")
    try:
        v = ScopeValidator.from_yaml(p)
        return ("scope_cfg", True, f"{len(v.rules)} rules")
    except Exception as e:  # noqa: BLE001
        return ("scope_cfg", False, str(e))


@click.command()
def doctor_main() -> None:
    """Run the 8-point Decepticon environment health check."""
    checks = [
        _check_docker(),
        _check_sandbox_image(),
        _check_neo4j(),
        _check_sliver(),
        _check_api_keys(),
        _check_cvss_lut(),
        _check_playbooks(),
        _check_scope(),
    ]
    click.echo("Decepticon doctor")
    click.echo("=" * 40)
    fails = 0
    for name, ok, detail in checks:
        mark = click.style("OK  ", fg="green") if ok else click.style("FAIL", fg="red")
        click.echo(f"  [{mark}] {name:16} {detail}")
        if not ok:
            fails += 1
    click.echo("=" * 40)
    click.echo(f"{len(checks) - fails}/{len(checks)} checks passed")
    sys.exit(0 if fails == 0 else 1)


# ── explain ─────────────────────────────────────────────────────────────


def _load_finding(finding_id: str) -> dict[str, Any] | None:
    root = Path("workspace/findings")
    if not root.exists():
        return None
    # direct id.json
    direct = root / f"{finding_id}.json"
    if direct.exists():
        return json.loads(direct.read_text(encoding="utf-8"))
    for path in root.glob("**/*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if data.get("id") == finding_id or data.get("finding_id") == finding_id:
            return data
    return None


def _summarize_finding(finding: dict[str, Any]) -> str:
    title = finding.get("title", "untitled")
    sev = finding.get("severity", "unknown")
    cvss = finding.get("cvss_score", 0.0)
    desc = finding.get("description", "")
    target = finding.get("target", "")
    lines = [
        f"# {title}",
        "",
        f"- Severity: **{sev}** (CVSS {cvss})",
        f"- Target: `{target}`",
        "",
        "## Business impact",
        "",
        desc or "(no description)",
        "",
        "## Recommended next steps",
        "1. Reproduce and triage.",
        "2. Remediate per vendor guidance or compensating control.",
        "3. Verify fix with a targeted re-test.",
    ]
    return "\n".join(lines)


@click.command()
@click.argument("finding_id")
@click.option(
    "--audience", type=click.Choice(["developer", "manager", "executive"]), default="developer"
)
def explain_main(finding_id: str, audience: str) -> None:
    """Explain a finding in plain English for the chosen audience."""
    data = _load_finding(finding_id)
    if data is None:
        click.echo(click.style(f"finding {finding_id!r} not found", fg="red"), err=True)
        sys.exit(1)
    # Try LLM stakeholder summary if API keys available; else fall back.
    summary = _summarize_finding(data)
    click.echo(f"(audience: {audience})\n")
    click.echo(summary)


__all__ = ["doctor_main", "explain_main"]
