"""MCP tool implementations for Decepticon."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from decepticon.cleanup.emergency import emergency_stop
from decepticon.cleanup.registry import CleanupRegistry
from decepticon.core.logging import get_logger
from decepticon.playbooks.loader import list_playbooks
from decepticon.playbooks.runner import PlaybookRunner

log = get_logger("mcp.tools")


PLAYBOOK_DIR = Path("playbooks")
FINDINGS_DIR = Path("workspace/findings")


async def start_engagement(
    target: str, objective: str = "", scope: list[str] | None = None
) -> dict[str, Any]:
    """Start a new autonomous engagement. Returns {engagement_id, status}."""
    import uuid

    eid = str(uuid.uuid4())
    eng_dir = Path("workspace/engagements") / eid
    eng_dir.mkdir(parents=True, exist_ok=True)
    cfg = {
        "engagement_id": eid,
        "target": target,
        "objective": objective or "Find all exploitable vulnerabilities.",
        "scope": scope or [target],
        "status": "queued",
    }
    (eng_dir / "config.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    log.info("mcp.engagement.start", extra={"engagement_id": eid, "target": target})
    return cfg


async def get_findings(engagement_id: str | None = None) -> list[dict[str, Any]]:
    """Read findings JSON files from workspace/findings/[<engagement>]/."""
    root = FINDINGS_DIR if engagement_id is None else FINDINGS_DIR / engagement_id
    if not root.exists():
        return []
    out: list[dict[str, Any]] = []
    for p in sorted(root.glob("**/*.json")):
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except Exception:  # noqa: BLE001
            continue
    return out


async def get_status(engagement_id: str) -> dict[str, Any]:
    """Return the current status blob for an engagement."""
    cfg_path = Path("workspace/engagements") / engagement_id / "config.json"
    if not cfg_path.exists():
        return {"engagement_id": engagement_id, "status": "unknown"}
    return json.loads(cfg_path.read_text(encoding="utf-8"))


async def emergency_stop_tool() -> dict[str, Any]:
    """Run LIFO cleanup ledger; report executed/failed counts."""
    registry = CleanupRegistry()
    stats = await emergency_stop(registry, None, timeout_s=5.0)
    return stats


async def list_skills() -> list[str]:
    """Return the list of installed soundwave skills."""
    skills_dir = Path("skills")
    if not skills_dir.exists():
        return []
    return sorted(p.name for p in skills_dir.iterdir() if p.is_dir())


async def list_playbooks_tool() -> list[dict[str, Any]]:
    """Enumerate playbooks under the project playbooks/ directory."""
    out = []
    for pb in list_playbooks(PLAYBOOK_DIR):
        out.append(
            {
                "name": pb.name,
                "description": pb.description,
                "version": pb.version,
                "tags": pb.tags,
                "phase_count": len(pb.phases),
            }
        )
    return out


async def run_playbook(
    name: str, target: str, variables: dict[str, str] | None = None
) -> dict[str, Any]:
    """Run a named playbook against ``target``."""
    pbs = {p.name: p for p in list_playbooks(PLAYBOOK_DIR)}
    pb = pbs.get(name)
    if pb is None:
        return {"error": f"playbook {name!r} not found", "available": list(pbs)}
    runner = PlaybookRunner()
    results = await runner.run(pb, target=target, user_vars=variables or {})
    return {"playbook": name, "target": target, "phases": results}


__all__ = [
    "emergency_stop_tool",
    "get_findings",
    "get_status",
    "list_playbooks_tool",
    "list_skills",
    "run_playbook",
    "start_engagement",
]
