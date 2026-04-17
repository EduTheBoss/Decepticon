"""GitHub Action wrapper — writes SARIF, exits 1 on critical findings."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterable

from decepticon.core.logging import get_logger
from decepticon.integrations.sarif import findings_to_sarif

log = get_logger("integrations.github_action")


def run(findings: Iterable[dict], out_path: str | Path = "decepticon.sarif") -> int:
    """Write SARIF and return exit code (1 if any Critical, else 0)."""
    findings_list = list(findings)
    sarif = findings_to_sarif(findings_list)
    Path(out_path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    critical = sum(1 for f in findings_list if str(f.get("severity", "")).lower() == "critical")
    log.info("github_action.sarif_written", extra={"path": str(out_path), "critical": critical})
    return 1 if critical else 0


def main() -> None:
    """CLI entry — read JSON findings array from stdin."""
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"invalid findings JSON: {e}", file=sys.stderr)
        sys.exit(2)
    if not isinstance(data, list):
        print("findings payload must be a JSON array", file=sys.stderr)
        sys.exit(2)
    sys.exit(run(data))


__all__ = ["run", "main"]
