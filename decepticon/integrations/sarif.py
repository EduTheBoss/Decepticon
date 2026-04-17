"""SARIF 2.1.0 serialization."""

from __future__ import annotations

from typing import Any, Iterable


def _sarif_level(severity: str) -> str:
    s = severity.lower()
    if s in ("critical", "high"):
        return "error"
    if s == "medium":
        return "warning"
    if s == "none":
        return "none"
    return "note"


def _get(f: Any, name: str, default: Any = "") -> Any:
    if isinstance(f, dict):
        return f.get(name, default)
    return getattr(f, name, default)


def findings_to_sarif(findings: Iterable[Any]) -> dict[str, Any]:
    """Build a SARIF 2.1.0 run from an iterable of findings."""
    findings_list = list(findings)
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in findings_list:
        cat = str(_get(f, "attack_category", "security"))
        sev = str(_get(f, "severity", "Medium"))
        if cat not in rules:
            rules[cat] = {
                "id": cat,
                "name": cat,
                "shortDescription": {"text": cat},
                "defaultConfiguration": {"level": _sarif_level(sev)},
            }
        results.append(
            {
                "ruleId": cat,
                "level": _sarif_level(sev),
                "message": {"text": str(_get(f, "description", "") or _get(f, "title", ""))},
                "properties": {
                    "severity": sev,
                    "cvss_score": float(_get(f, "cvss_score", 0.0) or 0.0),
                    "cvss_vector": str(_get(f, "cvss_vector", "")),
                },
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": str(_get(f, "target", ""))}}}
                ],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "decepticon",
                        "version": "1.0.3",
                        "informationUri": "https://github.com/PurpleAILAB/Decepticon",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


__all__ = ["findings_to_sarif"]
