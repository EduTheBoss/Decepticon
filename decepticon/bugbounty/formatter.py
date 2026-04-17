"""Format findings for H1 / BC submission with CVSS 4.0 vector."""

from __future__ import annotations

from typing import Any

# Reuse existing DEC reporting renderers when available. We keep a local
# Markdown renderer so this module is independently usable in tests.


_H1_SEVERITY = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Info": "none",
    "None": "none",
}


def _get(f: Any, k: str, default: Any = "") -> Any:
    return f.get(k, default) if isinstance(f, dict) else getattr(f, k, default)


def format_hackerone(finding: Any) -> dict[str, Any]:
    """Produce the H1 report dict (title, vuln info, severity, PoC, fix)."""
    title = str(_get(finding, "title", "Security finding"))
    target = str(_get(finding, "target", ""))
    sev = str(_get(finding, "severity", "Medium"))
    cvss_score = float(_get(finding, "cvss_score", 0.0) or 0.0)
    cvss_vector = str(_get(finding, "cvss_vector", ""))
    desc = str(_get(finding, "description", ""))
    cves = list(_get(finding, "cve_ids", []) or [])
    evidence = list(_get(finding, "evidence", []) or [])

    info = ["## Summary", "", desc, ""]
    if cves:
        info += ["## CVE References", "", *[f"- {c}" for c in cves], ""]
    info += [
        "## CVSS",
        "",
        f"Score: {cvss_score:.1f} ({sev})",
    ]
    if cvss_vector:
        info += ["", f"Vector: `{cvss_vector}`"]

    poc_parts = ["## Steps to Reproduce", ""]
    if evidence:
        for i, e in enumerate(evidence, 1):
            poc_parts.append(f"### Step {i}")
            desc_e = _get(e, "description", "")
            cont_e = _get(e, "content", "")
            if desc_e:
                poc_parts.append(str(desc_e))
            poc_parts += ["```", str(cont_e), "```", ""]
    else:
        poc_parts.append("See attached evidence in the full report.")

    return {
        "title": f"{title} on {target}" if target else title,
        "vulnerability_information": "\n".join(info),
        "severity_rating": _H1_SEVERITY.get(sev, "medium"),
        "impact": _impact_text(sev),
        "proof_of_concept": "\n".join(poc_parts),
        "recommended_fix": str(_get(finding, "remediation", "")) or "See full report.",
    }


def format_bugcrowd(finding: Any) -> dict[str, Any]:
    """Produce the BC submission dict."""
    h1 = format_hackerone(finding)
    # Bugcrowd uses VRT categories; we pass the DEC attack_category through.
    return {
        "title": h1["title"],
        "vrt_id": str(_get(finding, "vrt_id", "")) or "",
        "description": h1["vulnerability_information"],
        "severity": _BC_SEVERITY.get(str(_get(finding, "severity", "Medium")), "P3"),
        "proof": h1["proof_of_concept"],
        "remediation": h1["recommended_fix"],
    }


_BC_SEVERITY = {
    "Critical": "P1",
    "High": "P2",
    "Medium": "P3",
    "Low": "P4",
    "Info": "P5",
    "None": "P5",
}


def _impact_text(severity: str) -> str:
    return {
        "Critical": "Full compromise of the application and its data.",
        "High": "Significant data exposure or system compromise.",
        "Medium": "Exploitable under certain conditions for unauthorized access.",
        "Low": "Limited direct impact; may chain with other findings.",
        "Info": "Informational; no direct impact.",
    }.get(severity, "Limited direct impact.")


__all__ = ["format_hackerone", "format_bugcrowd"]
