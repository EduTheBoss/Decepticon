"""SIEM format helpers: CEF, STIX 2.1, RFC 5424 syslog."""

from __future__ import annotations

import socket
from datetime import UTC, datetime
from typing import Any

_CEF_SEVERITY = {
    "Critical": 10,
    "High": 8,
    "Medium": 5,
    "Low": 3,
    "Info": 1,
    "None": 0,
}


def _get(f: Any, name: str, default: Any = "") -> Any:
    if isinstance(f, dict):
        return f.get(name, default)
    return getattr(f, name, default)


def to_cef(finding: Any) -> str:
    """Format finding as ArcSight CEF 0.x line."""
    sev = _CEF_SEVERITY.get(str(_get(finding, "severity", "Medium")), 5)
    title = str(_get(finding, "title", "security-finding"))
    category = str(_get(finding, "attack_category", "security"))
    target = str(_get(finding, "target", ""))
    cvss = float(_get(finding, "cvss_score", 0.0) or 0.0)
    desc = str(_get(finding, "description", "")).replace("|", "\\|").replace("\n", " ")
    return (
        f"CEF:0|Decepticon|decepticon|1.0|{category}|{title}|{sev}|"
        f"src={target} cat={category} cvss={cvss:.1f} msg={desc}"
    )


def to_stix(finding: Any) -> dict[str, Any]:
    """Return a STIX 2.1 bundle containing a single vulnerability SDO."""
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    fid = str(_get(finding, "id", "") or _get(finding, "finding_id", "") or "auto")
    sdo_id = (
        f"vulnerability--{fid}"
        if fid.count("-") >= 4
        else "vulnerability--00000000-0000-0000-0000-000000000000"
    )
    refs: list[dict[str, Any]] = []
    for cve in _get(finding, "cve_ids", []) or []:
        refs.append(
            {
                "source_name": "cve",
                "external_id": cve,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            }
        )
    vector = str(_get(finding, "cvss_vector", ""))
    if vector:
        refs.append({"source_name": "cvss-v4.0", "external_id": vector})

    vuln = {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": sdo_id,
        "created": now,
        "modified": now,
        "name": str(_get(finding, "title", "security-finding")),
        "description": str(_get(finding, "description", "")),
        "external_references": refs,
        "labels": [str(_get(finding, "severity", "Medium")).lower()],
    }
    bundle_id = f"bundle--{sdo_id.split('--', 1)[1]}"
    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": [vuln],
    }


def to_syslog_rfc5424(
    finding: Any, *, appname: str = "decepticon", hostname: str | None = None
) -> str:
    """Format finding as an RFC 5424 syslog line (facility local0)."""
    sev_map = {"Critical": 2, "High": 3, "Medium": 4, "Low": 5, "Info": 6, "None": 7}
    sev = sev_map.get(str(_get(finding, "severity", "Medium")), 4)
    pri = 16 * 8 + sev  # local0 = 16
    ts = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    host = hostname or socket.gethostname()
    msgid = str(_get(finding, "attack_category", "finding"))[:32]
    title = str(_get(finding, "title", "security-finding"))
    target = str(_get(finding, "target", ""))
    cvss = float(_get(finding, "cvss_score", 0.0) or 0.0)
    sd = f'[decepticon@53817 target="{target}" cvss="{cvss:.1f}" severity="{_get(finding, "severity", "Medium")}"]'
    return f"<{pri}>1 {ts} {host} {appname} - {msgid} {sd} {title}"


__all__ = ["to_cef", "to_stix", "to_syslog_rfc5424"]
