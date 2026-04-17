"""Jira client — async httpx, severity→priority map."""

from __future__ import annotations

import base64
import os
from typing import Any

import httpx
from pydantic import BaseModel

from decepticon.core.logging import get_logger

log = get_logger("integrations.jira")


_PRIORITY_MAP = {
    "Critical": "Highest",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "Info": "Lowest",
    "None": "Lowest",
}


class JiraFinding(BaseModel):
    title: str
    description: str = ""
    severity: str = "Medium"
    cvss_score: float = 0.0
    cvss_vector: str = ""
    target: str = ""
    cve_ids: list[str] = []
    attack_category: str = "security"


class JiraClient:
    """Minimal async Jira Cloud REST v3 client."""

    def __init__(
        self,
        *,
        url: str | None = None,
        user: str | None = None,
        token: str | None = None,
        project: str | None = None,
        issue_type: str = "Bug",
        timeout: float = 30.0,
    ):
        self.url = (url or os.getenv("JIRA_URL", "")).rstrip("/")
        self.user = user or os.getenv("JIRA_USER", "")
        self.token = token or os.getenv("JIRA_TOKEN", "")
        self.project = project or os.getenv("JIRA_PROJECT", "")
        self.issue_type = issue_type
        self._timeout = timeout

    @classmethod
    def severity_to_priority(cls, severity: str) -> str:
        return _PRIORITY_MAP.get(severity, "Medium")

    def _auth_header(self) -> dict[str, str]:
        raw = f"{self.user}:{self.token}".encode("utf-8")
        return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}

    def _describe(self, f: JiraFinding) -> str:
        lines = [
            f"h2. {f.title}",
            "",
            f"*Severity:* {f.severity} | *CVSS:* {f.cvss_score:.1f}",
            "",
            f.description,
            "",
            f"*Target:* {f.target}",
            f"*Category:* {f.attack_category}",
        ]
        if f.cve_ids:
            lines.append(f"*CVEs:* {', '.join(f.cve_ids)}")
        if f.cvss_vector:
            lines.append(f"*Vector:* `{f.cvss_vector}`")
        return "\n".join(lines)

    async def create_issue(self, finding: JiraFinding) -> str:
        """Create a Jira issue; returns issue key."""
        if not (self.url and self.user and self.token and self.project):
            raise RuntimeError("Jira credentials / project not configured")
        body: dict[str, Any] = {
            "fields": {
                "project": {"key": self.project},
                "summary": f"[decepticon] {finding.title}",
                "description": self._describe(finding),
                "issuetype": {"name": self.issue_type},
                "priority": {"name": self.severity_to_priority(finding.severity)},
                "labels": ["security", "decepticon", finding.severity.lower()],
            }
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            r = await client.post(
                f"{self.url}/rest/api/3/issue",
                headers={"Content-Type": "application/json", **self._auth_header()},
                json=body,
            )
            r.raise_for_status()
            data = r.json()
            key = data.get("key", "")
            log.info("jira.issue.created", extra={"key": key, "severity": finding.severity})
            return key


__all__ = ["JiraClient", "JiraFinding"]
