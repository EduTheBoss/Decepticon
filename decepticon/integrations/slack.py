"""Slack notifier — Block Kit messages via webhook."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

import httpx
from pydantic import BaseModel

from decepticon.core.logging import get_logger

log = get_logger("integrations.slack")


_EMOJI = {
    "Critical": ":red_circle:",
    "High": ":large_orange_circle:",
    "Medium": ":large_yellow_circle:",
    "Low": ":large_green_circle:",
    "Info": ":white_circle:",
    "None": ":white_circle:",
}


class SlackFinding(BaseModel):
    title: str
    severity: str = "Medium"
    cvss_score: float = 0.0
    target: str = ""
    description: str = ""


class SlackNotifier:
    def __init__(self, webhook_url: str | None = None, *, timeout: float = 10.0):
        self.webhook_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL", "")
        self._timeout = timeout

    async def _post(self, blocks: list[dict[str, Any]], *, text: str = "") -> None:
        if not self.webhook_url:
            log.debug("slack.no_webhook")
            return
        payload: dict[str, Any] = {"blocks": blocks}
        if text:
            payload["text"] = text
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            r = await client.post(self.webhook_url, json=payload)
            r.raise_for_status()

    async def notify_finding(self, f: SlackFinding) -> None:
        emoji = _EMOJI.get(f.severity, ":white_circle:")
        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} {f.severity} finding"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Title:*\n{f.title}"},
                    {"type": "mrkdwn", "text": f"*CVSS:*\n{f.cvss_score:.1f}"},
                    {"type": "mrkdwn", "text": f"*Target:*\n`{f.target}`"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{f.severity}"},
                ],
            },
        ]
        if f.description:
            blocks.append(
                {"type": "section", "text": {"type": "mrkdwn", "text": f.description[:3000]}}
            )
        await self._post(blocks, text=f"{f.severity}: {f.title}")

    async def notify_start(self, target: str, objective: str = "") -> None:
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": ":rocket: Engagement started"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n`{target}`"},
                    {"type": "mrkdwn", "text": f"*Objective:*\n{objective or 'N/A'}"},
                ],
            },
        ]
        await self._post(blocks, text=f"Engagement started on {target}")

    async def notify_complete(self, target: str, findings: int, duration_s: float) -> None:
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": ":white_check_mark: Engagement complete"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n`{target}`"},
                    {"type": "mrkdwn", "text": f"*Findings:*\n{findings}"},
                    {"type": "mrkdwn", "text": f"*Duration:*\n{duration_s:.1f}s"},
                ],
            },
        ]
        await self._post(blocks, text=f"Engagement complete on {target}")

    async def notify_daily_digest(self, summary: dict[str, int]) -> None:
        rows = "\n".join(f"*{k}:* {v}" for k, v in summary.items())
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": ":bar_chart: Daily digest"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": rows or "no activity"}},
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": datetime.utcnow().isoformat()}],
            },
        ]
        await self._post(blocks, text="Daily digest")


__all__ = ["SlackNotifier", "SlackFinding"]
