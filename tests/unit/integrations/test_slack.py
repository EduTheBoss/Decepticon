"""Slack Block Kit tests."""

from __future__ import annotations

import asyncio
import json

from decepticon.integrations.slack import SlackFinding, SlackNotifier


def test_block_kit_shape_finding(monkeypatch):
    captured: dict = {}

    class _Resp:
        def raise_for_status(self):
            pass

    class _FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def post(self, url, json=None):
            captured["payload"] = json
            return _Resp()

    from decepticon.integrations import slack as sl

    monkeypatch.setattr(sl.httpx, "AsyncClient", _FakeClient)

    n = SlackNotifier(webhook_url="https://hooks.slack.test/x")
    asyncio.run(
        n.notify_finding(
            SlackFinding(
                title="SQLi",
                severity="Critical",
                cvss_score=9.3,
                target="https://x/",
            )
        )
    )

    payload = captured["payload"]
    assert "blocks" in payload
    blocks = payload["blocks"]
    assert isinstance(blocks, list) and blocks
    types = {b["type"] for b in blocks}
    assert "header" in types
    assert "section" in types


def test_block_kit_start_has_target(monkeypatch):
    captured: dict = {}

    class _Resp:
        def raise_for_status(self):
            pass

    class _FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def post(self, url, json=None):
            captured["payload"] = json
            return _Resp()

    from decepticon.integrations import slack as sl

    monkeypatch.setattr(sl.httpx, "AsyncClient", _FakeClient)

    target_url = "https://example.com"
    n = SlackNotifier(webhook_url="https://hooks.slack.test/x")
    asyncio.run(n.notify_start(target_url, "scope: owasp top10"))
    payload = captured["payload"]
    expected_target_field = f"*Target:*\n`{target_url}`"
    field_texts: list[str] = []
    for b in payload["blocks"]:
        if not isinstance(b, dict):
            continue
        for fld in b.get("fields", []) or []:
            field_texts.append(fld.get("text", ""))
    assert expected_target_field in field_texts, field_texts
    _ = json.dumps(payload)
