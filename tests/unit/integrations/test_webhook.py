"""Webhook deliverer tests."""

from __future__ import annotations

import asyncio
import hashlib
import hmac

from decepticon.integrations import webhook as wh


def test_hmac_signature_stable():
    body = b'{"event_type":"finding","data":{"x":1}}'
    secret = "s3cret"
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert wh._sign(secret, body) == expected
    # Stable across calls
    assert wh._sign(secret, body) == wh._sign(secret, body)


def test_retry_count_on_failure(monkeypatch):
    attempts = {"n": 0}

    class _Resp:
        status_code = 500

    class _FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def post(self, url, content=None, headers=None):
            attempts["n"] += 1
            return _Resp()

    monkeypatch.setattr(wh.httpx, "AsyncClient", _FakeClient)
    monkeypatch.setattr(wh, "_BACKOFFS", (0.0, 0.0, 0.0))

    d = wh.WebhookDeliverer("https://example.test/hook", secret="k")
    ok = asyncio.run(d.send("finding", {"x": 1}))
    assert ok is False
    # 1 initial + 3 retries == 4 attempts
    assert attempts["n"] == 4


def test_webhook_event_filter():
    d = wh.WebhookDeliverer("x", events=("finding",))
    assert d.should_send("finding") is True
    assert d.should_send("engagement_start") is False
    d2 = wh.WebhookDeliverer("x")
    assert d2.should_send("anything") is True
