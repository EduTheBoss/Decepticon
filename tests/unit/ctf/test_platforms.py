"""CTF platform adapter tests."""

from __future__ import annotations

import asyncio

from decepticon.ctf import platforms as pl


class _Resp:
    def __init__(self, data, status=200):
        self._data = data
        self.status_code = status

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"http {self.status_code}")


def test_htb_list_machines_url(monkeypatch):
    captured: dict = {}

    class _FakeClient:
        def __init__(self, *a, **kw):
            self._h = kw.get("headers", {})

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def get(self, url, **kw):
            captured["url"] = url
            captured["headers"] = self._h
            return _Resp(
                {"info": [{"id": 1, "name": "Bashed", "os": "Linux", "difficultyText": "Easy"}]}
            )

    monkeypatch.setattr(pl.httpx, "AsyncClient", _FakeClient)

    a = pl.HackTheBoxAdapter(api_token="t")
    out = asyncio.run(a.list_machines())
    assert captured["url"] == f"{pl.HackTheBoxAdapter.BASE}/machine/list"
    assert captured["headers"].get("Authorization") == "Bearer t"
    assert out[0].name == "Bashed"


def test_thm_auth_header_shape(monkeypatch):
    captured: dict = {}

    class _FakeClient:
        def __init__(self, *a, **kw):
            self._h = kw.get("headers", {})

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def get(self, url, **kw):
            captured["url"] = url
            captured["headers"] = self._h
            return _Resp([])

    monkeypatch.setattr(pl.httpx, "AsyncClient", _FakeClient)

    a = pl.TryHackMeAdapter(session_cookie="abc123")
    asyncio.run(a.list_machines())
    assert "connect.sid=abc123" in captured["headers"]["Cookie"]
    assert captured["headers"]["Accept"] == "application/json"
