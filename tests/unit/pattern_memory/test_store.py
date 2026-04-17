"""Pattern memory store tests (SQLite fallback)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

aiosqlite = pytest.importorskip("aiosqlite")

from decepticon.pattern_memory.store import PatternStore  # noqa: E402


def test_record_find_update_round_trip(tmp_path: Path):
    db = tmp_path / "patterns.db"
    store = PatternStore(path=db)

    async def _run():
        pid = await store.record(
            "sqli", {"target": "https://x/"}, [0.1, 0.2, 0.3, 0.4], engagement_id="e1"
        )
        assert pid
        # Schema creation idempotent: calling record again works
        pid2 = await store.record("xss", {"target": "https://y/"}, [0.9, 0.1, 0.0, 0.0])
        assert pid2
        out = await store.find_similar([0.1, 0.2, 0.3, 0.4], k=2)
        assert out and out[0]["id"] == pid
        await store.update_success(pid, True)
        await store.update_success(pid, False)
        n = await store.count()
        assert n == 2

    asyncio.run(_run())


def test_schema_idempotent(tmp_path: Path):
    db = tmp_path / "patterns.db"
    s1 = PatternStore(path=db)
    s2 = PatternStore(path=db)

    async def _r():
        await s1.record("x", {}, [1.0, 0.0])
        await s2.record("x", {}, [0.0, 1.0])
        assert await s2.count() == 2

    asyncio.run(_r())
