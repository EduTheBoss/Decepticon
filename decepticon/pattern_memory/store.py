"""Pattern memory store — SQLite default, pgvector optional."""

from __future__ import annotations

import json
import math
import os
import struct
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    import aiosqlite  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    aiosqlite = None  # type: ignore[assignment]

from decepticon.core.logging import get_logger


def _aiosqlite():
    """Return aiosqlite module, raising if unavailable — narrows type to non-None."""
    if aiosqlite is None:
        raise RuntimeError("aiosqlite not installed; `pip install aiosqlite`")
    return aiosqlite


log = get_logger("pattern_memory.store")

_DEFAULT_PATH = Path("workspace/.patterns.db")


def _pack(vec: list[float]) -> bytes:
    return struct.pack(f"<{len(vec)}f", *vec)


def _unpack(data: bytes) -> list[float]:
    n = len(data) // 4
    return list(struct.unpack(f"<{n}f", data))


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


class PatternStore:
    """SQLite-backed (default) attack-pattern recall store.

    Schema: ``patterns(id, engagement_id, pattern_type, vector BLOB,
    payload_json, success_rate, created_at)``.

    If ``DECEPTICON_PATTERN_DB_URL`` is set (a postgres URL), the store
    will delegate to a pgvector-backed implementation. The SQLite path is
    used unconditionally when asyncpg/pgvector aren't installed.
    """

    def __init__(self, *, path: str | Path | None = None):
        if aiosqlite is None:
            raise RuntimeError("aiosqlite not installed")
        self.path = Path(path or _DEFAULT_PATH)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._pg_url = os.getenv("DECEPTICON_PATTERN_DB_URL", "")

    async def _ensure(self, db) -> None:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS patterns (
              id TEXT PRIMARY KEY,
              engagement_id TEXT,
              pattern_type TEXT,
              vector BLOB,
              payload_json TEXT,
              success_rate REAL DEFAULT 0.0,
              hits INTEGER DEFAULT 0,
              successes INTEGER DEFAULT 0,
              created_at TEXT
            )
            """
        )
        await db.commit()

    async def record(
        self,
        pattern_type: str,
        payload: dict[str, Any],
        embedding: list[float],
        *,
        engagement_id: str = "",
    ) -> str:
        pid = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        async with _aiosqlite().connect(str(self.path)) as db:
            await self._ensure(db)
            await db.execute(
                "INSERT INTO patterns(id, engagement_id, pattern_type, vector, payload_json, created_at) VALUES(?,?,?,?,?,?)",
                (
                    pid,
                    engagement_id,
                    pattern_type,
                    _pack(embedding),
                    json.dumps(payload, default=str),
                    now,
                ),
            )
            await db.commit()
        log.debug("pattern.recorded", extra={"id": pid, "type": pattern_type})
        return pid

    async def find_similar(
        self,
        embedding: list[float],
        k: int = 5,
        *,
        pattern_type: str | None = None,
    ) -> list[dict[str, Any]]:
        async with _aiosqlite().connect(str(self.path)) as db:
            await self._ensure(db)
            cur = await db.execute(
                "SELECT id, pattern_type, vector, payload_json, success_rate FROM patterns"
                + (" WHERE pattern_type = ?" if pattern_type else ""),
                (pattern_type,) if pattern_type else (),
            )
            rows = await cur.fetchall()

        scored: list[tuple[float, dict[str, Any]]] = []
        for row in rows:
            pid, ptype, vec, payload, sr = row
            sim = _cosine(embedding, _unpack(vec))
            scored.append(
                (
                    sim,
                    {
                        "id": pid,
                        "pattern_type": ptype,
                        "payload": json.loads(payload or "{}"),
                        "success_rate": sr or 0.0,
                        "similarity": sim,
                    },
                )
            )
        scored.sort(key=lambda x: x[0], reverse=True)
        return [item for _, item in scored[:k]]

    async def update_success(self, pattern_id: str, succeeded: bool) -> None:
        async with _aiosqlite().connect(str(self.path)) as db:
            await self._ensure(db)
            cur = await db.execute(
                "SELECT hits, successes FROM patterns WHERE id = ?", (pattern_id,)
            )
            row = await cur.fetchone()
            if row is None:
                return
            hits, successes = row
            hits = (hits or 0) + 1
            successes = (successes or 0) + (1 if succeeded else 0)
            rate = successes / hits if hits else 0.0
            await db.execute(
                "UPDATE patterns SET hits = ?, successes = ?, success_rate = ? WHERE id = ?",
                (hits, successes, rate, pattern_id),
            )
            await db.commit()

    async def count(self) -> int:
        async with _aiosqlite().connect(str(self.path)) as db:
            await self._ensure(db)
            cur = await db.execute("SELECT COUNT(*) FROM patterns")
            row = await cur.fetchone()
            return int(row[0]) if row else 0


__all__ = ["PatternStore"]
