"""ASMWatcher — background loop capturing + diffing attack surface snapshots.

Snapshots persist to ``workspace/asm/<target>/<iso8601>.json`` for audit.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any, Awaitable, Callable, Protocol

from decepticon.asm.differ import SurfaceDiff, diff_snapshots
from decepticon.asm.snapshot import AttackSurfaceSnapshot, capture_snapshot
from decepticon.core.logging import get_logger

log = get_logger("asm.watcher")


class _SandboxLike(Protocol):
    async def run(self, cmd: str, *, timeout: float | None = None) -> Any:
        pass


DiffCallback = Callable[[str, SurfaceDiff], Awaitable[None] | None]


class ASMWatcher:
    def __init__(
        self,
        target: str,
        *,
        interval_s: float = 3600.0,
        sandbox: _SandboxLike | None = None,
        callback: DiffCallback | None = None,
        persist_dir: str | Path = "workspace/asm",
    ):
        self.target = target
        self.interval_s = interval_s
        self.sandbox = sandbox
        self.callback = callback
        self.persist_dir = Path(persist_dir) / target
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self._prev: AttackSurfaceSnapshot | None = None
        self._task: asyncio.Task | None = None
        self._stopping = asyncio.Event()

    async def _tick(self) -> None:
        snap = await capture_snapshot(self.target, self.sandbox)
        ts = snap.captured_at.strftime("%Y%m%dT%H%M%SZ")
        path = self.persist_dir / f"{ts}.json"
        path.write_text(snap.model_dump_json(indent=2), encoding="utf-8")
        diff = diff_snapshots(self._prev, snap)
        self._prev = snap
        if self._prev is not None and diff.is_significant and self.callback:
            out = self.callback(self.target, diff)
            if asyncio.iscoroutine(out):
                _ = await out
        log.info(
            "asm.tick",
            extra={"target": self.target, "added": len(diff.added), "removed": len(diff.removed)},
        )

    async def run_forever(self) -> None:
        self._stopping.clear()
        while not self._stopping.is_set():
            try:
                await self._tick()
            except Exception as e:  # noqa: BLE001
                log.error("asm.tick_error", extra={"err": str(e)})
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=self.interval_s)
            except asyncio.TimeoutError:
                # Interval elapsed without stop request — loop around.
                continue

    def start(self) -> asyncio.Task:
        self._task = asyncio.create_task(self.run_forever())
        return self._task

    def stop(self) -> None:
        self._stopping.set()


def main() -> None:
    parser = argparse.ArgumentParser(description="Decepticon ASM watcher")
    parser.add_argument("target")
    parser.add_argument("--interval", type=float, default=3600.0, help="seconds between scans")
    args = parser.parse_args()

    watcher = ASMWatcher(args.target, interval_s=args.interval)

    async def _go() -> None:
        await watcher.run_forever()

    try:
        asyncio.run(_go())
    except KeyboardInterrupt:
        sys.exit(0)


__all__ = ["ASMWatcher", "main"]
