"""Diff trigger — launches a new engagement when new assets appear."""

from __future__ import annotations

import time
from typing import Any, Awaitable, Callable, Protocol

from decepticon.asm.differ import SurfaceDiff
from decepticon.core.logging import get_logger

log = get_logger("asm.trigger")


class _OrchestratorLike(Protocol):
    async def launch(self, target: str, reason: str = "") -> Any:
        pass


class TriggerEngine:
    """Rate-limited auto-launcher: max N campaigns per target per 24h."""

    def __init__(
        self,
        *,
        max_per_day: int = 3,
        launch: Callable[[str, SurfaceDiff], Awaitable[Any]] | None = None,
    ):
        self.max_per_day = max_per_day
        self._launch = launch
        self._history: dict[str, list[float]] = {}

    def _can(self, target: str) -> bool:
        cutoff = time.time() - 86400.0
        hist = [t for t in self._history.get(target, []) if t > cutoff]
        self._history[target] = hist
        return len(hist) < self.max_per_day

    def _record(self, target: str) -> None:
        self._history.setdefault(target, []).append(time.time())

    async def on_new_asset(self, target: str, diff: SurfaceDiff) -> bool:
        if not diff.is_significant:
            return False
        if not self._can(target):
            log.info("asm.trigger.ratelimited", extra={"target": target})
            return False
        self._record(target)
        if self._launch:
            await self._launch(target, diff)
        log.info(
            "asm.trigger.launched",
            extra={"target": target, "new_assets": len(diff.added)},
        )
        return True


async def on_new_asset(diff: SurfaceDiff, orchestrator: _OrchestratorLike) -> bool:
    """Simple functional helper: launch engagement for any added asset."""
    if not diff.is_significant:
        return False
    for a in diff.added:
        await orchestrator.launch(a.value, reason=f"new {a.kind}")
    return True


__all__ = ["TriggerEngine", "on_new_asset"]
