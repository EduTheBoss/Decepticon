"""Emergency stop — LIFO cleanup executor with SIGINT trap."""

from __future__ import annotations

import asyncio
import signal
from typing import Any, Awaitable, Callable, Protocol

from decepticon.cleanup.registry import CleanupRegistry
from decepticon.core.logging import get_logger

log = get_logger("cleanup.emergency")


class _SandboxLike(Protocol):
    async def run(self, cmd: str, *, timeout: float | None = None) -> Any:
        pass


async def emergency_stop(
    registry: CleanupRegistry,
    sandbox: _SandboxLike | None,
    *,
    timeout_s: float = 5.0,
) -> dict[str, int]:
    """Run every pending cleanup action LIFO with a hard per-action timeout.

    Returns ``{executed, failed, skipped}`` counts.
    """
    executed = 0
    failed = 0
    skipped = 0
    for action in registry:
        if sandbox is None:
            skipped += 1
            continue
        try:
            await asyncio.wait_for(sandbox.run(action.cmd), timeout=timeout_s)
            registry.mark_executed(action.id)
            executed += 1
            log.info("cleanup.exec", extra={"id": action.id})
        except asyncio.TimeoutError:
            failed += 1
            log.error("cleanup.timeout", extra={"id": action.id, "cmd": action.cmd[:120]})
        except Exception as e:
            failed += 1
            log.error("cleanup.fail", extra={"id": action.id, "err": str(e)})
    return {"executed": executed, "failed": failed, "skipped": skipped}


def install_sigint_handler(
    callback: Callable[[], Awaitable[None] | None],
) -> None:
    """Install a SIGINT handler that schedules ``callback`` on the current loop."""

    def _handler(signum: int, frame: Any) -> None:  # noqa: ARG001
        log.warning("emergency.sigint")
        res = callback()
        if asyncio.iscoroutine(res):
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(res)
            except RuntimeError:
                asyncio.run(res)

    signal.signal(signal.SIGINT, _handler)


__all__ = ["emergency_stop", "install_sigint_handler"]
