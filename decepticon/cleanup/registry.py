"""Cleanup registry + campaign state machine.

Ported from PSA ``internal/pipeline/{cleanup,statemachine}.go`` with two key
changes from the Go original:

  * Actions persist as JSONL in ``workspace/.cleanup-ledger.jsonl`` rather
    than Postgres. One line per action; survives crashes; easy to tail.
  * Iteration is LIFO (last-registered runs first) to match tear-down
    semantics for exploitation chains.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Iterator

from pydantic import BaseModel, Field

from decepticon.core.logging import get_logger

log = get_logger("cleanup.registry")

_DEFAULT_LEDGER = Path("workspace/.cleanup-ledger.jsonl")


class CleanupAction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    cmd: str
    description: str = ""
    registered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    priority: int = 100
    executed: bool = False


class CampaignState(StrEnum):
    IDLE = "idle"
    RUNNING = "running"
    ABORTING = "aborting"
    ABORTED = "aborted"
    COMPLETE = "complete"


_VALID_TRANSITIONS: dict[CampaignState, frozenset[CampaignState]] = {
    CampaignState.IDLE: frozenset({CampaignState.RUNNING}),
    CampaignState.RUNNING: frozenset({CampaignState.ABORTING, CampaignState.COMPLETE}),
    CampaignState.ABORTING: frozenset({CampaignState.ABORTED}),
    CampaignState.ABORTED: frozenset({CampaignState.IDLE}),
    CampaignState.COMPLETE: frozenset({CampaignState.IDLE}),
}


class InvalidTransitionError(RuntimeError):
    pass


class CampaignStateMachine:
    def __init__(self, initial: CampaignState = CampaignState.IDLE):
        self._state = initial

    @property
    def state(self) -> CampaignState:
        return self._state

    def transition(self, new: CampaignState) -> None:
        allowed = _VALID_TRANSITIONS.get(self._state, frozenset())
        if new not in allowed:
            raise InvalidTransitionError(f"cannot transition {self._state} -> {new}")
        log.info("campaign.transition", extra={"from": self._state, "to": new})
        self._state = new


class CleanupRegistry:
    """Append-only LIFO cleanup action log persisted as JSONL."""

    def __init__(self, ledger_path: str | Path | None = None):
        self.ledger_path = Path(ledger_path or _DEFAULT_LEDGER)
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self._actions: list[CleanupAction] = []
        self._load()

    def _load(self) -> None:
        if not self.ledger_path.exists():
            return
        try:
            for line in self.ledger_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                self._actions.append(CleanupAction.model_validate_json(line))
        except Exception as e:
            log.warning("cleanup.ledger_load_failed", extra={"err": str(e)})

    def append(self, cmd: str, description: str = "", priority: int = 100) -> CleanupAction:
        action = CleanupAction(cmd=cmd, description=description, priority=priority)
        self._actions.append(action)
        with self.ledger_path.open("a", encoding="utf-8") as fh:
            fh.write(action.model_dump_json() + "\n")
        log.info("cleanup.registered", extra={"cmd": cmd[:120], "id": action.id})
        return action

    def pending(self) -> list[CleanupAction]:
        return [a for a in self._actions if not a.executed]

    def mark_executed(self, action_id: str) -> None:
        for a in self._actions:
            if a.id == action_id:
                a.executed = True
                break
        # Rewrite the ledger (small files only; ok)
        with self.ledger_path.open("w", encoding="utf-8") as fh:
            for a in self._actions:
                fh.write(a.model_dump_json() + "\n")

    def __iter__(self) -> Iterator[CleanupAction]:
        # LIFO: newest first, respecting priority (lower priority runs later).
        return iter(
            sorted(
                (a for a in self._actions if not a.executed),
                key=lambda a: (a.priority, -a.registered_at.timestamp()),
            )
        )

    def clear(self) -> None:
        self._actions.clear()
        if self.ledger_path.exists():
            self.ledger_path.unlink()


__all__ = [
    "CleanupAction",
    "CleanupRegistry",
    "CampaignState",
    "CampaignStateMachine",
    "InvalidTransitionError",
]
