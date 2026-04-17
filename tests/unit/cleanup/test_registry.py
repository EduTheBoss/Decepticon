"""Cleanup registry + campaign state machine tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from decepticon.cleanup.registry import (
    CampaignState,
    CampaignStateMachine,
    CleanupRegistry,
    InvalidTransitionError,
)


def test_append_and_persist_jsonl(tmp_path: Path):
    ledger = tmp_path / "ledger.jsonl"
    r = CleanupRegistry(ledger_path=ledger)
    r.append("rm -rf /tmp/a", description="first")
    r.append("rm -rf /tmp/b", description="second")
    assert ledger.exists()
    lines = [ln for ln in ledger.read_text().splitlines() if ln.strip()]
    assert len(lines) == 2

    # Reload picks up existing lines
    r2 = CleanupRegistry(ledger_path=ledger)
    assert len(r2.pending()) == 2


def test_lifo_iteration(tmp_path: Path):
    ledger = tmp_path / "l.jsonl"
    r = CleanupRegistry(ledger_path=ledger)
    r.append("one", priority=100)
    r.append("two", priority=100)
    r.append("three", priority=100)
    order = [a.cmd for a in iter(r)]
    # LIFO: newest first
    assert order == ["three", "two", "one"]


def test_state_machine_valid_transitions():
    sm = CampaignStateMachine()
    assert sm.state == CampaignState.IDLE
    sm.transition(CampaignState.RUNNING)
    sm.transition(CampaignState.COMPLETE)
    sm.transition(CampaignState.IDLE)

    sm2 = CampaignStateMachine()
    sm2.transition(CampaignState.RUNNING)
    sm2.transition(CampaignState.ABORTING)
    sm2.transition(CampaignState.ABORTED)


def test_state_machine_rejects_invalid():
    sm = CampaignStateMachine()
    sm.transition(CampaignState.RUNNING)
    sm.transition(CampaignState.COMPLETE)
    with pytest.raises(InvalidTransitionError):
        sm.transition(CampaignState.RUNNING)
    with pytest.raises(InvalidTransitionError):
        sm.transition(CampaignState.ABORTING)
