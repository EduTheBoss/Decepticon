"""Cleanup ledger + emergency stop."""

from decepticon.cleanup.emergency import emergency_stop, install_sigint_handler
from decepticon.cleanup.registry import (
    CampaignState,
    CampaignStateMachine,
    CleanupAction,
    CleanupRegistry,
    InvalidTransitionError,
)

__all__ = [
    "CampaignState",
    "CampaignStateMachine",
    "CleanupAction",
    "CleanupRegistry",
    "InvalidTransitionError",
    "emergency_stop",
    "install_sigint_handler",
]
