"""Attack surface monitoring — snapshot, diff, watch, trigger."""

from decepticon.asm.differ import SurfaceDiff, diff_snapshots
from decepticon.asm.snapshot import (
    Asset,
    AssetKind,
    AttackSurfaceSnapshot,
    capture_snapshot,
)
from decepticon.asm.trigger import TriggerEngine, on_new_asset
from decepticon.asm.watcher import ASMWatcher

__all__ = [
    "ASMWatcher",
    "Asset",
    "AssetKind",
    "AttackSurfaceSnapshot",
    "SurfaceDiff",
    "TriggerEngine",
    "capture_snapshot",
    "diff_snapshots",
    "on_new_asset",
]
