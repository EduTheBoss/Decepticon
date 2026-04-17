"""Attack surface diffing."""

from __future__ import annotations

from pydantic import BaseModel, Field

from decepticon.asm.snapshot import Asset, AttackSurfaceSnapshot


class SurfaceDiff(BaseModel):
    added: list[Asset] = Field(default_factory=list)
    removed: list[Asset] = Field(default_factory=list)
    changed: list[tuple[Asset, Asset]] = Field(default_factory=list)

    @property
    def is_significant(self) -> bool:
        return bool(self.added or self.changed)


def diff_snapshots(old: AttackSurfaceSnapshot | None, new: AttackSurfaceSnapshot) -> SurfaceDiff:
    if old is None:
        return SurfaceDiff(added=list(new.assets))
    old_map = {a.key: a for a in old.assets}
    new_map = {a.key: a for a in new.assets}
    added = [new_map[k] for k in new_map.keys() - old_map.keys()]
    removed = [old_map[k] for k in old_map.keys() - new_map.keys()]
    changed: list[tuple[Asset, Asset]] = []
    for k in old_map.keys() & new_map.keys():
        if old_map[k].metadata != new_map[k].metadata:
            changed.append((old_map[k], new_map[k]))
    return SurfaceDiff(added=added, removed=removed, changed=changed)


__all__ = ["SurfaceDiff", "diff_snapshots"]
