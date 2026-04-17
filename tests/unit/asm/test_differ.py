"""ASM differ tests."""

from __future__ import annotations

from decepticon.asm.differ import diff_snapshots
from decepticon.asm.snapshot import Asset, AssetKind, AttackSurfaceSnapshot


def _snap(target: str, assets: list[Asset]) -> AttackSurfaceSnapshot:
    return AttackSurfaceSnapshot(target=target, assets=assets)


def test_added_detected():
    old = _snap("x", [Asset(kind=AssetKind.SUBDOMAIN, value="a.x")])
    new = _snap(
        "x",
        [
            Asset(kind=AssetKind.SUBDOMAIN, value="a.x"),
            Asset(kind=AssetKind.SUBDOMAIN, value="b.x"),
        ],
    )
    d = diff_snapshots(old, new)
    assert [a.value for a in d.added] == ["b.x"]
    assert d.removed == []


def test_removed_detected():
    old = _snap(
        "x",
        [
            Asset(kind=AssetKind.SUBDOMAIN, value="a.x"),
            Asset(kind=AssetKind.SUBDOMAIN, value="b.x"),
        ],
    )
    new = _snap("x", [Asset(kind=AssetKind.SUBDOMAIN, value="a.x")])
    d = diff_snapshots(old, new)
    assert [a.value for a in d.removed] == ["b.x"]
    assert d.added == []


def test_changed_via_metadata():
    old = _snap("x", [Asset(kind=AssetKind.ENDPOINT, value="x:80", metadata={"title": "old"})])
    new = _snap("x", [Asset(kind=AssetKind.ENDPOINT, value="x:80", metadata={"title": "new"})])
    d = diff_snapshots(old, new)
    assert len(d.changed) == 1


def test_empty_to_populated():
    new = _snap("x", [Asset(kind=AssetKind.SUBDOMAIN, value="a.x")])
    d = diff_snapshots(None, new)
    assert len(d.added) == 1
    assert d.removed == []
    assert d.changed == []
