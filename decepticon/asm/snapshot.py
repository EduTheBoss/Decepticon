"""Attack surface snapshot primitives."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, Field


class AssetKind(StrEnum):
    SUBDOMAIN = "subdomain"
    HOST = "host"
    PORT = "port"
    ENDPOINT = "endpoint"
    TECHNOLOGY = "technology"
    CERT = "cert"


class Asset(BaseModel):
    kind: AssetKind
    value: str
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.value}"


class AttackSurfaceSnapshot(BaseModel):
    target: str
    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    assets: list[Asset] = Field(default_factory=list)

    def asset_keys(self) -> set[str]:
        return {a.key for a in self.assets}


class _SandboxLike(Protocol):
    async def run(self, cmd: str, *, timeout: float | None = None) -> Any:
        pass


async def capture_snapshot(
    target: str, sandbox: _SandboxLike | None = None
) -> AttackSurfaceSnapshot:
    """Run subfinder + httpx through the sandbox and parse results.

    Falls back to an empty snapshot when no sandbox is supplied (unit tests).
    """
    snap = AttackSurfaceSnapshot(target=target)
    if sandbox is None:
        return snap
    try:
        sub = await sandbox.run(f"subfinder -silent -d {target}", timeout=120.0)
        lines = (getattr(sub, "stdout", None) or str(sub)).splitlines()
        for line in lines:
            host = line.strip()
            if host:
                snap.assets.append(Asset(kind=AssetKind.SUBDOMAIN, value=host))
    except Exception:  # noqa: BLE001 — best-effort recon
        pass

    try:
        probe_input = (
            "\n".join(a.value for a in snap.assets if a.kind == AssetKind.SUBDOMAIN) or target
        )
        probe = await sandbox.run(
            f"echo '{probe_input}' | httpx -silent -tech-detect -title -status-code",
            timeout=120.0,
        )
        text = getattr(probe, "stdout", None) or str(probe)
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            snap.assets.append(
                Asset(kind=AssetKind.ENDPOINT, value=line.split()[0], metadata={"raw": line})
            )
    except Exception:  # noqa: BLE001
        pass

    return snap


__all__ = [
    "Asset",
    "AssetKind",
    "AttackSurfaceSnapshot",
    "capture_snapshot",
]
