"""Import BB program scope into a ScopeValidator."""

from __future__ import annotations

from typing import Any

from decepticon.bugbounty import bugcrowd, hackerone, intigriti
from decepticon.bugbounty.schemas import (
    ProgramMetadata,
    ScopeAsset,
    ScopeAssetKind,
)
from decepticon.core.logging import get_logger
from decepticon.scope.validator import ScopeAction, ScopeKind, ScopeRule, ScopeValidator

log = get_logger("bugbounty.importer")


def _to_rule(asset: ScopeAsset, action: ScopeAction) -> ScopeRule | None:
    if asset.kind in (ScopeAssetKind.URL, ScopeAssetKind.WILDCARD, ScopeAssetKind.DOMAIN):
        pat = asset.identifier
        for p in ("https://", "http://"):
            if pat.startswith(p):
                pat = pat[len(p) :]
        pat = pat.rstrip("/")
        if not pat:
            return None
        return ScopeRule(pattern=pat, kind=ScopeKind.DOMAIN, action=action, notes=asset.notes)
    if asset.kind == ScopeAssetKind.IP:
        return ScopeRule(
            pattern=f"{asset.identifier}/32", kind=ScopeKind.CIDR, action=action, notes=asset.notes
        )
    if asset.kind == ScopeAssetKind.CIDR:
        return ScopeRule(
            pattern=asset.identifier, kind=ScopeKind.CIDR, action=action, notes=asset.notes
        )
    return None


async def import_program(
    platform: str,
    handle: str,
    creds: dict[str, Any] | None = None,
) -> tuple[ScopeValidator, ProgramMetadata]:
    """Fetch program scope and return (validator, metadata)."""
    creds = creds or {}
    p = platform.lower()
    if p == "hackerone":
        md = await hackerone.fetch_program_scope(
            handle,
            api_user=creds.get("api_user"),
            api_token=creds.get("api_token"),
        )
    elif p == "bugcrowd":
        md = await bugcrowd.fetch_program_scope(handle)
    elif p == "intigriti":
        md = await intigriti.fetch_program_scope(handle, api_token=creds.get("api_token"))
    else:
        raise ValueError(f"unsupported platform {platform!r}")

    rules: list[ScopeRule] = []
    for a in md.in_scope:
        r = _to_rule(a, ScopeAction.ALLOW)
        if r:
            rules.append(r)
    for a in md.out_of_scope:
        r = _to_rule(a, ScopeAction.DENY)
        if r:
            rules.append(r)

    log.info(
        "bugbounty.import",
        extra={"platform": p, "handle": handle, "rules": len(rules)},
    )
    return ScopeValidator(rules=rules), md


__all__ = ["import_program"]
