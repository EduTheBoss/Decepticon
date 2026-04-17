"""Intigriti program scope fetcher (Researcher API)."""

from __future__ import annotations

import os
from typing import Any

import httpx

from decepticon.bugbounty.schemas import ProgramMetadata, ScopeAsset, ScopeAssetKind
from decepticon.core.logging import get_logger

log = get_logger("bugbounty.intigriti")


_KIND_MAP = {
    "url": ScopeAssetKind.URL,
    "wildcard": ScopeAssetKind.WILDCARD,
    "api": ScopeAssetKind.URL,
    "android": ScopeAssetKind.ANDROID,
    "ios": ScopeAssetKind.IOS,
    "network": ScopeAssetKind.CIDR,
    "other": ScopeAssetKind.OTHER,
}


async def fetch_program_scope(
    handle: str,
    api_token: str | None = None,
    *,
    timeout: float = 30.0,
) -> ProgramMetadata:
    """Fetch Intigriti program via the researcher API."""
    token = api_token or os.getenv("INTIGRITI_API_TOKEN", "")
    if not token:
        raise RuntimeError("Intigriti API token required")
    headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
    url = f"https://api.intigriti.com/external/researcher/v1/programs/{handle}"
    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        r = await client.get(url)
        r.raise_for_status()
    data: dict[str, Any] = r.json() or {}
    md = ProgramMetadata(
        platform="intigriti",
        handle=handle,
        name=data.get("name", handle),
        policy=data.get("description", ""),
        url=f"https://app.intigriti.com/programs/{handle}",
    )
    for group in ("in", "out"):
        bucket = "in_scope" if group == "in" else "out_of_scope"
        for item in data.get(bucket, []) or []:
            asset = ScopeAsset(
                kind=_KIND_MAP.get(str(item.get("type", "other")).lower(), ScopeAssetKind.OTHER),
                identifier=str(item.get("endpoint") or item.get("name") or ""),
                eligible_for_bounty=group == "in",
                notes=str(item.get("description", "") or ""),
            )
            getattr(md, bucket).append(asset)
    log.info("intigriti.scope_fetched", extra={"handle": handle, "in_scope": len(md.in_scope)})
    return md


__all__ = ["fetch_program_scope"]
