"""HackerOne program scope fetcher (Hacker API)."""

from __future__ import annotations

import base64
import os

import httpx

from decepticon.bugbounty.schemas import ProgramMetadata, ScopeAsset, ScopeAssetKind
from decepticon.core.logging import get_logger

log = get_logger("bugbounty.hackerone")


_KIND_MAP = {
    "URL": ScopeAssetKind.URL,
    "WILDCARD": ScopeAssetKind.WILDCARD,
    "DOMAIN": ScopeAssetKind.DOMAIN,
    "IP_ADDRESS": ScopeAssetKind.IP,
    "CIDR": ScopeAssetKind.CIDR,
    "GOOGLE_PLAY_APP_ID": ScopeAssetKind.ANDROID,
    "APPLE_STORE_APP_ID": ScopeAssetKind.IOS,
    "EXECUTABLE": ScopeAssetKind.EXECUTABLE,
}


async def fetch_program_scope(
    handle: str,
    api_user: str | None = None,
    api_token: str | None = None,
    *,
    timeout: float = 30.0,
) -> ProgramMetadata:
    """Fetch H1 program metadata + structured scope via the Hacker API."""
    user = api_user or os.getenv("HACKERONE_API_USER", "")
    token = api_token or os.getenv("HACKERONE_API_TOKEN", "")
    if not (user and token):
        raise RuntimeError("HackerOne API user + token required")
    auth = base64.b64encode(f"{user}:{token}".encode("utf-8")).decode("ascii")

    headers = {"Accept": "application/json", "Authorization": "Basic " + auth}
    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        prog_resp = await client.get(f"https://api.hackerone.com/v1/hackers/programs/{handle}")
        prog_resp.raise_for_status()
        scopes_resp = await client.get(
            f"https://api.hackerone.com/v1/hackers/programs/{handle}/structured_scopes"
        )
        scopes_resp.raise_for_status()

    prog = prog_resp.json().get("data", {}).get("attributes", {})
    md = ProgramMetadata(
        platform="hackerone",
        handle=handle,
        name=prog.get("name", handle),
        policy=prog.get("policy", ""),
        url=f"https://hackerone.com/{handle}",
    )
    for entry in scopes_resp.json().get("data", []):
        a = entry.get("attributes", {})
        asset = ScopeAsset(
            kind=_KIND_MAP.get(a.get("asset_type", ""), ScopeAssetKind.OTHER),
            identifier=a.get("asset_identifier", ""),
            eligible_for_bounty=bool(a.get("eligible_for_bounty", True)),
            max_severity=a.get("max_severity", "") or "",
            notes=a.get("instruction", "") or "",
        )
        if a.get("eligible_for_submission", True):
            md.in_scope.append(asset)
        else:
            md.out_of_scope.append(asset)

    log.info(
        "hackerone.scope_fetched",
        extra={
            "handle": handle,
            "in_scope": len(md.in_scope),
            "out_of_scope": len(md.out_of_scope),
        },
    )
    return md


__all__ = ["fetch_program_scope"]
