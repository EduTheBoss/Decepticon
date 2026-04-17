"""Bugcrowd program scope fetcher — public engagement brief scrape.

Public Bugcrowd program pages expose a ``targets`` JSON section. We fetch
the public engagement page and parse it. Private programs require a
session cookie which this module accepts via env ``BUGCROWD_COOKIE``.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

import httpx

from decepticon.bugbounty.schemas import ProgramMetadata, ScopeAsset, ScopeAssetKind
from decepticon.core.logging import get_logger

log = get_logger("bugbounty.bugcrowd")


_CATEGORY_MAP = {
    "website": ScopeAssetKind.URL,
    "api": ScopeAssetKind.URL,
    "android": ScopeAssetKind.ANDROID,
    "ios": ScopeAssetKind.IOS,
    "hardware": ScopeAssetKind.OTHER,
    "executable": ScopeAssetKind.EXECUTABLE,
    "other": ScopeAssetKind.OTHER,
}


async def fetch_program_scope(handle: str, *, timeout: float = 30.0) -> ProgramMetadata:
    """Fetch BC program brief. Parses the public engagement page JSON."""
    url = f"https://bugcrowd.com/{handle}"
    headers = {"Accept": "text/html,application/json", "User-Agent": "decepticon/1.0"}
    cookie = os.getenv("BUGCROWD_COOKIE", "")
    if cookie:
        headers["Cookie"] = cookie

    async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True) as client:
        r = await client.get(url + "/crowdcontrol/targets.json")
        if r.status_code == 404:
            # Fallback: parse embedded JSON on the public page
            page = await client.get(url)
            page.raise_for_status()
            match = re.search(r'data-react-props="([^"]+)"', page.text)
            data: dict[str, Any] = {}
            if match:
                raw = match.group(1).replace("&quot;", '"').replace("&amp;", "&")
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    data = {}
            targets = data.get("targets", []) if isinstance(data, dict) else []
        else:
            r.raise_for_status()
            targets = r.json() if isinstance(r.json(), list) else r.json().get("targets", [])

    md = ProgramMetadata(platform="bugcrowd", handle=handle, name=handle, url=url)
    for t in targets:
        if not isinstance(t, dict):
            continue
        kind = _CATEGORY_MAP.get(str(t.get("category", "other")).lower(), ScopeAssetKind.OTHER)
        asset = ScopeAsset(
            kind=kind,
            identifier=str(t.get("name") or t.get("target") or ""),
            eligible_for_bounty=bool(t.get("in_scope", True)),
            notes=str(t.get("description", "") or ""),
        )
        if asset.eligible_for_bounty:
            md.in_scope.append(asset)
        else:
            md.out_of_scope.append(asset)

    log.info("bugcrowd.scope_fetched", extra={"handle": handle, "in_scope": len(md.in_scope)})
    return md


__all__ = ["fetch_program_scope"]
