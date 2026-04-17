"""Bug bounty shared schemas."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class ScopeAssetKind(StrEnum):
    URL = "url"
    WILDCARD = "wildcard"
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    ANDROID = "android"
    IOS = "ios"
    EXECUTABLE = "executable"
    OTHER = "other"


class ScopeAsset(BaseModel):
    kind: ScopeAssetKind
    identifier: str
    eligible_for_bounty: bool = True
    max_severity: str = ""
    notes: str = ""


class ProgramMetadata(BaseModel):
    platform: str  # hackerone | bugcrowd | intigriti
    handle: str
    name: str = ""
    policy: str = ""
    url: str = ""
    in_scope: list[ScopeAsset] = Field(default_factory=list)
    out_of_scope: list[ScopeAsset] = Field(default_factory=list)
    rewards_range: tuple[int, int] | None = None


__all__ = ["ProgramMetadata", "ScopeAsset", "ScopeAssetKind"]
