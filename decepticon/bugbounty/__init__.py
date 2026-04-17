"""Bug bounty integrations: H1, Bugcrowd, Intigriti, dedup, import."""

from decepticon.bugbounty.dedup import FindingFingerprint, dedup
from decepticon.bugbounty.formatter import format_bugcrowd, format_hackerone
from decepticon.bugbounty.importer import import_program
from decepticon.bugbounty.schemas import (
    ProgramMetadata,
    ScopeAsset,
    ScopeAssetKind,
)

__all__ = [
    "FindingFingerprint",
    "ProgramMetadata",
    "ScopeAsset",
    "ScopeAssetKind",
    "dedup",
    "format_bugcrowd",
    "format_hackerone",
    "import_program",
]
