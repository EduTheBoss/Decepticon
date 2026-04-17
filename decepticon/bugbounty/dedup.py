"""Finding deduplication via fingerprinting."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable
from urllib.parse import urlparse

from pydantic import BaseModel

from decepticon.core.logging import get_logger

log = get_logger("bugbounty.dedup")


def _normalize_title(title: str) -> str:
    t = title.lower()
    t = re.sub(r"\s+", " ", t).strip()
    # Strip numeric tokens that drift between scans (IDs, counts)
    t = re.sub(r"\b\d{3,}\b", "", t)
    return t


def _url_path(target: str) -> str:
    try:
        p = urlparse(target if "://" in target else f"http://{target}")
        path = (p.path or "/").rstrip("/") or "/"
        return f"{p.hostname or ''}{path}"
    except Exception:  # noqa: BLE001
        return target


class FindingFingerprint(BaseModel):
    digest: str
    title_norm: str
    cwe: str
    url_path: str

    @classmethod
    def compute(cls, finding: Any) -> "FindingFingerprint":
        get = (
            (lambda k, d="": finding.get(k, d))
            if isinstance(finding, dict)
            else (lambda k, d="": getattr(finding, k, d))
        )
        title = _normalize_title(str(get("title", "") or ""))
        cwe = str(get("cwe", "") or get("cwe_id", "") or "")
        url = _url_path(str(get("target", "") or get("url", "") or ""))
        proof = str(get("proof", "") or get("evidence", "") or "")
        proof_hash = hashlib.sha256(proof.encode("utf-8", errors="replace")).hexdigest()[:16]
        basis = f"{title}|{cwe}|{url}|{proof_hash}"
        digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
        return cls(digest=digest, title_norm=title, cwe=cwe, url_path=url)


def dedup(findings: Iterable[Any]) -> list[Any]:
    """Return findings with duplicates removed (first-wins)."""
    seen: dict[str, Any] = {}
    for f in findings:
        fp = FindingFingerprint.compute(f)
        if fp.digest in seen:
            log.debug("dedup.duplicate", extra={"digest": fp.digest[:12]})
            continue
        seen[fp.digest] = f
    return list(seen.values())


__all__ = ["FindingFingerprint", "dedup"]
