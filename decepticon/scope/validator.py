"""Scope validator — deny-by-default target gate.

Extracts IPs, CIDRs, hostnames, URLs from command strings and checks each
against configured rules. Ported from PSA ``internal/scope/validator.go``
with YAML-loadable ``ScopeRule`` definitions.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from decepticon.core.logging import get_logger

log = get_logger("scope.validator")


class ScopeKind(StrEnum):
    CIDR = "cidr"
    DOMAIN = "domain"
    GLOB = "glob"
    URL = "url"


class ScopeAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class ScopeRule(BaseModel):
    pattern: str
    kind: ScopeKind
    action: ScopeAction = ScopeAction.ALLOW
    notes: str = ""


class ScopeResult(BaseModel):
    allowed: bool
    reason: str = ""
    matched_rule: ScopeRule | None = None
    target: str = ""


# IPv4, IPv6 (simplified), and hostname detection
_TARGET_RE = re.compile(
    r"(?P<url>https?://[^\s'\"`)]+)"
    r"|(?P<cidr>\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b)"
    r"|(?P<ipv4>\b(?:\d{1,3}\.){3}\d{1,3}\b)"
    r"|(?P<host>\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b)"
)

# Strings that regex matches but are never real targets
_NON_TARGETS = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "github.com",
        "api.github.com",
        "raw.githubusercontent.com",
        "golang.org",
        "google.com",
        "huggingface.co",
        "pypi.org",
        "files.pythonhosted.org",
    }
)
_FILE_EXT = (
    ".yaml",
    ".yml",
    ".json",
    ".xml",
    ".txt",
    ".log",
    ".conf",
    ".cfg",
    ".md",
    ".py",
    ".go",
    ".ts",
    ".js",
)


def _extract_targets(command: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for m in _TARGET_RE.finditer(command):
        val = next((m.group(k) for k in ("url", "cidr", "ipv4", "host") if m.group(k)), None)
        if not val:
            continue
        v = val.strip().lower()
        if v in _NON_TARGETS:
            continue
        if any(v.endswith(ext) for ext in _FILE_EXT):
            continue
        if v in seen:
            continue
        seen.add(v)
        out.append(val)
    return out


def _host_of(target: str) -> str:
    """Strip scheme/port/path from a URL or host:port."""
    t = target
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    t = t.split("?", 1)[0]
    # IPv6 [::1]:80
    if t.startswith("["):
        end = t.find("]")
        if end > 0:
            return t[1:end]
    if ":" in t and t.count(":") == 1:
        t = t.split(":", 1)[0]
    return t


def _match_cidr(host: str, pattern: str) -> bool:
    try:
        ip = ipaddress.ip_address(_host_of(host))
        net = ipaddress.ip_network(pattern, strict=False)
        return ip in net
    except (ValueError, TypeError):
        return False


def _match_domain(host: str, pattern: str) -> bool:
    host = _host_of(host).lower().rstrip(".")
    pat = pattern.lower().rstrip(".")
    if pat.startswith("*."):
        return host.endswith(pat[1:])
    if host == pat:
        return True
    return host.endswith("." + pat)


def _match_url(url: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(url, pattern)


def _rule_matches(rule: ScopeRule, target: str) -> bool:
    if rule.kind == ScopeKind.CIDR:
        return _match_cidr(target, rule.pattern)
    if rule.kind == ScopeKind.DOMAIN:
        return _match_domain(target, rule.pattern)
    if rule.kind == ScopeKind.URL:
        return _match_url(target, rule.pattern)
    if rule.kind == ScopeKind.GLOB:
        return fnmatch.fnmatchcase(_host_of(target), rule.pattern)
    return False


class ScopeValidator(BaseModel):
    """Deny-by-default scope validator."""

    rules: list[ScopeRule] = Field(default_factory=list)

    def check(self, command: str, target_hint: str | None = None) -> ScopeResult:  # noqa: D401
        return self._do_check(command, target_hint)

    # Backwards-compat alias. ``validate`` is kept as a thin wrapper because
    # the earlier API shipped with this name; new code should prefer ``check``
    # to avoid shadowing ``pydantic.BaseModel``'s classmethod of the same name.
    def validate(self, command: str, target_hint: str | None = None) -> ScopeResult:  # type: ignore[override]
        return self._do_check(command, target_hint)

    def _do_check(self, command: str, target_hint: str | None = None) -> ScopeResult:
        """Extract targets from ``command`` and validate each.

        Returns first deny hit, or allow if every target matches an allow rule.
        Empty ruleset or no targets = deny.
        """
        if not self.rules:
            return ScopeResult(
                allowed=False,
                reason="scope has no rules; deny-by-default",
                target=target_hint or "",
            )

        targets: list[str] = []
        if target_hint:
            targets.append(target_hint)
        targets.extend(_extract_targets(command))

        if not targets:
            return ScopeResult(
                allowed=False,
                reason="no scopeable target found in command",
                target="",
            )

        # Pass 1: any explicit deny is terminal
        for t in targets:
            for rule in self.rules:
                if rule.action == ScopeAction.DENY and _rule_matches(rule, t):
                    log.info("scope.deny", extra={"target": t, "rule": rule.pattern})
                    return ScopeResult(
                        allowed=False,
                        reason=f"target {t!r} matches deny rule {rule.pattern!r}",
                        matched_rule=rule,
                        target=t,
                    )

        # Pass 2: every target must match at least one allow
        matched: ScopeRule | None = None
        for t in targets:
            ok = False
            for rule in self.rules:
                if rule.action == ScopeAction.ALLOW and _rule_matches(rule, t):
                    ok = True
                    matched = rule
                    break
            if not ok:
                return ScopeResult(
                    allowed=False,
                    reason=f"target {t!r} not in any allow rule",
                    target=t,
                )
        return ScopeResult(
            allowed=True,
            reason="all targets allowed",
            matched_rule=matched,
            target=targets[0],
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> "ScopeValidator":
        """Load scope config YAML.

        Expected shape (mirrors soundwave/roe-template structure)::

            scope:
              allow:
                - {pattern: "*.example.com", kind: domain}
                - {pattern: "10.0.0.0/24", kind: cidr}
              deny:
                - {pattern: "admin.example.com", kind: domain, notes: "prod"}
        """
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        raw = data.get("scope", data)
        rules: list[ScopeRule] = []
        for item in raw.get("allow", []) or []:
            rules.append(ScopeRule(**{**item, "action": ScopeAction.ALLOW}))
        for item in raw.get("deny", []) or []:
            rules.append(ScopeRule(**{**item, "action": ScopeAction.DENY}))
        # Also support flat rules list with explicit action
        for item in raw.get("rules", []) or []:
            rules.append(ScopeRule(**item))
        return cls(rules=rules)


__all__ = [
    "ScopeKind",
    "ScopeAction",
    "ScopeRule",
    "ScopeResult",
    "ScopeValidator",
]
