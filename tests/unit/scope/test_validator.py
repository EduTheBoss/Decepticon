"""Scope validator tests."""

from __future__ import annotations

from pathlib import Path

from decepticon.scope.validator import (
    ScopeAction,
    ScopeKind,
    ScopeRule,
    ScopeValidator,
)


def _mk(allow=None, deny=None):
    rules = []
    for p, k in allow or []:
        rules.append(ScopeRule(pattern=p, kind=k, action=ScopeAction.ALLOW))
    for p, k in deny or []:
        rules.append(ScopeRule(pattern=p, kind=k, action=ScopeAction.DENY))
    return ScopeValidator(rules=rules)


def test_allow_and_deny_basic():
    v = _mk(allow=[("*.example.com", ScopeKind.DOMAIN)])
    assert v.validate("curl https://api.example.com/x").allowed is True
    assert v.validate("curl https://evil.com/x").allowed is False


def test_cidr_membership():
    v = _mk(allow=[("192.168.1.0/24", ScopeKind.CIDR)])
    assert v.validate("nmap 192.168.1.50").allowed is True
    assert v.validate("nmap 192.168.2.50").allowed is False


def test_domain_glob():
    v = _mk(allow=[("*.example.com", ScopeKind.DOMAIN)])
    assert v.validate("curl https://api.example.com/").allowed is True
    assert v.validate("curl https://evil.com/").allowed is False


def test_target_extraction_from_commands():
    v = _mk(allow=[("*.example.com", ScopeKind.DOMAIN), ("10.0.0.0/8", ScopeKind.CIDR)])
    for cmd in (
        "nmap -sV 10.0.0.5",
        "curl -I https://api.example.com/v1",
        "nuclei -u https://api.example.com",
        "ffuf -u https://api.example.com/FUZZ",
    ):
        assert v.validate(cmd).allowed is True, cmd


def test_yaml_load(tmp_path: Path):
    p = tmp_path / "scope.yaml"
    p.write_text(
        "scope:\n"
        "  allow:\n"
        "    - {pattern: '*.example.com', kind: domain}\n"
        "  deny:\n"
        "    - {pattern: 'admin.example.com', kind: domain}\n",
        encoding="utf-8",
    )
    v = ScopeValidator.from_yaml(p)
    assert v.validate("curl https://api.example.com").allowed is True
    assert v.validate("curl https://admin.example.com").allowed is False
