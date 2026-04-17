"""Bug bounty dedup fingerprint tests."""

from __future__ import annotations

from decepticon.bugbounty.dedup import FindingFingerprint, dedup


def _f(**kw):
    base = {
        "title": "SQL injection in /api/login",
        "cwe": "CWE-89",
        "target": "https://api.example.com/api/login",
        "proof": "payload: ' OR 1=1--",
    }
    base.update(kw)
    return base


def test_fingerprint_stable():
    a = FindingFingerprint.compute(_f())
    b = FindingFingerprint.compute(_f())
    assert a.digest == b.digest


def test_different_url_path_different_fingerprint():
    a = FindingFingerprint.compute(_f(target="https://api.example.com/api/login"))
    b = FindingFingerprint.compute(_f(target="https://api.example.com/api/admin"))
    assert a.digest != b.digest


def test_dedup_idempotent():
    findings = [_f(), _f(), _f(target="https://api.example.com/api/admin")]
    once = dedup(findings)
    twice = dedup(once)
    assert len(once) == 2
    assert len(twice) == 2
    assert [FindingFingerprint.compute(x).digest for x in once] == [
        FindingFingerprint.compute(x).digest for x in twice
    ]
