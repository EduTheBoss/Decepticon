"""SARIF 2.1.0 integration tests (PSA-migrated)."""

from __future__ import annotations

from decepticon.integrations.sarif import findings_to_sarif


def _finding(**kw):
    base = {
        "title": "SQLi in /login",
        "description": "UNION-based SQLi in email parameter",
        "severity": "High",
        "attack_category": "injection",
        "target": "https://api.example.com/login",
        "cvss_score": 8.1,
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    }
    base.update(kw)
    return base


def test_sarif_shape_and_version():
    out = findings_to_sarif([_finding()])
    assert out["version"] == "2.1.0"
    assert out["runs"][0]["tool"]["driver"]["name"] == "decepticon"
    assert isinstance(out["runs"][0]["results"], list)
    assert len(out["runs"][0]["results"]) == 1


def test_cvss4_vector_in_properties():
    out = findings_to_sarif([_finding()])
    props = out["runs"][0]["results"][0]["properties"]
    assert props["cvss_vector"].startswith("CVSS:4.0/")
    assert float(props["cvss_score"]) == 8.1
