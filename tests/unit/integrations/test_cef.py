"""CEF format tests."""

from __future__ import annotations

from decepticon.integrations.siem import to_cef


def test_cef_header_format():
    f = {
        "title": "SQLi",
        "severity": "Critical",
        "attack_category": "injection",
        "target": "https://x/",
        "cvss_score": 9.3,
        "description": "root cause",
    }
    line = to_cef(f)
    assert line.startswith("CEF:0|Decepticon|decepticon|")
    parts = line.split("|")
    # CEF:0 | vendor | product | version | sig | name | severity | extensions
    assert len(parts) >= 8
    assert parts[1] == "Decepticon"
    assert parts[5] == "SQLi"  # name
    assert parts[6] == "10"  # severity mapping Critical=10


def test_cef_pipe_and_newline_escaping():
    f = {"title": "t", "severity": "Low", "description": "a|b\nc", "target": "h"}
    line = to_cef(f)
    assert "a\\|b" in line
    assert "\n" not in line.split("msg=", 1)[1]
