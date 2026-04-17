"""Plugin loader tests."""

from __future__ import annotations

from pathlib import Path

from decepticon.plugins.loader import PluginLoader

REPO_ROOT = Path(__file__).resolve().parents[3]
EXAMPLES_DIR = REPO_ROOT / "decepticon" / "plugins" / "examples"


def test_discovers_example_plugin():
    loader = PluginLoader()
    loader.discover_user(EXAMPLES_DIR)
    names = {p.name for p in loader.plugins}
    assert "cvss-explainer" in names


def test_dispatch_on_finding():
    loader = PluginLoader()
    loader.discover_user(EXAMPLES_DIR)
    finding = {
        "title": "x",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    }
    loader.dispatch("on_finding", finding)
    assert "cvss4_explanation" in finding
    assert "macroVector" in finding["cvss4_explanation"]
