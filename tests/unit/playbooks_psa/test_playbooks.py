"""PSA playbook loader/runner tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from decepticon.playbooks.loader import PlaybookLoader, list_playbooks
from decepticon.playbooks.runner import PlaybookRunner
from decepticon.playbooks.schema import Phase, Playbook

REPO_ROOT = Path(__file__).resolve().parents[3]
PLAYBOOK_DIR = REPO_ROOT / "playbooks"


def test_load_owasp_top10():
    pb = PlaybookLoader.load(PLAYBOOK_DIR / "owasp-top10.yaml")
    assert pb.name
    assert pb.phases


def test_load_all_shipped_playbooks():
    loaded = list_playbooks(PLAYBOOK_DIR)
    assert len(loaded) >= 4


def test_schema_rejects_missing_name(tmp_path: Path):
    p = tmp_path / "bad.yaml"
    p.write_text("description: no name\nphases: []\n", encoding="utf-8")
    with pytest.raises(Exception):
        PlaybookLoader.load(p)


def test_schema_rejects_empty_phases(tmp_path: Path):
    p = tmp_path / "bad.yaml"
    p.write_text("name: x\nphases: []\n", encoding="utf-8")
    with pytest.raises(Exception):
        PlaybookLoader.load(p)


def test_variable_substitution_in_post_analysis():
    pb = Playbook(
        name="test",
        phases=[
            Phase(
                name="p1",
                agents=["recon"],
                post_analysis="scan ${target_domain} thoroughly",
            )
        ],
    )
    r = PlaybookRunner()
    variables = {"target_domain": "example.com"}
    out = r._substitute(pb.phases[0].post_analysis, variables)
    assert out == "scan example.com thoroughly"
