"""CVSS 4.0 scoring engine tests."""

from __future__ import annotations

import pytest

from decepticon.scoring.cvss4 import (
    CVSS4ParseError,
    parse_vector,
    score_from_vector,
    severity_from_score,
)

KNOWN_VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def test_parse_vector_round_trip():
    m = parse_vector(KNOWN_VECTOR)
    assert m.AV == "N" and m.AC == "L" and m.VC == "H"
    # Round-trip: rebuild vector and reparse — should match base metrics
    s = score_from_vector(KNOWN_VECTOR)
    assert s.vector.startswith("CVSS:4.0/")
    m2 = parse_vector(s.vector)
    for k in ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"):
        assert getattr(m, k) == getattr(m2, k)


def test_known_vector_scores_9_3_critical():
    s = score_from_vector(KNOWN_VECTOR)
    assert s.score == 9.3
    assert str(s.severity) == "Critical"


@pytest.mark.parametrize(
    "score,expected",
    [
        (0.0, "None"),
        (3.9, "Low"),
        (4.0, "Medium"),
        (6.9, "Medium"),
        (7.0, "High"),
        (8.9, "High"),
        (9.0, "Critical"),
        (10.0, "Critical"),
    ],
)
def test_severity_band_boundaries(score: float, expected: str):
    assert str(severity_from_score(score)) == expected


def test_reject_malformed_vector():
    with pytest.raises(CVSS4ParseError):
        parse_vector("not-a-vector")
    with pytest.raises(CVSS4ParseError):
        parse_vector("CVSS:3.1/AV:N/AC:L")
