"""CVSS v4.0 scoring engine + finding severity pipeline."""

from decepticon.scoring.cvss4 import (
    CVSS4Metrics,
    CVSS4Score,
    parse_vector,
    score_from_metrics,
    score_from_vector,
    severity_from_score,
)

__all__ = [
    "CVSS4Metrics",
    "CVSS4Score",
    "parse_vector",
    "score_from_metrics",
    "score_from_vector",
    "severity_from_score",
]
