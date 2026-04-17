"""Example plugin: annotate findings with CVSS 4.0 macroVector breakdown."""

from __future__ import annotations

from typing import Any

from decepticon.core.logging import get_logger
from decepticon.plugins.types import Plugin
from decepticon.scoring.cvss4 import parse_vector, score_from_metrics

log = get_logger("plugins.cvss_explainer")


_EQ_NAMES = (
    "EQ1 (AV+PR+UI)",
    "EQ2 (AC+AT)",
    "EQ3 (VC+VI)",
    "EQ4 (SC+SI+SA/MSI+MSA)",
    "EQ5 (E threat)",
    "EQ6 (CR/IR/AR + V*)",
)


class CVSSExplainerPlugin(Plugin):
    name = "cvss-explainer"
    version = "1.0.0"

    def on_finding(self, finding: Any) -> None:
        vec = (
            finding.get("cvss_vector")
            if isinstance(finding, dict)
            else getattr(finding, "cvss_vector", "")
        )
        if not vec or not str(vec).startswith("CVSS:4.0/"):
            return
        try:
            metrics = parse_vector(str(vec))
            score = score_from_metrics(metrics)
        except Exception as e:  # noqa: BLE001
            log.debug("cvss_explainer.parse_fail", extra={"err": str(e)})
            return
        breakdown = [f"{name}={score.macro_vector[i]}" for i, name in enumerate(_EQ_NAMES)]
        explanation = (
            f"CVSS 4.0 macroVector: {score.macro_vector} -> {score.score} ({score.severity}). "
            + "  ".join(breakdown)
        )
        if isinstance(finding, dict):
            finding.setdefault("cvss4_explanation", explanation)
        else:
            try:
                setattr(finding, "cvss4_explanation", explanation)
            except Exception:  # noqa: BLE001
                pass


__all__ = ["CVSSExplainerPlugin"]
