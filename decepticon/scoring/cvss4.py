"""CVSS v4.0 scoring engine (FIRST spec).

Full base + threat + environmental vector support. MacroVector lookup table
transcribed verbatim from the FIRST reference calculator
(github.com/FIRSTdotorg/cvss-v4-calculator).

Public API:
    parse_vector(s)         -> CVSS4Metrics
    score_from_metrics(m)   -> CVSS4Score
    score_from_vector(s)    -> CVSS4Score
    severity_from_score(f)  -> str
"""

from __future__ import annotations

from enum import StrEnum
from typing import Mapping

from pydantic import BaseModel, Field

from decepticon.core.logging import get_logger

log = get_logger("scoring.cvss4")


# ── Official macroVector lookup table (FIRST, Red Hat; BSD-2-Clause) ─────
CVSS_LOOKUP_GLOBAL: dict[str, float] = {
    "000000": 10.0,
    "000001": 9.9,
    "000010": 9.8,
    "000011": 9.5,
    "000020": 9.5,
    "000021": 9.2,
    "000100": 10.0,
    "000101": 9.6,
    "000110": 9.3,
    "000111": 8.7,
    "000120": 9.1,
    "000121": 8.1,
    "000200": 9.3,
    "000201": 9.0,
    "000210": 8.9,
    "000211": 8.0,
    "000220": 8.1,
    "000221": 6.8,
    "001000": 9.8,
    "001001": 9.5,
    "001010": 9.5,
    "001011": 9.2,
    "001020": 9.0,
    "001021": 8.4,
    "001100": 9.3,
    "001101": 9.2,
    "001110": 8.9,
    "001111": 8.1,
    "001120": 8.1,
    "001121": 6.5,
    "001200": 8.8,
    "001201": 8.0,
    "001210": 7.8,
    "001211": 7.0,
    "001220": 6.9,
    "001221": 4.8,
    "002001": 9.2,
    "002011": 8.2,
    "002021": 7.2,
    "002101": 7.9,
    "002111": 6.9,
    "002121": 5.0,
    "002201": 6.9,
    "002211": 5.5,
    "002221": 2.7,
    "010000": 9.9,
    "010001": 9.7,
    "010010": 9.5,
    "010011": 9.2,
    "010020": 9.2,
    "010021": 8.5,
    "010100": 9.5,
    "010101": 9.1,
    "010110": 9.0,
    "010111": 8.3,
    "010120": 8.4,
    "010121": 7.1,
    "010200": 9.2,
    "010201": 8.1,
    "010210": 8.2,
    "010211": 7.1,
    "010220": 7.2,
    "010221": 5.3,
    "011000": 9.5,
    "011001": 9.3,
    "011010": 9.2,
    "011011": 8.5,
    "011020": 8.5,
    "011021": 7.3,
    "011100": 9.2,
    "011101": 8.2,
    "011110": 8.0,
    "011111": 7.2,
    "011120": 7.0,
    "011121": 5.9,
    "011200": 8.4,
    "011201": 7.0,
    "011210": 7.1,
    "011211": 5.2,
    "011220": 5.0,
    "011221": 3.0,
    "012001": 8.6,
    "012011": 7.5,
    "012021": 5.2,
    "012101": 7.1,
    "012111": 5.2,
    "012121": 2.9,
    "012201": 6.3,
    "012211": 2.9,
    "012221": 1.7,
    "100000": 9.8,
    "100001": 9.5,
    "100010": 9.4,
    "100011": 8.7,
    "100020": 9.1,
    "100021": 8.1,
    "100100": 9.4,
    "100101": 8.9,
    "100110": 8.6,
    "100111": 7.4,
    "100120": 7.7,
    "100121": 6.4,
    "100200": 8.7,
    "100201": 7.5,
    "100210": 7.4,
    "100211": 6.3,
    "100220": 6.3,
    "100221": 4.9,
    "101000": 9.4,
    "101001": 8.9,
    "101010": 8.8,
    "101011": 7.7,
    "101020": 7.6,
    "101021": 6.7,
    "101100": 8.6,
    "101101": 7.6,
    "101110": 7.4,
    "101111": 5.8,
    "101120": 5.9,
    "101121": 5.0,
    "101200": 7.2,
    "101201": 5.7,
    "101210": 5.7,
    "101211": 5.2,
    "101220": 5.2,
    "101221": 2.5,
    "102001": 8.3,
    "102011": 7.0,
    "102021": 5.4,
    "102101": 6.5,
    "102111": 5.8,
    "102121": 2.6,
    "102201": 5.3,
    "102211": 2.1,
    "102221": 1.3,
    "110000": 9.5,
    "110001": 9.0,
    "110010": 8.8,
    "110011": 7.6,
    "110020": 7.6,
    "110021": 7.0,
    "110100": 9.0,
    "110101": 7.7,
    "110110": 7.5,
    "110111": 6.2,
    "110120": 6.1,
    "110121": 5.3,
    "110200": 7.7,
    "110201": 6.6,
    "110210": 6.8,
    "110211": 5.9,
    "110220": 5.2,
    "110221": 3.0,
    "111000": 8.9,
    "111001": 7.8,
    "111010": 7.6,
    "111011": 6.7,
    "111020": 6.2,
    "111021": 5.8,
    "111100": 7.4,
    "111101": 5.9,
    "111110": 5.7,
    "111111": 5.7,
    "111120": 4.7,
    "111121": 2.3,
    "111200": 6.1,
    "111201": 5.2,
    "111210": 5.7,
    "111211": 2.9,
    "111220": 2.4,
    "111221": 1.6,
    "112001": 7.1,
    "112011": 5.9,
    "112021": 3.0,
    "112101": 5.8,
    "112111": 2.6,
    "112121": 1.5,
    "112201": 2.3,
    "112211": 1.3,
    "112221": 0.6,
    "200000": 9.3,
    "200001": 8.7,
    "200010": 8.6,
    "200011": 7.2,
    "200020": 7.5,
    "200021": 5.8,
    "200100": 8.6,
    "200101": 7.4,
    "200110": 7.4,
    "200111": 6.1,
    "200120": 5.6,
    "200121": 3.4,
    "200200": 7.0,
    "200201": 5.4,
    "200210": 5.2,
    "200211": 4.0,
    "200220": 4.0,
    "200221": 2.2,
    "201000": 8.5,
    "201001": 7.5,
    "201010": 7.4,
    "201011": 5.5,
    "201020": 6.2,
    "201021": 5.1,
    "201100": 7.2,
    "201101": 5.7,
    "201110": 5.5,
    "201111": 4.1,
    "201120": 4.6,
    "201121": 1.9,
    "201200": 5.3,
    "201201": 3.6,
    "201210": 3.4,
    "201211": 1.9,
    "201220": 1.9,
    "201221": 0.8,
    "202001": 6.4,
    "202011": 5.1,
    "202021": 2.0,
    "202101": 4.7,
    "202111": 2.1,
    "202121": 1.1,
    "202201": 2.4,
    "202211": 0.9,
    "202221": 0.4,
    "210000": 8.8,
    "210001": 7.5,
    "210010": 7.3,
    "210011": 5.3,
    "210020": 6.0,
    "210021": 5.0,
    "210100": 7.3,
    "210101": 5.5,
    "210110": 5.9,
    "210111": 4.0,
    "210120": 4.1,
    "210121": 2.0,
    "210200": 5.4,
    "210201": 4.3,
    "210210": 4.5,
    "210211": 2.2,
    "210220": 2.0,
    "210221": 1.1,
    "211000": 7.5,
    "211001": 5.5,
    "211010": 5.8,
    "211011": 4.5,
    "211020": 4.0,
    "211021": 2.1,
    "211100": 6.1,
    "211101": 5.1,
    "211110": 4.8,
    "211111": 1.8,
    "211120": 2.0,
    "211121": 0.9,
    "211200": 4.6,
    "211201": 1.8,
    "211210": 1.7,
    "211211": 0.7,
    "211220": 0.8,
    "211221": 0.2,
    "212001": 5.3,
    "212011": 2.4,
    "212021": 1.4,
    "212101": 2.4,
    "212111": 1.2,
    "212121": 0.5,
    "212201": 1.0,
    "212211": 0.3,
    "212221": 0.1,
}


MAX_SEVERITY: dict[str, dict] = {
    "eq1": {0: 1, 1: 4, 2: 5},
    "eq2": {0: 1, 1: 2},
    "eq3eq6": {0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}},
    "eq4": {0: 6, 1: 5, 2: 4},
    "eq5": {0: 1, 1: 1, 2: 1},
}


MAX_COMPOSED: dict[str, dict] = {
    "eq1": {
        0: ["AV:N/PR:N/UI:N/"],
        1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
        2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
    },
    "eq2": {0: ["AC:L/AT:N/"], 1: ["AC:H/AT:N/", "AC:L/AT:P/"]},
    "eq3": {
        0: {
            0: ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
            1: [
                "VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/",
                "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/",
            ],
        },
        1: {
            0: [
                "VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/",
                "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/",
            ],
            1: [
                "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
                "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
                "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
            ],
        },
        2: {1: ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]},
    },
    "eq4": {0: ["SC:H/SI:S/SA:S/"], 1: ["SC:H/SI:H/SA:H/"], 2: ["SC:L/SI:L/SA:L/"]},
    "eq5": {0: ["E:A/"], 1: ["E:P/"], 2: ["E:U/"]},
}


# ── Enums ──────────────────────────────────────────────────────────────


class Severity(StrEnum):
    NONE = "None"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


# Allowed metric values (spec § 3.1)
_ALLOWED: dict[str, set[str]] = {
    # Base
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "AT": {"N", "P"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "P", "A"},
    "VC": {"H", "L", "N"},
    "VI": {"H", "L", "N"},
    "VA": {"H", "L", "N"},
    "SC": {"H", "L", "N"},
    "SI": {"H", "L", "N"},
    "SA": {"H", "L", "N"},
    # Threat
    "E": {"X", "A", "P", "U"},
    # Environmental security requirements
    "CR": {"X", "H", "M", "L"},
    "IR": {"X", "H", "M", "L"},
    "AR": {"X", "H", "M", "L"},
    # Modified base
    "MAV": {"X", "N", "A", "L", "P"},
    "MAC": {"X", "L", "H"},
    "MAT": {"X", "N", "P"},
    "MPR": {"X", "N", "L", "H"},
    "MUI": {"X", "N", "P", "A"},
    "MVC": {"X", "H", "L", "N"},
    "MVI": {"X", "H", "L", "N"},
    "MVA": {"X", "H", "L", "N"},
    "MSC": {"X", "H", "L", "N"},
    "MSI": {"X", "S", "H", "L", "N"},
    "MSA": {"X", "S", "H", "L", "N"},
    # Supplemental (parsed but don't affect score)
    "S": {"X", "N", "P"},
    "AU": {"X", "N", "Y"},
    "R": {"X", "A", "U", "I"},
    "V": {"X", "D", "C"},
    "RE": {"X", "L", "M", "H"},
    "U": {"X", "Clear", "Green", "Amber", "Red"},
}

_BASE_REQUIRED = [
    "AV",
    "AC",
    "AT",
    "PR",
    "UI",
    "VC",
    "VI",
    "VA",
    "SC",
    "SI",
    "SA",
]


# ── Data models ────────────────────────────────────────────────────────


class CVSS4Metrics(BaseModel):
    """Parsed CVSS 4.0 metric set.

    Stores raw string values as provided (e.g. "N", "H", "X").
    ``X`` (Not Defined) means "use spec default".
    """

    # Base (required)
    AV: str
    AC: str
    AT: str
    PR: str
    UI: str
    VC: str
    VI: str
    VA: str
    SC: str
    SI: str
    SA: str
    # Threat
    E: str = "X"
    # Environmental security requirements
    CR: str = "X"
    IR: str = "X"
    AR: str = "X"
    # Modified base
    MAV: str = "X"
    MAC: str = "X"
    MAT: str = "X"
    MPR: str = "X"
    MUI: str = "X"
    MVC: str = "X"
    MVI: str = "X"
    MVA: str = "X"
    MSC: str = "X"
    MSI: str = "X"
    MSA: str = "X"

    def as_dict(self) -> dict[str, str]:
        return self.model_dump()


class CVSS4Score(BaseModel):
    """Computed CVSS 4.0 score output."""

    score: float = Field(ge=0.0, le=10.0)
    severity: Severity
    macro_vector: str
    vector: str
    metrics: CVSS4Metrics


# ── Parsing ────────────────────────────────────────────────────────────


class CVSS4ParseError(ValueError):
    pass


def parse_vector(s: str) -> CVSS4Metrics:
    """Parse a CVSS 4.0 vector string into a metric set.

    Required prefix: ``CVSS:4.0/``. Order is arbitrary after the prefix.
    Raises CVSS4ParseError on any malformed input.
    """
    s = s.strip()
    if not s.startswith("CVSS:4.0/"):
        raise CVSS4ParseError(f"missing CVSS:4.0/ prefix: {s!r}")
    body = s[len("CVSS:4.0/") :]
    parts = [p for p in body.split("/") if p]
    found: dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            raise CVSS4ParseError(f"invalid metric token {part!r}")
        k, v = part.split(":", 1)
        if k not in _ALLOWED:
            # Unknown metric: skip silently per spec's forward compat hint
            log.debug("cvss4.unknown_metric", extra={"metric": k})
            continue
        if v not in _ALLOWED[k]:
            raise CVSS4ParseError(f"invalid value {v!r} for {k}")
        found[k] = v

    missing = [m for m in _BASE_REQUIRED if m not in found]
    if missing:
        raise CVSS4ParseError(f"missing required base metrics: {missing}")

    return CVSS4Metrics(**found)


def vector_from_metrics(m: CVSS4Metrics) -> str:
    """Serialize metrics back to canonical vector form.

    Only emits non-X metrics beyond the required base.
    """
    d = m.as_dict()
    out = ["CVSS:4.0"]
    order = [
        "AV",
        "AC",
        "AT",
        "PR",
        "UI",
        "VC",
        "VI",
        "VA",
        "SC",
        "SI",
        "SA",
        "E",
        "CR",
        "IR",
        "AR",
        "MAV",
        "MAC",
        "MAT",
        "MPR",
        "MUI",
        "MVC",
        "MVI",
        "MVA",
        "MSC",
        "MSI",
        "MSA",
    ]
    for k in order:
        v = d.get(k, "X")
        if k in _BASE_REQUIRED or v != "X":
            out.append(f"{k}:{v}")
    return "/".join(out)


# ── Metric effective value (applies defaults + modifier overrides) ─────


def _m(metrics: Mapping[str, str], key: str) -> str:
    """Effective value per spec (FIRST ref calc function ``m``)."""
    selected = metrics.get(key, "X")
    # Threat/env defaults when X
    if key == "E" and selected == "X":
        return "A"
    if key in ("CR", "IR", "AR") and selected == "X":
        return "H"
    # Modified base overrides
    mkey = "M" + key
    if mkey in metrics:
        mod = metrics[mkey]
        if mod != "X":
            return mod
    return selected


# ── MacroVector computation (spec § 3.2) ────────────────────────────────


def _macro_vector(metrics: Mapping[str, str]) -> str:
    mv = {
        k: _m(metrics, k)
        for k in (
            "AV",
            "PR",
            "UI",
            "AC",
            "AT",
            "VC",
            "VI",
            "VA",
            "SC",
            "SI",
            "SA",
            "E",
            "CR",
            "IR",
            "AR",
            "MSI",
            "MSA",
        )
    }

    # EQ1
    if mv["AV"] == "N" and mv["PR"] == "N" and mv["UI"] == "N":
        eq1 = "0"
    elif (
        (mv["AV"] == "N" or mv["PR"] == "N" or mv["UI"] == "N")
        and not (mv["AV"] == "N" and mv["PR"] == "N" and mv["UI"] == "N")
        and mv["AV"] != "P"
    ):
        eq1 = "1"
    else:
        eq1 = "2"

    # EQ2
    eq2 = "0" if (mv["AC"] == "L" and mv["AT"] == "N") else "1"

    # EQ3
    if mv["VC"] == "H" and mv["VI"] == "H":
        eq3 = "0"
    elif mv["VC"] == "H" or mv["VI"] == "H" or mv["VA"] == "H":
        eq3 = "1"
    else:
        eq3 = "2"

    # EQ4
    if mv["MSI"] == "S" or mv["MSA"] == "S":
        eq4 = "0"
    elif mv["SC"] == "H" or mv["SI"] == "H" or mv["SA"] == "H":
        eq4 = "1"
    else:
        eq4 = "2"

    # EQ5
    if mv["E"] == "A":
        eq5 = "0"
    elif mv["E"] == "P":
        eq5 = "1"
    else:
        eq5 = "2"

    # EQ6
    if (
        (mv["CR"] == "H" and mv["VC"] == "H")
        or (mv["IR"] == "H" and mv["VI"] == "H")
        or (mv["AR"] == "H" and mv["VA"] == "H")
    ):
        eq6 = "0"
    else:
        eq6 = "1"

    return eq1 + eq2 + eq3 + eq4 + eq5 + eq6


# ── Level tables for severity-distance ──────────────────────────────────

_AV_L = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
_PR_L = {"N": 0.0, "L": 0.1, "H": 0.2}
_UI_L = {"N": 0.0, "P": 0.1, "A": 0.2}
_AC_L = {"L": 0.0, "H": 0.1}
_AT_L = {"N": 0.0, "P": 0.1}
_VC_L = {"H": 0.0, "L": 0.1, "N": 0.2}
_VI_L = {"H": 0.0, "L": 0.1, "N": 0.2}
_VA_L = {"H": 0.0, "L": 0.1, "N": 0.2}
_SC_L = {"H": 0.1, "L": 0.2, "N": 0.3}
_SI_L = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
_SA_L = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
_CR_L = {"H": 0.0, "M": 0.1, "L": 0.2}
_IR_L = {"H": 0.0, "M": 0.1, "L": 0.2}
_AR_L = {"H": 0.0, "M": 0.1, "L": 0.2}


def _extract(metric: str, vector_fragment: str) -> str:
    """Pull a metric value out of a composed max-vector fragment."""
    idx = vector_fragment.find(metric + ":")
    if idx < 0:
        return ""
    tail = vector_fragment[idx + len(metric) + 1 :]
    slash = tail.find("/")
    return tail[:slash] if slash > 0 else tail


def _get_eq_maxes(mv: str, eq: int):
    key = f"eq{eq}"
    return MAX_COMPOSED[key][int(mv[eq - 1])]


# ── Score computation (spec § 3.3) ──────────────────────────────────────


def score_from_metrics(m: CVSS4Metrics) -> CVSS4Score:
    """Compute CVSS 4.0 score from parsed metrics."""
    sel = m.as_dict()

    # Zero-impact shortcut
    if all(_m(sel, k) == "N" for k in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return CVSS4Score(
            score=0.0,
            severity=Severity.NONE,
            macro_vector="".join(["0"] * 6),
            vector=vector_from_metrics(m),
            metrics=m,
        )

    mv_str = _macro_vector(sel)
    if mv_str not in CVSS_LOOKUP_GLOBAL:
        # Should never happen for valid inputs
        raise CVSS4ParseError(f"macroVector {mv_str} not in LUT")

    value = CVSS_LOOKUP_GLOBAL[mv_str]

    eq1 = int(mv_str[0])
    eq2 = int(mv_str[1])
    eq3 = int(mv_str[2])
    eq4 = int(mv_str[3])
    eq5 = int(mv_str[4])
    eq6 = int(mv_str[5])

    # Next-lower macros
    def _look(s: str) -> float | None:
        return CVSS_LOOKUP_GLOBAL.get(s)

    eq1_next = f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}"
    eq2_next = f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}"

    # eq3 + eq6 combined
    eq3eq6_next_left: str | None = None
    eq3eq6_next_right: str | None = None
    eq3eq6_next: str | None = None
    if eq3 == 1 and eq6 == 1:
        eq3eq6_next = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}"
    elif eq3 == 0 and eq6 == 1:
        eq3eq6_next = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}"
    elif eq3 == 1 and eq6 == 0:
        eq3eq6_next = f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}"
    elif eq3 == 0 and eq6 == 0:
        eq3eq6_next_left = f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}"
        eq3eq6_next_right = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}"
    else:
        eq3eq6_next = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6 + 1}"

    eq4_next = f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}"
    eq5_next = f"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}"

    s1 = _look(eq1_next)
    s2 = _look(eq2_next)
    if eq3 == 0 and eq6 == 0:
        sl = _look(eq3eq6_next_left or "")
        sr = _look(eq3eq6_next_right or "")
        # NaN-propagation: if either missing, take the other; if both missing, None
        if sl is None and sr is None:
            s36 = None
        elif sl is None:
            s36 = sr
        elif sr is None:
            s36 = sl
        else:
            s36 = max(sl, sr)
    else:
        s36 = _look(eq3eq6_next or "")
    s4 = _look(eq4_next)
    s5 = _look(eq5_next)

    # Find max-severity vector whose severity distance is non-negative in all metrics
    eq1_maxes = _get_eq_maxes(mv_str, 1)
    eq2_maxes = _get_eq_maxes(mv_str, 2)
    eq3_eq6_maxes = MAX_COMPOSED["eq3"][eq3][eq6]
    eq4_maxes = _get_eq_maxes(mv_str, 4)
    eq5_maxes = _get_eq_maxes(mv_str, 5)

    # Compose all candidate max vectors
    max_vectors: list[str] = []
    for a in eq1_maxes:
        for b in eq2_maxes:
            for c in eq3_eq6_maxes:
                for d in eq4_maxes:
                    for e in eq5_maxes:
                        max_vectors.append(a + b + c + d + e)

    # Find the first candidate where all severity-distances are >= 0
    (
        sd_AV,
        sd_PR,
        sd_UI,
        sd_AC,
        sd_AT,
        sd_VC,
        sd_VI,
        sd_VA,
        sd_SC,
        sd_SI,
        sd_SA,
        sd_CR,
        sd_IR,
        sd_AR,
    ) = (0.0,) * 14

    for mx in max_vectors:

        def _sd(metric: str, table: Mapping[str, float]) -> float:
            mx_val = _extract(metric, mx)
            sel_val = _m(sel, metric)
            return table.get(sel_val, 0.0) - table.get(mx_val, 0.0)

        sd_AV = _sd("AV", _AV_L)
        sd_PR = _sd("PR", _PR_L)
        sd_UI = _sd("UI", _UI_L)
        sd_AC = _sd("AC", _AC_L)
        sd_AT = _sd("AT", _AT_L)
        sd_VC = _sd("VC", _VC_L)
        sd_VI = _sd("VI", _VI_L)
        sd_VA = _sd("VA", _VA_L)
        sd_SC = _sd("SC", _SC_L)
        sd_SI = _sd("SI", _SI_L)
        sd_SA = _sd("SA", _SA_L)
        sd_CR = _sd("CR", _CR_L)
        sd_IR = _sd("IR", _IR_L)
        sd_AR = _sd("AR", _AR_L)

        if all(
            x >= 0
            for x in (
                sd_AV,
                sd_PR,
                sd_UI,
                sd_AC,
                sd_AT,
                sd_VC,
                sd_VI,
                sd_VA,
                sd_SC,
                sd_SI,
                sd_SA,
                sd_CR,
                sd_IR,
                sd_AR,
            )
        ):
            break

    csd_eq1 = sd_AV + sd_PR + sd_UI
    csd_eq2 = sd_AC + sd_AT
    csd_eq3eq6 = sd_VC + sd_VI + sd_VA + sd_CR + sd_IR + sd_AR
    csd_eq4 = sd_SC + sd_SI + sd_SA

    step = 0.1
    n_lower = 0
    normed = [0.0, 0.0, 0.0, 0.0, 0.0]

    max_sev_eq1 = MAX_SEVERITY["eq1"][eq1] * step
    max_sev_eq2 = MAX_SEVERITY["eq2"][eq2] * step
    max_sev_eq3eq6 = MAX_SEVERITY["eq3eq6"][eq3][eq6] * step
    max_sev_eq4 = MAX_SEVERITY["eq4"][eq4] * step

    if s1 is not None:
        n_lower += 1
        avail = value - s1
        normed[0] = avail * (csd_eq1 / max_sev_eq1 if max_sev_eq1 else 0.0)
    if s2 is not None:
        n_lower += 1
        avail = value - s2
        normed[1] = avail * (csd_eq2 / max_sev_eq2 if max_sev_eq2 else 0.0)
    if s36 is not None:
        n_lower += 1
        avail = value - s36
        normed[2] = avail * (csd_eq3eq6 / max_sev_eq3eq6 if max_sev_eq3eq6 else 0.0)
    if s4 is not None:
        n_lower += 1
        avail = value - s4
        normed[3] = avail * (csd_eq4 / max_sev_eq4 if max_sev_eq4 else 0.0)
    if s5 is not None:
        n_lower += 1
        # eq5 percent is always 0 per spec
        normed[4] = 0.0

    mean_distance = 0.0 if n_lower == 0 else sum(normed) / n_lower

    value -= mean_distance
    if value < 0:
        value = 0.0
    if value > 10:
        value = 10.0

    final = round(value * 10) / 10.0

    return CVSS4Score(
        score=final,
        severity=severity_from_score(final),
        macro_vector=mv_str,
        vector=vector_from_metrics(m),
        metrics=m,
    )


def score_from_vector(s: str) -> CVSS4Score:
    return score_from_metrics(parse_vector(s))


def severity_from_score(score: float) -> Severity:
    if score == 0.0:
        return Severity.NONE
    if score < 4.0:
        return Severity.LOW
    if score < 7.0:
        return Severity.MEDIUM
    if score < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL


__all__ = [
    "CVSS4Metrics",
    "CVSS4Score",
    "CVSS4ParseError",
    "Severity",
    "CVSS_LOOKUP_GLOBAL",
    "parse_vector",
    "score_from_metrics",
    "score_from_vector",
    "severity_from_score",
    "vector_from_metrics",
]
