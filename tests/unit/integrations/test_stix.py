"""STIX 2.1 bundle tests."""

from __future__ import annotations

from decepticon.integrations.siem import to_stix


def test_stix_bundle_shape():
    f = {
        "title": "RCE",
        "description": "deserialization",
        "severity": "Critical",
        "target": "https://x/",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "cve_ids": ["CVE-2025-0001"],
    }
    b = to_stix(f)
    assert b["type"] == "bundle"
    assert b["id"].startswith("bundle--")
    objs = b["objects"]
    assert len(objs) >= 1
    # Must contain at least one SDO (vulnerability in this impl) with spec_version 2.1
    sdo = objs[0]
    assert sdo["spec_version"] == "2.1"
    assert sdo["type"] in ("vulnerability", "indicator", "observed-data")
