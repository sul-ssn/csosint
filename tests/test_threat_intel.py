"""Парсинг официальных FIRST EPSS и CISA KEV feeds."""

from __future__ import annotations

from cve_service.threat_intel import parse_epss, parse_kev


def test_parse_epss_numbers_and_date():
    rows = parse_epss(
        {
            "data": [
                {
                    "cve": "CVE-2021-44228",
                    "epss": "0.943580000",
                    "percentile": "0.999560000",
                    "date": "2026-07-14",
                }
            ]
        }
    )
    assert rows[0]["cve_id"] == "CVE-2021-44228"
    assert rows[0]["epss_score"] == 0.94358
    assert rows[0]["epss_percentile"] == 0.99956
    assert rows[0]["epss_date"].isoformat().startswith("2026-07-14")


def test_parse_kev_operational_fields():
    rows = parse_kev(
        {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "dateAdded": "2021-12-10",
                    "dueDate": "2021-12-24",
                    "requiredAction": "Apply updates per vendor instructions.",
                    "knownRansomwareCampaignUse": "Known",
                }
            ]
        }
    )
    row = rows[0]
    assert row["kev"] is True
    assert row["kev_ransomware_use"] == "Known"
    assert row["kev_due_date"].isoformat().startswith("2021-12-24")
    assert "Apply updates" in row["kev_required_action"]
