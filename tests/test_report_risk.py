"""Тесты риск-модели отчёта (gateway.risk) — чистые функции, без БД."""

from __future__ import annotations

import pytest

from gateway.risk import (
    build_exec_summary,
    priority,
    rank_findings,
    risk_factors,
    risk_score,
    severity_bucket,
    summarize,
    top_risks,
)


@pytest.mark.parametrize(
    "cvss,conf,expected",
    [
        (9.8, "high", 98.0),
        (9.8, "medium", 73.5),
        (9.8, "low", 49.0),
        (7.5, "high", 75.0),
        (None, "high", 50.0),  # CVSS неизвестен → консервативная середина
        (0.0, "high", 0.0),
    ],
)
def test_risk_score(cvss, conf, expected):
    assert risk_score(cvss, conf) == expected


def test_exploitation_intel_increases_risk_with_cap():
    assert risk_score(7.0, "high", epss_score=0.8) == 82.0
    assert risk_score(7.0, "high", epss_score=0.8, kev=True) == 100.0
    assert risk_score(5.0, "medium", kev=True, ransomware_use="Known") == 62.5


def test_risk_factors_explain_kev_epss_and_ransomware():
    factors = risk_factors(
        {
            "cvss_score": 8.0,
            "match_confidence": "high",
            "epss_score": 0.42,
            "kev": True,
            "kev_ransomware_use": "Known",
        }
    )
    assert [item["factor"] for item in factors] == [
        "cvss",
        "confidence",
        "epss",
        "kev",
        "ransomware",
    ]
    assert sum(item["impact"] for item in factors if item["factor"] in {"epss", "kev"}) == 26.3


@pytest.mark.parametrize(
    "score,tier",
    [(98.0, "critical"), (80.0, "critical"), (60.0, "high"), (49.0, "medium"), (29.9, "low")],
)
def test_priority_tiers(score, tier):
    assert priority(score) == tier


@pytest.mark.parametrize(
    "sev,bucket",
    [
        ("CRITICAL", "critical"),
        ("high", "high"),
        ("Medium", "medium"),
        (None, "unknown"),
        ("weird", "unknown"),
    ],
)
def test_severity_bucket(sev, bucket):
    assert severity_bucket(sev) == bucket


def test_severity_beats_confidence_in_ranking():
    # Критичная CVE со средней достоверностью должна опережать слабую CVE с высокой.
    critical_medium = {"cve_id": "CVE-A", "cvss_score": 9.1, "match_confidence": "medium"}
    weak_high = {"cve_id": "CVE-B", "cvss_score": 4.0, "match_confidence": "high"}
    ranked = rank_findings([weak_high, critical_medium])
    assert ranked[0]["cve_id"] == "CVE-A"
    assert ranked[0]["risk_score"] > ranked[1]["risk_score"]
    assert ranked[0]["priority"] == "high"  # 9.1*0.75*10 = 68.2


def test_summarize_distributions_and_posture():
    vulns = [
        {"cvss_score": 9.8, "match_confidence": "high", "severity": "CRITICAL"},
        {"cvss_score": 5.0, "match_confidence": "low", "severity": "MEDIUM"},
        {"cvss_score": None, "match_confidence": "medium", "severity": None},
    ]
    rank_findings(vulns)
    s = summarize(1, 2, 3, vulns)
    assert s["vulnerabilities"] == 3
    assert s["by_severity"]["critical"] == 1
    assert s["by_severity"]["medium"] == 1
    assert s["by_severity"]["unknown"] == 1
    assert s["by_confidence"] == {"high": 1, "medium": 1, "low": 1}
    assert s["max_risk_score"] == 98.0
    assert s["risk_posture"] == "critical"


def test_summarize_empty_posture_none():
    s = summarize(0, 0, 0, [])
    assert s["risk_posture"] == "none"
    assert s["max_risk_score"] == 0.0


def test_top_risks_caps_and_orders():
    vulns = [{"cvss_score": float(i), "match_confidence": "high"} for i in range(1, 11)]
    rank_findings(vulns)
    top = top_risks(vulns, n=3)
    assert len(top) == 3
    assert top[0]["cvss_score"] == 10.0  # самый рискованный первым


def test_exec_summary_empty_and_populated():
    empty = build_exec_summary("example.com", 1, 2, [], summarize(1, 1, 2, []))
    assert "не выявлено" in empty

    vulns = [
        {
            "cve_id": "CVE-2021-44228",
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "match_confidence": "high",
            "ip": "203.0.113.5",
            "port": 8080,
            "product": "Apache Log4j",
            "version": "2.14.1",
        }
    ]
    rank_findings(vulns)
    text = build_exec_summary("example.com", 1, 1, vulns, summarize(1, 1, 1, vulns))
    assert "CVE-2021-44228" in text
    assert "Наибольший риск" in text
    assert "203.0.113.5:8080" in text
