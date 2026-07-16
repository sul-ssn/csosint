"""Детерминированные exposure findings и attack paths."""

from __future__ import annotations

from gateway.deep_analysis import (
    analyze_exposure,
    analyze_infrastructure,
    build_attack_paths,
    deep_summary,
)


def test_sensitive_ports_and_unknown_version_generate_findings():
    findings = analyze_exposure(
        [],
        [
            {
                "id": 1,
                "ip": "203.0.113.5",
                "port": 6379,
                "product": "redis",
                "version": None,
                "source": "internetdb",
            }
        ],
    )
    assert [item["kind"] for item in findings] == ["database", "unknown_version"]
    assert findings[0]["severity"] == "critical"
    assert findings[0]["asset"] == "203.0.113.5:6379"
    assert "пассивного источника" in findings[0]["evidence"][0]


def test_non_production_domain_is_flagged_without_claiming_compromise():
    findings = analyze_exposure([{"id": 1, "fqdn": "api.staging.example.com"}], [])
    assert len(findings) == 1
    assert findings[0]["kind"] == "non_production"
    assert findings[0]["confidence"] == "medium"
    assert "Проверьте" in findings[0]["remediation"]


def test_attack_path_contains_evidence_and_kev_action():
    vuln = {
        "service_id": 4,
        "cve_id": "CVE-2021-44228",
        "priority": "critical",
        "risk_score": 100.0,
        "match_confidence": "high",
        "epss_score": 0.99,
        "kev": True,
        "kev_required_action": "Apply mitigations.",
        "ip": "203.0.113.5",
        "port": 8080,
        "product": "Log4j",
        "description": "Remote code execution.",
        "risk_factors": [{"detail": "CISA confirms exploitation"}],
    }
    paths = build_attack_paths("example.com", "domain", [], [], [vuln])
    assert len(paths) == 1
    assert paths[0]["likelihood"] == "high"
    assert [node["type"] for node in paths[0]["nodes"]] == [
        "entry",
        "ip",
        "service",
        "cve",
    ]
    assert paths[0]["evidence"] == ["CISA confirms exploitation"]
    assert paths[0]["remediation"] == "Apply mitigations."


def test_low_priority_non_exploited_cve_does_not_create_path():
    vuln = {
        "service_id": 1,
        "cve_id": "CVE-X",
        "priority": "low",
        "risk_score": 10.0,
        "kev": False,
    }
    assert build_attack_paths("1.2.3.4", "ip", [], [], [vuln]) == []
    summary = deep_summary([], [])
    assert summary["attack_paths"] == 0
    assert summary["critical_findings"] == 0


def test_expired_shared_certificate_and_network_cluster():
    findings = analyze_infrastructure(
        [
            {
                "fingerprint": "crtsh:old",
                "not_after": "2020-01-01T00:00:00+00:00",
                "domains": [f"d{i}.example.com" for i in range(5)],
            }
        ],
        [
            {"address": f"203.0.113.{i}", "network_cidr": "203.0.113.0/24"}
            for i in range(1, 4)
        ],
    )
    kinds = {item["kind"] for item in findings}
    assert kinds == {"certificate_expiry", "shared_certificate", "infrastructure_cluster"}
    expired = next(item for item in findings if item["kind"] == "certificate_expiry")
    assert expired["severity"] == "high"
