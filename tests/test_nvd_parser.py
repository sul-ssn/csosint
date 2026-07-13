"""Парсинг ответа NVD (design-nvd-sync §5, §6, §11, §12)."""

from __future__ import annotations

from cve_service.nvd.parser import parse_configurations, parse_cve


def _cve(**over) -> dict:
    base = {
        "id": "CVE-0000-0001",
        "descriptions": [
            {"lang": "es", "value": "hola"},
            {"lang": "en", "value": "an english description"},
        ],
        "published": "2021-12-10T10:15:09.143",
        "lastModified": "2022-01-01T00:00:00.000",
    }
    base.update(over)
    return {"cve": base}


def test_english_description_and_dates() -> None:
    pc = parse_cve(_cve())
    assert pc.record.description == "an english description"
    assert pc.record.published is not None
    assert pc.record.published.tzinfo is not None  # naive-таймстемп получил UTC


def test_cvss_priority_v31_over_v2() -> None:
    metrics = {
        "cvssMetricV2": [
            {
                "type": "Primary",
                "cvssData": {"version": "2.0", "baseScore": 5.0, "vectorString": "AV:N"},
                "baseSeverity": "MEDIUM",
            }
        ],
        "cvssMetricV31": [
            {
                "type": "Primary",
                "cvssData": {
                    "version": "3.1",
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL",
                    "vectorString": "CVSS:3.1/AV:N",
                },
            }
        ],
    }
    pc = parse_cve(_cve(metrics=metrics))
    assert pc.record.cvss_version == "3.1"
    assert pc.record.cvss_score == 9.8
    assert pc.record.severity == "CRITICAL"


def test_cvss_v2_severity_from_metric_level() -> None:
    metrics = {
        "cvssMetricV2": [
            {
                "type": "Primary",
                "cvssData": {"version": "2.0", "baseScore": 7.5, "vectorString": "AV:N"},
                "baseSeverity": "HIGH",
            }
        ]
    }
    pc = parse_cve(_cve(metrics=metrics))
    assert pc.record.cvss_version == "2.0"
    assert pc.record.severity == "HIGH"


def test_no_cvss_no_configurations_does_not_crash() -> None:
    pc = parse_cve(_cve(vulnStatus="Rejected"))
    assert pc.record.cvss_version is None
    assert pc.record.severity == "UNKNOWN"
    assert pc.matches == []


def test_version_end_excluding_single_row() -> None:
    cve = _cve(
        configurations=[
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "negate": False,
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "2.4.0",
                                "versionEndExcluding": "2.4.52",
                            }
                        ],
                    }
                ]
            }
        ]
    )
    rows = parse_configurations(cve["cve"])
    assert len(rows) == 1
    r = rows[0]
    assert (r.vendor, r.product, r.part) == ("apache", "http_server", "a")
    assert (r.version_start, r.version_start_type) == ("2.4.0", "including")
    assert (r.version_end, r.version_end_type) == ("2.4.52", "excluding")
    assert r.vulnerable_bool is True
    assert r.node_operator == "OR"


def test_and_configuration_preserves_operator() -> None:
    # log4j «running on»: AND между узлами — сохраняем config_operator для штрафа.
    cve = _cve(
        configurations=[
            {
                "operator": "AND",
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "2.0",
                                "versionEndExcluding": "2.15.0",
                            }
                        ],
                    },
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": False,
                                "criteria": "cpe:2.3:a:apache:solr:*:*:*:*:*:*:*:*",
                            }
                        ],
                    },
                ],
            }
        ]
    )
    rows = parse_configurations(cve["cve"])
    assert len(rows) == 2
    assert all(r.config_operator == "AND" for r in rows)
    vuln = [r for r in rows if r.vulnerable_bool]
    assert len(vuln) == 1 and vuln[0].product == "log4j"
