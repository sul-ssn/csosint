"""Snapshot-нормализация и сравнение поверхности атаки между сканами."""

from __future__ import annotations

from types import SimpleNamespace

from collector_service.snapshot import build_snapshot
from collector_service.types import CollectResult, DnsRecords, HostService

from gateway.history import compare_snapshots


def _snap(entity_type: str, key: str, fingerprint: str, details: dict):
    return SimpleNamespace(
        entity_type=entity_type, entity_key=key, fingerprint=fingerprint, details=details
    )


def test_snapshot_has_stable_keys_and_aggregates_observations():
    result = CollectResult()
    result.add_subdomain("WWW.Example.com.", "crtsh")
    result.add_subdomain("www.example.com", "dns")
    result.add_resolution("www.example.com", "203.0.113.4", "dns")
    result.add_service(HostService("203.0.113.4", 443, "internetdb", product="nginx"))
    result.add_service(HostService("203.0.113.4", 443, "shodan", version="1.24"))
    result.add_dns(DnsRecords("www.example.com", a=["203.0.113.4"]))
    result.add_dns(DnsRecords("www.example.com", mx=["mail.example.com"]))
    result.add_vuln("203.0.113.4", "CVE-2026-0001", "internetdb")
    result.add_vuln("203.0.113.4", "CVE-2026-0001", "shodan")

    snapshot = build_snapshot(result)
    keyed = {(row["entity_type"], row["entity_key"]): row for row in snapshot}
    assert len(keyed) == len(snapshot)  # уникальный entity key в рамках job
    assert keyed[("domain", "www.example.com")]["details"]["sources"] == ["crtsh", "dns"]
    service = keyed[("service", "203.0.113.4:443/tcp")]["details"]
    assert service["products"] == ["nginx"]
    assert service["versions"] == ["1.24"]
    assert service["sources"] == ["internetdb", "shodan"]
    assert keyed[("dns", "www.example.com")]["details"]["mx"] == ["mail.example.com"]
    assert keyed[("vulnerability", "203.0.113.4:CVE-2026-0001")]["details"][
        "sources"
    ] == ["internetdb", "shodan"]


def test_compare_snapshots_reports_added_removed_and_changed():
    previous = [
        _snap("domain", "old.example.com", "a", {"fqdn": "old.example.com"}),
        _snap("ip", "203.0.113.1", "b", {"address": "203.0.113.1", "country": "US"}),
    ]
    current = [
        _snap("domain", "new.example.com", "c", {"fqdn": "new.example.com"}),
        _snap("ip", "203.0.113.1", "d", {"address": "203.0.113.1", "country": "KZ"}),
    ]
    diff = compare_snapshots(current, previous)
    assert diff["summary"] == {
        "added": 1,
        "changed": 1,
        "removed": 1,
        "total": 3,
        "by_type": {"domain": 2, "ip": 1},
    }
    changed = next(item for item in diff["changes"] if item["status"] == "changed")
    assert changed["entity_key"] == "203.0.113.1"
    assert changed["changed_fields"] == ["country"]


def test_compare_identical_snapshots_is_stable():
    rows = [_snap("service", "1.2.3.4:443/tcp", "same", {"port": 443})]
    diff = compare_snapshots(rows, rows)
    assert diff["summary"]["total"] == 0
    assert diff["changes"] == []
