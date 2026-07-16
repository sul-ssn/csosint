"""Канонический снимок результата сбора для сравнения последовательных сканов."""

from __future__ import annotations

import hashlib
import json

from .types import CollectResult


def _row(entity_type: str, entity_key: str, details: dict) -> dict:
    encoded = json.dumps(details, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {
        "entity_type": entity_type,
        "entity_key": entity_key,
        "fingerprint": hashlib.sha256(encoded.encode()).hexdigest(),
        "details": details,
    }


def build_snapshot(result: CollectResult) -> list[dict]:
    """Нормализовать нестабильный CollectResult в набор сущностей со стабильными ключами."""
    rows: list[dict] = []
    for fqdn, sources in sorted(result.subdomains.items()):
        rows.append(_row("domain", fqdn, {"fqdn": fqdn, "sources": sorted(sources)}))

    info_by_ip: dict[str, dict] = {ip: {"address": ip} for ip in result.ips}
    for info in result.ip_infos:
        item = info_by_ip.setdefault(info.ip, {"address": info.ip})
        for key in (
            "asn",
            "org_name",
            "country",
            "network_cidr",
            "network_start",
            "network_end",
        ):
            value = getattr(info, key)
            if value and not item.get(key):
                item[key] = value
    for ip, details in sorted(info_by_ip.items()):
        rows.append(_row("ip", ip, details))

    resolutions: dict[str, dict] = {}
    for fqdn, ip, source in sorted(result.resolutions):
        key = f"{fqdn}->{ip}"
        item = resolutions.setdefault(key, {"fqdn": fqdn, "ip": ip, "sources": []})
        if source not in item["sources"]:
            item["sources"].append(source)
    rows.extend(_row("resolution", key, value) for key, value in resolutions.items())

    services: dict[str, dict] = {}
    for svc in sorted(result.services, key=lambda s: (s.ip, s.port, s.protocol or "", s.source)):
        key = f"{svc.ip}:{svc.port}/{svc.protocol or 'tcp'}"
        item = services.setdefault(
            key,
            {
                "ip": svc.ip,
                "port": svc.port,
                "protocol": svc.protocol or "tcp",
                "products": [],
                "versions": [],
                "cpes": [],
                "sources": [],
            },
        )
        for field, value in (
            ("products", svc.product),
            ("versions", svc.version),
            ("cpes", svc.cpe_uri),
            ("sources", svc.source),
        ):
            if value and value not in item[field]:
                item[field].append(value)
    rows.extend(_row("service", key, value) for key, value in services.items())

    dns: dict[str, dict] = {}
    for record in sorted(result.dns_records, key=lambda r: r.fqdn):
        item = dns.setdefault(
            record.fqdn,
            {"fqdn": record.fqdn, "a": [], "aaaa": [], "mx": [], "ns": [], "txt": []},
        )
        for field in ("a", "aaaa", "mx", "ns", "txt"):
            item[field] = sorted(set(item[field]) | set(getattr(record, field)))
    rows.extend(_row("dns", key, value) for key, value in dns.items())

    vulns: dict[str, dict] = {}
    for vuln in sorted(result.vulns, key=lambda v: (v.ip, v.cve_id, v.source)):
        key = f"{vuln.ip}:{vuln.cve_id}"
        item = vulns.setdefault(
            key, {"ip": vuln.ip, "cve_id": vuln.cve_id, "sources": []}
        )
        if vuln.source not in item["sources"]:
            item["sources"].append(vuln.source)
    rows.extend(_row("vulnerability", key, value) for key, value in vulns.items())
    for cert in sorted(result.certificates, key=lambda item: item.fingerprint):
        rows.append(
            _row(
                "certificate",
                cert.fingerprint,
                {
                    "fingerprint": cert.fingerprint,
                    "names": sorted(cert.names),
                    "issuer": cert.issuer,
                    "not_before": cert.not_before,
                    "not_after": cert.not_after,
                    "source": cert.source,
                },
            )
        )
    return rows
