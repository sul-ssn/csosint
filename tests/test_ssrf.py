"""SSRF-guard и валидация ввода (ТЗ §11, §12)."""

from __future__ import annotations

import pytest
from collector_service.sources import dns_records
from collector_service.types import CollectResult
from fastapi.testclient import TestClient

from csosint_common.netguard import is_public_ip, is_valid_domain
from csosint_common.schemas import ScanRequest, TargetType
from gateway.main import app


@pytest.mark.parametrize(
    ("ip", "expected"),
    [
        ("8.8.8.8", True),
        ("1.1.1.1", True),
        ("2606:4700:4700::1111", True),
        ("127.0.0.1", False),  # loopback
        ("10.0.0.1", False),  # RFC1918
        ("192.168.1.1", False),
        ("172.16.5.5", False),
        ("169.254.169.254", False),  # cloud metadata (link-local)
        ("0.0.0.0", False),  # unspecified
        ("::1", False),  # IPv6 loopback
        ("fe80::1", False),  # IPv6 link-local
        ("fc00::1", False),  # IPv6 ULA
        ("not-an-ip", False),
    ],
)
def test_is_public_ip(ip: str, expected: bool) -> None:
    assert is_public_ip(ip) is expected


@pytest.mark.parametrize(
    ("domain", "ok"),
    [
        ("example.com", True),
        ("www.sub.example.co.uk", True),
        ("xn--e1afmkfd.xn--p1ai", True),
        ("localhost", False),  # один уровень — не FQDN
        ("-bad.com", False),
        ("a..b.com", False),
        ("ex ample.com", False),
        ("", False),
    ],
)
def test_is_valid_domain(domain: str, ok: bool) -> None:
    assert is_valid_domain(domain) is ok


def test_scanrequest_rejects_private_ip() -> None:
    with pytest.raises(ValueError):
        ScanRequest(target="169.254.169.254", type=TargetType.ip)


def test_scanrequest_rejects_bad_domain() -> None:
    with pytest.raises(ValueError):
        ScanRequest(target="not_a_domain", type=TargetType.domain)


def test_scanrequest_accepts_valid() -> None:
    assert ScanRequest(target="8.8.8.8", type=TargetType.ip).target == "8.8.8.8"
    assert ScanRequest(target="example.com", type=TargetType.domain).type == TargetType.domain


def test_scan_endpoint_rejects_private_ip() -> None:
    # Валидация срабатывает до похода в БД → 422 без Postgres.
    with TestClient(app) as client:
        resp = client.post("/api/v1/scan", json={"target": "127.0.0.1", "type": "ip"})
    assert resp.status_code == 422


def test_scan_endpoint_rejects_bad_domain() -> None:
    with TestClient(app) as client:
        resp = client.post("/api/v1/scan", json={"target": "bad_domain", "type": "domain"})
    assert resp.status_code == 422


async def test_dns_drops_private_resolved_ips() -> None:
    # DNS rebinding: имя резолвится в приватный IP → в recon/граф не попадает.
    answers = {"A": ["8.8.8.8", "127.0.0.1", "10.0.0.5"]}

    async def fake_resolve(qname: str, rdtype: str) -> list[str]:
        return answers.get(rdtype, [])

    result = CollectResult()
    await dns_records.collect(result, "x.example.com", resolve=fake_resolve)
    ips = {ip for _, ip, _ in result.resolutions}
    assert ips == {"8.8.8.8"}
