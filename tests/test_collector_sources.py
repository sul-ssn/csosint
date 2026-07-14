"""Коннекторы сбора: чистые парсеры + http-ретраи (ТЗ §4, §12). Сеть — respx."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
import respx
import tenacity
from collector_service.cpe import cpe22_to_23
from collector_service.http import SourceError, build_client, get_json
from collector_service.sources import (
    censys,
    crtsh,
    dns_records,
    internetdb,
    rdap,
    securitytrails,
    shodan,
    virustotal,
)
from collector_service.types import CollectResult


@pytest.fixture(autouse=True)
def _no_retry_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    # Убираем реальные паузы бэкоффа — тесты быстрые.
    monkeypatch.setattr(
        "collector_service.http.wait_random_exponential", lambda **kw: tenacity.wait_none()
    )


# --- CPE 2.2 → 2.3 --------------------------------------------------------- #
def test_cpe22_to_23() -> None:
    assert (
        cpe22_to_23("cpe:/a:openbsd:openssh:8.2p1")
        == "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*"
    )
    assert cpe22_to_23("cpe:2.3:a:x:y:1:*:*:*:*:*:*:*") == "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"
    assert cpe22_to_23("garbage") is None


# --- InternetDB ------------------------------------------------------------ #
def test_internetdb_parse_ports_and_host_cpe() -> None:
    data = {
        "ports": [22, 443],
        "cpes": ["cpe:/a:openbsd:openssh:8.2p1"],
        "hostnames": ["h.example.com"],
    }
    services = internetdb.parse("1.2.3.4", data)
    ports = sorted(s.port for s in services)
    assert ports == [0, 22, 443]  # 0 = host-level CPE (порт не сопоставлен)
    cpe_svc = next(s for s in services if s.port == 0)
    assert cpe_svc.cpe_uri == "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*"
    assert all(s.source == "internetdb" for s in services)


# --- Certificate Transparency --------------------------------------------- #
def test_crtsh_parse_filters_and_strips_wildcards() -> None:
    data = [
        {"name_value": "a.example.com\n*.example.com", "common_name": "example.com"},
        {"name_value": "other.com"},
    ]
    assert crtsh.parse_crtsh("example.com", data) == {"a.example.com", "example.com"}


def test_certspotter_parse() -> None:
    data = [{"dns_names": ["x.example.com", "*.example.com", "evil.com"]}]
    assert crtsh.parse_certspotter("example.com", data) == {"x.example.com", "example.com"}


@respx.mock
async def test_crtsh_falls_back_to_certspotter() -> None:
    respx.get("https://crt.sh/").mock(return_value=httpx.Response(502))
    respx.get("https://api.certspotter.com/v1/issuances").mock(
        return_value=httpx.Response(200, json=[{"dns_names": ["fallback.example.com"]}])
    )
    result = CollectResult()
    async with build_client() as client:
        await crtsh.collect(result, "example.com", client)
    assert "fallback.example.com" in result.subdomains
    assert result.subdomains["fallback.example.com"] == {"certspotter"}


# --- RDAP ------------------------------------------------------------------ #
def test_rdap_parse_org_from_entities() -> None:
    data = {
        "name": "GOOGLE",
        "country": "US",
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [["version", {}, "text", "4.0"], ["fn", {}, "text", "Google LLC"]],
                ],
            }
        ],
    }
    info = rdap.parse_ip("8.8.8.8", data)
    assert info.org_name == "Google LLC"
    assert info.country == "US"


def test_rdap_parse_falls_back_to_name() -> None:
    info = rdap.parse_ip("1.1.1.1", {"name": "CLOUDFLARENET", "country": "US"})
    assert info.org_name == "CLOUDFLARENET"


# --- Опциональные источники ------------------------------------------------ #
def test_shodan_parse() -> None:
    data = {
        "data": [
            {
                "port": 22,
                "transport": "tcp",
                "product": "OpenSSH",
                "version": "8.2p1",
                "cpe": ["cpe:/a:openbsd:openssh:8.2p1"],
                "data": "SSH-2.0-OpenSSH_8.2p1",
            }
        ]
    }
    svcs = shodan.parse("1.2.3.4", data)
    assert len(svcs) == 1
    assert (svcs[0].port, svcs[0].product, svcs[0].version) == (22, "OpenSSH", "8.2p1")
    assert svcs[0].cpe_uri.startswith("cpe:2.3:a:openbsd:openssh:8.2p1")
    assert svcs[0].banner == "SSH-2.0-OpenSSH_8.2p1"


def test_censys_parse() -> None:
    nginx_cpe = "cpe:2.3:a:f5:nginx:1.20.0:*:*:*:*:*:*:*"
    software = [{"product": "nginx", "version": "1.20.0", "uniform_resource_identifier": nginx_cpe}]
    data = {
        "result": {"services": [{"port": 443, "transport_protocol": "TCP", "software": software}]}
    }
    svcs = censys.parse("1.2.3.4", data)
    assert (svcs[0].port, svcs[0].product, svcs[0].version) == (443, "nginx", "1.20.0")
    assert svcs[0].cpe_uri == nginx_cpe


def test_securitytrails_parse_appends_domain() -> None:
    assert securitytrails.parse("example.com", {"subdomains": ["www", "mail"]}) == {
        "www.example.com",
        "mail.example.com",
    }


def test_virustotal_parse_filters_foreign() -> None:
    data = {"data": [{"id": "www.example.com"}, {"id": "evil.com"}]}
    assert virustotal.parse("example.com", data) == {"www.example.com"}


def test_optional_is_enabled_flags() -> None:
    empty = SimpleNamespace(
        shodan_api_key=None,
        censys_api_id=None,
        censys_api_secret=None,
        securitytrails_api_key=None,
        virustotal_api_key=None,
    )
    assert not shodan.is_enabled(empty)
    assert not censys.is_enabled(empty)
    assert not securitytrails.is_enabled(empty)
    assert not virustotal.is_enabled(empty)
    assert shodan.is_enabled(SimpleNamespace(shodan_api_key="k"))
    assert censys.is_enabled(SimpleNamespace(censys_api_id="a", censys_api_secret="b"))


# --- DNS (fake resolver) --------------------------------------------------- #
async def test_dns_collect_with_fake_resolver() -> None:
    answers = {
        "A": ["1.2.3.4"],
        "AAAA": ["2606:4700:4700::1111"],
        "MX": ["10 mail.example.com."],
        "NS": ["ns1.example.com."],
        "TXT": ['"v=spf1 -all"'],
    }

    async def fake_resolve(qname: str, rdtype: str) -> list[str]:
        return answers[rdtype]

    result = CollectResult()
    rec = await dns_records.collect(result, "www.example.com", resolve=fake_resolve)
    assert rec.a == ["1.2.3.4"]
    assert rec.aaaa == ["2606:4700:4700::1111"]
    assert ("www.example.com", "1.2.3.4", "dns") in result.resolutions
    assert ("www.example.com", "2606:4700:4700::1111", "dns") in result.resolutions


async def test_dns_swallows_per_record_errors() -> None:
    async def boom(qname: str, rdtype: str) -> list[str]:
        raise RuntimeError("resolver down")

    result = CollectResult()
    rec = await dns_records.collect(result, "x.example.com", resolve=boom)
    assert rec.a == [] and result.resolutions == set()  # не падаем


# --- HTTP-ретраи ----------------------------------------------------------- #
@respx.mock
async def test_get_json_retries_5xx_then_succeeds() -> None:
    route = respx.get("https://x.test/j").mock(
        side_effect=[httpx.Response(503), httpx.Response(200, json={"ok": True})]
    )
    async with build_client() as client:
        data = await get_json(client, "https://x.test/j")
    assert data == {"ok": True}
    assert route.call_count == 2


@respx.mock
async def test_get_json_4xx_not_retried() -> None:
    route = respx.get("https://x.test/j").mock(return_value=httpx.Response(404))
    async with build_client() as client:
        with pytest.raises(SourceError):
            await get_json(client, "https://x.test/j")
    assert route.call_count == 1
