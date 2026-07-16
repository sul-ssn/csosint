"""Оркестрация сбора: degraded/skip-логика и провенанс. Сеть — respx."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
import respx
import tenacity
from collector_service.pipeline import collect

_NO_KEYS = SimpleNamespace(
    shodan_api_key=None,
    censys_api_id=None,
    censys_api_secret=None,
    securitytrails_api_key=None,
    virustotal_api_key=None,
)


@pytest.fixture(autouse=True)
def _no_retry_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "collector_service.http.wait_random_exponential", lambda **kw: tenacity.wait_none()
    )


@respx.mock
async def test_ip_scan_collects_and_skips_optional() -> None:
    respx.get("https://internetdb.shodan.io/1.2.3.4").mock(
        return_value=httpx.Response(200, json={"ports": [443], "cpes": [], "hostnames": []})
    )
    respx.get("https://rdap.org/ip/1.2.3.4").mock(
        return_value=httpx.Response(200, json={"name": "TESTNET", "country": "US"})
    )
    result = await collect("1.2.3.4", "ip", _NO_KEYS)

    assert [s.port for s in result.services] == [443]
    assert result.ip_infos[0].org_name == "TESTNET"
    # Опциональные без ключей — тихо пропущены (graceful degradation).
    assert result.degraded["shodan"].startswith("skipped")
    assert result.degraded["censys"].startswith("skipped")
    assert "internetdb" not in result.degraded and "rdap" not in result.degraded


@respx.mock
async def test_domain_scan_end_to_end() -> None:
    respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(200, json=[{"name_value": "www.example.com"}])
    )
    respx.get("https://internetdb.shodan.io/1.2.3.4").mock(
        return_value=httpx.Response(200, json={"ports": [80], "cpes": [], "hostnames": []})
    )
    respx.get("https://rdap.org/ip/1.2.3.4").mock(
        return_value=httpx.Response(200, json={"name": "NET", "country": "US"})
    )

    async def fake_resolve(qname: str, rdtype: str) -> list[str]:
        return ["1.2.3.4"] if rdtype == "A" else []

    result = await collect("example.com", "domain", _NO_KEYS, resolve=fake_resolve)

    assert "example.com" in result.subdomains  # seed
    assert "www.example.com" in result.subdomains  # из CT
    assert ("www.example.com", "1.2.3.4", "dns") in result.resolutions
    assert [s.port for s in result.services] == [80]  # recon по резолвнутому IP
    # Опциональные пассивные DNS без ключей — пропущены.
    assert result.degraded["securitytrails"].startswith("skipped")
    assert result.degraded["virustotal"].startswith("skipped")


@respx.mock
async def test_source_failure_is_degraded_not_fatal() -> None:
    respx.get("https://internetdb.shodan.io/9.9.9.9").mock(return_value=httpx.Response(404))
    respx.get("https://rdap.org/ip/9.9.9.9").mock(
        return_value=httpx.Response(200, json={"name": "Q", "country": "US"})
    )
    result = await collect("9.9.9.9", "ip", _NO_KEYS)

    # InternetDB упал → помечен degraded, но задача не рухнула и RDAP отработал.
    assert result.degraded["internetdb"].startswith("failed")
    assert result.ip_infos[0].org_name == "Q"
    assert result.services == []


async def test_org_target_is_out_of_scope() -> None:
    result = await collect("Example Corp", "org", _NO_KEYS)
    assert result.degraded["org"].startswith("skipped")
    assert result.services == []
