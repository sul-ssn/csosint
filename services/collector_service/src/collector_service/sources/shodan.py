"""Shodan (опц., платный/членский ключ) — баннеры и доп. поля сверх InternetDB
(ТЗ §4.1, §4.5). Нет ключа → источник пропускается пайплайном."""

from __future__ import annotations

from ..cpe import cpe22_to_23
from ..http import get_json
from ..types import CollectResult, HostService

_BASE = "https://api.shodan.io"
SOURCE = "shodan"


def is_enabled(settings) -> bool:
    return bool(settings.shodan_api_key)


def parse(ip: str, data: dict) -> list[HostService]:
    services: list[HostService] = []
    for item in data.get("data", []):
        port = item.get("port")
        if port is None:
            continue
        cpes = item.get("cpe23") or item.get("cpe") or []
        cpe_uri = cpe22_to_23(cpes[0]) if cpes else None
        services.append(
            HostService(
                ip=ip,
                port=int(port),
                source=SOURCE,
                protocol=item.get("transport"),
                product=item.get("product"),
                version=item.get("version"),
                cpe_uri=cpe_uri,
                banner=item.get("data"),
            )
        )
    return services


async def collect(result: CollectResult, ip: str, client, settings) -> None:
    data = await get_json(
        client, f"{_BASE}/shodan/host/{ip}", params={"key": settings.shodan_api_key}
    )
    for svc in parse(ip, data):
        result.add_service(svc)
    for hostname in data.get("hostnames", []):
        result.add_subdomain(hostname, SOURCE)
        result.add_resolution(hostname, ip, SOURCE)
