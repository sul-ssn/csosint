"""InternetDB — primary-источник портов/CPE/CVE по IP.

Бесплатно, без ключа: `https://internetdb.shodan.io/{ip}`. Отдаёт открытые порты,
hostnames, host-level CPE, теги и `vulns` (готовые CVE от Shodan). `vulns`
показываем как host-level находки (source=internetdb, confidence=high); свой
CPE-матчинг по локальной базе NVD остаётся дополнением.
"""

from __future__ import annotations

from ..cpe import cpe22_to_23
from ..http import get_json
from ..types import CollectResult, HostService

_BASE = "https://internetdb.shodan.io"
SOURCE = "internetdb"

# Порт-сентинел для host-level CPE: InternetDB не коррелирует port↔CPE,
# поэтому такие наблюдения кладём с port=0 («порт не сопоставлен»).
HOST_LEVEL_PORT = 0


def parse(ip: str, data: dict) -> list[HostService]:
    services: list[HostService] = []
    for port in data.get("ports", []):
        try:
            services.append(HostService(ip=ip, port=int(port), source=SOURCE))
        except (TypeError, ValueError):
            continue
    for raw_cpe in data.get("cpes", []):
        uri = cpe22_to_23(raw_cpe)
        if uri:
            services.append(HostService(ip=ip, port=HOST_LEVEL_PORT, source=SOURCE, cpe_uri=uri))
    return services


def parse_vulns(data: dict) -> list[str]:
    """CVE-идентификаторы из поля `vulns` (мусор отфильтрован)."""
    return sorted({c for v in data.get("vulns", []) if (c := str(v)).startswith("CVE-")})


async def collect(result: CollectResult, ip: str, client) -> None:
    """Фетч+парс InternetDB по IP; наполняет result. Бросает SourceError при сбое."""
    data = await get_json(client, f"{_BASE}/{ip}")
    services = parse(ip, data)
    vulns = parse_vulns(data)
    # host-level якорь (port=0) — к нему привязываем host-level CVE от Shodan.
    if vulns and not any(s.port == HOST_LEVEL_PORT for s in services):
        services.append(HostService(ip=ip, port=HOST_LEVEL_PORT, source=SOURCE))
    for svc in services:
        result.add_service(svc)
    host_cpe = next((s.cpe_uri for s in services if s.port == HOST_LEVEL_PORT and s.cpe_uri), None)
    for cve_id in vulns:
        result.add_vuln(ip, cve_id, SOURCE, host_cpe)
    # hostnames — обратные имена для IP; фиксируем как поддомены + резолвы.
    for hostname in data.get("hostnames", []):
        result.add_subdomain(hostname, SOURCE)
        result.add_resolution(hostname, ip, SOURCE)
