"""InternetDB — primary-источник портов/CPE по IP (ТЗ §4.1).

Бесплатно, без ключа: `https://internetdb.shodan.io/{ip}`. Отдаёт открытые порты,
hostnames, host-level CPE, теги и `vulns`. `vulns` пользователю НЕ показываем —
это эталон для кросс-чека матчинга (ТЗ §4.1, §6); наружу идёт наша корреляция.
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


async def collect(result: CollectResult, ip: str, client) -> None:
    """Фетч+парс InternetDB по IP; наполняет result. Бросает SourceError при сбое."""
    data = await get_json(client, f"{_BASE}/{ip}")
    for svc in parse(ip, data):
        result.add_service(svc)
    # hostnames — обратные имена для IP; фиксируем как поддомены + резолвы.
    for hostname in data.get("hostnames", []):
        result.add_subdomain(hostname, SOURCE)
        result.add_resolution(hostname, ip, SOURCE)
