"""VirusTotal (опц., free API key) — пассивный DNS/поддомены.
Нет ключа → пропуск."""

from __future__ import annotations

from ..http import get_json
from ..types import CollectResult

_BASE = "https://www.virustotal.com/api/v3"
SOURCE = "virustotal"


def is_enabled(settings) -> bool:
    return bool(settings.virustotal_api_key)


def parse(domain: str, data: dict) -> set[str]:
    # data[].id — уже полные FQDN; фильтруем на всякий случай по домену.
    out: set[str] = set()
    for item in data.get("data", []):
        fqdn = str(item.get("id", "")).lower().rstrip(".")
        if fqdn and (fqdn == domain or fqdn.endswith("." + domain)):
            out.add(fqdn)
    return out


async def collect(result: CollectResult, domain: str, client, settings) -> None:
    domain = domain.lower().rstrip(".")
    data = await get_json(
        client,
        f"{_BASE}/domains/{domain}/subdomains",
        params={"limit": 40},
        headers={"x-apikey": settings.virustotal_api_key},
    )
    for sub in parse(domain, data):
        result.add_subdomain(sub, SOURCE)
