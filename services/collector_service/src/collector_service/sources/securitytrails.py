"""SecurityTrails (опц., free tier) — пассивный DNS/историчные поддомены,
усиливает поиск активов сверх CT. Нет ключа → пропуск."""

from __future__ import annotations

from ..http import get_json
from ..types import CollectResult

_BASE = "https://api.securitytrails.com/v1"
SOURCE = "securitytrails"


def is_enabled(settings) -> bool:
    return bool(settings.securitytrails_api_key)


def parse(domain: str, data: dict) -> set[str]:
    # API отдаёт метки поддоменов относительно домена: "www" → "www.example.com".
    return {f"{label}.{domain}".lower().rstrip(".") for label in data.get("subdomains", [])}


async def collect(result: CollectResult, domain: str, client, settings) -> None:
    domain = domain.lower().rstrip(".")
    data = await get_json(
        client,
        f"{_BASE}/domain/{domain}/subdomains",
        headers={"APIKEY": settings.securitytrails_api_key},
    )
    for sub in parse(domain, data):
        result.add_subdomain(sub, SOURCE)
