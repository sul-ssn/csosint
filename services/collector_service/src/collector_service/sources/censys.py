"""Censys (опц., free tier) — хосты/сервисы, альтернатива Shodan.

Search API v2 с Basic-auth (api_id:api_secret). Нет пары ключей → пропуск."""

from __future__ import annotations

import base64

from ..cpe import cpe22_to_23
from ..http import get_json
from ..types import CollectResult, HostService

_BASE = "https://search.censys.io/api/v2"
SOURCE = "censys"


def is_enabled(settings) -> bool:
    return bool(settings.censys_api_id and settings.censys_api_secret)


def _auth_header(settings) -> dict[str, str]:
    token = base64.b64encode(
        f"{settings.censys_api_id}:{settings.censys_api_secret}".encode()
    ).decode()
    return {"Authorization": f"Basic {token}"}


def parse(ip: str, data: dict) -> list[HostService]:
    services: list[HostService] = []
    for s in data.get("result", {}).get("services", []):
        port = s.get("port")
        if port is None:
            continue
        software = s.get("software") or []
        product = version = cpe_uri = None
        if software:
            product = software[0].get("product")
            version = software[0].get("version")
            uri = software[0].get("uniform_resource_identifier")
            cpe_uri = cpe22_to_23(uri) if uri else None
        services.append(
            HostService(
                ip=ip,
                port=int(port),
                source=SOURCE,
                protocol=s.get("transport_protocol"),
                product=product,
                version=version,
                cpe_uri=cpe_uri,
            )
        )
    return services


async def collect(result: CollectResult, ip: str, client, settings) -> None:
    data = await get_json(client, f"{_BASE}/hosts/{ip}", headers=_auth_header(settings))
    for svc in parse(ip, data):
        result.add_service(svc)
