"""RDAP по IP — владелец диапазона/страна.

RDAP вместо whois: структурированный JSON, без хрупкого парсинга. Ходим через
редиректор `rdap.org`, который направляет к authoritative RDAP-серверу RIR.
Домен-RDAP в v1 не персистим (в схеме §5 нет полей владельца домена) — фокус на
IP → asn/org/country для `ip_addresses`.
"""

from __future__ import annotations

from ..http import get_json
from ..types import CollectResult, IpInfo

_BASE = "https://rdap.org"
SOURCE = "rdap"


def _org_from_entities(data: dict) -> str | None:
    """Достать имя организации из vCard registrant/administrative-сущности."""
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if not ({"registrant", "administrative", "abuse"} & set(roles)):
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) == 2:
            for field in vcard[1]:
                if isinstance(field, list) and field and field[0] == "fn":
                    return field[3] if len(field) > 3 else None
    return None


def parse_ip(ip: str, data: dict) -> IpInfo:
    # Верхнеуровневое `name` — имя сети (напр. "GOOGLE"); org уточняем по entities.
    org = _org_from_entities(data) or data.get("name")
    asns = data.get("arin_originas0_originautnums") or []
    asn = f"AS{asns[0]}" if asns else None
    cidr = None
    for item in data.get("cidr0_cidrs", []):
        prefix = item.get("v4prefix") or item.get("v6prefix")
        if prefix and item.get("length") is not None:
            cidr = f"{prefix}/{item['length']}"
            break
    return IpInfo(
        ip=ip,
        source=SOURCE,
        asn=asn,
        org_name=org,
        country=data.get("country"),
        network_cidr=cidr,
        network_start=data.get("startAddress"),
        network_end=data.get("endAddress"),
    )


async def collect_ip(result: CollectResult, ip: str, client) -> None:
    data = await get_json(client, f"{_BASE}/ip/{ip}")
    result.add_ip_info(parse_ip(ip, data))
