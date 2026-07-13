"""DNS-записи через dnspython (ТЗ §4.4).

A/AAAA/MX/NS/TXT. Резолвер инъектируется (`resolve`) — юнит-тесты гоняют парсинг
на фейковом резолвере, без реальных DNS-запросов. Поддомены берём пассивно из CT
(§4.3), брутфорс НЕ добавляем (принцип passive by design).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from ..types import CollectResult, DnsRecords

SOURCE = "dns"
_RDTYPES = (("A", "a"), ("AAAA", "aaaa"), ("MX", "mx"), ("NS", "ns"), ("TXT", "txt"))

ResolveFn = Callable[[str, str], Awaitable[list[str]]]


async def _default_resolve(qname: str, rdtype: str) -> list[str]:
    import dns.asyncresolver

    answers = await dns.asyncresolver.resolve(qname, rdtype)
    return [r.to_text() for r in answers]


async def collect(
    result: CollectResult,
    fqdn: str,
    client=None,
    *,
    resolve: ResolveFn | None = None,
) -> DnsRecords:
    """Резолвит fqdn по пяти типам; наполняет DnsRecords + рёбра резолва (A/AAAA)."""
    resolve = resolve or _default_resolve
    fqdn = fqdn.lower().rstrip(".")
    rec = DnsRecords(fqdn=fqdn)
    for rdtype, attr in _RDTYPES:
        try:
            values = await resolve(fqdn, rdtype)
        except Exception:
            # NXDOMAIN/NoAnswer/таймаут одной записи не должны валить весь сбор.
            values = []
        cleaned = [v.strip().rstrip(".") if rdtype in ("A", "AAAA") else v.strip() for v in values]
        getattr(rec, attr).extend(cleaned)
        if rdtype in ("A", "AAAA"):
            for ip in cleaned:
                result.add_resolution(fqdn, ip, SOURCE)
    result.add_dns(rec)
    return rec
