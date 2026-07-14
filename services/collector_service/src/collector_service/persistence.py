"""Запись результата сбора в PostgreSQL (ТЗ §5).

Провенанс: у сервисов проставлен `source`; при конфликте по IP не перетираем уже
известные asn/org/country (COALESCE — первое ненулевое наблюдение остаётся).
Сервисы по обработанным IP пересобираем (delete+insert), чтобы повторный скан
не плодил дубли (в таблице нет уникального ключа по ip+port).
"""

from __future__ import annotations

from sqlalchemy import delete, func, insert, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from csosint_common.models import CveRecord, Domain, DomainIp, IpAddress, Service, ServiceCve

from .types import CollectResult

# host-level порт-сентинел (см. sources/internetdb) — якорь для host-level CVE.
_HOST_PORT = 0


async def _upsert_domains(session: AsyncSession, result: CollectResult) -> dict[str, int]:
    fqdns = set(result.subdomains) | {fqdn for fqdn, _, _ in result.resolutions}
    if not fqdns:
        return {}
    stmt = pg_insert(Domain).values([{"fqdn": f} for f in sorted(fqdns)])
    stmt = stmt.on_conflict_do_update(
        index_elements=[Domain.fqdn], set_={"last_seen": func.now()}
    ).returning(Domain.fqdn, Domain.id)
    rows = await session.execute(stmt)
    return {fqdn: did for fqdn, did in rows.all()}


async def _upsert_ips(session: AsyncSession, result: CollectResult) -> dict[str, int]:
    ips = result.ips
    if not ips:
        return {}
    # Первое ненулевое наблюдение asn/org/country на IP.
    info: dict[str, dict] = {ip: {"asn": None, "org_name": None, "country": None} for ip in ips}
    for obs in result.ip_infos:
        cur = info.setdefault(obs.ip, {"asn": None, "org_name": None, "country": None})
        cur["asn"] = cur["asn"] or obs.asn
        cur["org_name"] = cur["org_name"] or obs.org_name
        cur["country"] = cur["country"] or obs.country
    values = [{"address": ip, **info[ip]} for ip in sorted(ips)]
    stmt = pg_insert(IpAddress).values(values)
    stmt = stmt.on_conflict_do_update(
        index_elements=[IpAddress.address],
        set_={
            "asn": func.coalesce(IpAddress.asn, stmt.excluded.asn),
            "org_name": func.coalesce(IpAddress.org_name, stmt.excluded.org_name),
            "country": func.coalesce(IpAddress.country, stmt.excluded.country),
        },
    ).returning(IpAddress.address, IpAddress.id)
    rows = await session.execute(stmt)
    return {addr: iid for addr, iid in rows.all()}


async def _upsert_domain_ip(
    session: AsyncSession, result: CollectResult, domains: dict[str, int], ips: dict[str, int]
) -> None:
    edges = {
        (domains[fqdn], ips[ip])
        for fqdn, ip, _ in result.resolutions
        if fqdn in domains and ip in ips
    }
    if not edges:
        return
    stmt = pg_insert(DomainIp).values([{"domain_id": d, "ip_id": i} for d, i in sorted(edges)])
    stmt = stmt.on_conflict_do_update(
        index_elements=[DomainIp.domain_id, DomainIp.ip_id],
        set_={"resolved_at": func.now()},
    )
    await session.execute(stmt)


async def _replace_services(
    session: AsyncSession, result: CollectResult, ips: dict[str, int]
) -> int:
    ip_ids = {ips[svc.ip] for svc in result.services if svc.ip in ips}
    if ip_ids:
        # Пересобираем сервисы по затронутым IP — идемпотентность повторного скана.
        await session.execute(delete(Service).where(Service.ip_id.in_(ip_ids)))
    rows = [
        {
            "ip_id": ips[svc.ip],
            "port": svc.port,
            "protocol": svc.protocol,
            "product": svc.product,
            "version": svc.version,
            "cpe_uri": svc.cpe_uri,
            "banner": svc.banner,
            "source": svc.source,
        }
        for svc in result.services
        if svc.ip in ips
    ]
    if rows:
        await session.execute(insert(Service), rows)
    return len(rows)


async def _write_vulns(
    session: AsyncSession, result: CollectResult, ips: dict[str, int], anchor: dict[int, int]
) -> int:
    """Host-level CVE от источника (InternetDB) → cve_records + service_cve.

    cve_records пишем минимально (severity/cvss дозаполнит синк NVD), существующие
    не перетираем. service_cve привязываем к host-level якорю IP, confidence=high.
    """
    if not result.vulns:
        return 0
    cve_ids = sorted({v.cve_id for v in result.vulns})
    await session.execute(
        pg_insert(CveRecord)
        .values([{"cve_id": c} for c in cve_ids])
        .on_conflict_do_nothing(index_elements=[CveRecord.cve_id])
    )
    rows: list[dict] = []
    seen: set[tuple[int, str]] = set()
    for v in result.vulns:
        ip_id = ips.get(v.ip)
        sid = anchor.get(ip_id) if ip_id is not None else None
        if sid is None or (sid, v.cve_id) in seen:
            continue
        seen.add((sid, v.cve_id))
        rows.append(
            {
                "service_id": sid,
                "cve_id": v.cve_id,
                "match_confidence": "high",
                "matched_cpe": v.cpe_uri,
            }
        )
    if rows:
        await session.execute(
            pg_insert(ServiceCve)
            .values(rows)
            .on_conflict_do_nothing(index_elements=[ServiceCve.service_id, ServiceCve.cve_id])
        )
    return len(rows)


async def persist(session: AsyncSession, result: CollectResult) -> dict:
    """Записать весь CollectResult; вернуть счётчики + id сервисов под матчинг."""
    domains = await _upsert_domains(session, result)
    ips = await _upsert_ips(session, result)
    await _upsert_domain_ip(session, result, domains, ips)
    n_services = await _replace_services(session, result, ips)
    service_ids: list[int] = []
    anchor: dict[int, int] = {}  # ip_id -> host-level якорь (port=0, иначе первый сервис)
    if ips:
        rows = await session.execute(
            select(Service.id, Service.ip_id, Service.port).where(
                Service.ip_id.in_(set(ips.values()))
            )
        )
        for sid, ip_id, port in rows.all():
            service_ids.append(sid)
            if ip_id not in anchor or port == _HOST_PORT:
                anchor[ip_id] = sid
    n_vulns = await _write_vulns(session, result, ips, anchor)
    return {
        "domains": len(domains),
        "ips": len(ips),
        "services": n_services,
        "vulns": n_vulns,
        "degraded": len(result.degraded),
        "service_ids": service_ids,
    }
