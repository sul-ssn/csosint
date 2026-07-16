"""Запись результата сбора в PostgreSQL.

Провенанс: у сервисов проставлен `source`; при конфликте по IP не перетираем уже
известные asn/org/country (COALESCE — первое ненулевое наблюдение остаётся).
Сервисы по обработанным IP пересобираем (delete+insert), чтобы повторный скан
не плодил дубли (в таблице нет уникального ключа по ip+port).
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import delete, func, insert, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from csosint_common.models import (
    Certificate,
    CveRecord,
    Domain,
    DomainCertificate,
    DomainIp,
    IpAddress,
    ScanSnapshot,
    Service,
    ServiceCve,
)

from .snapshot import build_snapshot
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
    fields = ("asn", "org_name", "country", "network_cidr", "network_start", "network_end")
    info: dict[str, dict] = {ip: dict.fromkeys(fields) for ip in ips}
    for obs in result.ip_infos:
        cur = info.setdefault(obs.ip, dict.fromkeys(fields))
        for field in fields:
            cur[field] = cur[field] or getattr(obs, field)
    values = [{"address": ip, **info[ip]} for ip in sorted(ips)]
    stmt = pg_insert(IpAddress).values(values)
    stmt = stmt.on_conflict_do_update(
        index_elements=[IpAddress.address],
        set_={
            "asn": func.coalesce(IpAddress.asn, stmt.excluded.asn),
            "org_name": func.coalesce(IpAddress.org_name, stmt.excluded.org_name),
            "country": func.coalesce(IpAddress.country, stmt.excluded.country),
            "network_cidr": func.coalesce(IpAddress.network_cidr, stmt.excluded.network_cidr),
            "network_start": func.coalesce(IpAddress.network_start, stmt.excluded.network_start),
            "network_end": func.coalesce(IpAddress.network_end, stmt.excluded.network_end),
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


def _timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        return None


async def _upsert_certificates(
    session: AsyncSession, result: CollectResult, domains: dict[str, int]
) -> int:
    if not result.certificates:
        return 0
    values = [
        {
            "fingerprint": cert.fingerprint,
            "issuer": cert.issuer,
            "not_before": _timestamp(cert.not_before),
            "not_after": _timestamp(cert.not_after),
            "source": cert.source,
        }
        for cert in result.certificates
    ]
    stmt = pg_insert(Certificate).values(values)
    stmt = stmt.on_conflict_do_update(
        index_elements=[Certificate.fingerprint],
        set_={
            "issuer": func.coalesce(stmt.excluded.issuer, Certificate.issuer),
            "not_before": func.coalesce(stmt.excluded.not_before, Certificate.not_before),
            "not_after": func.coalesce(stmt.excluded.not_after, Certificate.not_after),
            "last_seen": func.now(),
        },
    ).returning(Certificate.fingerprint, Certificate.id)
    cert_ids = {fingerprint: cid for fingerprint, cid in (await session.execute(stmt)).all()}
    edges = {
        (domains[name], cert_ids[cert.fingerprint])
        for cert in result.certificates
        for name in cert.names
        if name in domains and cert.fingerprint in cert_ids
    }
    if edges:
        await session.execute(
            pg_insert(DomainCertificate)
            .values([{"domain_id": did, "certificate_id": cid} for did, cid in sorted(edges)])
            .on_conflict_do_update(
                index_elements=[DomainCertificate.domain_id, DomainCertificate.certificate_id],
                set_={"observed_at": func.now()},
            )
        )
    return len(cert_ids)


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


async def persist(
    session: AsyncSession, result: CollectResult, *, job_id: int | None = None
) -> dict:
    """Записать весь CollectResult; вернуть счётчики + id сервисов под матчинг."""
    domains = await _upsert_domains(session, result)
    ips = await _upsert_ips(session, result)
    await _upsert_domain_ip(session, result, domains, ips)
    n_certificates = await _upsert_certificates(session, result, domains)
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
    snapshot_rows = build_snapshot(result)
    if job_id is not None and snapshot_rows:
        await session.execute(
            insert(ScanSnapshot), [{"job_id": job_id, **row} for row in snapshot_rows]
        )
    return {
        "domains": len(domains),
        "ips": len(ips),
        "services": n_services,
        "vulns": n_vulns,
        "snapshot_entities": len(snapshot_rows),
        "certificates": n_certificates,
        "degraded": len(result.degraded),
        "service_ids": service_ids,
    }
