"""Итоговый JSON-отчёт по скану (ТЗ §7).

Собирает активы и «потенциальные» CVE связной компоненты цели скана. Матчинг —
оценка вероятности, НЕ подтверждение (ТЗ §6): дисклеймер обязателен в выводе.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from csosint_common.models import CveRecord, Domain, IpAddress, Service, ServiceCve

from .graph import component_for
from .risk import build_exec_summary, rank_findings, summarize, top_risks

DISCLAIMER = (
    "«potentially vulnerable»: наличие версии с известной CVE не означает, что хост "
    "реально уязвим (возможен бэкпорт-патч). Это оценка вероятности, не подтверждение."
)


async def build_report(session: AsyncSession, job) -> dict:
    domain_ids, ip_ids = await component_for(
        session,
        domain=job.target if job.type == "domain" else None,
        ip=job.target if job.type == "ip" else None,
    )

    domains = (
        (
            await session.execute(select(Domain.id, Domain.fqdn).where(Domain.id.in_(domain_ids)))
        ).all()
        if domain_ids
        else []
    )
    ip_rows = (
        (
            await session.execute(
                select(
                    IpAddress.id, IpAddress.address, IpAddress.org_name, IpAddress.country
                ).where(IpAddress.id.in_(ip_ids))
            )
        ).all()
        if ip_ids
        else []
    )
    ip_addr = {iid: addr for iid, addr, _, _ in ip_rows}

    svc_rows = (
        (
            await session.execute(
                select(
                    Service.id,
                    Service.ip_id,
                    Service.port,
                    Service.product,
                    Service.version,
                    Service.cpe_uri,
                    Service.source,
                ).where(Service.ip_id.in_(ip_ids))
            )
        ).all()
        if ip_ids
        else []
    )
    services = {
        sid: {
            "id": sid,
            "ip": ip_addr.get(ip_id),
            "port": port,
            "product": product,
            "version": version,
            "cpe_uri": cpe_uri,
            "source": source,
        }
        for sid, ip_id, port, product, version, cpe_uri, source in svc_rows
    }

    vulns: list[dict] = []
    if services:
        rows = (
            await session.execute(
                select(
                    ServiceCve.service_id,
                    ServiceCve.cve_id,
                    ServiceCve.match_confidence,
                    CveRecord.severity,
                    CveRecord.cvss_version,
                    CveRecord.cvss_score,
                    CveRecord.description,
                )
                .join(CveRecord, CveRecord.cve_id == ServiceCve.cve_id)
                .where(ServiceCve.service_id.in_(services.keys()))
            )
        ).all()
        for sid, cve_id, conf, severity, cvss_v, cvss_s, desc in rows:
            svc = services[sid]
            vulns.append(
                {
                    "service_id": sid,
                    "ip": svc["ip"],
                    "port": svc["port"],
                    "product": svc["product"],
                    "version": svc["version"],
                    "cve_id": cve_id,
                    "match_confidence": conf,
                    "severity": severity,
                    "cvss_version": cvss_v,
                    "cvss_score": cvss_s,
                    "description": desc,
                }
            )
    # Приоритизация по риску (severity × достоверность), не по одной достоверности.
    rank_findings(vulns)
    summary = summarize(len(domains), len(ip_rows), len(services), vulns)

    return {
        "job": {
            "id": job.id,
            "target": job.target,
            "type": job.type,
            "status": job.status,
            "created_at": job.created_at,
            "finished_at": job.finished_at,
            "degraded_sources": job.degraded_sources,
        },
        "summary": summary,
        "exec_summary": build_exec_summary(job.target, len(ip_rows), len(services), vulns, summary),
        "top_risks": top_risks(vulns),
        "assets": {
            "domains": [{"id": did, "fqdn": fqdn} for did, fqdn in domains],
            "ips": [
                {"id": iid, "address": addr, "org_name": org, "country": country}
                for iid, addr, org, country in ip_rows
            ],
            "services": list(services.values()),
        },
        "vulnerabilities": vulns,
        "disclaimer": DISCLAIMER,
    }
