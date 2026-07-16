"""Итоговый JSON-отчёт по скану.

Собирает активы и «потенциальные» CVE связной компоненты цели скана. Матчинг —
оценка вероятности, НЕ подтверждение: дисклеймер обязателен в выводе.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from csosint_common.models import (
    Certificate,
    CveRecord,
    Domain,
    DomainCertificate,
    IpAddress,
    Service,
    ServiceCve,
)

from .deep_analysis import (
    analyze_exposure,
    analyze_infrastructure,
    build_attack_paths,
    deep_summary,
)
from .graph import component_for
from .history import build_history
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
                    IpAddress.id,
                    IpAddress.address,
                    IpAddress.org_name,
                    IpAddress.country,
                    IpAddress.asn,
                    IpAddress.network_cidr,
                    IpAddress.network_start,
                    IpAddress.network_end,
                ).where(IpAddress.id.in_(ip_ids))
            )
        ).all()
        if ip_ids
        else []
    )
    ip_addr = {row.id: row.address for row in ip_rows}

    cert_rows = (
        (
            await session.execute(
                select(
                    Certificate.id,
                    Certificate.fingerprint,
                    Certificate.issuer,
                    Certificate.not_before,
                    Certificate.not_after,
                    Certificate.source,
                    Domain.fqdn,
                )
                .join(
                    DomainCertificate,
                    DomainCertificate.certificate_id == Certificate.id,
                )
                .join(Domain, Domain.id == DomainCertificate.domain_id)
                .where(DomainCertificate.domain_id.in_(domain_ids))
            )
        ).all()
        if domain_ids
        else []
    )
    certificates: dict[int, dict] = {}
    for cert_id, fingerprint, issuer, not_before, not_after, source, fqdn in cert_rows:
        cert = certificates.setdefault(
            cert_id,
            {
                "id": cert_id,
                "fingerprint": fingerprint,
                "issuer": issuer,
                "not_before": not_before,
                "not_after": not_after,
                "source": source,
                "domains": [],
            },
        )
        cert["domains"].append(fqdn)

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
                    CveRecord.epss_score,
                    CveRecord.epss_percentile,
                    CveRecord.kev,
                    CveRecord.kev_date_added,
                    CveRecord.kev_due_date,
                    CveRecord.kev_required_action,
                    CveRecord.kev_ransomware_use,
                )
                .join(CveRecord, CveRecord.cve_id == ServiceCve.cve_id)
                .where(ServiceCve.service_id.in_(services.keys()))
            )
        ).all()
        for (
            sid,
            cve_id,
            conf,
            severity,
            cvss_v,
            cvss_s,
            desc,
            epss,
            epss_pct,
            kev,
            kev_added,
            kev_due,
            kev_action,
            ransomware,
        ) in rows:
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
                    "epss_score": epss,
                    "epss_percentile": epss_pct,
                    "kev": kev,
                    "kev_date_added": kev_added,
                    "kev_due_date": kev_due,
                    "kev_required_action": kev_action,
                    "kev_ransomware_use": ransomware,
                }
            )
    # Приоритизация по риску (severity × достоверность), не по одной достоверности.
    rank_findings(vulns)
    summary = summarize(len(domains), len(ip_rows), len(services), vulns)
    history = await build_history(session, job)
    domain_assets = [{"id": did, "fqdn": fqdn} for did, fqdn in domains]
    ip_assets = [
        {
            "id": row.id,
            "address": row.address,
            "org_name": row.org_name,
            "country": row.country,
            "asn": row.asn,
            "network_cidr": row.network_cidr,
            "network_start": row.network_start,
            "network_end": row.network_end,
        }
        for row in ip_rows
    ]
    certificate_assets = list(certificates.values())
    service_assets = list(services.values())
    findings = analyze_exposure(domain_assets, service_assets)
    findings.extend(analyze_infrastructure(certificate_assets, ip_assets))
    findings.sort(
        key=lambda item: {"critical": 4, "high": 3, "medium": 2, "low": 1}[
            item["severity"]
        ],
        reverse=True,
    )
    attack_paths = build_attack_paths(
        job.target, job.type, domain_assets, service_assets, vulns
    )

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
        "history": history,
        "deep_analysis": {
            "summary": deep_summary(findings, attack_paths),
            "findings": findings,
            "attack_paths": attack_paths,
        },
        "assets": {
            "domains": domain_assets,
            "ips": ip_assets,
            "certificates": certificate_assets,
            "services": service_assets,
        },
        "vulnerabilities": vulns,
        "disclaimer": DISCLAIMER,
    }
