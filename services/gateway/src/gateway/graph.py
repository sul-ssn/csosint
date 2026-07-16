"""Построение графа связей из PostgreSQL.

Отдельной графовой СУБД нет: связная компонента активов считается **рекурсивным
CTE** по двудольному графу `domain ↔ ip` (общий host связывает разные домены),
а сервисы и CVE подтягиваются листовыми джойнами. Результат — `{nodes, edges}`
в формате Cytoscape. Сборку JSON держим чистой функцией (тестируется без БД).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from csosint_common.models import (
    Certificate,
    CveRecord,
    Domain,
    DomainCertificate,
    DomainIp,
    IpAddress,
    Service,
    ServiceCve,
)

# Рекурсивная компонента: старт-узел + замыкание по рёбрам domain↔ip.
# Одна самоссылка на `comp` в рекурсивном терме (требование Postgres) —
# двунаправленность вынесена в нерекурсивный `edges`.
_COMPONENT_SQL = """
WITH RECURSIVE
edges AS (
    SELECT 'domain'::text AS sk, domain_id AS sid, 'ip'::text AS dk, ip_id AS did FROM domain_ip
    UNION ALL
    SELECT 'ip'::text, ip_id, 'domain'::text, domain_id FROM domain_ip
),
comp(kind, id) AS (
    {seed}
    UNION
    SELECT e.dk, e.did FROM comp JOIN edges e ON e.sk = comp.kind AND e.sid = comp.id
)
SELECT DISTINCT kind, id FROM comp
"""
_SEED_DOMAIN = "SELECT 'domain'::text, id FROM domains WHERE fqdn = :val"
_SEED_IP = "SELECT 'ip'::text, id FROM ip_addresses WHERE address = :val"


@dataclass(slots=True)
class GraphData:
    domains: list[tuple] = field(default_factory=list)  # (id, fqdn)
    ips: list[tuple] = field(default_factory=list)  # id,address,org,country,asn,cidr,start,end
    certificates: list[tuple] = field(default_factory=list)  # id,fingerprint,issuer,not_after
    edges_domain_certificate: list[tuple] = field(default_factory=list)
    edges_domain_ip: list[tuple] = field(default_factory=list)  # (domain_id, ip_id)
    services: list[tuple] = field(
        default_factory=list
    )  # (id, ip_id, port, product, version, source)
    service_cves: list[tuple] = field(default_factory=list)  # (service_id, cve_id, confidence)
    cves: list[tuple] = field(default_factory=list)  # (cve_id, severity, cvss_score)


def _node(node_id: str, label: str, ntype: str, **extra) -> dict:
    return {"data": {"id": node_id, "label": label, "type": ntype, **extra}}


def _edge(source: str, target: str, etype: str) -> dict:
    return {
        "data": {"id": f"{source}->{target}", "source": source, "target": target, "type": etype}
    }


def to_cytoscape(g: GraphData) -> dict:
    """Собрать GraphData в {nodes, edges} для Cytoscape. Узлы дедуплицируются по id."""
    nodes: dict[str, dict] = {}
    edges: dict[str, dict] = {}

    for did, fqdn in g.domains:
        nodes[f"domain:{did}"] = _node(f"domain:{did}", fqdn, "domain")
    for ip_row in g.ips:
        iid, address, org, country, *network = ip_row
        asn = network[0] if len(network) > 0 else None
        cidr = network[1] if len(network) > 1 else None
        start = network[2] if len(network) > 2 else None
        end = network[3] if len(network) > 3 else None
        nodes[f"ip:{iid}"] = _node(
            f"ip:{iid}", address, "ip", org_name=org, country=country, asn=asn, network=cidr
        )
        if country:
            cid = f"country:{country}"
            nodes.setdefault(cid, _node(cid, country, "country"))
            edges[f"ip:{iid}->{cid}"] = _edge(f"ip:{iid}", cid, "geo")
        if org:
            oid = f"org:{org}"
            nodes.setdefault(oid, _node(oid, org, "org"))
            edges[f"ip:{iid}->{oid}"] = _edge(f"ip:{iid}", oid, "hosted")
        if asn:
            aid = f"asn:{asn}"
            nodes.setdefault(aid, _node(aid, asn, "asn"))
            edges[f"ip:{iid}->{aid}"] = _edge(f"ip:{iid}", aid, "announced_by")
        network_label = cidr or (f"{start}–{end}" if start and end else None)
        if network_label:
            nid = f"netblock:{network_label}"
            nodes.setdefault(nid, _node(nid, network_label, "netblock"))
            edges[f"ip:{iid}->{nid}"] = _edge(f"ip:{iid}", nid, "member_of")
    for cert_id, fingerprint, issuer, not_after in g.certificates:
        short = fingerprint.split(":", 1)[-1][:12]
        nodes[f"certificate:{cert_id}"] = _node(
            f"certificate:{cert_id}",
            f"cert {short}",
            "certificate",
            fingerprint=fingerprint,
            issuer=issuer,
            not_after=not_after.isoformat() if not_after else None,
        )
    for sid, ip_id, port, product, version, source in g.services:
        label = product or "service"
        if version:
            label = f"{label} {version}"
        nodes[f"service:{sid}"] = _node(
            f"service:{sid}", f"{label}:{port}", "service", port=port, source=source
        )
        edges[f"ip:{ip_id}->service:{sid}"] = _edge(f"ip:{ip_id}", f"service:{sid}", "runs")
    for cve_id, severity, score in g.cves:
        label = f"{cve_id} ({score})" if score is not None else cve_id
        nodes[f"cve:{cve_id}"] = _node(
            f"cve:{cve_id}", label, "cve", severity=severity, cvss_score=score
        )

    for domain_id, ip_id in g.edges_domain_ip:
        if f"domain:{domain_id}" in nodes and f"ip:{ip_id}" in nodes:
            edges[f"domain:{domain_id}->ip:{ip_id}"] = _edge(
                f"domain:{domain_id}", f"ip:{ip_id}", "resolves"
            )
    for domain_id, cert_id in g.edges_domain_certificate:
        src, dst = f"domain:{domain_id}", f"certificate:{cert_id}"
        if src in nodes and dst in nodes:
            edges[f"{src}->{dst}"] = _edge(src, dst, "covered_by")
    for service_id, cve_id, confidence in g.service_cves:
        src, dst = f"service:{service_id}", f"cve:{cve_id}"
        if src in nodes and dst in nodes:
            e = _edge(src, dst, "vulnerable")
            e["data"]["confidence"] = confidence
            edges[e["data"]["id"]] = e

    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


async def _component(session: AsyncSession, seed: str, val: str) -> tuple[list[int], list[int]]:
    rows = (await session.execute(text(_COMPONENT_SQL.format(seed=seed)), {"val": val})).all()
    domain_ids = [rid for kind, rid in rows if kind == "domain"]
    ip_ids = [rid for kind, rid in rows if kind == "ip"]
    return domain_ids, ip_ids


async def _fetch(session: AsyncSession, domain_ids: list[int], ip_ids: list[int]) -> GraphData:
    g = GraphData()
    if domain_ids:
        seed_cert_ids = list(
            (
                await session.scalars(
                    select(DomainCertificate.certificate_id).where(
                        DomainCertificate.domain_id.in_(domain_ids)
                    )
                )
            ).all()
        )
        if seed_cert_ids:
            g.edges_domain_certificate = [
                tuple(row)
                for row in (
                    await session.execute(
                        select(
                            DomainCertificate.domain_id, DomainCertificate.certificate_id
                        ).where(DomainCertificate.certificate_id.in_(seed_cert_ids))
                    )
                ).all()
            ]
            domain_ids = sorted({*domain_ids, *(row[0] for row in g.edges_domain_certificate)})
            g.certificates = [
                tuple(row)
                for row in (
                    await session.execute(
                        select(
                            Certificate.id,
                            Certificate.fingerprint,
                            Certificate.issuer,
                            Certificate.not_after,
                        ).where(Certificate.id.in_(seed_cert_ids))
                    )
                ).all()
            ]
            linked_ip_ids = list(
                (
                    await session.scalars(
                        select(DomainIp.ip_id).where(DomainIp.domain_id.in_(domain_ids))
                    )
                ).all()
            )
            ip_ids = sorted({*ip_ids, *linked_ip_ids})
    if domain_ids:
        g.domains = [
            tuple(r)
            for r in (
                await session.execute(
                    select(Domain.id, Domain.fqdn).where(Domain.id.in_(domain_ids))
                )
            ).all()
        ]
    if ip_ids:
        g.ips = [
            tuple(r)
            for r in (
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
        ]
        g.edges_domain_ip = [
            tuple(r)
            for r in (
                await session.execute(
                    select(DomainIp.domain_id, DomainIp.ip_id).where(DomainIp.ip_id.in_(ip_ids))
                )
            ).all()
        ]
        g.services = [
            tuple(r)
            for r in (
                await session.execute(
                    select(
                        Service.id,
                        Service.ip_id,
                        Service.port,
                        Service.product,
                        Service.version,
                        Service.source,
                    ).where(Service.ip_id.in_(ip_ids))
                )
            ).all()
        ]
    service_ids = [s[0] for s in g.services]
    if service_ids:
        g.service_cves = [
            tuple(r)
            for r in (
                await session.execute(
                    select(
                        ServiceCve.service_id, ServiceCve.cve_id, ServiceCve.match_confidence
                    ).where(ServiceCve.service_id.in_(service_ids))
                )
            ).all()
        ]
        cve_ids = sorted({sc[1] for sc in g.service_cves})
        if cve_ids:
            g.cves = [
                tuple(r)
                for r in (
                    await session.execute(
                        select(CveRecord.cve_id, CveRecord.severity, CveRecord.cvss_score).where(
                            CveRecord.cve_id.in_(cve_ids)
                        )
                    )
                ).all()
            ]
    return g


async def component_for(
    session: AsyncSession, *, domain: str | None = None, ip: str | None = None
) -> tuple[list[int], list[int]]:
    """Связная компонента (domain_ids, ip_ids) от корня — общая для графа и отчёта."""
    if domain is not None:
        return await _component(session, _SEED_DOMAIN, domain.lower().rstrip("."))
    if ip is not None:
        return await _component(session, _SEED_IP, ip)
    return [], []


async def build_graph(
    session: AsyncSession, *, domain: str | None = None, ip: str | None = None
) -> dict:
    """Граф связной компоненты от корня (домен или IP) → Cytoscape {nodes, edges}."""
    domain_ids, ip_ids = await component_for(session, domain=domain, ip=ip)
    g = await _fetch(session, domain_ids, ip_ids)
    return to_cytoscape(g)
