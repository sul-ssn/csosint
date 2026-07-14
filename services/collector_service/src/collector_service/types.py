"""Нормализованный результат сбора (ТЗ §4, §5).

Источники разные, а таблицы БД — общие. Каждый коннектор наполняет `CollectResult`
нормализованными наблюдениями с пометкой `source`. Провенанс: фиксируем ВСЕ
наблюдения (кто что сказал), не перетираем при конфликте (ТЗ §4.5).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class HostService:
    ip: str
    port: int
    source: str
    protocol: str | None = None
    product: str | None = None
    version: str | None = None
    cpe_uri: str | None = None
    banner: str | None = None


@dataclass(slots=True)
class HostVuln:
    """CVE, заявленная источником по IP (напр. InternetDB `vulns`) — без матчинга."""

    ip: str
    cve_id: str
    source: str
    cpe_uri: str | None = None


@dataclass(slots=True)
class IpInfo:
    """RDAP/обогащение по IP: владелец диапазона, ASN, страна."""

    ip: str
    source: str
    asn: str | None = None
    org_name: str | None = None
    country: str | None = None


@dataclass(slots=True)
class DnsRecords:
    fqdn: str
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CollectResult:
    """Агрегат сбора по одной цели. Пишется в БД слоем persistence."""

    # fqdn -> источники, где он засветился
    subdomains: dict[str, set[str]] = field(default_factory=dict)
    # (fqdn, ip, source) — рёбра «домен резолвится в IP»
    resolutions: set[tuple[str, str, str]] = field(default_factory=set)
    services: list[HostService] = field(default_factory=list)
    vulns: list[HostVuln] = field(default_factory=list)
    ip_infos: list[IpInfo] = field(default_factory=list)
    dns_records: list[DnsRecords] = field(default_factory=list)
    # источник -> причина деградации (skipped: нет ключа / failed: источник упал)
    degraded: dict[str, str] = field(default_factory=dict)

    def add_subdomain(self, fqdn: str, source: str) -> None:
        self.subdomains.setdefault(fqdn.lower().rstrip("."), set()).add(source)

    def add_resolution(self, fqdn: str, ip: str, source: str) -> None:
        self.resolutions.add((fqdn.lower().rstrip("."), ip, source))

    def add_service(self, svc: HostService) -> None:
        self.services.append(svc)

    def add_vuln(self, ip: str, cve_id: str, source: str, cpe_uri: str | None = None) -> None:
        self.vulns.append(HostVuln(ip=ip, cve_id=cve_id, source=source, cpe_uri=cpe_uri))

    def add_ip_info(self, info: IpInfo) -> None:
        self.ip_infos.append(info)

    def add_dns(self, rec: DnsRecords) -> None:
        self.dns_records.append(rec)

    def mark_degraded(self, source: str, reason: str) -> None:
        self.degraded[source] = reason

    @property
    def ips(self) -> set[str]:
        """Все IP, встреченные в сервисах, резолвах и RDAP."""
        found = {svc.ip for svc in self.services}
        found |= {ip for _, ip, _ in self.resolutions}
        found |= {info.ip for info in self.ip_infos}
        return found
