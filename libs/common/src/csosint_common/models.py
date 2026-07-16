"""ORM-модели PostgreSQL.

PostgreSQL хранит и сырьё, и локальную копию NVD, и связи графа (граф считается
рекурсивными CTE, отдельная графовая БД не используется.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _pk() -> Mapped[int]:
    return mapped_column(BigInteger, primary_key=True, autoincrement=True)


# --------------------------------------------------------------------------- #
#  Активы: организация → домены → IP → сервисы
# --------------------------------------------------------------------------- #
class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[int] = _pk()
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    domains: Mapped[list[Domain]] = relationship(back_populates="organization")


class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[int] = _pk()
    org_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id", ondelete="SET NULL"))
    fqdn: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    organization: Mapped[Organization | None] = relationship(back_populates="domains")


class IpAddress(Base):
    __tablename__ = "ip_addresses"

    id: Mapped[int] = _pk()
    address: Mapped[str] = mapped_column(String(45), unique=True, nullable=False)  # IPv6-safe
    asn: Mapped[str | None] = mapped_column(String(32))
    org_name: Mapped[str | None] = mapped_column(String(512))
    country: Mapped[str | None] = mapped_column(String(2))
    network_cidr: Mapped[str | None] = mapped_column(String(64))
    network_start: Mapped[str | None] = mapped_column(String(45))
    network_end: Mapped[str | None] = mapped_column(String(45))
    geo: Mapped[dict | None] = mapped_column(JSONB)


class DomainIp(Base):
    """M:N «домен резолвится в несколько IP»."""

    __tablename__ = "domain_ip"

    domain_id: Mapped[int] = mapped_column(
        ForeignKey("domains.id", ondelete="CASCADE"), primary_key=True
    )
    ip_id: Mapped[int] = mapped_column(
        ForeignKey("ip_addresses.id", ondelete="CASCADE"), primary_key=True
    )
    resolved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Certificate(Base):
    __tablename__ = "certificates"

    id: Mapped[int] = _pk()
    fingerprint: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    issuer: Mapped[str | None] = mapped_column(String(512))
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class DomainCertificate(Base):
    __tablename__ = "domain_certificate"

    domain_id: Mapped[int] = mapped_column(
        ForeignKey("domains.id", ondelete="CASCADE"), primary_key=True
    )
    certificate_id: Mapped[int] = mapped_column(
        ForeignKey("certificates.id", ondelete="CASCADE"), primary_key=True
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Service(Base):
    __tablename__ = "services"

    id: Mapped[int] = _pk()
    ip_id: Mapped[int] = mapped_column(
        ForeignKey("ip_addresses.id", ondelete="CASCADE"), nullable=False
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str | None] = mapped_column(String(16))
    product: Mapped[str | None] = mapped_column(String(256))
    version: Mapped[str | None] = mapped_column(String(128))
    cpe_uri: Mapped[str | None] = mapped_column(String(512))  # от InternetDB, если есть
    banner: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str | None] = mapped_column(String(32))  # internetdb|shodan|censys
    seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


# --------------------------------------------------------------------------- #
#  Задачи сбора
# --------------------------------------------------------------------------- #
class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = _pk()
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False)  # domain|ip|org
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    degraded_sources: Mapped[dict | None] = mapped_column(JSONB)  # частичные сбои


class ScanSnapshot(Base):
    """Неизменяемое наблюдение актива в рамках конкретного скана.

    Глобальные asset-таблицы показывают текущее состояние, snapshot сохраняет
    фактический результат каждого запуска для истории и change detection.
    """

    __tablename__ = "scan_snapshots"
    __table_args__ = (
        UniqueConstraint("job_id", "entity_type", "entity_key", name="uq_scan_snapshot_entity"),
        Index("ix_scan_snapshot_job_type", "job_id", "entity_type"),
    )

    id: Mapped[int] = _pk()
    job_id: Mapped[int] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_key: Mapped[str] = mapped_column(String(768), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


# --------------------------------------------------------------------------- #
#  Локальная копия NVD (design-nvd-sync)
# --------------------------------------------------------------------------- #
class CveRecord(Base):
    __tablename__ = "cve_records"

    id: Mapped[int] = _pk()
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # CVSS: версия обязательна, приоритет v3.1→v3.0→v2
    cvss_version: Mapped[str | None] = mapped_column(String(8))
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(128))
    severity: Mapped[str | None] = mapped_column(String(16))
    # Exploitability intelligence: FIRST EPSS + CISA KEV.
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    epss_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    kev_date_added: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    kev_due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    kev_required_action: Mapped[str | None] = mapped_column(Text)
    kev_ransomware_use: Mapped[str | None] = mapped_column(String(32))
    raw: Mapped[dict | None] = mapped_column(JSONB)  # пересбор без ре-фетча NVD


class CveCpeMatch(Base):
    """Распакованные cpeMatch из configurations (design-nvd-sync §6).

    Применимость CVE = много строк с диапазонами версий; группировка AND
    сохраняется через config/node-операторы.
    """

    __tablename__ = "cve_cpe_match"
    __table_args__ = (
        Index(
            "ix_cve_cpe_match_product",
            "part",
            "vendor",
            "product",
            postgresql_where="vulnerable_bool",
        ),
    )

    id: Mapped[int] = _pk()
    cve_id: Mapped[str] = mapped_column(
        ForeignKey("cve_records.cve_id", ondelete="CASCADE"), nullable=False
    )
    cpe_uri: Mapped[str] = mapped_column(String(512), nullable=False)
    vendor: Mapped[str | None] = mapped_column(String(128))
    product: Mapped[str | None] = mapped_column(String(128))
    part: Mapped[str | None] = mapped_column(String(1))  # a|o|h
    vulnerable_bool: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # группировка AND-конфигураций «running on»
    config_idx: Mapped[int | None] = mapped_column(Integer)
    node_idx: Mapped[int | None] = mapped_column(Integer)
    config_operator: Mapped[str | None] = mapped_column(String(4))  # AND|OR
    node_operator: Mapped[str | None] = mapped_column(String(4))  # AND|OR
    # диапазоны версий; *_type ∈ {including, excluding}
    version_start: Mapped[str | None] = mapped_column(String(64))
    version_start_type: Mapped[str | None] = mapped_column(String(16))
    version_end: Mapped[str | None] = mapped_column(String(64))
    version_end_type: Mapped[str | None] = mapped_column(String(16))


class CpeDictionary(Base):
    """Опциональный CPE-словарь для фаззи-маппинга product→CPE (design-cpe-matching §7)."""

    __tablename__ = "cpe_dictionary"
    __table_args__ = (UniqueConstraint("cpe_uri", name="uq_cpe_dictionary_uri"),)

    id: Mapped[int] = _pk()
    cpe_uri: Mapped[str] = mapped_column(String(512), nullable=False)
    vendor: Mapped[str | None] = mapped_column(String(128))
    product: Mapped[str | None] = mapped_column(String(128))
    title: Mapped[str | None] = mapped_column(String(512))


class SyncState(Base):
    """Курсор/резюмируемость синка (design-nvd-sync §3)."""

    __tablename__ = "sync_state"

    source: Mapped[str] = mapped_column(String(32), primary_key=True)  # nvd_cve|nvd_cpe
    phase: Mapped[str | None] = mapped_column(String(16))  # bootstrap|incremental
    last_mod_cursor: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    bootstrap_index: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str | None] = mapped_column(String(16))  # idle|running|failed
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)


# --------------------------------------------------------------------------- #
#  Результат матчинга
# --------------------------------------------------------------------------- #
class ServiceCve(Base):
    __tablename__ = "service_cve"

    service_id: Mapped[int] = mapped_column(
        ForeignKey("services.id", ondelete="CASCADE"), primary_key=True
    )
    cve_id: Mapped[str] = mapped_column(
        ForeignKey("cve_records.cve_id", ondelete="CASCADE"), primary_key=True
    )
    match_confidence: Mapped[str] = mapped_column(String(8), nullable=False)  # high|medium|low
    matched_cpe: Mapped[str | None] = mapped_column(String(512))
    matched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class RawResponse(Base):
    """Аудит сырых ответов внешних API (опц., помогает при флакающих источниках)."""

    __tablename__ = "raw_responses"

    id: Mapped[int] = _pk()
    job_id: Mapped[int | None] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"))
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    request: Mapped[str | None] = mapped_column(Text)
    response: Mapped[dict | None] = mapped_column(JSONB)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
