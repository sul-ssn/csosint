"""initial schema (ТЗ §5.1)

Revision ID: 0001
Revises:
Create Date: 2026-07-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_now = sa.text("now()")


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now, nullable=False),
    )

    op.create_table(
        "ip_addresses",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("address", sa.String(45), nullable=False, unique=True),
        sa.Column("asn", sa.String(32)),
        sa.Column("org_name", sa.String(512)),
        sa.Column("country", sa.String(2)),
        sa.Column("geo", postgresql.JSONB()),
    )

    op.create_table(
        "domains",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "org_id",
            sa.BigInteger(),
            sa.ForeignKey("organizations.id", ondelete="SET NULL"),
        ),
        sa.Column("fqdn", sa.String(255), nullable=False, unique=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=_now, nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=_now, nullable=False),
    )

    op.create_table(
        "domain_ip",
        sa.Column(
            "domain_id",
            sa.BigInteger(),
            sa.ForeignKey("domains.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "ip_id",
            sa.BigInteger(),
            sa.ForeignKey("ip_addresses.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), server_default=_now, nullable=False),
    )

    op.create_table(
        "services",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "ip_id",
            sa.BigInteger(),
            sa.ForeignKey("ip_addresses.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(16)),
        sa.Column("product", sa.String(256)),
        sa.Column("version", sa.String(128)),
        sa.Column("cpe_uri", sa.String(512)),
        sa.Column("banner", sa.Text()),
        sa.Column("source", sa.String(32)),
        sa.Column("seen_at", sa.DateTime(timezone=True), server_default=_now, nullable=False),
    )

    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("target", sa.String(512), nullable=False),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now, nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("error", sa.Text()),
        sa.Column("degraded_sources", postgresql.JSONB()),
    )

    op.create_table(
        "cve_records",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("cve_id", sa.String(32), nullable=False, unique=True),
        sa.Column("description", sa.Text()),
        sa.Column("published", sa.DateTime(timezone=True)),
        sa.Column("modified", sa.DateTime(timezone=True)),
        sa.Column("cvss_version", sa.String(8)),
        sa.Column("cvss_score", sa.Float()),
        sa.Column("cvss_vector", sa.String(128)),
        sa.Column("severity", sa.String(16)),
        sa.Column("raw", postgresql.JSONB()),
    )

    op.create_table(
        "cve_cpe_match",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "cve_id",
            sa.String(32),
            sa.ForeignKey("cve_records.cve_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("cpe_uri", sa.String(512), nullable=False),
        sa.Column("vendor", sa.String(128)),
        sa.Column("product", sa.String(128)),
        sa.Column("part", sa.String(1)),
        sa.Column("vulnerable_bool", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("config_idx", sa.Integer()),
        sa.Column("node_idx", sa.Integer()),
        sa.Column("config_operator", sa.String(4)),
        sa.Column("node_operator", sa.String(4)),
        sa.Column("version_start", sa.String(64)),
        sa.Column("version_start_type", sa.String(16)),
        sa.Column("version_end", sa.String(64)),
        sa.Column("version_end_type", sa.String(16)),
    )
    op.create_index(
        "ix_cve_cpe_match_product",
        "cve_cpe_match",
        ["part", "vendor", "product"],
        postgresql_where=sa.text("vulnerable_bool"),
    )

    op.create_table(
        "cpe_dictionary",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("cpe_uri", sa.String(512), nullable=False),
        sa.Column("vendor", sa.String(128)),
        sa.Column("product", sa.String(128)),
        sa.Column("title", sa.String(512)),
        sa.UniqueConstraint("cpe_uri", name="uq_cpe_dictionary_uri"),
    )

    op.create_table(
        "sync_state",
        sa.Column("source", sa.String(32), primary_key=True),
        sa.Column("phase", sa.String(16)),
        sa.Column("last_mod_cursor", sa.DateTime(timezone=True)),
        sa.Column("bootstrap_index", sa.Integer()),
        sa.Column("status", sa.String(16)),
        sa.Column("last_run_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
    )

    op.create_table(
        "service_cve",
        sa.Column(
            "service_id",
            sa.BigInteger(),
            sa.ForeignKey("services.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "cve_id",
            sa.String(32),
            sa.ForeignKey("cve_records.cve_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("match_confidence", sa.String(8), nullable=False),
        sa.Column("matched_cpe", sa.String(512)),
        sa.Column("matched_at", sa.DateTime(timezone=True), server_default=_now, nullable=False),
    )

    op.create_table(
        "raw_responses",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("job_id", sa.BigInteger(), sa.ForeignKey("scan_jobs.id", ondelete="CASCADE")),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("request", sa.Text()),
        sa.Column("response", postgresql.JSONB()),
        sa.Column("fetched_at", sa.DateTime(timezone=True), server_default=_now, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("raw_responses")
    op.drop_table("service_cve")
    op.drop_table("sync_state")
    op.drop_table("cpe_dictionary")
    op.drop_index("ix_cve_cpe_match_product", table_name="cve_cpe_match")
    op.drop_table("cve_cpe_match")
    op.drop_table("cve_records")
    op.drop_table("scan_jobs")
    op.drop_table("services")
    op.drop_table("domain_ip")
    op.drop_table("domains")
    op.drop_table("ip_addresses")
    op.drop_table("organizations")
