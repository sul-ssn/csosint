"""certificates and network metadata

Revision ID: 0004
Revises: 0003
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("ip_addresses", sa.Column("network_cidr", sa.String(64)))
    op.add_column("ip_addresses", sa.Column("network_start", sa.String(45)))
    op.add_column("ip_addresses", sa.Column("network_end", sa.String(45)))
    op.create_table(
        "certificates",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("fingerprint", sa.String(128), unique=True, nullable=False),
        sa.Column("issuer", sa.String(512)),
        sa.Column("not_before", sa.DateTime(timezone=True)),
        sa.Column("not_after", sa.DateTime(timezone=True)),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_table(
        "domain_certificate",
        sa.Column(
            "domain_id",
            sa.BigInteger(),
            sa.ForeignKey("domains.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "certificate_id",
            sa.BigInteger(),
            sa.ForeignKey("certificates.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )


def downgrade() -> None:
    op.drop_table("domain_certificate")
    op.drop_table("certificates")
    op.drop_column("ip_addresses", "network_end")
    op.drop_column("ip_addresses", "network_start")
    op.drop_column("ip_addresses", "network_cidr")
