"""per-scan asset snapshots for history and change detection

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan_snapshots",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "job_id",
            sa.BigInteger(),
            sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("entity_key", sa.String(768), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=False),
        sa.Column(
            "observed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "job_id", "entity_type", "entity_key", name="uq_scan_snapshot_entity"
        ),
    )
    op.create_index(
        "ix_scan_snapshot_job_type", "scan_snapshots", ["job_id", "entity_type"]
    )


def downgrade() -> None:
    op.drop_index("ix_scan_snapshot_job_type", table_name="scan_snapshots")
    op.drop_table("scan_snapshots")
