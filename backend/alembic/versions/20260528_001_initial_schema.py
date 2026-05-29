"""initial schema — scans table

Revision ID: 001
Revises:
Create Date: 2026-05-28
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("target", sa.Text, nullable=False),
        sa.Column("scan_type", sa.String(32), nullable=False),
        sa.Column("target_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="completed"),
        sa.Column("risk_score", sa.Integer, nullable=True),
        sa.Column("risk_level", sa.String(32), nullable=True),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        sa.Column("result_json", JSONB, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_scans_target_hash", "scans", ["target_hash"])
    op.create_index("ix_scans_risk_level", "scans", ["risk_level"])
    op.create_index("ix_scans_created_at", "scans", ["created_at"])
    op.create_index(
        "ix_scans_risk_level_created_at", "scans", ["risk_level", "created_at"]
    )


def downgrade() -> None:
    op.drop_table("scans")
