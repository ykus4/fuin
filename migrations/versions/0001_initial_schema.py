"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-07-01 00:00:00

Creates the base schema for fresh installs.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "apps",
        sa.Column("app_id", sa.String(), primary_key=True),
        sa.Column("package_name", sa.String(), nullable=False),
        sa.Column("apk_signature", sa.String(), nullable=False),
        sa.Column("packed_apk_path", sa.String(), nullable=True),
        sa.Column("analysis", sa.JSON(), nullable=True),
        sa.Column("mapping_path", sa.String(), nullable=True),
        sa.Column("webhook_urls", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_table(
        "jobs",
        sa.Column("job_id", sa.String(), primary_key=True),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("progress_step", sa.String(), nullable=True),
        sa.Column("progress_pct", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("app_id", sa.String(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("jobs")
    op.drop_table("apps")
