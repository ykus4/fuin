"""normalize webhooks + add indexes + foreign keys

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-01 00:00:01

- Splits ``apps.webhook_urls`` (comma-separated TEXT) into a normalized
  ``app_webhooks`` table.
- Adds ``ix_apps_created_at``, ``ix_jobs_created_at`` for cleanup queries.
- Adds FK on ``jobs.app_id → apps.app_id`` (ON DELETE SET NULL).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "app_webhooks",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "app_id",
            sa.String(),
            sa.ForeignKey("apps.app_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("url", sa.String(), nullable=False),
    )
    op.create_index("ix_app_webhooks_app_id", "app_webhooks", ["app_id"])
    op.create_index("ix_apps_created_at", "apps", ["created_at"])
    op.create_index("ix_jobs_created_at", "jobs", ["created_at"])

    # Migrate any existing webhook_urls (comma-separated text) into the new table.
    conn = op.get_bind()
    rows = conn.execute(
        sa.text("SELECT app_id, webhook_urls FROM apps WHERE webhook_urls IS NOT NULL")
    ).fetchall()
    for app_id, urls in rows:
        for raw in (urls or "").split(","):
            url = raw.strip()
            if url:
                conn.execute(
                    sa.text("INSERT INTO app_webhooks (app_id, url) VALUES (:a, :u)"),
                    {"a": app_id, "u": url},
                )

    with op.batch_alter_table("apps") as batch:
        batch.drop_column("webhook_urls")

    with op.batch_alter_table("jobs") as batch:
        batch.create_foreign_key(
            "fk_jobs_app_id_apps", "apps", ["app_id"], ["app_id"], ondelete="SET NULL"
        )


def downgrade() -> None:
    with op.batch_alter_table("jobs") as batch:
        batch.drop_constraint("fk_jobs_app_id_apps", type_="foreignkey")

    with op.batch_alter_table("apps") as batch:
        batch.add_column(sa.Column("webhook_urls", sa.Text(), nullable=True))

    conn = op.get_bind()
    rows = conn.execute(sa.text("SELECT app_id, url FROM app_webhooks")).fetchall()
    grouped: dict[str, list[str]] = {}
    for app_id, url in rows:
        grouped.setdefault(app_id, []).append(url)
    for app_id, urls in grouped.items():
        conn.execute(
            sa.text("UPDATE apps SET webhook_urls = :u WHERE app_id = :a"),
            {"u": ",".join(urls), "a": app_id},
        )

    op.drop_index("ix_jobs_created_at", table_name="jobs")
    op.drop_index("ix_apps_created_at", table_name="apps")
    op.drop_index("ix_app_webhooks_app_id", table_name="app_webhooks")
    op.drop_table("app_webhooks")
