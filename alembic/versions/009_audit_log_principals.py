"""Add actor_principal_type + actor_principal_id columns to audit_logs.

Revision ID: 009
Revises: 008
Create Date: 2026-05-14
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "009"
down_revision: str | None = "008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_cols = {col["name"] for col in inspector.get_columns("audit_logs")}

    if "actor_principal_type" not in existing_cols:
        op.add_column(
            "audit_logs", sa.Column("actor_principal_type", sa.String(16), nullable=True)
        )
    if "actor_principal_id" not in existing_cols:
        op.add_column(
            "audit_logs", sa.Column("actor_principal_id", sa.String(128), nullable=True)
        )


def downgrade() -> None:
    op.drop_column("audit_logs", "actor_principal_id")
    op.drop_column("audit_logs", "actor_principal_type")
