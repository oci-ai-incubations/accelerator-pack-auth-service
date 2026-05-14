"""Add users.allowed_scopes column for per-user scope override (spec 003).

Revision ID: 010
Revises: 009
Create Date: 2026-05-14
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "010"
down_revision: str | None = "009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_cols = {col["name"] for col in inspector.get_columns("users")}

    if "allowed_scopes" not in existing_cols:
        op.add_column("users", sa.Column("allowed_scopes", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "allowed_scopes")
