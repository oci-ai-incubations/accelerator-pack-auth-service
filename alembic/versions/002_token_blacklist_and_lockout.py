"""Add token_blacklist and failed_login_attempts tables.

Revision ID: 002
Revises: 001
Create Date: 2026-03-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "002"
down_revision: str | None = "001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "token_blacklist",
        sa.Column("id", sa.Integer, sa.Identity(always=True), primary_key=True),
        sa.Column("jti", sa.String(36), nullable=False, unique=True, index=True),
        sa.Column("expires_at", sa.DateTime, nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )

    op.create_table(
        "failed_login_attempts",
        sa.Column("id", sa.Integer, sa.Identity(always=True), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False, index=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("attempted_at", sa.DateTime, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("failed_login_attempts")
    op.drop_table("token_blacklist")
