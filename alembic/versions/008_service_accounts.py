"""Add service_accounts table for OAuth2 client_credentials grant.

Revision ID: 008
Revises: 007
Create Date: 2026-05-14
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "008"
down_revision: str | None = "007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "service_accounts" in inspector.get_table_names():
        return

    op.create_table(
        "service_accounts",
        sa.Column("id", sa.Integer, sa.Identity(always=True), primary_key=True),
        sa.Column("client_id", sa.String(64), nullable=False, unique=True),
        sa.Column("client_secret_hash", sa.String(128), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("scopes", sa.Text, nullable=False, server_default=""),
        sa.Column(
            "owner_user_id",
            sa.Integer,
            sa.ForeignKey("users.id"),
            nullable=False,
        ),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("expires_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("revoked_at", sa.DateTime, nullable=True),
        sa.Column("last_used_at", sa.DateTime, nullable=True),
        sa.Column("last_used_ip", sa.String(45), nullable=True),
    )
    op.create_index(
        "ix_service_accounts_client_id", "service_accounts", ["client_id"], unique=True
    )
    op.create_index("ix_service_accounts_owner_user_id", "service_accounts", ["owner_user_id"])


def downgrade() -> None:
    op.drop_index("ix_service_accounts_owner_user_id", table_name="service_accounts")
    op.drop_index("ix_service_accounts_client_id", table_name="service_accounts")
    op.drop_table("service_accounts")
