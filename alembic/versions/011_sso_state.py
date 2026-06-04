"""Add sso_state table for CSRF state + OIDC nonce persistence.

Revision ID: 011
Revises: 010
Create Date: 2026-05-14
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "011"
down_revision: str | None = "010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "sso_state" in inspector.get_table_names():
        return
    op.create_table(
        "sso_state",
        sa.Column("state", sa.String(128), primary_key=True),
        sa.Column("nonce", sa.String(64), nullable=False),
        sa.Column(
            "provider_id",
            sa.Integer(),
            sa.ForeignKey("identity_providers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("redirect_uri", sa.String(2048), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_sso_state_expires_at", "sso_state", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_sso_state_expires_at", table_name="sso_state")
    op.drop_table("sso_state")
