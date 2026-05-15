"""Add signing_keys table for RS256 JWT signing.

Revision ID: 007
Revises: 006
Create Date: 2026-05-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "007"
down_revision: str | None = "006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "signing_keys" in inspector.get_table_names():
        return

    op.create_table(
        "signing_keys",
        sa.Column("id", sa.Integer, sa.Identity(always=True), primary_key=True),
        sa.Column("kid", sa.String(64), nullable=False, unique=True),
        sa.Column("algorithm", sa.String(16), nullable=False, server_default="RS256"),
        sa.Column("public_pem", sa.Text, nullable=False),
        sa.Column("private_pem", sa.Text, nullable=False),
        sa.Column(
            "status",
            sa.Enum("active", "rotating_out", "revoked", name="signingkeystatus"),
            nullable=False,
            server_default="active",
        ),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("rotated_at", sa.DateTime, nullable=True),
        sa.Column("revoked_at", sa.DateTime, nullable=True),
    )
    op.create_index("ix_signing_keys_kid", "signing_keys", ["kid"], unique=True)
    op.create_index("ix_signing_keys_status", "signing_keys", ["status"])


def downgrade() -> None:
    op.drop_index("ix_signing_keys_status", table_name="signing_keys")
    op.drop_index("ix_signing_keys_kid", table_name="signing_keys")
    op.drop_table("signing_keys")
    sa.Enum(name="signingkeystatus").drop(op.get_bind(), checkfirst=True)
