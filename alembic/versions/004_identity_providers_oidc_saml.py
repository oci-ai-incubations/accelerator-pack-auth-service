"""Add identity_providers, external_identities, claim_role_mappings tables.

Revision ID: 004
Revises: 003
Create Date: 2026-03-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "004"
down_revision: str | None = "003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "identity_providers",
        sa.Column("id", sa.Integer, sa.Identity(always=True), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.Integer,
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "type",
            sa.Enum("oidc", "saml", name="providertype"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), unique=True, nullable=False, index=True),
        sa.Column("config", sa.JSON, nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("1")),
        sa.Column("priority", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )

    op.create_table(
        "external_identities",
        sa.Column("id", sa.Integer, sa.Identity(always=True), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer,
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "provider_id",
            sa.Integer,
            sa.ForeignKey("identity_providers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("external_id", sa.String(255), nullable=False),
        sa.Column("email", sa.String(320), nullable=True),
        sa.Column("raw_claims", sa.JSON, nullable=True),
        sa.Column("last_login_at", sa.DateTime, nullable=True),
        sa.UniqueConstraint("provider_id", "external_id", name="uq_provider_external_id"),
    )

    op.create_table(
        "claim_role_mappings",
        sa.Column("id", sa.Integer, sa.Identity(always=True), primary_key=True),
        sa.Column(
            "provider_id",
            sa.Integer,
            sa.ForeignKey("identity_providers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("claim_key", sa.String(255), nullable=False),
        sa.Column("claim_value_pattern", sa.String(255), nullable=False),
        sa.Column(
            "role_id",
            sa.Integer,
            sa.ForeignKey("roles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("priority", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("is_regex", sa.Boolean, nullable=False, server_default=sa.text("0")),
    )


def downgrade() -> None:
    op.drop_table("claim_role_mappings")
    op.drop_table("external_identities")
    op.drop_table("identity_providers")
