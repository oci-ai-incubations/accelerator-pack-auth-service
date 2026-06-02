"""Make service_accounts.owner_user_id nullable.

Env-seeded (bootstrap) service accounts are created at startup with no human
owner, so the owner_user_id FK must allow NULL. Admin-API-created accounts
continue to set it to the creating admin's id.

Revision ID: 012
Revises: 011
Create Date: 2026-06-02
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "012"
down_revision: str | None = "011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # SQLite (test engine) can't ALTER COLUMN nullability and gets its schema
    # from the models (already nullable) via create_all, so this is a no-op
    # there; Oracle/Postgres get the real ALTER.
    if op.get_bind().dialect.name == "sqlite":
        return
    op.alter_column(
        "service_accounts",
        "owner_user_id",
        existing_type=sa.Integer(),
        nullable=True,
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        return
    op.alter_column(
        "service_accounts",
        "owner_user_id",
        existing_type=sa.Integer(),
        nullable=False,
    )
