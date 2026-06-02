"""Make audit_logs.user_id nullable.

The legacy ``user_id`` column was created NOT NULL, but machine-principal
(service-account / client_credentials) audit events have no user — they record
the actor via ``actor_principal_type`` / ``actor_principal_id`` instead. The
model already declares ``user_id`` nullable; this migration brings the DB column
in line so ``oauth_token_issued`` (and other client-driven events) can be logged
without an ORA-01400 / NOT NULL violation.

Revision ID: 013
Revises: 012
Create Date: 2026-06-02
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "013"
down_revision: str | None = "012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # SQLite (test engine) can't ALTER COLUMN nullability and gets its schema
    # from the models (already nullable) via create_all, so this is a no-op
    # there; Oracle/Postgres get the real ALTER.
    if op.get_bind().dialect.name == "sqlite":
        return
    op.alter_column(
        "audit_logs",
        "user_id",
        existing_type=sa.Integer(),
        nullable=True,
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        return
    op.alter_column(
        "audit_logs",
        "user_id",
        existing_type=sa.Integer(),
        nullable=False,
    )
