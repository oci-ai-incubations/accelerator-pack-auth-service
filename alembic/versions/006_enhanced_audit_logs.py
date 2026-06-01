"""Enhance audit_logs with structured fields.

Revision ID: 006
Revises: 005
Create Date: 2026-03-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "006"
down_revision: str | None = "005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("audit_logs", sa.Column("timestamp", sa.DateTime, nullable=True))
    op.add_column("audit_logs", sa.Column("event_type", sa.String(100), nullable=True))
    op.add_column("audit_logs", sa.Column("actor_user_id", sa.Integer, nullable=True))
    op.add_column("audit_logs", sa.Column("actor_email", sa.String(320), nullable=True))
    op.add_column("audit_logs", sa.Column("target_type", sa.String(100), nullable=True))
    op.add_column("audit_logs", sa.Column("target_id", sa.String(255), nullable=True))
    op.add_column("audit_logs", sa.Column("tenant_id", sa.Integer, nullable=True))
    op.add_column("audit_logs", sa.Column("details", sa.Text, nullable=True))
    op.add_column("audit_logs", sa.Column("ip_address", sa.String(45), nullable=True))
    op.add_column("audit_logs", sa.Column("user_agent", sa.String(500), nullable=True))
    op.add_column(
        "audit_logs",
        sa.Column(
            "result",
            sa.Enum("success", "failure", name="auditresult"),
            nullable=True,
            server_default="success",
        ),
    )
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])
    op.create_index("ix_audit_logs_event_type", "audit_logs", ["event_type"])


def downgrade() -> None:
    op.drop_index("ix_audit_logs_event_type", table_name="audit_logs")
    op.drop_index("ix_audit_logs_timestamp", table_name="audit_logs")
    op.drop_column("audit_logs", "result")
    op.drop_column("audit_logs", "user_agent")
    op.drop_column("audit_logs", "ip_address")
    op.drop_column("audit_logs", "details")
    op.drop_column("audit_logs", "tenant_id")
    op.drop_column("audit_logs", "target_id")
    op.drop_column("audit_logs", "target_type")
    op.drop_column("audit_logs", "actor_email")
    op.drop_column("audit_logs", "actor_user_id")
    op.drop_column("audit_logs", "event_type")
    op.drop_column("audit_logs", "timestamp")
