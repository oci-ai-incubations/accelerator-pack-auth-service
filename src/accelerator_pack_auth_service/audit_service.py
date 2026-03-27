"""Audit service: structured event logging, query, export, and retention."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .models import AuditLog, AuditResult


async def log_event(
    db: AsyncSession,
    event_type: str,
    *,
    actor_user_id: int | None = None,
    actor_email: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    tenant_id: int | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    result: AuditResult = AuditResult.success,
) -> AuditLog | None:
    """Write a structured audit log entry."""
    if not settings.audit_enabled:
        return None

    entry = AuditLog(
        timestamp=datetime.now(UTC),
        event_type=event_type,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        target_type=target_type,
        target_id=target_id,
        tenant_id=tenant_id,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
        result=result,
        # Legacy fields for backward compat
        user_id=actor_user_id,
        action=event_type,
        created_at=datetime.now(UTC),
    )
    db.add(entry)
    await db.commit()
    return entry


async def query_audit_logs(
    db: AsyncSession,
    *,
    event_type: str | None = None,
    actor_user_id: int | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    result_filter: str | None = None,
    from_date: datetime | None = None,
    to_date: datetime | None = None,
    offset: int = 0,
    limit: int = 50,
) -> tuple[list[AuditLog], int]:
    """Query audit logs with filters and pagination. Returns (logs, total_count)."""
    query = select(AuditLog)
    count_query = select(func.count()).select_from(AuditLog)

    if event_type:
        query = query.where(AuditLog.event_type == event_type)
        count_query = count_query.where(AuditLog.event_type == event_type)
    if actor_user_id is not None:
        query = query.where(AuditLog.actor_user_id == actor_user_id)
        count_query = count_query.where(AuditLog.actor_user_id == actor_user_id)
    if target_type:
        query = query.where(AuditLog.target_type == target_type)
        count_query = count_query.where(AuditLog.target_type == target_type)
    if target_id:
        query = query.where(AuditLog.target_id == target_id)
        count_query = count_query.where(AuditLog.target_id == target_id)
    if result_filter:
        query = query.where(AuditLog.result == result_filter)
        count_query = count_query.where(AuditLog.result == result_filter)
    if from_date:
        query = query.where(AuditLog.timestamp >= from_date)
        count_query = count_query.where(AuditLog.timestamp >= from_date)
    if to_date:
        query = query.where(AuditLog.timestamp <= to_date)
        count_query = count_query.where(AuditLog.timestamp <= to_date)

    total = await db.scalar(count_query)
    result = await db.execute(query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit))
    return list(result.scalars().all()), total or 0


def audit_log_to_dict(log: AuditLog) -> dict:
    """Convert an audit log entry to a serializable dict."""
    return {
        "id": log.id,
        "timestamp": log.timestamp.isoformat() if log.timestamp else None,
        "event_type": log.event_type,
        "actor_user_id": log.actor_user_id,
        "actor_email": log.actor_email,
        "target_type": log.target_type,
        "target_id": log.target_id,
        "tenant_id": log.tenant_id,
        "details": log.details,
        "ip_address": log.ip_address,
        "user_agent": log.user_agent,
        "result": log.result.value if log.result else None,
    }


async def purge_old_logs(db: AsyncSession) -> int:
    """Delete audit logs older than retention period. Returns count deleted."""
    cutoff = datetime.now(UTC) - timedelta(days=settings.audit_retention_days)
    result = await db.execute(delete(AuditLog).where(AuditLog.timestamp < cutoff))
    await db.commit()
    return result.rowcount
