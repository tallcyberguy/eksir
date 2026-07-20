"""Centralised audit logging.

Writes to the `audit_log` table. Wrapped so a logging failure never bubbles up
and breaks the user action it was meant to record.

Action naming convention:  <noun>.<verb>
  auth.login_ok, auth.login_failed, auth.logout
  user.create, user.delete
  webhook.create, webhook.patch, webhook.delete
  autoclose.create, autoclose.patch, autoclose.delete
  incident.patch, incident.regenerate, incident.paste
  v1.blocklist, v1.isolate, v1.restore, v1.collect_file
  pipeline.step_failed, pipeline.failed
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from .db.models import AuditLog
from .logging_config import get_logger

logger = get_logger("isoc.audit")


async def log(
    session: AsyncSession,
    *,
    action: str,
    user_id: uuid.UUID | None = None,
    target_type: str | None = None,
    target_id: uuid.UUID | None = None,
    tenant_id: uuid.UUID | None = None,
    diff: dict[str, Any] | None = None,
) -> None:
    """Append one audit entry. Never raises.

    `tenant_id` is the tenant the action affected (None for platform-level
    actions like login, user CRUD, ad-hoc V1 ops). Used for filtering + scope.
    """
    try:
        session.add(
            AuditLog(
                user_id=user_id,
                action=action,
                target_type=target_type,
                target_id=target_id,
                tenant_id=tenant_id,
                diff=_serialise(diff),
                ts=datetime.now(timezone.utc),
            )
        )
        # Don't commit here — the caller's transaction owns commit/rollback.
        # If they roll back, the audit entry rolls back too, which is the
        # right behaviour: we don't want phantom audit entries for actions
        # that never happened.
        await session.flush()
    except Exception as e:  # never break the caller
        logger.warning("audit.write_failed", action=action, error=str(e))


def _serialise(value: Any) -> Any:
    """Make values JSONB-safe: convert UUID/datetime/enum to primitives."""
    if value is None:
        return None
    if isinstance(value, dict):
        return {k: _serialise(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_serialise(v) for v in value]
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if hasattr(value, "value") and hasattr(value, "name"):  # enum-ish
        return str(value)
    return value
