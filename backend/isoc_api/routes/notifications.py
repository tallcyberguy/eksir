"""In-app notifications (B1) — list / unread-count / mark-read for the current
user. Producers (case @mentions today) create rows via `notify.py`; this is the
read + acknowledge surface behind the top-bar bell."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..db.models import Notification, User
from ..db.session import get_session

router = APIRouter()


def _serialise(n: Notification) -> dict:
    return {
        "id": str(n.id),
        "kind": n.kind,
        "title": n.title,
        "body": n.body,
        "link": n.link,
        "read": n.read_at is not None,
        "created_at": n.created_at.isoformat() if n.created_at else None,
    }


@router.get("")
async def list_notifications(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
    unread_only: bool = Query(default=False),
    limit: int = Query(default=30, ge=1, le=100),
) -> list[dict]:
    """The current user's notifications, newest first."""
    q = select(Notification).where(Notification.user_id == user.id)
    if unread_only:
        q = q.where(Notification.read_at.is_(None))
    q = q.order_by(Notification.created_at.desc()).limit(limit)
    rows = (await session.execute(q)).scalars().all()
    return [_serialise(n) for n in rows]


@router.get("/unread-count")
async def unread_count(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
) -> dict:
    """Unread count for the bell badge."""
    n = (
        await session.execute(
            select(func.count(Notification.id)).where(
                Notification.user_id == user.id, Notification.read_at.is_(None)
            )
        )
    ).scalar() or 0
    return {"count": int(n)}


@router.post("/{notification_id}/read")
async def mark_read(
    notification_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
) -> dict:
    n = await session.get(Notification, notification_id)
    if n is None or n.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "notification not found")
    if n.read_at is None:
        n.read_at = datetime.now(timezone.utc)
    return _serialise(n)


@router.post("/read-all")
async def mark_all_read(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
) -> dict:
    """Mark all of the current user's unread notifications read."""
    await session.execute(
        update(Notification)
        .where(Notification.user_id == user.id, Notification.read_at.is_(None))
        .values(read_at=datetime.now(timezone.utc))
    )
    return {"ok": True}
