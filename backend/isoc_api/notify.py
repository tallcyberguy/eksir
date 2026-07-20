"""In-app notification creation (B1 substrate, Feature 8).

A thin helper over the Notification model, kept separate so any producer (case
mentions today; SLA breach alerting later) creates notifications the same way.
Never commits — the caller owns the transaction.
"""

from __future__ import annotations

import html as _html
import uuid
from collections.abc import Iterable

from sqlalchemy.ext.asyncio import AsyncSession

from .db.models import Notification


def mention_email_html(*, author: str, case_number: str, preview: str, url: str) -> str:
    """Email body for an @mention. Assembled by string interpolation, so every
    interpolated value is HTML-escaped here (email clients strip <style>, hence
    inline styles + no reliance on a template autoescape). Pure — unit-tested."""
    a = _html.escape(author or "A teammate")
    cn = _html.escape(case_number or "a case")
    pv = _html.escape(preview or "")
    u = _html.escape(url or "", quote=True)
    link = (
        f'<p style="margin:16px 0 0;"><a href="{u}" style="color:#00D4FF;">View the case &rarr;</a></p>'
        if u
        else ""
    )
    return (
        '<div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;'
        'background:#07111F;color:#E6EDF7;padding:24px;border-radius:8px;max-width:560px;">'
        '<div style="font-weight:700;letter-spacing:1.5px;color:#00D4FF;">&#x2B22; EKSIR &middot; SOC</div>'
        f'<h2 style="margin:12px 0 6px;font-size:18px;color:#E6EDF7;">{a} mentioned you</h2>'
        f'<p style="margin:0 0 10px;color:#A6B0CF;font-size:14px;">On case '
        f'<b style="color:#E6EDF7;">{cn}</b>:</p>'
        '<div style="background:#0E2044;border-left:3px solid #00D4FF;padding:12px 14px;'
        f'border-radius:4px;font-size:14px;white-space:pre-wrap;color:#E6EDF7;">{pv}</div>'
        f"{link}"
        "</div>"
    )


def _as_uuid(value: uuid.UUID | str) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


async def notify_users(
    session: AsyncSession,
    user_ids: Iterable[uuid.UUID | str],
    *,
    kind: str,
    title: str,
    link: str | None = None,
    body: str | None = None,
    actor_id: uuid.UUID | None = None,
) -> int:
    """Create one Notification per DISTINCT recipient, skipping the actor (you
    never notify yourself). Returns how many were created. Does not commit."""
    seen: set[str] = set()
    created = 0
    for raw in user_ids:
        if raw is None:
            continue
        uid = _as_uuid(raw)
        key = str(uid)
        if key in seen or (actor_id is not None and uid == actor_id):
            continue
        seen.add(key)
        session.add(
            Notification(
                user_id=uid, kind=kind, title=title, link=link, body=body, actor_id=actor_id
            )
        )
        created += 1
    return created
