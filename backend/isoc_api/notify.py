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


def credentials_email_html(
    *, full_name: str, email: str, temp_password: str, login_url: str, kind: str = "invite"
) -> str:
    """Email body delivering a user's sign-in credentials. `kind="invite"` for a
    brand-new account, `kind="reset"` for an admin password reset. Same discipline
    as mention_email_html: inline styles, every interpolated value HTML-escaped,
    no template autoescape. Pure, unit-tested."""
    name = _html.escape(full_name or email or "there")
    em = _html.escape(email or "")
    pw = _html.escape(temp_password or "")
    u = _html.escape(login_url or "", quote=True)
    heading = "Your EKSIR account is ready" if kind == "reset" else "Welcome to EKSIR"
    lead = (
        "Your password has been reset by an administrator. Use the temporary "
        "password below to sign in, then change it from your account settings."
        if kind == "reset"
        else "An account has been created for you. Use the temporary password "
        "below to sign in, then change it from your account settings."
    )
    button = (
        f'<p style="margin:18px 0 0;"><a href="{u}" '
        'style="display:inline-block;background:#00D4FF;color:#07111F;font-weight:700;'
        'text-decoration:none;padding:10px 18px;border-radius:6px;">Sign in &rarr;</a></p>'
        if u
        else ""
    )
    return (
        '<div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;'
        'background:#07111F;color:#E6EDF7;padding:24px;border-radius:8px;max-width:560px;">'
        '<div style="font-weight:700;letter-spacing:1.5px;color:#00D4FF;">&#x2B22; EKSIR &middot; SOC</div>'
        f'<h2 style="margin:12px 0 6px;font-size:18px;color:#E6EDF7;">{heading}</h2>'
        f'<p style="margin:0 0 12px;color:#A6B0CF;font-size:14px;">Hi {name}, {lead}</p>'
        '<table style="border-collapse:collapse;font-size:14px;margin:6px 0;">'
        '<tr><td style="padding:4px 12px 4px 0;color:#A6B0CF;">Email</td>'
        f'<td style="padding:4px 0;color:#E6EDF7;"><b>{em}</b></td></tr>'
        '<tr><td style="padding:4px 12px 4px 0;color:#A6B0CF;">Temporary password</td>'
        '<td style="padding:4px 0;"><code style="background:#0E2044;border:1px solid #1d3a6b;'
        f'padding:2px 8px;border-radius:4px;color:#E6EDF7;">{pw}</code></td></tr>'
        "</table>"
        '<p style="margin:12px 0 0;color:#7C8AAF;font-size:12px;">'
        "For your security, change this password right after signing in.</p>"
        f"{button}"
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
