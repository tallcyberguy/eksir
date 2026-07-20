"""Outbound SMTP for customer notifications.

Uses stdlib smtplib in a thread pool (asyncio.to_thread) — no new dependency,
and SMTP is rare enough in this app that an async-native client isn't worth
the extra surface.

If smtp_host is unset, `is_configured()` returns False so the caller short-
circuits with a friendly 503. Sending never blocks on background work.
"""

from __future__ import annotations

import asyncio
import smtplib
import ssl
from email.message import EmailMessage
from typing import Iterable

from .logging_config import get_logger
from .settings import settings

logger = get_logger("isoc.smtp")


def is_configured() -> bool:
    return bool(settings.smtp_host)


class SMTPNotConfigured(Exception):
    """Raised when send is called without SMTP_HOST set."""


def _send_sync(
    *,
    to_addrs: list[str],
    cc_addrs: list[str],
    subject: str,
    html_body: str,
    from_addr: str,
    attachments: list[tuple[str, str, bytes]] | None = None,
) -> None:
    """Blocking SMTP send. Called via asyncio.to_thread."""
    if not settings.smtp_host:
        raise SMTPNotConfigured("smtp_host is empty")

    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    if cc_addrs:
        msg["Cc"] = ", ".join(cc_addrs)
    msg["Subject"] = subject
    # set_content sets a text/plain fallback; add_alternative attaches the HTML.
    msg.set_content(
        "Your email client does not support HTML — please open the EKSIR notification on a modern client."
    )
    msg.add_alternative(html_body, subtype="html")

    for filename, mime, content in attachments or []:
        maintype, _, subtype = mime.partition("/")
        msg.add_attachment(
            content,
            maintype=maintype or "application",
            subtype=subtype or "octet-stream",
            filename=filename,
        )

    recipients = list({*to_addrs, *cc_addrs})

    pw = settings.smtp_password.get_secret_value() if settings.smtp_password else None

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as smtp:
        smtp.ehlo()
        if settings.smtp_use_tls:
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
        if settings.smtp_user and pw:
            smtp.login(settings.smtp_user, pw)
        smtp.send_message(msg, from_addr=from_addr, to_addrs=recipients)


async def send_html_email(
    *,
    to: str,
    cc: Iterable[str] = (),
    subject: str,
    html_body: str,
    attachments: Iterable[tuple[str, str, bytes]] = (),
) -> None:
    """Send a single HTML notification, optionally with file attachments
    (each a `(filename, mime, bytes)` tuple — e.g. a rendered report PDF).

    Raises SMTPNotConfigured if SMTP_HOST is unset, smtplib.SMTPException for
    most transport errors, or generic OSError/TimeoutError on network issues.
    """
    if not is_configured():
        raise SMTPNotConfigured("SMTP is not configured")

    from_addr = settings.smtp_from or (settings.smtp_user or "soc@example.invalid")
    to_addrs = [to.strip()] if to and to.strip() else []
    cc_addrs = [a.strip() for a in cc if a and a.strip()]
    if not to_addrs:
        raise ValueError("at least one TO recipient is required")

    await asyncio.to_thread(
        _send_sync,
        to_addrs=to_addrs,
        cc_addrs=cc_addrs,
        subject=subject,
        html_body=html_body,
        from_addr=from_addr,
        attachments=list(attachments),
    )
    logger.info("smtp.sent", to=to_addrs, cc=cc_addrs or None, subject=subject)
