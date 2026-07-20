"""Outbound customer mail — dispatches to SMTP or Microsoft Graph per
EMAIL_SEND_VIA. The route layer talks only to this module.

- "smtp"  → stdlib smtplib client (needs SMTP AUTH; basic-auth, deprecating on M365).
- "graph" → app-only Microsoft Graph sendMail, reusing the GRAPH_* credentials
            and the Mail.Send application permission (OAuth, no passwords).
"""

from __future__ import annotations

from typing import Iterable

from . import smtp_client
from .adapters import graph_mail_adapter
from .logging_config import get_logger
from .settings import settings

logger = get_logger("isoc.mailer")


class MailNotConfigured(Exception):
    """Raised when the selected mail backend isn't configured."""


def backend() -> str:
    return "graph" if (settings.email_send_via or "smtp").lower() == "graph" else "smtp"


def is_configured() -> bool:
    return graph_mail_adapter.can_send() if backend() == "graph" else smtp_client.is_configured()


async def send_html_email(
    *,
    to: str,
    cc: Iterable[str] = (),
    subject: str,
    html_body: str,
    attachments: Iterable[tuple[str, str, bytes]] = (),
) -> None:
    """Send one HTML notification via the configured backend, optionally with
    file attachments (each a `(filename, mime, bytes)` tuple — e.g. a report PDF).

    Raises MailNotConfigured if the backend isn't configured; transport errors
    propagate to the caller (which maps them to a 502)."""
    if not is_configured():
        raise MailNotConfigured(f"{backend()} mail backend is not configured")

    cc_list = [a.strip() for a in cc if a and a.strip()]
    if not (to and to.strip()):
        raise ValueError("at least one TO recipient is required")
    atts = list(attachments)

    if backend() == "graph":
        await graph_mail_adapter.send_mail(
            to=to.strip(), cc=cc_list, subject=subject, html_body=html_body, attachments=atts
        )
        logger.info("mailer.sent", backend="graph", to=to, cc=cc_list or None, subject=subject)
    else:
        await smtp_client.send_html_email(
            to=to, cc=cc_list, subject=subject, html_body=html_body, attachments=atts
        )
