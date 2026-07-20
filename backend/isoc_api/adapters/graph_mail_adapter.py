"""Microsoft Graph mailbox ingest — app-only (client-credentials) poller.

Reads unread mail from a single mailbox via OUTBOUND Graph calls only (no public
endpoint, no inbound webhook). The OAuth token is cached in-process until ~1 min
before expiry. Thin async wrapper — no business logic, mirrors v1_adapter style.

Scoping note: the app is granted **Mail.ReadWrite**, so after ingest the poller
calls `mark_read()` — the `isRead eq false` filter then excludes the message on
the next poll and the inbox stays tidy. A DB de-dupe on `internetMessageId` is
still the correctness backstop (mark-read is best-effort and may fail). A
`Mail.Read`-only deployment just sets `graph_mark_read=false` and relies on the
DB de-dupe alone.
"""

from __future__ import annotations

import base64
import re
import time
from typing import Any

import httpx

from ..logging_config import get_logger
from ..settings import settings

logger = get_logger("isoc.graph_mail")

_GRAPH = "https://graph.microsoft.com/v1.0"
_SCOPE = "https://graph.microsoft.com/.default"
_MAX_BODY_CHARS = 20000

# Module-level token cache: {"value": <jwt>, "exp": <epoch seconds>}.
_token_cache: dict[str, Any] = {"value": None, "exp": 0.0}


class GraphError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def is_configured() -> bool:
    return bool(
        settings.graph_tenant_id
        and settings.graph_client_id
        and settings.graph_client_secret
        and settings.graph_mailbox
    )


def can_send() -> bool:
    """True if app-only Graph creds + a sender mailbox are configured (Mail.Send)."""
    return bool(
        settings.graph_tenant_id
        and settings.graph_client_id
        and settings.graph_client_secret
        and (settings.graph_send_from or settings.graph_mailbox)
    )


async def _token() -> str:
    """Return a cached app-only access token, refreshing when within 60s of expiry."""
    now = time.time()
    cached = _token_cache.get("value")
    if cached and now < float(_token_cache.get("exp", 0.0)) - 60:
        return cached

    secret = settings.graph_client_secret
    secret = secret.get_secret_value() if hasattr(secret, "get_secret_value") else str(secret)
    url = f"https://login.microsoftonline.com/{settings.graph_tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": settings.graph_client_id,
        "scope": _SCOPE,
        "client_secret": secret,
        "grant_type": "client_credentials",
    }
    async with httpx.AsyncClient(timeout=30.0) as c:
        resp = await c.post(url, data=data)
    if not resp.is_success:
        try:
            j = resp.json()
            msg = j.get("error_description") or j.get("error") or resp.text[:300]
        except Exception:
            msg = resp.text[:300]
        raise GraphError(resp.status_code, f"token request failed: {msg}")

    j = resp.json()
    _token_cache["value"] = j["access_token"]
    _token_cache["exp"] = now + float(j.get("expires_in", 3599))
    return _token_cache["value"]


async def list_unread(top: int = 25) -> list[dict]:
    """Return unread inbox messages (with plain-text body) for the configured mailbox.

    The `Prefer: outlook.body-content-type="text"` header makes Graph render
    `body.content` as text/plain — the Vision One parser keys on the text form,
    not HTML. `$orderby` is intentionally omitted: Graph rejects it combined with
    `$filter` unless the same property is filtered.
    """
    token = await _token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Prefer": 'outlook.body-content-type="text"',
    }
    params = {
        "$filter": "isRead eq false",
        "$top": str(top),
        "$select": "id,subject,from,receivedDateTime,internetMessageId,hasAttachments,body",
    }
    url = f"{_GRAPH}/users/{settings.graph_mailbox}/mailFolders/inbox/messages"
    async with httpx.AsyncClient(timeout=30.0) as c:
        resp = await c.get(url, headers=headers, params=params)
    if not resp.is_success:
        try:
            msg = (resp.json().get("error") or {}).get("message") or resp.text[:300]
        except Exception:
            msg = resp.text[:300]
        raise GraphError(resp.status_code, msg)
    return (resp.json() or {}).get("value", [])


async def mark_read(message_id: str) -> None:
    """Mark a message read (requires Mail.ReadWrite).

    Best-effort tidiness: it stops the `isRead eq false` poll from returning the
    same message. `message_id` is the Graph message id (the `id` field), NOT the
    internetMessageId. Raises GraphError on failure; callers treat that as
    non-fatal since DB de-dupe still prevents re-ingest.
    """
    token = await _token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = f"{_GRAPH}/users/{settings.graph_mailbox}/messages/{message_id}"
    async with httpx.AsyncClient(timeout=30.0) as c:
        resp = await c.patch(url, headers=headers, json={"isRead": True})
    if not resp.is_success:
        try:
            msg = (resp.json().get("error") or {}).get("message") or resp.text[:300]
        except Exception:
            msg = resp.text[:300]
        raise GraphError(resp.status_code, msg)


async def send_mail(
    *,
    to: str,
    cc: list[str] | None,
    subject: str,
    html_body: str,
    attachments: list[tuple[str, str, bytes]] | None = None,
) -> None:
    """Send an HTML email as the configured mailbox via Graph (requires Mail.Send).

    `attachments` are `(filename, mime, bytes)` tuples sent as Graph
    fileAttachments (base64). Sender = graph_send_from, falling back to
    graph_mailbox. Graph returns 202 on success; raises GraphError on a non-2xx."""
    sender = settings.graph_send_from or settings.graph_mailbox
    if not sender:
        raise GraphError(0, "no sender mailbox configured (graph_send_from / graph_mailbox)")
    message: dict[str, Any] = {
        "subject": subject,
        "body": {"contentType": "HTML", "content": html_body},
        "toRecipients": [{"emailAddress": {"address": to}}],
    }
    if cc:
        message["ccRecipients"] = [{"emailAddress": {"address": a}} for a in cc]
    if attachments:
        message["attachments"] = [
            {
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": filename,
                "contentType": mime,
                "contentBytes": base64.b64encode(content).decode("ascii"),
            }
            for filename, mime, content in attachments
        ]
    token = await _token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = f"{_GRAPH}/users/{sender}/sendMail"
    async with httpx.AsyncClient(timeout=30.0) as c:
        resp = await c.post(
            url, headers=headers, json={"message": message, "saveToSentItems": True}
        )
    if not resp.is_success:
        try:
            msg = (resp.json().get("error") or {}).get("message") or resp.text[:300]
        except Exception:
            msg = resp.text[:300]
        raise GraphError(resp.status_code, msg)


_FWD_PREFIX_RE = re.compile(r"^\s*(?:fw|fwd|re)\s*:\s*", re.IGNORECASE)


def company_from_subject(subject: str | None) -> str | None:
    """V1 tenant/company name = the leading subject segment before the first '|'
    (e.g. 'Acme GmbH | Workbench | ...'). Strips a forwarding prefix
    (Fw:/Fwd:/Re:). Returns None when the subject has no '|' (not a V1 Workbench
    notification) so the caller can quarantine rather than mis-attribute."""
    if not subject:
        return None
    s = _FWD_PREFIX_RE.sub("", subject).strip()
    if "|" not in s:
        return None
    return s.split("|", 1)[0].strip() or None


def message_to_alert_text(msg: dict) -> str:
    """Build the raw alert text fed to the pipeline parser.

    Prepends `Subject:` so the parser always sees the subject's structured fields
    (severity / score / model / Workbench id) even when the forwarded body text
    is sparse. The existing visionone parser handles the rest.
    """
    subject = (msg.get("subject") or "").strip()
    body = ((msg.get("body") or {}).get("content") or "").strip()[:_MAX_BODY_CHARS]
    return f"Subject: {subject}\n\n{body}"


def message_origin(msg: dict) -> dict[str, Any]:
    """Compact provenance dict stored under raw_payload['original'] for audit + dedupe."""
    frm = (msg.get("from") or {}).get("emailAddress") or {}
    return {
        "internet_message_id": msg.get("internetMessageId") or msg.get("id"),
        "graph_id": msg.get("id"),
        "subject": msg.get("subject"),
        "from": frm.get("address"),
        "received": msg.get("receivedDateTime"),
        "has_attachments": bool(msg.get("hasAttachments")),
    }
