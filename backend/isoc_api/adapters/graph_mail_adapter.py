"""Microsoft Graph outbound mail: app-only (client-credentials) sender.

Sends customer-notification email as a shared mailbox via outbound Graph calls
(requires Mail.Send). The OAuth token is cached in-process until ~1 min before
expiry. Thin async wrapper, no business logic, mirrors v1_adapter style.

Inbound mailbox ingestion (the old Vision One email-forward poller) was retired
in favour of the direct connector pull, so this module is now send-only.
"""

from __future__ import annotations

import base64
import time
from typing import Any

import httpx

from ..settings import settings

_GRAPH = "https://graph.microsoft.com/v1.0"
_SCOPE = "https://graph.microsoft.com/.default"

# Module-level token cache: {"value": <jwt>, "exp": <epoch seconds>}.
_token_cache: dict[str, Any] = {"value": None, "exp": 0.0}


class GraphError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


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
