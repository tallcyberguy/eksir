"""Unit tests for Feature 8 — case collaboration (pure parts).

The DB routes are validated on the stack; here we lock the @mention parsing and
the notify skip-self / dedup logic.
"""

from __future__ import annotations

import uuid

from isoc_api import notify
from isoc_api.mentions import extract_mention_tokens, parse_mentions, resolve_mentions
from isoc_api.notify import mention_email_html

_USERS = [
    {"id": "u-jane", "full_name": "Jane Doe", "email": "jane.doe@soc.example"},
    {"id": "u-bob", "full_name": "Bob Smith", "email": "bob@soc.example"},
]


# ── extract_mention_tokens ──────────────────────────────────────────────────
def test_extract_basic_and_lowercased():
    assert extract_mention_tokens("Hey @jane.doe and @Bob!") == ["jane.doe", "bob"]


def test_extract_strips_trailing_dot_and_dedups():
    assert extract_mention_tokens("@bob. @bob @a") == ["bob", "a"]


def test_extract_ignores_email_addresses():
    # the '@' in an email is preceded by a word char → not a mention
    assert extract_mention_tokens("mail me at bob@soc.example please") == []


def test_extract_none_when_no_mentions():
    assert extract_mention_tokens("nothing to see here") == []


# ── resolve_mentions ────────────────────────────────────────────────────────
def test_resolve_by_email_local_part():
    assert resolve_mentions(["bob"], _USERS) == ["u-bob"]


def test_resolve_by_full_name_slug_variants():
    assert resolve_mentions(["jane.doe"], _USERS) == ["u-jane"]
    assert resolve_mentions(["janedoe"], _USERS) == ["u-jane"]
    assert resolve_mentions(["jane-doe"], _USERS) == ["u-jane"]


def test_resolve_drops_unknown_and_dedups_preserving_order():
    tokens = ["bob", "nobody", "jane.doe", "bob"]
    assert resolve_mentions(tokens, _USERS) == ["u-bob", "u-jane"]


def test_parse_mentions_end_to_end():
    assert parse_mentions("cc @jane.doe and @bob", _USERS) == ["u-jane", "u-bob"]


# ── notify.notify_users (skip-self + dedup) ─────────────────────────────────
class _StubSession:
    def __init__(self):
        self.added: list = []

    def add(self, obj):
        self.added.append(obj)


async def test_notify_skips_actor_and_dedups():
    s = _StubSession()
    actor = uuid.uuid4()
    u1 = uuid.uuid4()
    created = await notify.notify_users(
        s,
        [str(u1), str(u1), str(actor)],
        kind="mention",
        title="t",
        link="/cases/x",
        actor_id=actor,
    )
    assert created == 1
    assert len(s.added) == 1
    assert s.added[0].user_id == u1
    assert s.added[0].kind == "mention"


async def test_notify_handles_empty_and_none():
    s = _StubSession()
    created = await notify.notify_users(s, [None], kind="comment", title="t")
    assert created == 0
    assert s.added == []


# ── notify.mention_email_html (escaping + link) ─────────────────────────────
def test_mention_email_html_escapes_user_content():
    html = mention_email_html(
        author="Jane <b>Doe</b>",
        case_number="CASE-1",
        preview="see <script>alert(1)</script>",
        url="http://x/cases/1",
    )
    assert "<script>" not in html  # the raw tag must be escaped
    assert "&lt;script&gt;" in html
    assert "Jane &lt;b&gt;Doe&lt;/b&gt;" in html
    assert 'href="http://x/cases/1"' in html
    assert "CASE-1" in html


def test_mention_email_html_omits_link_when_no_url():
    html = mention_email_html(author="A", case_number="CASE-2", preview="hi", url="")
    assert "href=" not in html


# ── notify.credentials_email_html (escaping + kind + link) ──────────────────
def test_credentials_email_html_escapes_and_includes_password():
    html = notify.credentials_email_html(
        full_name="Ada <b>L</b>",
        email="ada@example.com",
        temp_password="p@ss<w0rd>",  # pragma: allowlist secret
        login_url="http://localhost/login",
        kind="invite",
    )
    # user-controlled values must be escaped, never rendered as markup
    assert "<b>L</b>" not in html
    assert "Ada &lt;b&gt;L&lt;/b&gt;" in html
    assert "p@ss&lt;w0rd&gt;" in html
    assert "ada@example.com" in html
    assert 'href="http://localhost/login"' in html
    assert "Welcome to EKSIR" in html


def test_credentials_email_html_reset_kind_wording():
    html = notify.credentials_email_html(
        full_name="",
        email="x@y.z",
        temp_password="abc123",  # pragma: allowlist secret
        login_url="",
        kind="reset",
    )
    assert "reset" in html.lower()
    assert "Welcome to EKSIR" not in html
    assert "href=" not in html  # no button when login_url is empty
