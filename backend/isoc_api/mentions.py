"""Pure @mention parsing for case comments (Feature 8).

No DB access — resolves tokens against a caller-supplied user list so the whole
thing is deterministically unit-testable (tests/test_mentions.py).
"""

from __future__ import annotations

import re

# An @handle: starts alphanumeric, then letters/digits/._- (covers @jane.doe,
# @j_smith, @jane-doe, and @jane@corp.com's local part). A leading '@' inside an
# email address won't match because it isn't preceded by a word boundary here —
# callers pass comment prose, not raw addresses.
_MENTION_RE = re.compile(r"(?<![\w@])@([A-Za-z0-9][A-Za-z0-9._-]*)")


def extract_mention_tokens(body: str) -> list[str]:
    """Distinct @-tokens in the comment body, lower-cased, first-seen order.
    A trailing dot (sentence end, e.g. '@jane.') is stripped."""
    seen: set[str] = set()
    out: list[str] = []
    for m in _MENTION_RE.finditer(body or ""):
        tok = m.group(1).lower().rstrip(".")
        if tok and tok not in seen:
            seen.add(tok)
            out.append(tok)
    return out


def _handles(user: dict) -> set[str]:
    """The @handles a user answers to: the email local-part (and full email),
    plus the full_name slugged three ways (dot / none / hyphen separated)."""
    handles: set[str] = set()
    email = (user.get("email") or "").strip().lower()
    if email:
        handles.add(email)
        if "@" in email:
            handles.add(email.split("@", 1)[0])
    name = (user.get("full_name") or "").strip().lower()
    if name:
        parts = [p for p in re.split(r"\s+", name) if p]
        if parts:
            handles.add(".".join(parts))
            handles.add("".join(parts))
            handles.add("-".join(parts))
    return {h for h in handles if h}


def resolve_mentions(tokens: list[str], users: list[dict]) -> list[str]:
    """Map @tokens → user-id strings. Each token is matched against every user's
    handles (email local-part / slugged full_name). Unknown tokens are dropped;
    the result is de-duplicated and ordered by first appearance. `users` items
    are dicts with `id`, `email`, `full_name`."""
    by_handle: dict[str, str] = {}
    for u in users:
        uid = str(u.get("id"))
        for h in _handles(u):
            by_handle.setdefault(h, uid)
    seen: set[str] = set()
    out: list[str] = []
    for t in tokens:
        uid = by_handle.get(t)
        if uid and uid not in seen:
            seen.add(uid)
            out.append(uid)
    return out


def parse_mentions(body: str, users: list[dict]) -> list[str]:
    """Convenience: extract tokens from `body` and resolve them against `users`."""
    return resolve_mentions(extract_mention_tokens(body), users)
