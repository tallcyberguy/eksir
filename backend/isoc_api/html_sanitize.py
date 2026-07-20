"""Sanitize analyst-edited HTML before it's emailed to a customer.

The notification editor lets analysts edit the final HTML. That markup is
semi-trusted (internal SOC authors) but goes to external recipients, so we strip
active content (scripts, event handlers, javascript: URLs) while keeping the
inline styles + table layout that email clients require.
"""

from __future__ import annotations

import bleach

_ALLOWED_TAGS = [
    "html",
    "head",
    "body",
    "meta",
    "title",
    "style",
    "table",
    "thead",
    "tbody",
    "tfoot",
    "tr",
    "td",
    "th",
    "col",
    "colgroup",
    "div",
    "span",
    "p",
    "a",
    "img",
    "br",
    "hr",
    "center",
    "font",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "strong",
    "em",
    "b",
    "i",
    "u",
    "small",
    "sub",
    "sup",
    "ul",
    "ol",
    "li",
    "blockquote",
    "pre",
    "code",
]

_COMMON_ATTRS = [
    "style",
    "class",
    "id",
    "align",
    "valign",
    "width",
    "height",
    "bgcolor",
    "color",
    "border",
    "cellpadding",
    "cellspacing",
    "dir",
    "title",
]

_ALLOWED_ATTRS = {
    "*": _COMMON_ATTRS,
    "a": _COMMON_ATTRS + ["href", "target", "rel"],
    "img": _COMMON_ATTRS + ["src", "alt"],
    "td": _COMMON_ATTRS + ["colspan", "rowspan"],
    "th": _COMMON_ATTRS + ["colspan", "rowspan"],
    "meta": ["charset", "name", "content", "http-equiv"],
}


def sanitize_email_html(html: str | None) -> str:
    """Strip scripts/handlers/unsafe URLs; keep email-safe markup + inline CSS."""
    return bleach.clean(
        html or "",
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRS,
        protocols=["http", "https", "mailto", "cid", "data"],
        strip=True,
        strip_comments=False,
    )
