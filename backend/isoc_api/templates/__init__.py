"""Jinja2 environment for customer-facing notifications.

Lazy module-level singleton — instantiated once per process; templates are
cached by Jinja's default loader. Auto-escape is ON for HTML/XML files,
which means user-controlled fields (incident_analysis, recommended_actions
etc.) cannot break the template by containing `<script>` or `&` etc.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TEMPLATE_DIR = Path(__file__).parent

env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "htm", "xml"]),
    trim_blocks=True,
    lstrip_blocks=True,
)
