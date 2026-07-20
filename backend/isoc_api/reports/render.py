"""Report rendering (Feature 7): Jinja HTML + lazy-imported WeasyPrint PDF.

Uses a dedicated Jinja environment with **autoescape unconditionally on** — the
report embeds strings that originate from ingested alerts (IOC values, rule
names, source products), so every interpolation must be escaped regardless of
the template's file extension. (The shared templates.env only autoescapes files
whose name ends in .html/.htm/.xml, which a *.html.j2 name does not satisfy.)

WeasyPrint is imported lazily inside html_to_pdf so a missing native lib (Pango/
Cairo) can never break module import or the HTML-preview path — the PDF endpoint
degrades to a clear error instead.
"""

from __future__ import annotations

import base64
from pathlib import Path

import structlog
from jinja2 import Environment, FileSystemLoader

logger = structlog.get_logger(__name__)

_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=True,
    trim_blocks=True,
    lstrip_blocks=True,
)

_REPORT_TEMPLATE = "reports/report.html.j2"


class PdfUnavailable(RuntimeError):
    """WeasyPrint or its native libraries could not be loaded at runtime."""


def logo_data_uri(logo_bytes: bytes | None, mime: str | None) -> str | None:
    """Embed the logo as a self-contained data-URI (no external fetch), or None."""
    if not logo_bytes:
        return None
    return f"data:{mime or 'image/png'};base64,{base64.b64encode(logo_bytes).decode('ascii')}"


def render_report_html(context: dict) -> str:
    """Render the branded report HTML from a build_report_context() dict."""
    return _env.get_template(_REPORT_TEMPLATE).render(**context)


def html_to_pdf(html: str) -> bytes:
    """Render report HTML to PDF bytes via WeasyPrint. Raises PdfUnavailable if
    WeasyPrint (or its native deps) isn't importable on this deployment."""
    try:
        # Lazy: loads the native Pango/Cairo libs via ctypes only when called.
        from weasyprint import HTML  # type: ignore[import-not-found]
    except Exception as e:  # ImportError, or OSError when the .so's are absent
        logger.warning("reports.pdf_unavailable", error=str(e))
        raise PdfUnavailable(str(e)) from e
    return HTML(string=html).write_pdf()
