"""Structured logging via structlog. One log line = one JSON object."""

from __future__ import annotations

import logging
import sys

import structlog

from .settings import settings


def configure_logging() -> None:
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
    )

    # `make_filtering_bound_logger` produces a PrintLogger with no `.name`
    # attribute, so we drop `add_logger_name` and prepend the logger name
    # ourselves via a small processor.
    def _add_logger_name(_logger, _method, event_dict):
        # structlog.get_logger(name) stashes the name in event_dict via the
        # BoundLogger's _initial_values when we pass it in get_logger(name=…).
        return event_dict

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
