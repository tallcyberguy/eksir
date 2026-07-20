"""Pure date / reporting-period / schedule-due math (Feature 7).

No DB, no I/O — every function takes its `now` explicitly so the schedule
logic is deterministically unit-testable. All instants are UTC.
"""

from __future__ import annotations

import calendar
from datetime import datetime, timedelta, timezone

# Reports fire at 06:00 UTC — after the period has fully closed, before the
# working day. A fixed hour keeps next_run_after() deterministic.
RUN_HOUR = 6

CADENCES = ("monthly", "weekly")


def month_bounds(year: int, month: int) -> tuple[datetime, datetime]:
    """[first-of-month 00:00:00, last-of-month 23:59:59] in UTC."""
    last_day = calendar.monthrange(year, month)[1]
    start = datetime(year, month, 1, tzinfo=timezone.utc)
    end = datetime(year, month, last_day, 23, 59, 59, tzinfo=timezone.utc)
    return start, end


def six_month_starts(year: int, month: int) -> list[tuple[int, int]]:
    """The (year, month) pairs for the trailing 6 months ending at (year, month),
    oldest first — for the FP-rate sparkline."""
    result = []
    y, m = year, month
    for _ in range(6):
        result.append((y, m))
        m -= 1
        if m == 0:
            m = 12
            y -= 1
    return list(reversed(result))


def _next_month(year: int, month: int) -> tuple[int, int]:
    return (year + 1, 1) if month == 12 else (year, month + 1)


def _prev_month(year: int, month: int) -> tuple[int, int]:
    return (year - 1, 12) if month == 1 else (year, month - 1)


def next_run_after(cadence: str, now: datetime) -> datetime:
    """The next UTC instant a schedule of this cadence should fire, strictly
    after `now`. monthly → 06:00 on the 1st of next month; weekly → 06:00 next
    Monday. Unknown cadence falls back to monthly."""
    now = now.astimezone(timezone.utc)
    if cadence == "weekly":
        # weekday(): Mon=0 … Sun=6. Days until the *next* Monday (never 0).
        days = (7 - now.weekday()) % 7 or 7
        return (now + timedelta(days=days)).replace(
            hour=RUN_HOUR, minute=0, second=0, microsecond=0
        )
    y, m = _next_month(now.year, now.month)
    return datetime(y, m, 1, RUN_HOUR, tzinfo=timezone.utc)


def period_for(cadence: str, now: datetime) -> tuple[datetime, datetime]:
    """The most-recent COMPLETE reporting window ending before `now` — what a
    cron firing at `now` reports on. monthly → the previous calendar month;
    weekly → the previous Monday–Sunday week."""
    now = now.astimezone(timezone.utc)
    if cadence == "weekly":
        this_monday = (now - timedelta(days=now.weekday())).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        start = this_monday - timedelta(days=7)
        end = this_monday - timedelta(seconds=1)
        return start, end
    py, pm = _prev_month(now.year, now.month)
    return month_bounds(py, pm)


def schedule_due(next_run_at: datetime | None, now: datetime) -> bool:
    """True when a schedule should fire: it has never run (next_run_at is None)
    or its scheduled instant has passed."""
    if next_run_at is None:
        return True
    return next_run_at <= now.astimezone(timezone.utc)
