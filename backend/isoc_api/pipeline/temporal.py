"""Temporal context derivation — when did this alert fire, locally?

The raw ISO timestamp in `normalized.timestamp` is easy to overlook in a
20-line briefing. We extract the local hour, classify business vs. after
hours, and weekday vs. weekend, so the LLM gets an explicit signal it can
weigh in its verdict.

Business hours window: configurable, default Mon-Fri 09:00-18:00 in the
alert's own timezone offset (we don't translate timezones — most SIEM
events arrive with the customer's local offset already).
"""

from __future__ import annotations

from datetime import datetime

# Default Mon-Fri 09:00 to 18:00, alert-local.
BUSINESS_START_HOUR = 9
BUSINESS_END_HOUR = 18


def derive(ts_iso: str | None) -> dict | None:
    """Parse the ISO timestamp and return temporal context, or None on failure.

    Returns:
      {
        "local_iso":    "2026-05-24T23:12:59+03:00",
        "local_hour":   23,
        "weekday":      "Sunday",
        "is_business_hours": False,
        "is_weekend":   True,
        "category":     "after-hours-weekend" | "after-hours" | "business-hours" | "weekend",
      }
    """
    if not ts_iso or not isinstance(ts_iso, str):
        return None
    try:
        # Python doesn't accept '+0300' (no colon) before 3.11; both forms occur in feeds.
        s = ts_iso.strip()
        if len(s) >= 5 and (s[-5] in "+-") and s[-3] != ":":
            s = s[:-2] + ":" + s[-2:]
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None

    hour = dt.hour
    weekday = dt.weekday()  # 0 = Monday
    is_weekend = weekday >= 5
    is_business = (not is_weekend) and (BUSINESS_START_HOUR <= hour < BUSINESS_END_HOUR)

    if is_business:
        category = "business-hours"
    elif is_weekend and not (BUSINESS_START_HOUR <= hour < BUSINESS_END_HOUR):
        category = "after-hours-weekend"
    elif is_weekend:
        category = "weekend"
    else:
        category = "after-hours"

    weekday_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

    return {
        "local_iso": dt.isoformat(),
        "local_hour": hour,
        "weekday": weekday_names[weekday],
        "is_business_hours": is_business,
        "is_weekend": is_weekend,
        "category": category,
    }
