"""UTC time helpers: normalization, 36-calendar-month retention, 12h display."""

from __future__ import annotations

import calendar
from datetime import datetime, timezone


def to_utc(value: datetime) -> datetime:
    """Normalize a datetime to aware UTC (naive is assumed UTC)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def canonical(value: datetime) -> str:
    """Canonical string form used for storage and comparisons."""
    value = to_utc(value)
    text = value.strftime("%Y-%m-%dT%H:%M:%S")
    if value.microsecond:
        text += ".%06d" % value.microsecond
    return text


def parse(text: str) -> datetime:
    """Inverse of canonical()."""
    return to_utc(datetime.fromisoformat(text))


def retention_line(now: datetime) -> datetime:
    """36 calendar months before ``now``; clamp day to month end; keep time."""
    now = to_utc(now)
    year = now.year - 3
    month = now.month
    day = min(now.day, calendar.monthrange(year, month)[1])
    return now.replace(year=year, month=month, day=day)


def format_12h(value: datetime) -> str:
    """Display like ``03/07/2026 02:05:09 PM`` (UTC, 12-hour clock)."""
    value = to_utc(value)
    return value.strftime("%m/%d/%Y %I:%M:%S %p")
