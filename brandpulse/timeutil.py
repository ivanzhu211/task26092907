"""UTC 时间处理：保留线计算与显示。"""

from __future__ import annotations

import calendar
from datetime import datetime, timedelta, timezone

from .errors import InvalidArgumentError

RETENTION_MONTHS = 36
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def validate_utc(at: datetime) -> datetime:
    """校验调用方传入的时间：必须是带时区的 UTC，归一化到 timezone.utc。"""
    if not isinstance(at, datetime):
        raise InvalidArgumentError("at 必须是 datetime")
    if at.tzinfo is None:
        raise InvalidArgumentError("时间必须带时区（UTC）")
    offset = at.utcoffset()
    if offset is None or offset != timedelta(0):
        raise InvalidArgumentError("时间必须是 UTC")
    if at.tzinfo is not timezone.utc:
        at = at.replace(tzinfo=timezone.utc)
    return at


def to_micros(at: datetime) -> int:
    """UTC datetime -> 自 epoch 的微秒整数。"""
    delta = validate_utc(at) - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def from_micros(micros: int) -> datetime:
    """微秒整数 -> UTC datetime。"""
    return _EPOCH + timedelta(microseconds=micros)


def retention_line(at: datetime) -> datetime:
    """at 往前推 36 个自然月；目标月无该日则取该月最后一天，时分秒不变。"""
    at = validate_utc(at)
    total = at.year * 12 + (at.month - 1) - RETENTION_MONTHS
    year, month0 = divmod(total, 12)
    month = month0 + 1
    last_day = calendar.monthrange(year, month)[1]
    day = min(at.day, last_day)
    return at.replace(year=year, month=month, day=day)


def format_at(at: datetime) -> str:
    """格式化为 MM/DD/YYYY hh:mm:ss AM/PM（12 小时制，午夜 12 AM、正午 12 PM）。"""
    at = validate_utc(at)
    hour12 = at.hour % 12
    if hour12 == 0:
        hour12 = 12
    meridiem = "AM" if at.hour < 12 else "PM"
    return (
        f"{at.month:02d}/{at.day:02d}/{at.year:04d} "
        f"{hour12:02d}:{at.minute:02d}:{at.second:02d} {meridiem}"
    )
