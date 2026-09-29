"""保留线与时间显示的边界测试。"""

from datetime import datetime, timezone

import pytest

from brandpulse.errors import InvalidArgumentError
from brandpulse.timeutil import format_at, retention_line

UTC = timezone.utc


def dt(y, m, d, hh=0, mm=0, ss=0, us=0):
    return datetime(y, m, d, hh, mm, ss, us, tzinfo=UTC)


def test_retention_plain():
    assert retention_line(dt(2026, 7, 3, 14, 5, 9)) == dt(2023, 7, 3, 14, 5, 9)


def test_retention_day31_kept():
    # 减 36 个自然月月份不变，31 日仍存在
    assert retention_line(dt(2024, 5, 31, 8, 0, 0)) == dt(2021, 5, 31, 8, 0, 0)
    assert retention_line(dt(2024, 12, 31, 8, 0, 0)) == dt(2021, 12, 31, 8, 0, 0)


def test_retention_leap_day_target_leap_year():
    assert retention_line(dt(2024, 2, 29, 12, 0, 0)) == dt(2021, 2, 28, 12, 0, 0)
    assert retention_line(dt(2028, 2, 29, 12, 0, 0)) == dt(2025, 2, 28, 12, 0, 0)


def test_retention_leap_day_four_years_keeps_29():
    assert retention_line(dt(2024, 2, 29, 0, 0, 0)) == dt(2021, 2, 28, 0, 0, 0)
    assert retention_line(dt(2024, 3, 1)) == dt(2021, 3, 1)


def test_retention_month_end_november():
    assert retention_line(dt(2023, 11, 30, 23, 59, 59)) == dt(2020, 11, 30, 23, 59, 59)


def test_retention_year_rollover():
    assert retention_line(dt(2023, 1, 15)) == dt(2020, 1, 15)


def test_retention_keeps_time():
    line = retention_line(dt(2026, 3, 31, 7, 8, 9, 654321))
    assert line == dt(2023, 3, 31, 7, 8, 9, 654321)


def test_format_midnight_and_noon():
    assert format_at(dt(2026, 7, 3, 0, 5, 9)) == "07/03/2026 12:05:09 AM"
    assert format_at(dt(2026, 7, 3, 12, 5, 9)) == "07/03/2026 12:05:09 PM"
    assert format_at(dt(2026, 7, 3, 23, 59, 59)) == "07/03/2026 11:59:59 PM"
    assert format_at(dt(2026, 7, 3, 11, 59, 59)) == "07/03/2026 11:59:59 AM"
    assert format_at(dt(2026, 3, 7, 14, 5, 9)) == "03/07/2026 02:05:09 PM"


def test_naive_rejected():
    with pytest.raises(InvalidArgumentError):
        retention_line(datetime(2026, 1, 1))


def test_retention_feb29_to_feb28_full_cycle():
    # 2024-02-29 12:00 -> 2021-02-28 12:00
    line = retention_line(dt(2024, 2, 29, 12, 0, 0))
    assert line == dt(2021, 2, 28, 12, 0, 0)
    # 2028 闰日回推 36 个月（2025 非闰）
    assert retention_line(dt(2028, 2, 29)) == dt(2025, 2, 28)
    # 从平年 2/28 回推仍是 2/28
    assert retention_line(dt(2025, 2, 28, 23, 59, 59)) == dt(2022, 2, 28, 23, 59, 59)
