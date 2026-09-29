"""功能测试：未设置/空串、同时刻最后一次、时钟、保留线报错、history 显示。"""

from datetime import datetime, timedelta, timezone

import pytest

from brandpulse import AuditStore
from brandpulse.errors import (
    ClockRejectedError,
    OutsideRetentionError,
)

from .conftest import KEY

UTC = timezone.utc


def d(y, mo, day, h=0, mi=0, s=0):
    return datetime(y, mo, day, h, mi, s, tzinfo=UTC)


def test_unset_differs_from_empty(db_path):
    st = AuditStore(db_path, KEY)
    t = d(2026, 1, 1, 12)
    assert st.set_fields("e", {"a": ""}, "u", t) == 1
    assert st.value_at("e", "a", t) == ""
    assert st.value_at("e", "b", t) is None
    # 改成未设置：产生一条审计
    t2 = d(2026, 1, 2, 12)
    assert st.set_fields("e", {"a": None}, "u", t2) == 1
    assert st.value_at("e", "a", t2) is None
    # 再设回空串也是实际变化
    t3 = d(2026, 1, 3, 12)
    assert st.set_fields("e", {"a": ""}, "u", t3) == 1
    assert st.value_at("e", "a", t3) == ""
    assert st.verify().ok


def test_same_instant_last_write_wins(db_path):
    st = AuditStore(db_path, KEY)
    t = d(2026, 1, 1, 12)
    assert st.set_fields("e", {"f": "v1"}, "u", t) == 1
    assert st.set_fields("e", {"f": "v2"}, "u", t) == 1
    assert st.set_fields("e", {"f": "v2"}, "u", t) == 0  # 无变化
    assert st.value_at("e", "f", t) == "v2"
    assert st.value_at("e", "f", d(2026, 1, 1, 11, 59, 59)) is None
    assert st.verify().ok


def test_clock_regression_rejected_equal_allowed(db_path):
    st = AuditStore(db_path, KEY)
    t = d(2026, 1, 1, 12)
    st.set_fields("e", {"f": "1"}, "u", t)
    st.set_fields("e", {"f": "2"}, "u", t)  # 相等允许
    with pytest.raises(ClockRejectedError):
        st.set_fields("e", {"f": "3"}, "u", d(2026, 1, 1, 11, 59, 59))
    now = d(2026, 5, 1)
    st.prune(now)
    with pytest.raises(ClockRejectedError):
        st.prune(d(2026, 4, 30))


def test_value_at_before_prune_line_errors(db_path):
    st = AuditStore(db_path, KEY)
    # 最后改动在保留线之前：checkpoint 必须支撑线上时刻查询
    st.set_fields("e", {"f": "v"}, "u", d(2022, 6, 1, 9, 0, 0))
    st.prune(d(2026, 9, 30, 23, 59, 59))
    # 保留线 = 2023-09-30 23:59:59
    with pytest.raises(OutsideRetentionError):
        st.value_at("e", "f", d(2023, 9, 30, 23, 59, 58))
    # 恰好保留线可以，且取到 prune 前的 checkpoint 值
    assert st.value_at("e", "f", d(2023, 9, 30, 23, 59, 59)) == "v"
    assert st.value_at("e", "f", d(2030, 1, 1)) == "v"


def test_rollback_target_before_line_rejected(db_path):
    st = AuditStore(db_path, KEY)
    st.set_fields("e", {"f": "v"}, "u", d(2020, 1, 1))
    st.set_fields("e", {"f": "w"}, "u", d(2026, 1, 1))
    at = d(2026, 9, 30, 12)  # 保留线 = 2023-09-30 12:00:00
    with pytest.raises(OutsideRetentionError):
        st.rollback("e", ["f"], d(2023, 9, 30, 11, 59, 59), "u", at)
    assert st.rollback("e", ["f"], d(2023, 9, 30, 12, 0, 0), "u", at) == 1
    assert st.value_at("e", "f", at) == "v"


def test_history_order_and_display(db_path):
    st = AuditStore(db_path, KEY)
    st.set_fields("e", {"f": "a"}, "alice", d(2026, 7, 3, 14, 5, 9))
    st.set_fields("e", {"f": "b"}, "bob", d(2026, 7, 4, 0, 0, 0))
    st.set_fields("e", {"g": "x"}, "bob", d(2026, 7, 4, 12, 0, 0))
    h = st.history("e")
    assert [x.field for x in h] == ["f", "f", "g"]
    assert h[0].at_text == "07/03/2026 02:05:09 PM"
    assert h[1].at_text == "07/04/2026 12:00:00 AM"
    assert h[2].at_text == "07/04/2026 12:00:00 PM"
    assert h[0].old is None and h[0].new == "a"


def _build_four_year_history(path):
    """同一串跨越四年多的操作。字段：
    late: 最后改动 ~40 个月前；recent: ~20 个月前；
    reset: 线前改动、线内被置空；empty: 线前空串、线内未设置。"""
    st = AuditStore(path, KEY)
    # 一个只在更早时改动、线后彻底消失的字段（放在最前以保持时间单调）
    st.set_fields("ghost", {"g": "gone"}, "alice", d(2021, 1, 1))
    st.set_fields("ghost", {"g": "still-gone"}, "alice", d(2022, 2, 2))
    base = d(2022, 5, 1, 12, 0, 0)
    st.set_fields("ent", {
        "late": "late-1",
        "recent": "recent-1",
        "reset": "r1",
        "empty": "",
    }, "alice", base)
    st.set_fields("ent", {"late": "late-2"}, "alice", d(2022, 11, 1, 12))
    # ~40 个月前（相对 2026-09-30）最后一次改 late
    st.set_fields("ent", {"late": "late-final"}, "bob", d(2023, 5, 15, 8, 30))
    st.set_fields("ent", {"recent": "recent-2"}, "bob", d(2023, 8, 1, 12))
    # 线前 reset 有值；线内置空串，再改未设置
    st.set_fields("ent", {"reset": ""}, "carol", d(2024, 3, 1, 9, 15))
    # empty：线前为空串，线内改为非空
    st.set_fields("ent", {"empty": "now-has"}, "dave", d(2024, 6, 1))
    st.set_fields("ent", {"reset": None}, "carol", d(2024, 9, 1, 9, 15))
    # ~20 个月前最后改 recent
    st.set_fields("ent", {"recent": "recent-final"}, "carol", d(2025, 1, 20, 18, 45))
    st.set_fields("ent", {"empty": None}, "dave", d(2025, 6, 1))
    return st


NOW = d(2026, 9, 30, 12, 0, 0)
COMPARE_TIMES = [
    d(2023, 9, 30, 12, 0, 0),   # 恰好保留线
    d(2023, 10, 1),
    d(2024, 1, 1, 0, 0, 0),     # 午夜
    d(2024, 3, 1, 9, 15),
    d(2024, 9, 1, 9, 14, 59),
    d(2024, 9, 1, 9, 15),
    d(2025, 1, 20, 18, 45),
    d(2025, 6, 1),
    d(2026, 9, 30, 12, 0, 0),
]


def test_pruned_matches_unpruned_across_retention_line(tmp_path):
    p_full = str(tmp_path / "full.db")
    p_pruned = str(tmp_path / "pruned.db")
    _build_four_year_history(p_full).close()
    st_p = _build_four_year_history(p_pruned)
    deleted = st_p.prune(NOW)
    assert deleted > 0
    st_p.close()

    st_f = AuditStore(p_full, KEY)
    st_p = AuditStore(p_pruned, KEY)
    assert st_p.verify().ok
    for t in COMPARE_TIMES:
        for field in ("late", "recent", "reset", "empty"):
            assert st_p.value_at("ent", field, t) == st_f.value_at("ent", field, t), (t, field)
    # 最后改动在线前的字段也必须一致
    assert st_p.value_at("ghost", "g", NOW) == "still-gone"
    assert st_p.value_at("ghost", "g", NOW) == st_f.value_at("ghost", "g", NOW)
    st_f.close()
    st_p.close()


def test_rollback_30_months_matches_between_stores(tmp_path):
    p_full = str(tmp_path / "full.db")
    p_pruned = str(tmp_path / "pruned.db")
    _build_four_year_history(p_full).close()
    st_p = _build_four_year_history(p_pruned)
    st_p.prune(NOW)
    st_p.close()

    target = d(2024, 3, 30, 12)  # 30 个月前
    at = d(2026, 10, 1, 10)
    fields = ["late", "recent", "reset", "empty"]

    st_f = AuditStore(p_full, KEY)
    st_p = AuditStore(p_pruned, KEY)
    st_f.rollback("ent", fields, target, "auditor", at)
    st_p.rollback("ent", fields, target, "auditor", at)
    for field in fields:
        assert st_p.value_at("ent", field, at) == st_f.value_at("ent", field, at)
        assert st_p.value_at("ent", field, d(2026, 10, 2)) == \
               st_f.value_at("ent", field, d(2026, 10, 2))
    assert st_p.verify().ok and st_f.verify().ok
    # 回滚审计标注目标时刻
    last = st_p.history("ent")[-1]
    assert last.is_rollback and last.target_at == target

    # prune 后：旧条目的 actor/at/old 不得在任何表中出现
    rows = st_p.conn.execute("SELECT actor, at, old FROM entries").fetchall()
    assert "late-2" not in {r[2] for r in rows}
    assert all(r[0] != "bob" or r[2] != "late-1" for r in rows)


def test_repeated_prune_baseline_replay_bound(db_path):
    st = AuditStore(db_path, KEY)
    st.set_fields("e", {"f": "old"}, "u", d(2020, 1, 1))
    st.set_fields("e", {"f": "mid"}, "u", d(2022, 1, 1))
    st.set_fields("e", {"f": "new"}, "u", d(2025, 1, 1))
    st.prune(d(2025, 6, 1))          # cutoff 2022-06-01
    st.prune(d(2026, 9, 30, 12))     # cutoff 2023-09-30 12
    r = st.verify()
    assert r.ok, r
    # 基线必须反映 2023-09-30 时刻的取值（mid），而非 new 或 old
    assert st.value_at("e", "f", d(2023, 9, 30, 12)) == "mid"
    assert st.value_at("e", "f", d(2024, 12, 31)) == "mid"
    assert st.value_at("e", "f", d(2026, 9, 30, 12)) == "new"


def test_rollback_audit_records_old_new_and_unset(db_path):
    st = AuditStore(db_path, KEY)
    t0 = d(2026, 1, 1, 12)
    st.set_fields("e", {"f": "v0", "g": "g0"}, "u", t0)
    t1 = d(2026, 2, 1, 12)
    st.set_fields("e", {"f": "v1"}, "u", t1)
    at = d(2026, 3, 1, 12)
    # f 回滚到 t0 的 v0；g 在 t0 之后无变化（回滚无操作）
    assert st.rollback("e", ["f", "g"], t0, "auditor", at) == 1
    # 把 f 回滚到 t0 之前 => 未设置
    assert st.rollback("e", ["f"], d(2025, 12, 31), "auditor",
                       d(2026, 3, 2, 12)) == 1
    assert st.value_at("e", "f", d(2026, 3, 2, 13)) is None
    h = st.history("e")
    rb = [x for x in h if x.is_rollback]
    assert rb[0].old == "v1" and rb[0].new == "v0"
    assert rb[0].actor == "auditor" and rb[0].target_at == t0
    assert rb[1].old == "v0" and rb[1].new is None
    assert st.verify().ok


def test_rollback_empty_value_preserved(db_path):
    st = AuditStore(db_path, KEY)
    st.set_fields("e", {"f": ""}, "u", d(2026, 1, 1))
    st.set_fields("e", {"f": "x"}, "u", d(2026, 2, 1))
    st.rollback("e", ["f"], d(2026, 1, 1), "a", d(2026, 3, 1))
    assert st.value_at("e", "f", d(2026, 3, 1)) == ""
    assert st.verify().ok


def test_prune_boundary_leap_day_and_midnight_noon_display(tmp_path):
    """保留线落在 2/28（闰日回推）与午夜/正午 12 小时制显示的端到端覆盖。"""
    p = str(tmp_path / "leap.db")
    st = AuditStore(p, KEY)
    # 最后改动恰好落在保留线时刻：2021-02-28 12:00:00（由 2024-02-29 回推）
    boundary = d(2021, 2, 28, 12, 0, 0)
    st.set_fields("e", {"f": "on-line"}, "alice", boundary)
    st.set_fields("e", {"f": "after"}, "bob", d(2021, 3, 1, 0, 0, 0))
    st.prune(d(2024, 2, 29, 12, 0, 0))
    # 线上（相等保留）取值可查
    assert st.value_at("e", "f", boundary) == "on-line"
    # history 时间显示：午夜 12 AM / 正午 12 PM
    h = st.history("e")
    texts = [x.at_text for x in h]
    assert "02/28/2021 12:00:00 PM" in texts
    assert "03/01/2021 12:00:00 AM" in texts
    assert st.verify().ok
    st.close()
