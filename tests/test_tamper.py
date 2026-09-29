"""篡改矩阵：在已 prune 库的副本上用裸 SQL 逐一攻击，verify 必须全部失败。

威胁模型：攻击者没有密钥、没有旧副本，但能对库文件执行任意 SQL。
"""

import shutil
import sqlite3
from datetime import datetime, timezone

import pytest

from brandpulse import AuditStore

from .conftest import KEY

UTC = timezone.utc


def d(y, m, day, h=0, mi=0, s=0):
    return datetime(y, m, day, h, mi, s, tzinfo=UTC)


def _build_pruned(path):
    """四年多历史 + prune，覆盖：线前彻底删除字段、部分删除字段、线内字段。"""
    st = AuditStore(path, KEY)
    st.set_fields("ent", {
        "stage": "contacted",
        "tier": "gold",
        "payout": "1000",
        "budget": "5000",
    }, "alice", d(2022, 3, 1, 9, 30))
    st.set_fields("ent2", {"note": "old-note"}, "alice", d(2022, 3, 2, 9, 30))
    st.set_fields("ent", {"stage": "negotiating"}, "alice", d(2022, 9, 1, 9, 30))
    # ~40 个月前最后改 stage（相对 2026-09-30）
    st.set_fields("ent", {"stage": "ambassador"}, "bob", d(2023, 5, 20, 10, 15))
    st.set_fields("ent", {"tier": "platinum"}, "bob", d(2024, 2, 10, 14, 0))
    # ~20 个月前最后改 payout
    st.set_fields("ent", {"payout": "2500"}, "carol", d(2025, 1, 18, 11, 45))
    # 另一个实体：线前 + 线内都有改动（保持写时间单调，放在 budget 之前）
    st.set_fields("ent2", {"note": "fresh"}, "dave", d(2025, 3, 3))
    st.set_fields("ent", {"budget": "7500"}, "carol", d(2025, 11, 2, 8, 20))
    st.prune(d(2026, 9, 30, 12, 0, 0))
    assert st.verify().ok
    st.close()


@pytest.fixture()
def pruned_db(tmp_path):
    path = tmp_path / "pruned.db"
    _build_pruned(str(path))
    return path


def _raw(path):
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode=MEMORY")
    return conn


def _attack(tmp_path, pruned_db, name, attack):
    """复制一份干净库，施加一种攻击，返回 verify 报告。"""
    victim = tmp_path / name
    shutil.copyfile(pruned_db, victim)
    conn = _raw(victim)
    attack(conn)
    conn.commit()
    conn.close()
    st = AuditStore(str(victim), KEY, verify_on_open=False)
    report = st.verify()
    st.close()
    return report


def test_clean_db_passes(pruned_db):
    st = AuditStore(str(pruned_db), KEY, verify_on_open=False)
    assert st.verify().ok
    st.close()


# ---- 1. 改动保留条目内容 ---------------------------------------------------

def test_tamper_entry_new_value(tmp_path, pruned_db):
    def attack(c):
        c.execute("UPDATE entries SET new='hacked' WHERE new='platinum'")
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_tamper_entry_actor(tmp_path, pruned_db):
    def attack(c):
        c.execute("UPDATE entries SET actor='mallory' WHERE actor='carol'")
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_tamper_entry_time(tmp_path, pruned_db):
    def attack(c):
        c.execute("UPDATE entries SET at=at+1 WHERE new='2500'")
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_tamper_move_char_between_fields(tmp_path, pruned_db):
    # 把一个字段里的字符挪到相邻字段：tier 值改短，payout 改长
    def attack(c):
        c.execute("UPDATE entries SET new='platinu' WHERE new='platinum'")
        c.execute("UPDATE entries SET new='x2500' WHERE new='2500'")
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_tamper_entity_name(tmp_path, pruned_db):
    def attack(c):
        c.execute("UPDATE entries SET entity='entX' WHERE entity='ent2'")
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_tamper_field_name(tmp_path, pruned_db):
    def attack(c):
        c.execute("UPDATE entries SET field='payout2' WHERE new='2500'")
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_tamper_target_at_of_rollback(tmp_path, pruned_db):
    # 普通条目 target_at 是 NULL；把一个改成具体值
    def attack(c):
        c.execute("UPDATE entries SET target_at=1 WHERE new='7500'")
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


# ---- 2. 插入 / 调换 / 删除条目 ---------------------------------------------

def test_delete_latest_entries(tmp_path, pruned_db):
    def attack(c):
        c.execute("DELETE FROM entries WHERE seq=(SELECT MAX(seq) FROM entries)")
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_delete_retained_entry_middle(tmp_path, pruned_db):
    def attack(c):
        c.execute("DELETE FROM entries WHERE new='2500'")
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_swap_two_entries(tmp_path, pruned_db):
    # 调换两条普通条目的内容（连同 new/actor），seq 不变
    def attack(c):
        rows = c.execute(
            "SELECT seq, new, actor FROM entries WHERE new IN ('2500','7500') "
            "ORDER BY seq"
        ).fetchall()
        s1, n1, a1 = rows[0]
        s2, n2, a2 = rows[1]
        c.execute("UPDATE entries SET new=?, actor=? WHERE seq=?", (n2, a2, s1))
        c.execute("UPDATE entries SET new=?, actor=? WHERE seq=?", (n1, a1, s2))
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_insert_fake_entry_append(tmp_path, pruned_db):
    def attack(c):
        top = c.execute("SELECT MAX(seq) FROM entries").fetchone()[0]
        hmac = c.execute("SELECT hmac FROM entries WHERE seq=?", (top,)).fetchone()[0]
        c.execute(
            "INSERT INTO entries (seq, entity, field, actor, at, old, new, "
            "kind, target_at, prev_hmac, hmac) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (top + 1, "ent", "stage", "mallory", 1750000000000000,
             "ambassador", "fake", 0, None, hmac, hmac),
        )
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_insert_disguised_old_entry(tmp_path, pruned_db):
    # 伪装成已清理的最早条目：硬塞一个很小 seq 的假行
    def attack(c):
        anchor = c.execute("SELECT prev_hmac FROM entries ORDER BY seq LIMIT 1").fetchone()[0]
        c.execute(
            "INSERT INTO entries (seq, entity, field, actor, at, old, new, "
            "kind, target_at, prev_hmac, hmac) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (0, "ent", "stage", "mallory", 1, None, "ghost", 0, None,
             anchor, anchor),
        )
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_tamper_prune_marker(tmp_path, pruned_db):
    def attack(c):
        c.execute("UPDATE entries SET at=at+1 WHERE kind=2")
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


# ---- 3. 改动 prune 后推出历史取值的数据（baselines / meta cutoff） ---------

def test_tamper_baseline_value(tmp_path, pruned_db):
    def attack(c):
        c.execute("UPDATE baselines SET value='rewritten' WHERE field='stage'")
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_tamper_baseline_unset_to_value(tmp_path, pruned_db):
    # 找一个基线为 NULL 的字段（若有），否则把某基线置空攻击
    def attack(c):
        c.execute("UPDATE baselines SET value=NULL WHERE 1=1")
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_insert_baseline_row(tmp_path, pruned_db):
    def attack(c):
        c.execute(
            "INSERT OR REPLACE INTO baselines (entity, field, value, hmac) "
            "VALUES ('ent','stage','x', x'00')"
        )
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_delete_baseline_row(tmp_path, pruned_db):
    def attack(c):
        c.execute("DELETE FROM baselines WHERE field='stage'")
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_rewind_meta_cutoff(tmp_path, pruned_db):
    # 直接把 cutoff 改小（攻击者无法重算 meta hmac）
    def attack(c):
        c.execute("UPDATE meta SET cutoff_at=1")
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_tamper_anchor(tmp_path, pruned_db):
    def attack(c):
        c.execute("UPDATE meta SET anchor_hmac=x'00' WHERE id=1")
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


# ---- 4. 当前值与审计不一致 -------------------------------------------------

def test_current_value_mismatch_via_states(tmp_path, pruned_db):
    def attack(c):
        # 直接改 states 当前值（不同步审计）
        c.execute("UPDATE states SET value='9999' WHERE field='payout'")
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_states_insert_rogue_row(tmp_path, pruned_db):
    def attack(c):
        c.execute(
            "INSERT OR REPLACE INTO states (entity, field, value, ver, hmac) "
            "VALUES ('ent','injected','x', 1, x'00')"
        )
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_states_delete_row(tmp_path, pruned_db):
    def attack(c):
        c.execute("DELETE FROM states WHERE field='payout'")
    # 累加器变化或当前态缺失都应报错
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_states_acc_tampered(tmp_path, pruned_db):
    def attack(c):
        c.execute("UPDATE meta SET states_acc=x'00' WHERE id=1")
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_head_seq_rewind(tmp_path, pruned_db):
    def attack(c):
        c.execute("UPDATE meta SET head_seq=head_seq-1 WHERE id=1")
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


# ---- 额外的重放 / 跨字段拼接攻击 ------------------------------------------

def test_state_row_swapped_between_fields(tmp_path, pruned_db):
    # 把一个字段的整行（含其合法 hmac）复制到另一个字段名上：字段名进入 MAC，
    # 必须失败
    def attack(c):
        row = c.execute(
            "SELECT entity, field, value, ver, hmac FROM states "
            "WHERE field='payout'"
        ).fetchone()
        c.execute(
            "INSERT OR REPLACE INTO states (entity, field, value, ver, hmac) "
            "VALUES (?,?,?,?,?)",
            (row[0], "clone", row[2], row[3], row[4]),
        )
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_baseline_row_copied_to_other_field(tmp_path, pruned_db):
    def attack(c):
        row = c.execute(
            "SELECT entity, field, value, hmac FROM baselines WHERE field='stage'"
        ).fetchone()
        c.execute(
            "INSERT OR REPLACE INTO baselines (entity, field, value, hmac) "
            "VALUES (?,?,?,?)",
            (row[0], "clone", row[2], row[3]),
        )
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_forged_marker_anchor_rejected(tmp_path, pruned_db):
    # 篡改标记载荷里的锚点 hex（标记 hmac 应失败）
    def attack(c):
        c.execute("UPDATE entries SET new='00' WHERE kind=2")
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_baseline_replay_old_cutoff(tmp_path, pruned_db):
    # 第二次 prune 后若把某基线 hmac 改回旧值无法重算（无密钥）；
    # 这里仅验证：直接替换成另一字段的合法基线 hmac 也会失败
    def attack(c):
        h = c.execute("SELECT hmac FROM baselines WHERE field='tier'").fetchone()[0]
        c.execute("UPDATE baselines SET hmac=? WHERE field='stage'", (h,))
    assert not _attack(tmp_path, pruned_db, "a.db", attack).ok


def test_pruned_sensitive_columns_gone(tmp_path, pruned_db):
    """约束：prune 后线前条目的 actor/at/old 不得再能从任何表查到。"""
    conn = _raw(pruned_db)
    # 最早的 actor alice 的 stage 旧值 contacted（线前）不应残留在 entries
    leaked = conn.execute(
        "SELECT COUNT(*) FROM entries WHERE actor='alice'"
    ).fetchone()[0]
    assert leaked == 0
    vals = {r[0] for r in conn.execute("SELECT old FROM entries") if r[0]}
    assert "contacted" not in vals and "negotiating" not in vals
    conn.close()


def test_no_sensitive_data_in_file_bytes(pruned_db):
    """prune 后线前条目的 actor/旧值不得残留在 db 文件任何位置（含空闲页）。"""
    st = AuditStore(str(pruned_db), KEY, verify_on_open=False)
    st.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    st.close()
    raw = open(pruned_db, "rb").read()
    # 基线里允许保留“保留线处的取值”（如 gold/old-note 是恢复历史所必需），
    # 但仅作为 value 存在，且不得带 actor/at/old。这里断言线前特有的
    # 操作人和中间旧值消失。
    for secret in (b"contacted", b"negotiating"):
        assert secret not in raw, f"敏感旧值残留在库文件中: {secret}"
    for secret in (b"alice", b"mallory"):
        assert secret not in raw, f"操作人残留在库文件中: {secret}"


def test_stale_anchor_cannot_start_forged_segment(tmp_path, pruned_db):
    """跨代锚点重放：拿到库里某个合法锚点，在缺口处接一段伪造普通条目。"""
    victim = tmp_path / "replay.db"
    shutil.copyfile(pruned_db, victim)
    conn = _raw(victim)
    # 取一个合法锚点（标记载荷里有）和一个较大的 seq 制造缺口
    payload = conn.execute("SELECT new FROM entries WHERE kind=2 LIMIT 1").fetchone()[0]
    anchor = bytes.fromhex(payload.split("\n")[0])
    top = conn.execute("SELECT MAX(seq) FROM entries").fetchone()[0]
    conn.execute(
        "INSERT INTO entries (seq, entity, field, actor, at, old, new, "
        "kind, target_at, prev_hmac, hmac) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (top + 100, "ent", "stage", "mallory", 1740000000000000,
         "ambassador", "forged", 0, None, anchor, anchor),
    )
    conn.commit()
    conn.close()
    st = AuditStore(str(victim), KEY, verify_on_open=False)
    assert not st.verify().ok
    st.close()


def test_old_marker_moved_to_wrong_place(tmp_path, pruned_db):
    """把 prune 标记挪到错误 seq（调换/删除伪装），链校验必须失败。"""
    victim = tmp_path / "move.db"
    shutil.copyfile(pruned_db, victim)
    conn = _raw(victim)
    # 删掉标记再用它的 hmac 在更早 seq 重建（攻击者无法重算，但模拟“调换”）
    row = conn.execute(
        "SELECT seq, entity, field, actor, at, old, new, kind, target_at, "
        "prev_hmac, hmac FROM entries WHERE kind=2"
    ).fetchone()
    conn.execute("DELETE FROM entries WHERE kind=2")
    # 在被删标记原位置与下一个条目之间制造一个“伪装缺口”：把标记放到一个
    # 与其 prev 不相称的 seq 上
    gap_seq = row[0] + 50
    conn.execute(
        "INSERT INTO entries (seq, entity, field, actor, at, old, new, "
        "kind, target_at, prev_hmac, hmac) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (gap_seq, row[1], row[2], row[3], row[4], row[5], row[6],
         row[7], row[8], row[9], row[10]),
    )
    conn.commit()
    conn.close()
    st = AuditStore(str(victim), KEY, verify_on_open=False)
    assert not st.verify().ok
    st.close()
