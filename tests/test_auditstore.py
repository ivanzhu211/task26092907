import os
import shutil
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone

from auditstore import (
    AuditStore,
    BeforeRetentionError,
    WriteRejected,
    format_12h,
    retention_line,
)

KEY = b"brandpulse-test-key"


def T(y, m, d, hh=0, mi=0, ss=0):
    return datetime(y, m, d, hh, mi, ss, tzinfo=timezone.utc)


PRUNE_NOW = T(2026, 9, 30, 12)          # retention line: 2023-09-30 12:00:00
ROLLBACK_TARGET = T(2024, 3, 30, 12)    # 30 months before prune time

# One shared 4+ year operation script. "stage" is last changed ~40 months
# before PRUNE_NOW (before the retention line); "tier" ~20 months before.
SCRIPT = [
    ("set", "inf-1", {"stage": "lead", "tier": "bronze", "budget_cap": "1000"},
     "alice", T(2022, 6, 15, 10)),
    ("set", "inf-1", {"payout": "500"}, "mallory", T(2022, 8, 1, 8)),
    ("set", "inf-1", {"stage": "contacted"}, "bob", T(2023, 1, 10, 9)),
    ("set", "inf-1", {"stage": "negotiating"}, "alice", T(2023, 5, 15, 8, 30)),
    ("set", "inf-1", {"tier": "silver"}, "carol", T(2023, 11, 1, 12)),
    ("set", "inf-1", {"budget_cap": "2000"}, "bob", T(2024, 2, 29, 23, 59)),
    ("set", "inf-2", {"stage": "lead"}, "alice", T(2024, 5, 5, 5)),
    ("set", "inf-1", {"tier": "gold"}, "alice", T(2025, 1, 15, 14)),
    ("set", "inf-1", {"note": ""}, "bob", T(2025, 7, 4, 0, 0)),
    ("set", "inf-1", {"note": "hello"}, "carol", T(2026, 3, 31, 12)),
]

SAMPLE_TIMES = [
    T(2023, 9, 30, 12),   # exactly the retention line
    T(2023, 10, 1),
    T(2024, 1, 1),
    T(2024, 2, 29, 23, 59),
    T(2024, 3, 30, 12),
    T(2025, 1, 15, 14),
    T(2025, 6, 1),
    T(2026, 1, 1),
    T(2026, 9, 30, 12),
]

FIELDS = ["stage", "tier", "budget_cap", "note", "payout", "never_set"]


def run_script(store):
    for op in SCRIPT:
        _, entity, changes, actor, at = op
        store.set_fields(entity, changes, actor, at)


class PruneEquivalenceTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path_full = os.path.join(self.dir, "full.db")
        self.path_pruned = os.path.join(self.dir, "pruned.db")
        self.full = AuditStore(self.path_full, KEY)
        self.pruned = AuditStore(self.path_pruned, KEY)
        run_script(self.full)
        run_script(self.pruned)
        self.pruned.prune(PRUNE_NOW)

    def tearDown(self):
        self.full.close()
        self.pruned.close()
        shutil.rmtree(self.dir)

    def test_value_at_matches_after_prune(self):
        for t in SAMPLE_TIMES:
            for field in FIELDS:
                for entity in ("inf-1", "inf-2"):
                    self.assertEqual(
                        self.full.value_at(entity, field, t),
                        self.pruned.value_at(entity, field, t),
                        f"{entity}.{field} at {t}",
                    )

    def test_field_last_changed_before_line_survives(self):
        # stage last changed 2023-05-15, before the 2023-09-30 line.
        self.assertEqual(
            self.pruned.value_at("inf-1", "stage", T(2026, 9, 30, 12)),
            "negotiating",
        )
        # tier last changed 2025-01-15, after the line.
        self.assertEqual(
            self.pruned.value_at("inf-1", "tier", T(2026, 9, 30, 12)), "gold"
        )

    def test_rollback_matches_after_prune(self):
        at = T(2026, 9, 30, 13)
        fields = ["stage", "tier", "budget_cap", "note"]
        self.full.rollback("inf-1", fields, ROLLBACK_TARGET, "dave", at)
        self.pruned.rollback("inf-1", fields, ROLLBACK_TARGET, "dave", at)
        for t in SAMPLE_TIMES + [T(2026, 9, 30, 14)]:
            if t < at:
                continue
            for field in FIELDS:
                self.assertEqual(
                    self.full.value_at("inf-1", field, t),
                    self.pruned.value_at("inf-1", field, t),
                    f"post-rollback {field} at {t}",
                )
        self.assertEqual(self.full.value_at("inf-1", "stage", at), "negotiating")
        self.assertEqual(self.full.value_at("inf-1", "tier", at), "silver")
        self.assertEqual(self.full.value_at("inf-1", "budget_cap", at), "2000")
        self.assertIsNone(self.full.value_at("inf-1", "note", at))
        self.assertEqual(self.full.verify(), (True, "OK"))
        self.assertEqual(self.pruned.verify(), (True, "OK"))

    def test_value_at_before_line_rejected(self):
        with self.assertRaises(BeforeRetentionError):
            self.pruned.value_at("inf-1", "stage", T(2023, 9, 30, 11, 59, 59))
        # the full store has no such restriction
        self.assertEqual(
            self.full.value_at("inf-1", "stage", T(2023, 9, 30, 11, 59, 59)),
            "negotiating",
        )

    def test_prune_erases_pruned_details(self):
        # strings that appear ONLY in pruned entries (actor/time/old_value)
        erased = ("mallory", "contacted", "2022-06-15", "2022-08-01",
                  "2023-01-10", "2023-05-15")
        conn = sqlite3.connect(self.path_pruned)
        try:
            for table in ("entries", "baseline", "current_values", "meta"):
                cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
                for col in cols:
                    rows = conn.execute(
                        f"SELECT {col} FROM {table} WHERE {col} IS NOT NULL"
                    )
                    for (value,) in rows:
                        if not isinstance(value, str):
                            continue
                        for gone in erased:
                            self.assertNotIn(
                                gone, value, f"{gone!r} leaked in {table}.{col}"
                            )
        finally:
            conn.close()

    def test_prune_does_not_rewrite_retained_macs(self):
        before = self.full._conn.execute(
            "SELECT seq, mac FROM entries ORDER BY seq"
        ).fetchall()
        self.full.prune(PRUNE_NOW)
        after = dict(
            self.full._conn.execute("SELECT seq, mac FROM entries").fetchall()
        )
        for seq, mac in before:
            if seq in after:
                self.assertEqual(mac, after[seq], f"entry {seq} mac rewritten")


class TamperTest(unittest.TestCase):
    """Each raw-SQL attack on a copy of the pruned DB must fail verify()."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        cls.master = os.path.join(cls.dir, "master.db")
        store = AuditStore(cls.master, KEY)
        run_script(store)
        store.prune(PRUNE_NOW)
        store.set_fields("inf-1", {"stage": "ambassador"}, "erin",
                         T(2026, 9, 30, 13))
        assert store.verify() == (True, "OK")
        store.close()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir)

    def check_tamper(self, label, sql, params=()):
        path = os.path.join(self.dir, "tampered.db")
        shutil.copy(self.master, path)
        conn = sqlite3.connect(path)
        try:
            statements = [sql] if isinstance(sql, str) else sql
            for statement in statements:
                conn.execute(statement, params)
            conn.commit()
        finally:
            conn.close()
        store = AuditStore(path, KEY)
        try:
            ok, msg = store.verify()
            self.assertFalse(ok, f"{label}: verify unexpectedly passed")
        finally:
            store.close()

    def test_untouched_copy_passes(self):
        path = os.path.join(self.dir, "clean.db")
        shutil.copy(self.master, path)
        store = AuditStore(path, KEY)
        try:
            self.assertEqual(store.verify(), (True, "OK"))
        finally:
            store.close()

    def test_modify_entry_value(self):
        self.check_tamper(
            "modify new_value",
            "UPDATE entries SET new_value='platinum' WHERE seq=("
            " SELECT min(seq) FROM entries WHERE kind='set')",
        )

    def test_move_char_between_fields(self):
        # move one character from old_value into actor of the same row
        self.check_tamper(
            "move char across columns",
            "UPDATE entries SET"
            " actor=actor||substr(old_value,length(old_value),1),"
            " old_value=substr(old_value,1,length(old_value)-1)"
            " WHERE seq=(SELECT min(seq) FROM entries"
            " WHERE kind='set' AND old_value IS NOT NULL)",
        )

    def test_modify_entry_time(self):
        self.check_tamper(
            "modify time",
            "UPDATE entries SET at='2025-01-15T14:00:01'"
            " WHERE at='2025-01-15T14:00:00'",
        )

    def test_insert_entry(self):
        self.check_tamper(
            "insert forged entry",
            "INSERT INTO entries (seq, kind, entity, field, actor, at,"
            " old_value, new_value, rollback_target, baseline_hash, mac)"
            " SELECT 999999, 'set', entity, field, actor, at, old_value,"
            " new_value, rollback_target, baseline_hash, mac"
            " FROM entries WHERE seq=(SELECT max(seq) FROM entries)",
        )

    def test_reorder_entries(self):
        self.check_tamper(
            "swap two entries",
            [
                "UPDATE entries SET seq=-1 WHERE seq=("
                " SELECT min(seq) FROM entries)",
                "UPDATE entries SET seq=(SELECT min(seq) FROM entries) WHERE seq=("
                " SELECT min(seq) FROM entries)+1",
                "UPDATE entries SET seq=(SELECT min(seq) FROM entries)+1"
                " WHERE seq=-1",
            ],
        )

    def test_delete_latest_entry(self):
        self.check_tamper(
            "delete newest entry",
            "DELETE FROM entries WHERE seq=(SELECT max(seq) FROM entries)",
        )

    def test_delete_earliest_retained_entry(self):
        # disguised as if prune had removed it
        self.check_tamper(
            "delete oldest retained entry",
            "DELETE FROM entries WHERE seq=(SELECT min(seq) FROM entries)",
        )

    def test_delete_middle_entry(self):
        self.check_tamper(
            "delete middle entry",
            "DELETE FROM entries WHERE seq=("
            " SELECT (min(seq)+max(seq))/2 FROM entries)",
        )

    def test_modify_baseline(self):
        self.check_tamper(
            "modify baseline value",
            "UPDATE baseline SET value='forged' WHERE entity='inf-1'"
            " AND field='stage'",
        )

    def test_delete_baseline_row(self):
        self.check_tamper(
            "delete baseline row",
            "DELETE FROM baseline WHERE entity='inf-1' AND field='stage'",
        )

    def test_insert_baseline_row(self):
        self.check_tamper(
            "insert baseline row",
            "INSERT INTO baseline (entity, field, value)"
            " VALUES ('inf-9', 'stage', 'lead')",
        )

    def test_modify_current_value(self):
        # makes current value disagree with the audit chain
        self.check_tamper(
            "modify current value",
            "UPDATE current_values SET value='platinum'"
            " WHERE entity='inf-1' AND field='tier'",
        )

    def test_delete_current_row(self):
        self.check_tamper(
            "delete current row",
            "DELETE FROM current_values WHERE entity='inf-1' AND field='tier'",
        )

    def test_insert_current_row(self):
        self.check_tamper(
            "insert current row",
            "INSERT INTO current_values (entity, field, value)"
            " VALUES ('inf-1', 'smuggled', 'x')",
        )

    def test_delete_checkpoint(self):
        self.check_tamper(
            "delete checkpoint entry",
            "DELETE FROM entries WHERE kind='checkpoint'",
        )

    def test_modify_meta(self):
        self.check_tamper(
            "modify meta head",
            "UPDATE meta SET head_seq=head_seq-1",
        )


class BoundaryTest(unittest.TestCase):
    def test_retention_line_month_end_and_leap(self):
        cases = [
            (T(2026, 3, 31, 14, 5, 9), T(2023, 3, 31, 14, 5, 9)),
            (T(2026, 3, 1, 0, 0, 0), T(2023, 3, 1, 0, 0, 0)),
            (T(2024, 2, 29, 8, 0, 0), T(2021, 2, 28, 8, 0, 0)),  # leap -> clamp
            (T(2028, 2, 29, 23, 59, 59), T(2025, 2, 28, 23, 59, 59)),
            (T(2026, 12, 31, 12), T(2023, 12, 31, 12)),
            (T(2026, 1, 1, 0, 0, 1), T(2023, 1, 1, 0, 0, 1)),
        ]
        for now, expected in cases:
            self.assertEqual(retention_line(now), expected, f"line of {now}")

    def test_prune_cutoff_at_leap_clamped_line(self):
        # prune at 2028-02-29 15:04:05 -> line 2025-02-28 15:04:05
        path = tempfile.mktemp(suffix=".db")
        store = AuditStore(path, KEY)
        try:
            store.set_fields("e", {"f": "too_old"}, "a", T(2025, 2, 28, 15, 4, 4))
            store.set_fields("e", {"g": "kept"}, "a", T(2025, 2, 28, 15, 4, 5))
            store.prune(T(2028, 2, 29, 15, 4, 5))
            kept = [e.field for e in store.history("e")]
            self.assertEqual(kept, ["g"])
            self.assertEqual(store.value_at("e", "f", T(2028, 2, 29, 15, 4, 5)),
                             "too_old")  # via baseline
            self.assertEqual(store.verify(), (True, "OK"))
        finally:
            store.close()
            os.unlink(path)

    def test_12h_display_midnight_and_noon(self):
        self.assertEqual(format_12h(T(2026, 3, 7, 0, 0, 0)),
                         "03/07/2026 12:00:00 AM")
        self.assertEqual(format_12h(T(2026, 3, 7, 12, 0, 0)),
                         "03/07/2026 12:00:00 PM")
        self.assertEqual(format_12h(T(2026, 3, 7, 14, 5, 9)),
                         "03/07/2026 02:05:09 PM")
        self.assertEqual(format_12h(T(2026, 3, 7, 1, 2, 3)),
                         "03/07/2026 01:02:03 AM")

    def test_history_uses_12h_display(self):
        path = tempfile.mktemp(suffix=".db")
        store = AuditStore(path, KEY)
        try:
            store.set_fields("e", {"f": "v"}, "a", T(2026, 3, 7, 14, 5, 9))
            store.set_fields("e", {"f": "w"}, "a", T(2026, 3, 8, 0, 0, 0))
            entries = store.history("e")
            self.assertEqual(entries[0].at, "03/07/2026 02:05:09 PM")
            self.assertEqual(entries[1].at, "03/08/2026 12:00:00 AM")
        finally:
            store.close()
            os.unlink(path)


class SemanticsTest(unittest.TestCase):
    def setUp(self):
        self.path = tempfile.mktemp(suffix=".db")
        self.store = AuditStore(self.path, KEY)

    def tearDown(self):
        self.store.close()
        os.unlink(self.path)

    def test_write_time_must_not_go_backwards(self):
        self.store.set_fields("e", {"f": "v"}, "a", T(2026, 5, 1, 12))
        with self.assertRaises(WriteRejected):
            self.store.set_fields("e", {"f": "x"}, "a", T(2026, 5, 1, 11, 59, 59))
        with self.assertRaises(WriteRejected):
            self.store.rollback("e", ["f"], T(2026, 5, 1), "a",
                                T(2026, 5, 1, 11))
        with self.assertRaises(WriteRejected):
            self.store.prune(T(2026, 5, 1, 10))
        # equal time is allowed
        self.store.set_fields("e", {"g": "y"}, "a", T(2026, 5, 1, 12))
        self.assertEqual(self.store.verify(), (True, "OK"))

    def test_same_instant_last_write_wins(self):
        self.store.set_fields("e", {"f": "first"}, "a", T(2026, 5, 1, 12))
        self.store.set_fields("e", {"f": "second"}, "b", T(2026, 5, 1, 12))
        self.assertEqual(self.store.value_at("e", "f", T(2026, 5, 1, 12)),
                         "second")

    def test_unset_vs_empty_string(self):
        self.store.set_fields("e", {"empty": "", "gone": "x"}, "a",
                              T(2026, 1, 1))
        self.store.set_fields("e", {"gone": None}, "a", T(2026, 1, 2))
        self.assertEqual(self.store.value_at("e", "empty", T(2026, 1, 3)), "")
        self.assertIsNone(self.store.value_at("e", "gone", T(2026, 1, 3)))
        self.assertIsNone(self.store.value_at("e", "never", T(2026, 1, 3)))
        history = self.store.history("e")
        self.assertEqual(history[2].old_value, "x")
        self.assertIsNone(history[2].new_value)

    def test_no_actual_change_records_nothing(self):
        self.store.set_fields("e", {"f": "v"}, "a", T(2026, 1, 1))
        self.store.set_fields("e", {"f": "v", "g": None}, "a", T(2026, 1, 2))
        self.assertEqual(len(self.store.history("e")), 1)

    def test_rollback_target_before_retention_line_rejected(self):
        self.store.set_fields("e", {"f": "v"}, "a", T(2023, 1, 1))
        with self.assertRaises(BeforeRetentionError):
            # line of 2026-06-15 is 2023-06-15; target 2023-06-14 is too early
            self.store.rollback("e", ["f"], T(2023, 6, 14), "a", T(2026, 6, 15))
        # exactly on the line is allowed
        self.store.rollback("e", ["f"], T(2023, 6, 15), "a", T(2026, 6, 15))
        self.assertEqual(self.store.verify(), (True, "OK"))

    def test_rollback_to_unset(self):
        self.store.set_fields("e", {"f": "v"}, "a", T(2026, 1, 1))
        self.store.rollback("e", ["f"], T(2025, 12, 31, 23, 59, 59), "a",
                            T(2026, 1, 2))
        self.assertIsNone(self.store.value_at("e", "f", T(2026, 1, 3)))
        entry = self.store.history("e")[-1]
        self.assertEqual(entry.kind, "rollback")
        self.assertIsNone(entry.new_value)
        self.assertEqual(entry.rollback_target, "12/31/2025 11:59:59 PM")

    def test_unicode_and_isolation_between_entities(self):
        self.store.set_fields("实体α", {"阶段🙂": "大使级"}, "运营甲",
                              T(2026, 1, 1))
        self.store.set_fields("实体β", {"阶段🙂": "观察"}, "运营乙",
                              T(2026, 1, 2))
        self.assertEqual(self.store.value_at("实体α", "阶段🙂", T(2026, 1, 3)),
                         "大使级")
        self.assertEqual(self.store.value_at("实体β", "阶段🙂", T(2026, 1, 3)),
                         "观察")
        self.assertEqual(len(self.store.history("实体α")), 1)
        self.assertEqual(self.store.verify(), (True, "OK"))

    def test_wrong_key_fails_verify(self):
        self.store.set_fields("e", {"f": "v"}, "a", T(2026, 1, 1))
        self.store.close()
        store = AuditStore(self.path, b"other-key")
        try:
            ok, _ = store.verify()
            self.assertFalse(ok)
        finally:
            store.close()
        self.store = AuditStore(self.path, KEY)  # reopened for tearDown


if __name__ == "__main__":
    unittest.main()
if __name__ == "__main__":
    unittest.main()


if __name__ == "__main__":
    unittest.main()
