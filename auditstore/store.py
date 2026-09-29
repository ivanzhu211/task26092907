"""SQLite-backed tamper-evident audit store."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from .crypto import canon_field, canon_int, hmac_chain, xor_bytes
from .timeutil import canonical, format_12h, parse, retention_line, to_utc

_ZERO = b"\x00" * 32

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  last_write TEXT,
  head_seq INTEGER NOT NULL,
  head_mac BLOB NOT NULL,
  prune_line TEXT,
  anchor_seq INTEGER NOT NULL,
  anchor_mac BLOB NOT NULL,
  current_xor BLOB NOT NULL,
  state_mac BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
  seq INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,
  entity TEXT,
  field TEXT,
  actor TEXT,
  at TEXT NOT NULL,
  old_value TEXT,
  new_value TEXT,
  rollback_target TEXT,
  baseline_hash BLOB,
  mac BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entries_ef ON entries(entity, field, at, seq);
CREATE TABLE IF NOT EXISTS baseline (
  entity TEXT NOT NULL,
  field TEXT NOT NULL,
  value TEXT,
  PRIMARY KEY (entity, field)
);
CREATE TABLE IF NOT EXISTS current_values (
  entity TEXT NOT NULL,
  field TEXT NOT NULL,
  value TEXT NOT NULL,
  PRIMARY KEY (entity, field)
);
"""


def _canon_blob(value: bytes | None) -> bytes:
    if value is None:
        return b"\xff"
    return b"\x01" + str(len(value)).encode("ascii") + b":" + value


class WriteRejected(Exception):
    """A write op carried a timestamp earlier than a previous write op."""


class BeforeRetentionError(Exception):
    """A read/rollback target predates the retention line."""


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    entity: str
    field: str
    actor: str
    at: str  # formatted 12-hour UTC display
    old_value: str | None
    new_value: str | None
    kind: str  # "set" | "rollback"
    rollback_target: str | None  # formatted 12-hour display when kind == "rollback"


class AuditStore:
    def __init__(self, path: str, key: bytes) -> None:
        if not key:
            raise ValueError("key must be non-empty")
        self._key = bytes(key)
        self._conn = sqlite3.connect(path)
        self._conn.executescript(_SCHEMA)
        row = self._conn.execute("SELECT COUNT(*) FROM meta").fetchone()
        if row[0] == 0:
            genesis = hmac_chain(self._key, b"genesis")
            self._conn.execute(
                "INSERT INTO meta (id, last_write, head_seq, head_mac, prune_line,"
                " anchor_seq, anchor_mac, current_xor, state_mac)"
                " VALUES (1, NULL, 0, ?, NULL, 0, ?, ?, ?)",
                (genesis, genesis, _ZERO, self._state_mac(
                    None, 0, genesis, None, 0, genesis, _ZERO)),
            )
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "AuditStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---- internal helpers ----

    def _state_mac(
        self,
        last_write: str | None,
        head_seq: int,
        head_mac: bytes,
        prune_line: str | None,
        anchor_seq: int,
        anchor_mac: bytes,
        current_xor: bytes,
    ) -> bytes:
        return hmac_chain(
            self._key,
            b"state",
            canon_field(last_write),
            canon_int(head_seq),
            _canon_blob(head_mac),
            canon_field(prune_line),
            canon_int(anchor_seq),
            _canon_blob(anchor_mac),
            _canon_blob(current_xor),
        )

    def _entry_mac(
        self,
        prev_mac: bytes,
        seq: int,
        kind: str,
        entity: str | None,
        field: str | None,
        actor: str | None,
        at: str,
        old_value: str | None,
        new_value: str | None,
        rollback_target: str | None,
        baseline_hash: bytes | None,
    ) -> bytes:
        return hmac_chain(
            self._key,
            b"entry",
            _canon_blob(prev_mac),
            canon_int(seq),
            canon_field(kind),
            canon_field(entity),
            canon_field(field),
            canon_field(actor),
            canon_field(at),
            canon_field(old_value),
            canon_field(new_value),
            canon_field(rollback_target),
            _canon_blob(baseline_hash),
        )

    def _current_mac(self, entity: str, field: str, value: str) -> bytes:
        return hmac_chain(
            self._key, b"cur", canon_field(entity), canon_field(field),
            canon_field(value),
        )

    def _baseline_mac(self, entity: str, field: str, value: str | None) -> bytes:
        return hmac_chain(
            self._key, b"base", canon_field(entity), canon_field(field),
            canon_field(value),
        )

    def _meta(self) -> sqlite3.Row | tuple:
        return self._conn.execute(
            "SELECT last_write, head_seq, head_mac, prune_line, anchor_seq,"
            " anchor_mac, current_xor FROM meta WHERE id = 1"
        ).fetchone()

    def _write_meta(
        self,
        last_write: str | None,
        head_seq: int,
        head_mac: bytes,
        prune_line: str | None,
        anchor_seq: int,
        anchor_mac: bytes,
        current_xor: bytes,
    ) -> None:
        state_mac = self._state_mac(
            last_write, head_seq, head_mac, prune_line, anchor_seq, anchor_mac,
            current_xor,
        )
        self._conn.execute(
            "UPDATE meta SET last_write=?, head_seq=?, head_mac=?, prune_line=?,"
            " anchor_seq=?, anchor_mac=?, current_xor=?, state_mac=? WHERE id=1",
            (last_write, head_seq, head_mac, prune_line, anchor_seq, anchor_mac,
             current_xor, state_mac),
        )

    def _check_write_time(self, at: datetime) -> str:
        at_text = canonical(at)
        last_write = self._meta()[0]
        if last_write is not None and at_text < last_write:
            raise WriteRejected(
                f"write at {at_text} is earlier than previous write {last_write}"
            )
        return at_text

    def _append_entry(
        self,
        head_seq: int,
        head_mac: bytes,
        kind: str,
        entity: str | None,
        field: str | None,
        actor: str | None,
        at: str,
        old_value: str | None,
        new_value: str | None,
        rollback_target: str | None,
        baseline_hash: bytes | None,
    ) -> tuple[int, bytes]:
        seq = head_seq + 1
        mac = self._entry_mac(
            head_mac, seq, kind, entity, field, actor, at, old_value, new_value,
            rollback_target, baseline_hash,
        )
        self._conn.execute(
            "INSERT INTO entries (seq, kind, entity, field, actor, at, old_value,"
            " new_value, rollback_target, baseline_hash, mac)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (seq, kind, entity, field, actor, at, old_value, new_value,
             rollback_target, baseline_hash, mac),
        )
        return seq, mac

    def _current_value(self, entity: str, field: str) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM current_values WHERE entity=? AND field=?",
            (entity, field),
        ).fetchone()
        return row[0] if row else None

    def set_fields(
        self,
        entity: str,
        changes: dict[str, str | None],
        actor: str,
        at: datetime,
    ) -> None:
        at_text = self._check_write_time(at)
        with self._conn:
            (last_write, head_seq, head_mac, prune_line, anchor_seq, anchor_mac,
             current_xor) = self._meta()
            for field in sorted(changes):
                new_value = changes[field]
                old_value = self._current_value(entity, field)
                if old_value == new_value and (old_value is None) == (new_value is None):
                    continue
                head_seq, head_mac = self._append_entry(
                    head_seq, head_mac,
                    "set", entity, field, actor, at_text, old_value, new_value,
                    None, None,
                )
                if old_value is not None:
                    current_xor = xor_bytes(
                        current_xor, self._current_mac(entity, field, old_value))
                if new_value is None:
                    self._conn.execute(
                        "DELETE FROM current_values WHERE entity=? AND field=?",
                        (entity, field))
                else:
                    self._conn.execute(
                        "INSERT OR REPLACE INTO current_values (entity, field,"
                        " value) VALUES (?,?,?)", (entity, field, new_value))
                    current_xor = xor_bytes(
                        current_xor, self._current_mac(entity, field, new_value))
            self._write_meta(at_text, head_seq, head_mac, prune_line, anchor_seq,
                             anchor_mac, current_xor)

    def value_at(self, entity: str, field: str, t: datetime) -> str | None:
        t_text = canonical(t)
        prune_line = self._meta()[3]
        if prune_line is not None and t_text < prune_line:
            raise BeforeRetentionError(
                f"{t_text} is earlier than retention line {prune_line}"
            )
        return self._value_at_unchecked(entity, field, t_text)

    def _value_at_unchecked(self, entity: str, field: str, t_text: str) -> str | None:
        row = self._conn.execute(
            "SELECT new_value FROM entries"
            " WHERE entity=? AND field=? AND at<=?"
            " ORDER BY at DESC, seq DESC LIMIT 1",
            (entity, field, t_text),
        ).fetchone()
        if row is not None:
            return row[0]
        row = self._conn.execute(
            "SELECT value FROM baseline WHERE entity=? AND field=?",
            (entity, field),
        ).fetchone()
        return row[0] if row else None

    def rollback(
        self,
        entity: str,
        fields: list[str],
        t: datetime,
        actor: str,
        at: datetime,
    ) -> None:
        at_text = self._check_write_time(at)
        t_text = canonical(t)
        line = retention_line(to_utc(at))
        if t_text < canonical(line):
            raise BeforeRetentionError(
                f"rollback target {t_text} is earlier than retention line"
                f" {canonical(line)}"
            )
        target_text = t_text
        with self._conn:
            (last_write, head_seq, head_mac, prune_line, anchor_seq, anchor_mac,
             current_xor) = self._meta()
            for field in sorted(set(fields)):
                new_value = self._value_at_unchecked(entity, field, target_text)
                old_value = self._current_value(entity, field)
                if old_value == new_value and (old_value is None) == (new_value is None):
                    continue
                head_seq, head_mac = self._append_entry(
                    head_seq, head_mac,
                    "rollback", entity, field, actor, at_text, old_value,
                    new_value, target_text, None,
                )
                if old_value is not None:
                    current_xor = xor_bytes(
                        current_xor, self._current_mac(entity, field, old_value))
                if new_value is None:
                    self._conn.execute(
                        "DELETE FROM current_values WHERE entity=? AND field=?",
                        (entity, field))
                else:
                    self._conn.execute(
                        "INSERT OR REPLACE INTO current_values (entity, field,"
                        " value) VALUES (?,?,?)", (entity, field, new_value))
                    current_xor = xor_bytes(
                        current_xor, self._current_mac(entity, field, new_value))
            self._write_meta(at_text, head_seq, head_mac, prune_line, anchor_seq,
                             anchor_mac, current_xor)

    def history(self, entity: str) -> list[AuditEntry]:
        rows = self._conn.execute(
            "SELECT seq, field, actor, at, old_value, new_value, kind,"
            " rollback_target FROM entries WHERE entity=? ORDER BY seq",
            (entity,),
        )
        result = []
        for seq, field, actor, at, old_value, new_value, kind, target in rows:
            result.append(AuditEntry(
                seq=seq,
                entity=entity,
                field=field,
                actor=actor,
                at=format_12h(parse(at)),
                old_value=old_value,
                new_value=new_value,
                kind=kind,
                rollback_target=format_12h(parse(target)) if target else None,
            ))
        return result

    def prune(self, now: datetime) -> None:
        now_text = self._check_write_time(now)
        line = canonical(retention_line(to_utc(now)))
        with self._conn:
            (last_write, head_seq, head_mac, prune_line, anchor_seq, anchor_mac,
             current_xor) = self._meta()
            self._conn.execute("DELETE FROM baseline")
            self._conn.execute(
                "INSERT INTO baseline (entity, field, value)"
                " SELECT entity, field, new_value FROM ("
                "   SELECT entity, field, new_value,"
                "     ROW_NUMBER() OVER (PARTITION BY entity, field"
                "                        ORDER BY at DESC, seq DESC) AS rn"
                "   FROM entries WHERE at < ? AND entity IS NOT NULL"
                " ) WHERE rn = 1",
                (line,),
            )
            row = self._conn.execute(
                "SELECT seq, mac FROM entries WHERE at < ?"
                " ORDER BY seq DESC LIMIT 1",
                (line,),
            ).fetchone()
            if row is not None:
                anchor_seq, anchor_mac = row[0], row[1]
            self._conn.execute("DELETE FROM entries WHERE at < ?", (line,))
            xor = _ZERO
            for entity, field, value in self._conn.execute(
                    "SELECT entity, field, value FROM baseline"):
                xor = xor_bytes(xor, self._baseline_mac(entity, field, value))
            baseline_hash = hmac_chain(
                self._key, b"baseline", canon_field(line), xor)
            head_seq, head_mac = self._append_entry(
                head_seq, head_mac, "checkpoint", None, None, None, now_text,
                None, None, None, baseline_hash,
            )
            self._write_meta(now_text, head_seq, head_mac, line, anchor_seq,
                             anchor_mac, current_xor)

    def verify(self) -> tuple[bool, str]:
        row = self._conn.execute(
            "SELECT last_write, head_seq, head_mac, prune_line, anchor_seq,"
            " anchor_mac, current_xor, state_mac FROM meta WHERE id = 1"
        ).fetchone()
        if row is None:
            return False, "meta row missing"
        (last_write, head_seq, head_mac, prune_line, anchor_seq, anchor_mac,
         current_xor, state_mac) = row
        expect = self._state_mac(last_write, head_seq, head_mac, prune_line,
                                 anchor_seq, anchor_mac, current_xor)
        if expect != state_mac:
            return False, "meta state mac mismatch"

        expected_seq = anchor_seq + 1
        prev_mac = anchor_mac
        last_seq = anchor_seq
        cursor = self._conn.execute(
            "SELECT seq, kind, entity, field, actor, at, old_value, new_value,"
            " rollback_target, baseline_hash, mac FROM entries ORDER BY seq"
        )
        for (seq, kind, entity, field, actor, at, old_value, new_value,
             rollback_target, baseline_hash, mac) in cursor:
            if seq != expected_seq:
                return False, f"entry sequence gap: expected {expected_seq}, found {seq}"
            computed = self._entry_mac(
                prev_mac, seq, kind, entity, field, actor, at, old_value,
                new_value, rollback_target, baseline_hash,
            )
            if computed != mac:
                return False, f"entry {seq} mac mismatch"
            prev_mac = mac
            last_seq = seq
            expected_seq += 1
        if last_seq != head_seq:
            return False, f"head seq mismatch: meta {head_seq}, chain {last_seq}"
        if prev_mac != head_mac:
            return False, "head mac mismatch"

        checkpoint = self._conn.execute(
            "SELECT baseline_hash FROM entries WHERE kind='checkpoint'"
            " ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if prune_line is None:
            if checkpoint is not None:
                return False, "checkpoint entry present but never pruned"
            count = self._conn.execute(
                "SELECT COUNT(*) FROM baseline").fetchone()[0]
            if count:
                return False, "baseline rows present but never pruned"
        else:
            if checkpoint is None:
                return False, "checkpoint entry missing after prune"
            xor = _ZERO
            for entity, field, value in self._conn.execute(
                    "SELECT entity, field, value FROM baseline"):
                xor = xor_bytes(xor, self._baseline_mac(entity, field, value))
            expect_hash = hmac_chain(
                self._key, b"baseline", canon_field(prune_line), xor)
            if expect_hash != checkpoint[0]:
                return False, "baseline hash mismatch"

        xor = _ZERO
        current_count = 0
        for entity, field, value in self._conn.execute(
                "SELECT entity, field, value FROM current_values"):
            xor = xor_bytes(xor, self._current_mac(entity, field, value))
            current_count += 1
            derived = self._derived_current(entity, field)
            if derived != value:
                return False, (
                    f"current value of ({entity!r}, {field!r}) disagrees with"
                    " audit chain"
                )
        if xor != current_xor:
            return False, "current values xor mismatch"
        expected_count = 0
        for entity, field in self._conn.execute(
                "SELECT entity, field FROM entries WHERE entity IS NOT NULL"
                " GROUP BY entity, field"
                " UNION SELECT entity, field FROM baseline"):
            if self._derived_current(entity, field) is not None:
                expected_count += 1
        if expected_count != current_count:
            return False, (
                f"current values count mismatch: expected {expected_count},"
                f" found {current_count}"
            )
        return True, "OK"

    def _derived_current(self, entity: str, field: str) -> str | None:
        row = self._conn.execute(
            "SELECT new_value FROM entries WHERE entity=? AND field=?"
            " ORDER BY seq DESC LIMIT 1",
            (entity, field),
        ).fetchone()
        if row is not None:
            return row[0]
        row = self._conn.execute(
            "SELECT value FROM baseline WHERE entity=? AND field=?",
            (entity, field),
        ).fetchone()
        return row[0] if row else None
