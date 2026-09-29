"""SQLite 表结构与建库初始化。"""

from __future__ import annotations

import sqlite3

SCHEMA_VERSION = 1

DDL = """
CREATE TABLE IF NOT EXISTS meta (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    head_seq    INTEGER NOT NULL,
    anchor_seq  INTEGER NOT NULL,
    anchor_hmac BLOB    NOT NULL,
    last_write  INTEGER NOT NULL,
    cutoff_at   INTEGER NOT NULL,
    states_acc  BLOB    NOT NULL,
    hmac        BLOB    NOT NULL
);

CREATE TABLE IF NOT EXISTS entries (
    seq       INTEGER PRIMARY KEY,
    entity    TEXT    NOT NULL,
    field     TEXT    NOT NULL,
    actor     TEXT    NOT NULL,
    at        INTEGER NOT NULL,
    old       TEXT,
    new       TEXT,
    kind      INTEGER NOT NULL,
    target_at INTEGER,
    prev_hmac BLOB    NOT NULL,
    hmac      BLOB    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entries_entity_seq ON entries(entity, seq);
CREATE INDEX IF NOT EXISTS idx_entries_field_time ON entries(entity, field, at);
CREATE INDEX IF NOT EXISTS idx_entries_at ON entries(at);

CREATE TABLE IF NOT EXISTS baselines (
    entity TEXT    NOT NULL,
    field  TEXT    NOT NULL,
    value  TEXT,
    hmac   BLOB    NOT NULL,
    PRIMARY KEY (entity, field)
);

CREATE TABLE IF NOT EXISTS states (
    entity TEXT    NOT NULL,
    field  TEXT    NOT NULL,
    value  TEXT,
    ver    INTEGER NOT NULL,
    hmac   BLOB    NOT NULL,
    PRIMARY KEY (entity, field)
);
"""


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    # 用 MEMORY 回滚日志：事务结束即释放，避免被 prune 删除的敏感页残留于
    # -wal/-journal 文件中（题目只要求单文件、不考虑进程被杀）。
    conn.execute("PRAGMA journal_mode=MEMORY")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA foreign_keys=ON")
    # 立即回收被删除页，降低旧数据在文件空闲页中的残留
    conn.execute("PRAGMA secure_delete=ON")
    return conn


def initialize(conn: sqlite3.Connection) -> None:
    conn.executescript(DDL)
    conn.commit()
