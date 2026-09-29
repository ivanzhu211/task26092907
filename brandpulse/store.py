"""审计存储主类 AuditStore：链式 HMAC + 每字段当前态 + 流式校验。"""

from __future__ import annotations

from datetime import datetime
from typing import Iterable, Mapping, Optional

from . import crypto
from .errors import (
    ClockRejectedError,
    InvalidArgumentError,
    OutsideRetentionError,
    TamperDetectedError,
)
from .models import KIND_PRUNE, KIND_ROLLBACK, KIND_SET, AuditEntry, VerifyReport
from .schema import connect, initialize
from .timeutil import from_micros, retention_line, to_micros, validate_utc

_DOMAIN_META = b"meta-v1"
_DOMAIN_ENTRY = b"entry-v1"
_DOMAIN_STATE = b"state-v1"
_DOMAIN_ANCHOR = b"anchor-v1"
_DOMAIN_BASELINE = b"baseline-v1"

_ZERO32 = bytes(32)

_KIND_INT = {KIND_SET: 0, KIND_ROLLBACK: 1, KIND_PRUNE: 2}
_KIND_NAME = {v: k for k, v in _KIND_INT.items()}


def _xor32(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


class AuditStore:
    """防篡改字段审计存储。"""

    def __init__(
        self,
        path: str,
        key: bytes,
        *,
        verify_on_open: bool = True,
    ):
        if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
            raise InvalidArgumentError("密钥必须是不少于 16 字节的随机字节串")
        self.path = path
        self._key = bytes(key)
        self.conn = connect(path)
        self.conn.isolation_level = None
        initialize(self.conn)
        row = self.conn.execute("SELECT COUNT(*) FROM meta").fetchone()[0]
        if row == 0:
            self._init_meta()
        else:
            self._load_meta()
            if verify_on_open:
                report = self.verify()
                if not report.ok:
                    raise TamperDetectedError(
                        f"存储校验失败：{report.problem}"
                    )

    # ---- meta / genesis -------------------------------------------------

    def _init_meta(self) -> None:
        anchor_hmac = crypto.mac(self._key, _DOMAIN_ANCHOR, crypto.i(0))
        self.conn.execute(
            "INSERT INTO meta (id, head_seq, anchor_seq, anchor_hmac, "
            "last_write, cutoff_at, states_acc, hmac) VALUES (1,0,0,?,0,0,?,?)",
            (anchor_hmac, _ZERO32, self._meta_hmac(0, 0, anchor_hmac, 0, 0, _ZERO32)),
        )
        self.conn.commit()
        self._load_meta()

    def _load_meta(self) -> None:
        row = self.conn.execute(
            "SELECT head_seq, anchor_seq, anchor_hmac, last_write, "
            "cutoff_at, states_acc, hmac FROM meta WHERE id=1"
        ).fetchone()
        (
            self.head_seq,
            self.anchor_seq,
            self.anchor_hmac,
            self.last_write,
            self.cutoff_at,
            self.states_acc,
            self.meta_hmac,
        ) = row

    def _meta_hmac(self, head, anchor_seq, anchor_hmac, last_write, cutoff, acc):
        return crypto.mac(
            self._key,
            _DOMAIN_META,
            crypto.i(head),
            crypto.i(anchor_seq),
            anchor_hmac,
            crypto.i(last_write),
            crypto.i(cutoff),
            acc,
        )

    def _save_meta(self) -> None:
        self.meta_hmac = self._meta_hmac(
            self.head_seq,
            self.anchor_seq,
            self.anchor_hmac,
            self.last_write,
            self.cutoff_at,
            self.states_acc,
        )
        self.conn.execute(
            "UPDATE meta SET head_seq=?, anchor_seq=?, anchor_hmac=?, "
            "last_write=?, cutoff_at=?, states_acc=?, hmac=? WHERE id=1",
            (
                self.head_seq,
                self.anchor_seq,
                self.anchor_hmac,
                self.last_write,
                self.cutoff_at,
                self.states_acc,
                self.meta_hmac,
            ),
        )

    # ---- 校验原语 -------------------------------------------------------

    def _entry_mac(self, seq, entity, field, actor, at_us, old, new,
                   kind, target_at, prev_hmac):
        return crypto.mac(
            self._key,
            _DOMAIN_ENTRY,
            crypto.i(seq),
            crypto.s(entity),
            crypto.s(field),
            crypto.s(actor),
            crypto.i(at_us),
            crypto.s(old),
            crypto.s(new),
            crypto.i(kind),
            crypto.ts(target_at),
            prev_hmac,
        )

    def _state_mac(self, entity, field, value, ver):
        return crypto.mac(
            self._key,
            _DOMAIN_STATE,
            crypto.s(entity),
            crypto.s(field),
            crypto.s(value),
            crypto.i(ver),
        )

    def _clock_gate(self, at_us: int) -> None:
        if at_us < self.last_write:
            raise ClockRejectedError(
                "写操作时间早于此前某次写操作（相等允许，更早拒绝）"
            )

    def _baseline_mac(self, entity, field, value, cutoff):
        return crypto.mac(
            self._key,
            _DOMAIN_BASELINE,
            crypto.s(entity),
            crypto.s(field),
            crypto.s(value),
            crypto.i(cutoff),
        )

    def _write_change(self, entity, field, actor, at_us, old, new,
                      kind, target_at):
        """追加一条审计并同步当前态；调用方已在事务内。返回新 seq。"""
        seq = self.head_seq + 1
        if self.head_seq == self.anchor_seq:
            prev_hmac = self.anchor_hmac
        else:
            prev_hmac = self.conn.execute(
                "SELECT hmac FROM entries WHERE seq=?", (self.head_seq,)
            ).fetchone()[0]
        entry_hmac = self._entry_mac(
            seq, entity, field, actor, at_us, old, new,
            _KIND_INT[kind], target_at, prev_hmac,
        )
        self.conn.execute(
            "INSERT INTO entries (seq, entity, field, actor, at, old, new, "
            "kind, target_at, prev_hmac, hmac) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (seq, entity, field, actor, at_us, old, new,
             _KIND_INT[kind], target_at, prev_hmac, entry_hmac),
        )

        state = self.conn.execute(
            "SELECT value, ver, hmac FROM states WHERE entity=? AND field=?",
            (entity, field),
        ).fetchone()
        if state is None:
            old_value, old_ver, old_hmac = None, 0, None
        else:
            old_value, old_ver, old_hmac = state
        if old_hmac is not None:
            self.states_acc = _xor32(
                self.states_acc,
                self._state_mac(entity, field, old_value, old_ver),
            )
        new_hmac = self._state_mac(entity, field, new, seq)
        self.states_acc = _xor32(self.states_acc, new_hmac)
        self.conn.execute(
            "INSERT INTO states (entity, field, value, ver, hmac) "
            "VALUES (?,?,?,?,?) "
            "ON CONFLICT(entity, field) DO UPDATE SET value=excluded.value, "
            "ver=excluded.ver, hmac=excluded.hmac",
            (entity, field, new, seq, new_hmac),
        )

        self.head_seq = seq
        return seq

    # ---- 公开写操作 -----------------------------------------------------

    def set_fields(
        self,
        entity: str,
        changes: Mapping[str, Optional[str]],
        actor: str,
        at: datetime,
    ) -> int:
        at = validate_utc(at)
        at_us = to_micros(at)
        self._require_text(entity, "entity")
        self._require_text(actor, "actor")
        if not isinstance(changes, Mapping):
            raise InvalidArgumentError("changes 必须是字段名 -> 值（或 None）的映射")
        normalized = {}
        for field, value in changes.items():
            self._require_text(field, "field")
            if value is not None and not isinstance(value, str):
                raise InvalidArgumentError("字段值必须是 Unicode 字符串或 None")
            normalized[field] = value

        self._clock_gate(at_us)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            count = 0
            for field in sorted(normalized):
                new = normalized[field]
                old = self._current(entity, field)
                if old == new:
                    continue
                self._write_change(
                    entity, field, actor, at_us, old, new, KIND_SET, None
                )
                count += 1
            self.last_write = at_us
            self._save_meta()
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        self._load_meta()
        return count

    def _current(self, entity: str, field: str):
        row = self.conn.execute(
            "SELECT value FROM states WHERE entity=? AND field=?",
            (entity, field),
        ).fetchone()
        return None if row is None else row[0]

    def rollback(
        self,
        entity: str,
        fields: Iterable[str],
        t: datetime,
        actor: str,
        at: datetime,
    ) -> int:
        t = validate_utc(t)
        at = validate_utc(at)
        t_us = to_micros(t)
        at_us = to_micros(at)
        self._require_text(entity, "entity")
        self._require_text(actor, "actor")
        field_list = sorted({self._as_field(f) for f in fields})
        line_us = to_micros(retention_line(at))
        if t_us < line_us:
            raise OutsideRetentionError(
                "回滚目标时刻早于 at 的保留线"
            )

        self._clock_gate(at_us)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            count = 0
            for field in field_list:
                target = self._value_at_unchecked(entity, field, t_us)
                old = self._current(entity, field)
                if old == target:
                    continue
                self._write_change(
                    entity, field, actor, at_us, old, target,
                    KIND_ROLLBACK, t_us,
                )
                count += 1
            self.last_write = at_us
            self._save_meta()
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        self._load_meta()
        return count

    @staticmethod
    def _require_text(value, name):
        if not isinstance(value, str):
            raise InvalidArgumentError(f"{name} 必须是 Unicode 字符串")
        if value == "":
            raise InvalidArgumentError(f"{name} 不能为空字符串")

    @staticmethod
    def _as_field(value):
        if not isinstance(value, str):
            raise InvalidArgumentError("field 必须是 Unicode 字符串")
        if value == "":
            raise InvalidArgumentError("field 不能为空字符串")
        return value

    # ---- 公开读操作 -----------------------------------------------------

    def value_at(self, entity: str, field: str, t: datetime) -> Optional[str]:
        t = validate_utc(t)
        self._require_text(entity, "entity")
        self._require_text(field, "field")
        t_us = to_micros(t)
        if t_us < self.cutoff_at:
            raise OutsideRetentionError(
                "查询时刻早于最近一次 prune 的保留线"
            )
        return self._value_at_unchecked(entity, field, t_us)

    def _value_at_unchecked(self, entity, field, t_us):
        row = self.conn.execute(
            "SELECT new FROM entries WHERE entity=? AND field=? AND at<=? "
            "ORDER BY seq DESC LIMIT 1",
            (entity, field, t_us),
        ).fetchone()
        if row is not None:
            return row[0]
        # t 不早于保留线，但该字段没有保留条目落在 <= t：
        # 取保留线处的基线（未设置/空串均已在基线中区分）。
        baseline = self.conn.execute(
            "SELECT value FROM baselines WHERE entity=? AND field=?",
            (entity, field),
        ).fetchone()
        if baseline is not None:
            return baseline[0]
        return None

    def history(self, entity: str) -> list[AuditEntry]:
        self._require_text(entity, "entity")
        rows = self.conn.execute(
            "SELECT seq, entity, field, actor, at, old, new, kind, "
            "target_at FROM entries WHERE entity=? AND kind!=? ORDER BY seq",
            (entity, _KIND_INT[KIND_PRUNE]),
        ).fetchall()
        return [
            AuditEntry(
                seq=seq,
                entity=e,
                field=field,
                actor=actor,
                at=from_micros(at_us),
                old=old,
                new=new,
                kind=_KIND_NAME[kind],
                target_at=None if target_at is None else from_micros(target_at),
            )
            for seq, e, field, actor, at_us, old, new, kind, target_at in rows
        ]

    def prune(self, now: datetime) -> int:
        now = validate_utc(now)
        now_us = to_micros(now)
        self._clock_gate(now_us)
        cutoff = to_micros(retention_line(now))
        if cutoff < self.cutoff_at:
            cutoff = self.cutoff_at

        self.conn.execute("BEGIN IMMEDIATE")
        deleted = 0
        try:
            # 临时表：本次被删 prune 标记所声明的锚点（数量很少，每代至多几个）。
            self.conn.execute(
                "CREATE TEMP TABLE IF NOT EXISTS _dead_anchors (hmac BLOB PRIMARY KEY)"
            )
            self.conn.execute("DELETE FROM _dead_anchors")

            # 流式扫描待删条目：
            #  - 普通条目：即时把该字段基线 upsert 为其 new（按 seq 升序，
            #    同字段最后一次写入自然胜出），内存 O(1)
            #  - prune 标记：收集其锚点载荷
            last_seq = None
            last_hmac = self.anchor_hmac
            cur = self.conn.execute(
                "SELECT seq, entity, field, new, hmac, kind FROM entries "
                "WHERE at<? ORDER BY seq",
                (cutoff,),
            )
            for seq, entity, field, new, entry_hmac, kind in cur:
                if kind == _KIND_INT[KIND_PRUNE]:
                    for part in (new or "").split("\n"):
                        try:
                            self.conn.execute(
                                "INSERT OR REPLACE INTO _dead_anchors(hmac) VALUES (?)",
                                (bytes.fromhex(part),),
                            )
                        except ValueError:
                            pass
                else:
                    self.conn.execute(
                        "INSERT INTO baselines (entity, field, value, hmac) "
                        "VALUES (?,?,?,?) "
                        "ON CONFLICT(entity, field) DO UPDATE SET "
                        "value=excluded.value, hmac=excluded.hmac",
                        (entity, field, new,
                         self._baseline_mac(entity, field, new, cutoff)),
                    )
                last_seq = seq
                last_hmac = entry_hmac

            if last_seq is not None:
                deleted = last_seq - self.anchor_seq
                self.conn.execute(
                    "DELETE FROM entries WHERE at<?", (cutoff,)
                )
                self.anchor_seq = last_seq
                # 锚点直接复用最后被删条目的原始链式 hmac：新一段保留条目的
                # prev_hmac 本就等于它，无需重写任何保留条目。
                self.anchor_hmac = last_hmac

                # 本次没有新删除、但历史上已有基线的字段，值不变，MAC 仍按新
                # cutoff 逐行重算（流式游标，O(1) 内存），防止旧基线重放。
                base_cur = self.conn.execute(
                    "SELECT entity, field, value FROM baselines"
                )
                for entity, field, value in base_cur:
                    self.conn.execute(
                        "UPDATE baselines SET hmac=? WHERE entity=? AND field=?",
                        (self._baseline_mac(entity, field, value, cutoff),
                         entity, field),
                    )

                # 存活锚点 = 当前新锚点 ∪ 被删标记声明、且仍被某保留普通条目
                # 引用的锚点。交集在 SQL 中完成，结果集很小。
                surviving = [self.anchor_hmac.hex()]
                anc_cur = self.conn.execute(
                    "SELECT d.hmac FROM _dead_anchors d WHERE EXISTS ("
                    "  SELECT 1 FROM entries e WHERE e.kind!=? "
                    "  AND e.prev_hmac=d.hmac)",
                    (_KIND_INT[KIND_PRUNE],),
                )
                for (anc_raw,) in anc_cur:
                    surviving.append(anc_raw.hex())
                anchor_payload = "\n".join(sorted(surviving))

                # 追加 prune 标记到链尾。
                marker_seq = self.head_seq + 1
                prior_head_row = self.conn.execute(
                    "SELECT hmac FROM entries WHERE seq=? ",
                    (self.head_seq,),
                ).fetchone()
                marker_prev = (
                    prior_head_row[0] if prior_head_row is not None
                    else self.anchor_hmac
                )
                marker = self._entry_mac(
                    marker_seq, "", "", "system", cutoff, None,
                    anchor_payload,
                    _KIND_INT[KIND_PRUNE], cutoff, marker_prev,
                )
                self.conn.execute(
                    "INSERT INTO entries (seq, entity, field, actor, at, old, "
                    "new, kind, target_at, prev_hmac, hmac) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (marker_seq, "", "", "system", cutoff, None,
                     anchor_payload,
                     _KIND_INT[KIND_PRUNE], cutoff, marker_prev, marker),
                )
                self.head_seq = marker_seq

            self.cutoff_at = cutoff
            self.last_write = now_us
            self._save_meta()
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        if deleted:
            # 重建物理文件，丢弃含已删敏感内容的空闲页，使 actor/at/old
            # 在文件字节层面也不可恢复。
            self.conn.execute("VACUUM")
        self._load_meta()
        return deleted

    # ---- 校验 -----------------------------------------------------------

    def verify(self) -> VerifyReport:
        try:
            report = self._verify_meta()
            if not report.ok:
                return report
            report = self._verify_entries()
            if not report.ok:
                return report
            report = self._verify_baselines()
            if not report.ok:
                return report
            return self._verify_states()
        except (ValueError, OverflowError, TypeError) as exc:
            return self._bad(f"库中存在无法解析的数据（疑似篡改）：{exc}")

    def _bad(self, problem, seq=None):
        return VerifyReport(ok=False, problem=problem, seq=seq)

    def _verify_meta(self):
        row = self.conn.execute(
            "SELECT head_seq, anchor_seq, anchor_hmac, last_write, "
            "cutoff_at, states_acc, hmac FROM meta"
        ).fetchall()
        if len(row) != 1:
            return self._bad("meta 表必须恰好一行")
        head, anchor_seq, anchor_hmac, last_write, cutoff, acc, hmac = row[0]
        expect = self._meta_hmac(
            head, anchor_seq, anchor_hmac, last_write, cutoff, acc
        )
        import hmac as _hmac_mod

        if not _hmac_mod.compare_digest(expect, hmac):
            return self._bad("meta 校验信息不匹配（元数据被篡改）")
        if anchor_seq == 0:
            expect_anchor = crypto.mac(
                self._key, _DOMAIN_ANCHOR, crypto.i(anchor_seq)
            )
            if not _hmac_mod.compare_digest(expect_anchor, anchor_hmac):
                return self._bad("锚点校验信息不匹配")
        if anchor_seq < 0 or head < anchor_seq or cutoff < 0 or last_write < 0:
            return self._bad("meta 中的序号/时间边界非法")
        return VerifyReport(ok=True)

    def _verify_entries(self):
        import hmac as _hmac_mod

        # 严格按 seq 走链：
        #   - 序号连续：prev 必须严格等于上一条 hmac；
        #   - 序号缺口（某代 prune 删了整段）：prev 必须是一个“此刻有效”的锚点。
        # 锚点作用域是局部的：
        #   - 最旧存活段的锚点 = meta.anchor_hmac；
        #   - 每走过一个 prune 标记，标记载荷里声明的锚点只对“它之后的下一段”
        #     生效。这样历史锚点不能被拿到别处去接伪造段。
        # 当某代的 prune 标记自己也在下一代被删时，仍存活的更旧普通条目所用
        # 的锚点，会被新一代标记的载荷原样携带，因此在库中始终可验证。
        # 最旧存活段允许的锚点：meta 当前锚点，以及每个存活 prune 标记
        # 载荷里携带的锚点（载荷受标记 hmac 保护，攻击者无法杜撰）。
        gap_anchors = {self.anchor_hmac}
        for (payload,) in self.conn.execute(
            "SELECT new FROM entries WHERE kind=?",
            (_KIND_INT[KIND_PRUNE],),
        ):
            for part in (payload or "").split("\n"):
                try:
                    gap_anchors.add(bytes.fromhex(part))
                except ValueError:
                    pass

        prev_hmac = None
        prev_seq = 0
        last_at = None
        cur = self.conn.execute(
            "SELECT seq, entity, field, actor, at, old, new, kind, "
            "target_at, prev_hmac, hmac FROM entries ORDER BY seq"
        )
        for (seq, entity, field, actor, at_us, old, new, kind,
             target_at, stored_prev, stored_hmac) in cur:
            if kind not in _KIND_NAME:
                return self._bad("未知的审计条目类型", seq)
            is_marker = kind == _KIND_INT[KIND_PRUNE]

            declared_parts = []
            if is_marker:
                if entity != "" or field != "" or actor != "system" \
                        or old is not None or target_at != at_us:
                    return self._bad("prune 标记结构非法", seq)
                try:
                    for part in (new or "").split("\n"):
                        declared_parts.append(bytes.fromhex(part))
                except ValueError:
                    return self._bad("prune 标记缺少合法锚点", seq)
                if not declared_parts:
                    return self._bad("prune 标记缺少合法锚点", seq)

            if is_marker:
                consecutive_ok = (
                    seq == prev_seq + 1
                    and prev_hmac is not None
                    and _hmac_mod.compare_digest(stored_prev, prev_hmac)
                )
                # 不连续时，标记前驱必须就是该代新锚点（其载荷第一项）。
                anchor_ok = (
                    prev_hmac is None
                    and stored_prev in gap_anchors
                ) or (not consecutive_ok and stored_prev in declared_parts)
                if not consecutive_ok and not anchor_ok:
                    return self._bad("prune 标记前向指针不匹配", seq)
            elif prev_hmac is None:
                if stored_prev not in gap_anchors:
                    return self._bad("链首锚点不匹配（最早条目被删除/伪装）", seq)
            elif seq == prev_seq + 1:
                if not _hmac_mod.compare_digest(stored_prev, prev_hmac):
                    return self._bad(
                        "前向链指针不匹配（条目被调换/插入/删除）", seq)
            else:
                if seq <= prev_seq:
                    return self._bad("审计链序号倒退（条目被调换）", seq)
                if stored_prev not in gap_anchors:
                    return self._bad(
                        "审计链序号不连续（条目被插入/删除/调换）", seq)

            expect = self._entry_mac(
                seq, entity, field, actor, at_us, old, new,
                kind, target_at, stored_prev,
            )
            if not _hmac_mod.compare_digest(expect, stored_hmac):
                return self._bad("条目校验信息不匹配（内容被篡改）", seq)

            if is_marker:
                # 标记之后的下一段，只允许锚定到它声明的锚点。
                gap_anchors = set(declared_parts)
            else:
                if last_at is not None and at_us < last_at:
                    return self._bad("条目时间顺序异常", seq)
                last_at = at_us
                # 一旦进入连续普通条目，后续必须严格链接，旧缺口锚点失效。
                gap_anchors = set()

            prev_hmac = stored_hmac
            prev_seq = seq

        if prev_seq != self.head_seq:
            return self._bad("最新条目缺失（末尾条目被删除）")
        return VerifyReport(ok=True)

    def _verify_baselines(self):
        import hmac as _hmac_mod

        cur = self.conn.execute(
            "SELECT entity, field, value, hmac FROM baselines "
            "ORDER BY entity, field"
        )
        for entity, field, value, stored in cur:
            expect = self._baseline_mac(entity, field, value, self.cutoff_at)
            if not _hmac_mod.compare_digest(expect, stored):
                return self._bad(
                    "基线校验信息不匹配（用于推出历史取值的数据被篡改）",
                )
        return VerifyReport(ok=True)

    def _verify_states(self):
        import hmac as _hmac_mod

        acc = _ZERO32
        cur = self.conn.execute(
            "SELECT entity, field, value, ver, hmac FROM states "
            "ORDER BY entity, field"
        )
        for entity, field, value, ver, stored in cur:
            expect = self._state_mac(entity, field, value, ver)
            if not _hmac_mod.compare_digest(expect, stored):
                return self._bad("当前态行校验信息不匹配", ver)
            acc = _xor32(acc, expect)
            if ver < 0 or ver > self.head_seq:
                return self._bad("当前态版本越界", ver)
            latest = self.conn.execute(
                "SELECT seq, new FROM entries WHERE entity=? AND field=? "
                "AND kind!=? ORDER BY seq DESC LIMIT 1",
                (entity, field, _KIND_INT[KIND_PRUNE]),
            ).fetchone()
            if latest is not None:
                latest_seq, latest_new = latest
                if latest_seq != ver or latest_new != value:
                    return self._bad("当前值与审计推导结果不一致", ver)
            else:
                if ver > self.anchor_seq:
                    return self._bad("当前态版本无对应审计条目", ver)
                # 最后改动已被 prune：当前值必须与基线一致
                baseline = self.conn.execute(
                    "SELECT value, hmac FROM baselines WHERE entity=? AND field=?",
                    (entity, field),
                ).fetchone()
                if baseline is None or baseline[0] != value:
                    return self._bad("当前值与保留线基线不一致", ver)
        if not _hmac_mod.compare_digest(acc, self.states_acc):
            return self._bad("当前态集合累加器不匹配（状态行被插入/删除/调换）")
        return VerifyReport(ok=True)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "AuditStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
