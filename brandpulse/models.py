"""数据类型定义。"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

# 审计条目类型
KIND_SET = "set"
KIND_ROLLBACK = "rollback"
KIND_PRUNE = "prune"

# 取值的“未设置”哨兵
UNSET = None

Value = Optional[str]


@dataclass(frozen=True)
class AuditEntry:
    """一条保留的字段变更审计。"""

    seq: int
    entity: str
    field: str
    actor: str
    at: datetime
    old: Value
    new: Value
    kind: str
    target_at: Optional[datetime]

    @property
    def is_rollback(self) -> bool:
        return self.kind == KIND_ROLLBACK

    @property
    def at_text(self) -> str:
        """12 小时制显示，如 03/07/2026 02:05:09 PM。"""
        from .timeutil import format_at

        return format_at(self.at)


@dataclass(frozen=True)
class VerifyReport:
    """verify 结果。"""

    ok: bool
    problem: Optional[str] = None
    seq: Optional[int] = None
