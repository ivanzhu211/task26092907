"""BrandPulse 防篡改审计存储（Python 标准库 + SQLite）。"""

from .errors import (
    BrandPulseError,
    ClockRejectedError,
    InvalidArgumentError,
    OutsideRetentionError,
    TamperDetectedError,
)
from .models import KIND_ROLLBACK, KIND_SET, AuditEntry, VerifyReport
from .store import AuditStore

__all__ = [
    "AuditStore",
    "AuditEntry",
    "VerifyReport",
    "KIND_SET",
    "KIND_ROLLBACK",
    "BrandPulseError",
    "ClockRejectedError",
    "OutsideRetentionError",
    "TamperDetectedError",
    "InvalidArgumentError",
]
