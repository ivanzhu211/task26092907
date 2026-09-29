"""冒烟测试：包可导入、类型可用。"""

import brandpulse
from brandpulse.models import AuditEntry, VerifyReport


def test_import():
    assert brandpulse.AuditStore
    assert VerifyReport(ok=True).ok
