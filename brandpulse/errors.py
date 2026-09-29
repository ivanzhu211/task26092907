"""异常类型定义。"""


class BrandPulseError(Exception):
    """BrandPulse 审计存储的基础异常。"""


class ClockRejectedError(BrandPulseError):
    """写操作时间早于此前任何一次写操作。"""


class OutsideRetentionError(BrandPulseError):
    """查询/回滚目标时刻早于当前保留线。"""


class TamperDetectedError(BrandPulseError):
    """verify 发现库被篡改（显式校验调用时使用）。"""


class InvalidArgumentError(BrandPulseError):
    """调用方参数非法。"""
