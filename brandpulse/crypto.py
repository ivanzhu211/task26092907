"""仅用标准库的 HMAC/SHA-256 校验原语与规范化编码。

所有待验数据都用“长度前缀 + 域标签”规范化后做 HMAC-SHA256，
以区分 None（未设置）与空字符串，并杜绝字段之间挪动字节的篡改。
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Optional

_TAG_NONE = 0
_TAG_SOME = 1


def b(value: bytes) -> bytes:
    """长度前缀编码一个二进制片段。"""
    return struct.pack(">Q", len(value)) + value


def i(value: int) -> bytes:
    """8 字节大端无符号整数。"""
    if not 0 <= value < 1 << 64:
        raise ValueError("整数超出 64 位无符号范围")
    return struct.pack(">Q", value)


def s(value: Optional[str]) -> bytes:
    """Unicode 字符串；None=未设置，与空字符串严格区分。"""
    if value is None:
        return bytes([_TAG_NONE])
    return bytes([_TAG_SOME]) + value.encode("utf-8")


def ts(value: Optional[int]) -> bytes:
    """微秒级时间戳；None 用独立标签。"""
    if value is None:
        return bytes([_TAG_NONE])
    return bytes([_TAG_SOME]) + i(value)


def _canonical(domain: bytes, parts: tuple[bytes, ...]) -> bytes:
    chunks = [b(domain)]
    chunks.extend(b(part) for part in parts)
    return b"".join(chunks)


def mac(key: bytes, domain: bytes, *parts: bytes) -> bytes:
    """HMAC-SHA256(key, 域标签 || 各长度前缀片段)。"""
    if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
        raise ValueError("密钥必须是不少于 16 字节的随机字节串")
    return hmac.new(bytes(key), _canonical(domain, parts), hashlib.sha256).digest()


def verify_mac(key: bytes, domain: bytes, expected: bytes, *parts: bytes) -> bool:
    return hmac.compare_digest(mac(key, domain, *parts), expected)
