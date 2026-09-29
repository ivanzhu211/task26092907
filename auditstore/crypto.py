"""Canonical serialization and keyed HMAC helpers for the audit chain."""

from __future__ import annotations

import hashlib
import hmac


def canon_field(value: str | None) -> bytes:
    """Length-prefixed encoding; distinguishes None (unset) from any string."""
    if value is None:
        return b"\xff"
    data = value.encode("utf-8")
    return b"\x00" + str(len(data)).encode("ascii") + b":" + data


def canon_int(value: int) -> bytes:
    return b"i" + str(value).encode("ascii") + b";"


def hmac_chain(key: bytes, *parts: bytes) -> bytes:
    """HMAC over the concatenation of parts."""
    mac = hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        mac.update(part)
    return mac.digest()


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))
