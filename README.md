# BrandPulse 审计存储（auditstore）

纯标准库 Python + SQLite 的防篡改审计存储，用于网红关系管理中的关键字段
（关系阶段、大使等级、合作报酬、活动预算上限等）。

## 特性

- 每次字段实际变化记一条审计（操作人、UTC 时间、字段、旧值、新值），
  全部条目串成 keyed-HMAC 哈希链。
- 审计只保留 36 个自然月；保留线按自然月回推，目标月没有该日则取月末，
  时分秒不变。
- `value_at` / `rollback` 可回到保留期内任意时刻；prune 之后结果与
  从未 prune 完全一致（靠 prune 时生成的基线快照 + 链上检查点保证）。
- `verify()` 流式校验：meta 状态 MAC → 条目链 → 基线检查点 → 当前值
  一致性，内存不随条目数增长。
- 密钥只在打开时由调用方传入，库文件不含任何可重算校验信息的材料。

## 结构

- `entries`：审计链（含 prune 检查点），`mac_i = HMAC(key, mac_{i-1} ‖ 条目)`。
- `baseline`：prune 时每个 (entity, field) 在保留线处的取值，由链上最近的
  checkpoint 条目里的 keyed 哈希保护。
- `current_values`：当前值镜像，由 meta 中 keyed 的 XOR 聚合保护，verify
  还会逐行与审计链推导值比对。
- `meta`：最近一次写时间、链头、prune 锚点、current 聚合，整体由
  `state_mac` 保护；删除最新条目、伪装清理最早条目都会破坏这些锚点。

## 使用

```python
from datetime import datetime, timezone
from auditstore import AuditStore

store = AuditStore("brandpulse.db", key=b"...")
store.set_fields("inf-1", {"stage": "active"}, "alice",
                 datetime(2026, 3, 7, 14, 5, 9, tzinfo=timezone.utc))
store.value_at("inf-1", "stage", datetime(2026, 6, 1, tzinfo=timezone.utc))
store.rollback("inf-1", ["stage"], some_time, "bob", now)
store.history("inf-1")          # 时间显示为 03/07/2026 02:05:09 PM
store.prune(now)                # 删除早于保留线 36 个月的条目
ok, msg = store.verify()
```

## 测试

```
python3 -m unittest discover -s tests
```
