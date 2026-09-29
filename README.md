# BrandPulse 审计存储

用 Python 标准库 + SQLite 实现的防篡改字段审计存储。适用于网红关系管理中
关系阶段、大使等级、合作报酬、活动预算上限等关键字段的变更留痕、36 个月
保留、任意时刻回滚与完整性校验。

## 特性

- 实体用字符串键，字段名/值均为任意 Unicode；`None` 表示“未设置”，与空串 `""` 严格区分。
- 所有时间为 UTC，由调用方传入；写操作时间早于此前写操作即拒绝（相等允许）。
- 保留期 36 个自然月：目标月无该日取月末，时分秒不变。
- `set_fields` 原子修改多字段，每个实际变化记一条审计（操作人/时间/字段/旧值/新值）。
- `value_at` 取任意时刻值（同一时刻多次改动以最后一次为准）。
- `rollback` 原子恢复多字段到目标时刻，回滚本身也记审计并标注目标时刻。
- `history` 返回保留审计，时间显示为 `MM/DD/YYYY hh:mm:ss AM/PM`。
- `prune` 删除保留线之前条目，但对任意不早于保留线的时刻，
  `value_at`/`rollback` 结果与从未 prune 完全一致。
- `verify` 流式校验，内存不随条目总数增长；报告首个问题位置。

## 防篡改设计（无密钥、仅有库文件的攻击者）

- 每条审计带 HMAC-SHA256（覆盖序号/实体/字段/操作人/时间/旧值/新值/类型/
  回滚目标时刻/前驱哈希），形成链式结构；字段采用长度前缀编码，
  `None` 与空串用不同标签，杜绝字段间挪字节。
- 每代 `prune` 写入一个链上“prune 标记”，并以最后被删条目的链式哈希为锚点；
- 保留线处的每字段取值存入 `baselines`（基线），MAC 绑定当前保留线，
  防止旧基线重放，支撑 prune 后的历史推导；
- 当前值 `states` 每行带 MAC，并用全量 XOR 累加器（存于 `meta`）覆盖
  “插入/删除/调换状态行”，并与保留审计交叉核对当前值；
- `meta` 单行带 MAC，保护头序号、锚点、保留线、最近写时间与累加器。
- 密钥与任何可重算材料都不写库；prune 不重写任何保留条目的校验信息，
  提交后 `VACUUM` 使被删 actor/at/old 在文件字节层不可恢复。

## 用法

```python
from datetime import datetime, timezone
from brandpulse import AuditStore

with AuditStore("brand.db", key=b"at-least-16-random-bytes") as store:
    store.set_fields("influencer:42", {"stage": "ambassador"}, "alice",
                     datetime(2026, 7, 3, 14, 5, 9, tzinfo=timezone.utc))
    store.value_at("influencer:42", "stage", datetime(2026, 8, 1, tzinfo=timezone.utc))
    store.rollback("influencer:42", ["stage"], datetime(2026, 7, 3, 14, 5, 9,
                   tzinfo=timezone.utc), "auditor", datetime(2026, 9, 1,
                   tzinfo=timezone.utc))
    store.prune(datetime(2026, 9, 30, tzinfo=timezone.utc))
    report = store.verify()
    assert report.ok
```

## 测试

```
python3 -m pytest -q
```
