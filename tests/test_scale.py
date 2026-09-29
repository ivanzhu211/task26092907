"""规模约束：verify/prune 的 Python 层内存不随条目总量线性增长
（tracemalloc 峰值），value_at 只走单字段索引。"""

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone

from brandpulse import AuditStore
from .conftest import KEY

UTC = timezone.utc

_WORKER = r'''
import sys, json, tracemalloc
from datetime import datetime, timezone
from brandpulse import AuditStore
path, mode = sys.argv[1], sys.argv[2]
st = AuditStore(path, b"brandpulse-test-key-0123456789", verify_on_open=False)
tracemalloc.start()
if mode == "verify":
    assert st.verify().ok
elif mode == "prune":
    st.prune(datetime(2023, 6, 1, tzinfo=timezone.utc))
    assert st.verify().ok
_, peak = tracemalloc.get_traced_memory()
tracemalloc.stop()
print(json.dumps({"bytes": peak}))
'''


def _build(path, n_entities, writes):
    st = AuditStore(path, KEY, verify_on_open=False)
    base = datetime(2020, 1, 1, tzinfo=UTC)
    for w in range(writes):
        at = base + timedelta(hours=w)
        changes = {f"f{j % 4}": f"v{w}-{j}" for j in range(4)}
        st.set_fields(f"ent{w % n_entities}", changes, "actor", at)
    st.close()


def _run_worker(path, mode):
    out = subprocess.run(
        [sys.executable, "-c", _WORKER, path, mode],
        capture_output=True, text=True, check=True, cwd=os.getcwd(),
    )
    return json.loads(out.stdout.strip())["bytes"]


def test_verify_prune_python_memory_flat(tmp_path):
    small = str(tmp_path / "small.db")
    big = str(tmp_path / "big.db")
    _build(small, 20, 200)      # 800 entries
    _build(big, 400, 4000)     # 16000 entries（20x）

    v_small = _run_worker(small, "verify")
    v_big = _run_worker(big, "verify")
    # Python 层峰值近似常数：20 倍条目数，增长不得超过一个很松的常数余量。
    assert v_big < v_small + 2_000_000, ("verify", v_small, v_big)

    p_small = _run_worker(small, "prune")
    p_big = _run_worker(big, "prune")
    assert p_big < p_small + 2_000_000, ("prune", p_small, p_big)


def test_value_at_uses_field_index_only(tmp_path):
    from brandpulse.timeutil import to_micros
    path = str(tmp_path / "s.db")
    st = AuditStore(path, KEY, verify_on_open=False)
    base = datetime(2024, 1, 1, tzinfo=UTC)
    for w in range(300):
        st.set_fields(f"ent{w}", {"f": f"v{w}"}, "a", base + timedelta(hours=w))
    plan = st.conn.execute(
        "EXPLAIN QUERY PLAN SELECT new FROM entries WHERE entity=? AND field=? "
        "AND at<=? ORDER BY seq DESC LIMIT 1",
        ("ent5", "f", to_micros(base + timedelta(hours=1000))),
    ).fetchall()
    detail = " ".join(str(r) for r in plan)
    assert "SCAN entries" not in detail, detail
    st.close()
