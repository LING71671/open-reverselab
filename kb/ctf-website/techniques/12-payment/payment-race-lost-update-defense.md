---
id: "ctf-website/12-payment/payment-race-lost-update-defense"
title: "余额扣减丢失更新 (Lost Update) 防御 — 条件原子更新、行锁与复式账本"
title_en: "Balance Deduction Lost Update Defense — Atomic Conditional Updates, Row Locks & Double-Entry Ledgers"
summary: >
  针对余额、积分与配额系统中 read-modify-write 非原子操作导致的并发丢失更新（Lost Update）漏洞，
  提供数据库条件原子扣减（WHERE balance >= amount）、悲观行锁（FOR UPDATE）、乐观版本号 CAS 与复式不可变账本防线。
summary_en: >
  Prevents lost-update race conditions in balance, credit, and quota systems caused by non-atomic read-modify-write
  patterns using conditional atomic SQL updates, SELECT FOR UPDATE pessimistic locks, optimistic CAS versioning,
  and immutable double-entry ledgers with CHECK constraints.
board: "ctf-website"
category: "12-payment"
signals: ["lost update防御", "并发扣款锁", "原子更新", "SELECT FOR UPDATE", "CAS版本号", "复式记账", "TOCTOU防护"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "kb_catalog"]
keywords: ["lost update defense", "atomic balance update", "SELECT FOR UPDATE", "optimistic locking", "double entry ledger", "concurrency control"]
difficulty: "advanced"
tags: ["defense", "blue-team", "hardening", "payment", "race-condition", "concurrency", "database"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/12-payment/payment-race-lost-update", "ctf-website/12-payment/payment-bypass-defense", "ctf-website/15-mass-assignment/02-parameter-tampering-defense"]
track: "blue"
defends: "ctf-website/12-payment/payment-race-lost-update"
---
# 余额扣减丢失更新 (Lost Update) 防御 — 条件原子更新、行锁与复式账本

> 配对攻击手册：[payment-race-lost-update.md](./payment-race-lost-update.md)。Lost Update 的本质是：应用层在事务外（或 `READ COMMITTED` 下未加锁）读取旧余额 `B`，计算 `B - cost` 后写回，导致并发请求彼此覆盖扣减结果。根治必须将“校验 + 扣减”下沉到数据库单条原子语句或悲观行锁事务中。

## 威胁模型与控制映射

| 脆弱模式 | 并发失效机制 | 推荐数据库/架构防线 |
|---|---|---|
| 应用层 `SELECT -> check -> UPDATE SET balance = new_val` | 两个并发事务同时读到 `balance=100`，各自算出 `70` 并写回，消费 2 次只扣 1 次 | **单条条件原子更新**：`UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?` 并检查 `rowcount == 1` |
| 先扣 Redis 缓存再异步写库 / 分布式锁超时 | 缓存与 DB 双写不一致，或 GC/网络抖动导致锁提前过期 | 以关系型数据库行锁为唯一权威状态机；幂等键 `UNIQUE(request_id)` 落同事务 |
| 缺乏 `CHECK (balance >= 0)` 约束 | 逻辑绕过时余额被扣成负数仍继续发货 | DDL 层强制增加 `CONSTRAINT chk_non_negative CHECK (balance >= 0)` 兜底 |
| 多步业务涉及余额 + 库存 + 订单状态 | 仅靠 `UPDATE` 无法跨多表保持快照一致性 | 在 `BEGIN` 事务内对目标账户行按统一主键顺序执行 `SELECT ... FOR UPDATE`，或使用乐观锁 `version = version + 1` |
| 重试风暴或同一请求并发重放 | 网关重试或客户端并发发同笔扣款请求 | 接口强制要求客户端生成 `idempotency_key`，写入 `UNIQUE(user_id, idempotency_key)` 流水表后执行扣款 |

## 核心加固实现

### 1. 生产级 SQL 原子扣减与复式流水模板

```sql
-- 1) 账户表强制非负约束与乐观版本号
CREATE TABLE IF NOT EXISTS wallet_accounts (
    account_id BIGINT PRIMARY KEY,
    balance_minor BIGINT NOT NULL CHECK (balance_minor >= 0),
    version BIGINT NOT NULL DEFAULT 0
);

-- 2) 不可变流水表 + 幂等唯一键（同事务落盘）
CREATE TABLE IF NOT EXISTS wallet_ledger (
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id BIGINT NOT NULL,
    idempotency_key TEXT NOT NULL,
    delta_minor BIGINT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(account_id, idempotency_key)
);

-- 3) 原子条件扣减（在事务中先插入幂等流水再扣余额，rowcount != 1 立即 ROLLBACK）
-- UPDATE wallet_accounts
-- SET balance_minor = balance_minor - :cost, version = version + 1
-- WHERE account_id = :id AND balance_minor >= :cost;
```

### 2. SQLite / Python 多线程并发扣款竞态自检验证

```python
# race_deduction_guard.py — 对比验证原子条件扣减 + 幂等键在高并发下的不变量
import sqlite3
import threading

def init_db(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY, balance INTEGER NOT NULL CHECK(balance >= 0))")
    conn.execute("CREATE TABLE IF NOT EXISTS ledger (id INTEGER PRIMARY KEY AUTOINCREMENT, account_id INTEGER, idem_key TEXT, delta INTEGER, UNIQUE(account_id, idem_key))")
    conn.execute("INSERT OR REPLACE INTO accounts (id, balance) VALUES (1, 100)")
    conn.execute("DELETE FROM ledger")
    conn.commit()
    conn.close()

def atomic_deduct(db_path: str, account_id: int, cost: int, idem_key: str) -> bool:
    if cost <= 0:
        raise ValueError("cost must be positive")
    conn = sqlite3.connect(db_path, timeout=10.0, isolation_level=None)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "INSERT INTO ledger (account_id, idem_key, delta) VALUES (?, ?, ?)",
                (account_id, idem_key, -cost),
            )
        except sqlite3.IntegrityError:
            conn.execute("ROLLBACK")
            return False  # 幂等键已存在，拦截重放

        cur = conn.execute(
            "UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?",
            (cost, account_id, cost),
        )
        if cur.rowcount != 1:
            conn.execute("ROLLBACK")
            return False  # 余额不足，整事务回滚（含流水）
        conn.execute("COMMIT")
        return True
    finally:
        conn.close()

if __name__ == "__main__":
    import tempfile, os
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        init_db(path)
        # 场景 1: 20 个并发请求各扣 30 元（初始 100 元，最多成功 3 次，余额必为 10）
        results = []
        barrier = threading.Barrier(20)
        def worker(i: int):
            barrier.wait()
            results.append(atomic_deduct(path, 1, 30, f"req-{i}"))
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads: t.start()
        for t in threads: t.join()

        success_count = sum(1 for r in results if r)
        conn = sqlite3.connect(path)
        final_balance = conn.execute("SELECT balance FROM accounts WHERE id = 1").fetchone()[0]
        ledger_sum = conn.execute("SELECT COALESCE(SUM(delta), 0) FROM ledger").fetchone()[0]
        conn.close()

        assert success_count == 3, f"expected 3 successes, got {success_count}"
        assert final_balance == 10, f"expected balance 10, got {final_balance}"
        assert 100 + ledger_sum == final_balance, "ledger sum diverged from balance"

        # 场景 2: 相同幂等键重放测试
        assert atomic_deduct(path, 1, 5, "same-key") is True
        assert atomic_deduct(path, 1, 5, "same-key") is False
        print("payment-race-lost-update-defense self-check passed")
    finally:
        for ext in ("", "-wal", "-shm"):
            if os.path.exists(path + ext):
                os.remove(path + ext)
```

## 防御工作流

```text
1. 消除 Read-Modify-Write：在余额、积分、配额、库存模块中搜索 `account.balance -= x; account.save()`，全部改为数据库条件原子更新或 `SELECT ... FOR UPDATE`。
2. 落盘幂等约束：将 `idempotency_key` 唯一索引与余额扣减置于同一本地数据库事务中，杜绝部分成功。
3. 施加物理兜底：为所有资产余额列添加 `CHECK (balance_minor >= 0)` 数据库约束。
4. 统一加锁序：跨账户转账按 `min(from_id, to_id)` 到 `max(from_id, to_id)` 固定顺序加行锁，消除死锁。
5. 并发压测回归：上线前用 Barrier 同步 20+ 并发线程轰炸扣款与优惠券接口，核验三账本（请求成功数、余额终值、流水总和）严格一致。
```

## 验证与判定标准

- **高并发不变量守恒**：初始余额 100 元并发发起 20 笔 30 元扣款，成功次数严格等于 `3`，剩余余额严格等于 `10`，且 `initial + SUM(ledger.delta) == final_balance`。
- **同幂等键零双扣**：携带相同 `idempotency_key` 并发重放 10 次，仅 1 次实际扣款并生成 1 条流水。
- **零负余额可能**：数据库层面尝试直接更新为负值触发 `CHECK constraint failed` 异常。

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 并发扣款边界验证 | `http_probe` | 验证重复幂等键与超额扣款请求返回 `409/400` |
| 参数篡改与支付防线关联 | `kb_router` | 检索优惠券并发控制与支付状态机防御文档 |
| 配对攻击细节对照 | `kb_read_file` | 对照读取 `ctf-website/12-payment/payment-race-lost-update` 复核防御效果 |
| 知识库防御索引 | `kb_catalog` | 查看所有支付与数据库并发防护条目 |
