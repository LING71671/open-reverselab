---
id: "ctf-website/15-mass-assignment/02-parameter-tampering-defense"
title: "参数篡改与优惠券竞态防御 — 契约校验、不可变折扣账本与防 TOCTOU"
title_en: "Parameter Tampering & Coupon Race Defense — Contract Validation, Immutable Discount Ledgers & Anti-TOCTOU"
summary: >
  针对价格/数量/货币参数篡改、优惠券批量盗领、弱券码预测、优惠叠加及 GrandNode 类 TOCTOU 并发核销漏洞，
  提供服务端契约重算、高熵一次性券码、原子状态机核销与统一记账币种绑定方案。
summary_en: >
  Defends against price/quantity/currency tampering, coupon batch harvesting, predictable coupon codes,
  discount stacking, and TOCTOU coupon race conditions (such as GrandNode CVE-2025-10216) using server-side
  contract recalculation, cryptographic coupon tokens, atomic redemption locks, and currency locking.
board: "ctf-website"
category: "15-mass-assignment"
signals: ["参数篡改防御", "优惠券并发锁", "TOCTOU防护", "货币锁定", "折扣封顶", "CWE-20"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "kb_catalog"]
keywords: ["parameter tampering defense", "coupon race protection", "TOCTOU prevention", "currency pinning", "CWE-20"]
difficulty: "advanced"
tags: ["defense", "blue-team", "hardening", "parameter-tampering", "coupon", "race-condition", "cwe-20"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/15-mass-assignment/02-parameter-tampering", "ctf-website/12-payment/payment-bypass-defense", "ctf-website/12-payment/payment-race-lost-update-defense"]
track: "blue"
defends: "ctf-website/15-mass-assignment/02-parameter-tampering"
---
# 参数篡改与优惠券竞态防御 — 契约校验、不可变折扣账本与防 TOCTOU

> 配对攻击手册：[02-parameter-tampering.md](./02-parameter-tampering.md)。参数篡改与优惠券竞态的核心防线在于“服务端契约闭环”：价格与汇率不由请求决定，优惠券领取与核销必须在同一数据库原子语句中完成配额扣减与去重。

## 威胁模型与控制映射

| 攻击向量 | 典型缺陷 | 防御控制措施 |
|---|---|---|
| 价格与数量操纵（0/负数/NaN/小数） | 仅在前端校验 `qty >= 1`，后端允许 `qty = -5` 或 `qty = 0.001` | 后端 Schema 强制 `quantity: int` 且 `1 <= qty <= max_per_order`；单价一律由服务端查商品主表 |
| 优惠券代码预测与批量领取 | 使用连续数字/短字母券码且领取接口无速率限制与单账号限额 | 券码采用 CSPRNG ≥ 10 字节随机串；领取写入 `UNIQUE(coupon_batch_id, user_id)` 防止重复领券 |
| 优惠券并发核销（TOCTOU） | 先查 `coupon.used < limit`，下单完成后再 `coupon.used += 1` | **单条原子抢占**：`UPDATE coupons SET remaining = remaining - 1 WHERE code = ? AND remaining > 0 AND expires_at > NOW()` 并结合 `UNIQUE(coupon_id, order_id)` |
| 跨订单/超时窗口复用（GrandNode 类缺陷） | 校验时间与锁定时间分离，或退款取消后未回滚/作废已消费标记 | 在订单锁定事务内一次性扣减券配额并写入核销流水；单券未明确标记 `stackable` 时互斥排他 |
| 货币与汇率混淆 | 传 `currency=VND` 配合 `USD` 单价数值，或利用过期汇率套利 | 商品目录按币种分别定价（非实时按前端币种换算）；支付网关金额、币种与订单下单时锁定快照完全一致 |

## 核心加固实现

### 1. 原子优惠券抢占与并发防 TOCTOU 验证器

```python
# coupon_atomic_guard.py — 原子核销优惠券与防叠加/TOCTOU 并发验证
import sqlite3
import threading
from dataclasses import dataclass

@dataclass(frozen=True)
class CouponPolicy:
    code: str
    discount_bps: int
    stack_group: str  # 同一互斥组不可叠加
    expires_epoch: int

def init_coupon_db(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("CREATE TABLE IF NOT EXISTS coupons (code TEXT PRIMARY KEY, remaining INTEGER NOT NULL CHECK(remaining >= 0), expires_at INTEGER NOT NULL, stack_group TEXT NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS coupon_redemptions (id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT NOT NULL, user_id TEXT NOT NULL, order_id TEXT NOT NULL, stack_group TEXT NOT NULL, UNIQUE(code, user_id), UNIQUE(order_id, stack_group))")
        conn.execute("INSERT OR REPLACE INTO coupons (code, remaining, expires_at, stack_group) VALUES ('VIP20', 1, 9999999999, 'promo')")
        conn.execute("DELETE FROM coupon_redemptions")
        conn.commit()
    finally:
        conn.close()

def atomic_redeem_coupon(db_path: str, code: str, user_id: str, order_id: str, now_epoch: int) -> bool:
    conn = sqlite3.connect(db_path, timeout=10.0, isolation_level=None)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT stack_group, expires_at FROM coupons WHERE code = ?", (code,)).fetchone()
        if not row or now_epoch > row[1]:
            conn.execute("ROLLBACK")
            return False
        stack_group = row[0]

        # 1) 原子扣减剩余次数，消除 check-then-act TOCTOU 窗口
        cur = conn.execute(
            "UPDATE coupons SET remaining = remaining - 1 WHERE code = ? AND remaining > 0 AND expires_at >= ?",
            (code, now_epoch),
        )
        if cur.rowcount != 1:
            conn.execute("ROLLBACK")
            return False

        # 2) 插入核销记录：同时限制单用户不可重复用同券 & 同订单互斥组不可叠加
        try:
            conn.execute(
                "INSERT INTO coupon_redemptions (code, user_id, order_id, stack_group) VALUES (?, ?, ?, ?)",
                (code, user_id, order_id, stack_group),
            )
        except sqlite3.IntegrityError:
            conn.execute("ROLLBACK")
            return False

        conn.execute("COMMIT")
        return True
    finally:
        conn.close()
```

### 2. 货币锁定与参数边界回归自检

```python
# parameter_contract_check.py — 币种锁定与并发核销自检
def lock_order_currency_price(catalog_prices: dict[tuple[str, str], int], sku: str, currency: str, qty: int) -> dict:
    if type(qty) is not int or not (1 <= qty <= 100):
        raise ValueError("quantity must be strict int in [1, 100]")
    if (sku, currency) not in catalog_prices:
        raise ValueError("currency not configured for sku")
    unit_minor = catalog_prices[(sku, currency)]
    return {"sku": sku, "currency": currency, "total_minor": unit_minor * qty}

if __name__ == "__main__":
    import os, tempfile
    assert lock_order_currency_price({("plan_a", "USD"): 2000, ("plan_a", "JPY"): 300000}, "plan_a", "JPY", 2)["total_minor"] == 600000
    for bad_qty in (0, -3, 1.5, True):
        try:
            lock_order_currency_price({("plan_a", "USD"): 2000}, "plan_a", "USD", bad_qty)
            raise AssertionError(f"should reject {bad_qty!r}")
        except ValueError:
            pass

    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        init_coupon_db(db_path)
        outcomes = []
        barrier = threading.Barrier(15)
        def worker(idx: int):
            barrier.wait()
            outcomes.append(atomic_redeem_coupon(db_path, "VIP20", f"u_{idx}", f"ord_{idx}", 1700000000))
        ts = [threading.Thread(target=worker, args=(i,)) for i in range(15)]
        for t in ts: t.start()
        for t in ts: t.join()
        assert sum(1 for x in outcomes if x) == 1, f"expected single redemption, got {sum(outcomes)}"
        print("02-parameter-tampering-defense self-check passed")
    finally:
        for ext in ("", "-wal", "-shm"):
            if os.path.exists(db_path + ext):
                os.remove(db_path + ext)
```

## 防御工作流

```text
1. 参数契约硬校验：所有数量、金额、折扣参数在入口层做强类型与上下界检查，拒绝浮点数量、非有限数及负数。
2. 货币维度独立定价：按 `(sku_id, currency)` 查表计价并在下单时锁定币种，严禁通过客户端传币种触发低价值汇率转换。
3. 券码高熵与领券去重：优惠券码采用不可预测随机串，领券表建 `UNIQUE(batch_id, user_id)` 防止并发刷券。
4. 核销单句原子化：将过期时间判断、配额扣减 `remaining > 0` 与 `coupon_redemptions` 互斥组唯一键放入同一事务，杜绝 TOCTOU。
5. 并发回归压测：利用 Barrier 并发对限量 1 次的优惠券发起 15+ 并发核销，确认仅 1 笔成功且数据库无负配额。
```

## 验证与判定标准

- **并发核销零超发**：剩余次数为 `1` 的优惠券面对 15 个并发不同账号请求时，仅 `1` 个成功核销，其余均返回失败且 `remaining == 0`。
- **互斥叠加零突破**：同一订单提交两张属于相同 `stack_group` 的优惠券，第二张触发唯一约束拒绝。
- **币种与数量边界牢固**：传入 `quantity=-1`、`quantity=0.5` 或未配置币种代码时，接口返回 `400/422`。

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 参数边界与并发核销探测 | `http_probe` | 验证畸形数量、未授权币种与重复券码请求的拦截状态 |
| 关联并发与支付防线 | `kb_router` | 检索丢失更新与支付绕过防御条目 |
| 配对攻击细节对照 | `kb_read_file` | 对照读取 `ctf-website/15-mass-assignment/02-parameter-tampering` 复核向量覆盖 |
| 知识库防御索引 | `kb_catalog` | 浏览参数校验与业务逻辑防护文档 |
