---
id: "ctf-website/12-payment/payment-logic-defense"
title: "支付业务逻辑纵深防御 — 多账本一致性、防注入与闭环校验"
title_en: "Payment Business Logic Defense — Multi-Ledger Consistency, Injection Isolation & Closed-Loop Validation"
summary: >
  针对支付链路中路由暴露、客户端价格信任、状态机跳转、回调伪造、订单 IDOR、优惠券/积分组合滥用以及 SQLi/NoSQLi
  引发的账本错位，建立端到端支付逻辑加固框架：权威账本分离、参数化账务读写、防跳转网关与全链不变量自检。
summary_en: >
  End-to-end defense for payment business logic flaws covering exposed admin routes, client price trust, state
  machine jumps, forged callbacks, order IDOR, coupon/points chaining, and SQLi/NoSQLi ledger desynchronization
  via separated authoritative ledgers, parameterized queries, redirect allowlists, and invariant checks.
board: "ctf-website"
category: "12-payment"
signals: ["Payment Logic", "支付逻辑防御", "账本一致性", "状态机保护", "防SQLi账本篡改", "Open Redirect防护", "优惠券封顶"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "kb_catalog"]
keywords: ["payment logic defense", "ledger consistency", "支付业务逻辑安全", "账本不变量", "优惠券积分互斥", "CWE-840"]
difficulty: "advanced"
tags: ["defense", "blue-team", "hardening", "payment", "logic-flaw", "state-machine", "database"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/12-payment/payment-logic", "ctf-website/12-payment/payment-bypass-defense", "ctf-website/24-database/02-sqli-advanced-defense"]
track: "blue"
defends: "ctf-website/12-payment/payment-logic"
---
# 支付业务逻辑纵深防御 — 多账本一致性、防注入与闭环校验

> 配对攻击手册：[payment-logic.md](../../../../red/ctf-website/techniques/12-payment/payment-logic.md)。支付逻辑脆弱点往往不是单一漏洞，而是“前端传参 + SQL/NoSQL 过滤不严 + 回调/退款状态机脱节”造成的账本分歧。防御目标是在任意局部异常时阻断非法资产转移。

## 威胁模型与控制映射

| 攻击面 | 脆弱根因 | 防御控制措施 |
|---|---|---|
| 调试路由与前端泄漏 | 生产环境保留 `/api/payment/mock_pay`、`/debug/ledger` 或前端 JS 暴露内部签名密钥 | 构建流水线剔除 mock/debug 路由，网关默认拒绝未注册路径，密钥严禁进前端包 |
| “谁说了算”账本错位 | 订单表、支付表、发货表分别由不同接口写入且互相不校验实付金额 | 确立单一权威支付账本（`payments.verified_minor`），发货前必须与 `orders.expected_minor` 强比对 |
| SQLi / NoSQLi 串联篡改账本 | 订单查询、优惠券校验或结算排序拼接用户输入，导致 `status='paid'` 被注入篡改 | 所有账务表全部使用预编译参数化查询，且数据库账号按职责分离（应用库账号禁止直接 `UPDATE payments.verified` 无日志字段） |
| 优惠券 + 积分 + 余额组合套利 | 组合顺序不固定、允许积分抵扣后按原价退款或负余额抵扣 | 固定计算管线顺序：`商品原价 -> 满减/单张优惠券 -> 积分抵扣 -> 实付现金`；退款严格按实付现金原路退回 |
| `return_url` Open Redirect / SSRF | 支付成功后直接 `302` 跳转至未校验的 `return_url` 或服务端回调内网 | 仅接收相对路径或后台白名单域名；禁止任何用户可控字段进入服务端出站请求 |
| 订单 IDOR 越权代付/篡改 | 使用他人 `order_id` 修改收货地址、切换优惠券或窃取发票 | 订单读写与状态变更均校验 `order.owner_id == current_session.user_id` |

## 核心加固实现

### 1. 组合抵扣结算管线与防套利退款约束

```python
# payment_pipeline_guard.py — 固定抵扣管线与实付退款封顶校验
from dataclasses import dataclass

@dataclass
class SettlementBreakdown:
    gross_minor: int
    coupon_discount_minor: int
    points_used_minor: int
    cash_paid_minor: int

def compute_settlement(
    gross_minor: int,
    coupon_discount_minor: int,
    points_balance_minor: int,
    requested_points_minor: int,
) -> SettlementBreakdown:
    if gross_minor <= 0:
        raise ValueError("gross_minor must be positive")
    if coupon_discount_minor < 0 or requested_points_minor < 0:
        raise ValueError("negative discount or points forbidden")

    # 固定顺序 1: 优惠券上限不超过商品总额
    applied_coupon = min(coupon_discount_minor, gross_minor)
    after_coupon = gross_minor - applied_coupon

    # 固定顺序 2: 积分仅能抵扣折后剩余部分且不超过用户实际余额
    if requested_points_minor > points_balance_minor:
        raise ValueError("insufficient points balance")
    applied_points = min(requested_points_minor, after_coupon)

    cash_due = after_coupon - applied_points
    return SettlementBreakdown(
        gross_minor=gross_minor,
        coupon_discount_minor=applied_coupon,
        points_used_minor=applied_points,
        cash_paid_minor=cash_due,
    )

def validate_refund_amount(breakdown: SettlementBreakdown, already_refunded_minor: int, request_refund_minor: int) -> int:
    """防止用低价实付订单套取全额原价现金退款。"""
    if request_refund_minor <= 0:
        raise ValueError("refund must be positive")
    remaining_cash_refundable = breakdown.cash_paid_minor - already_refunded_minor
    if request_refund_minor > remaining_cash_refundable:
        raise PermissionError("refund exceeds actual cash paid")
    return request_refund_minor
```

### 2. 重定向白名单与跨账本权威校验器

```python
# ledger_authority_guard.py — 账本一致性与安全跳转校验
from urllib.parse import urlparse

ALLOWED_REDIRECT_HOSTS = {"shop.example.com", "pay.example.com"}

def sanitize_return_url(raw_url: str, default_path: str = "/orders") -> str:
    if not raw_url:
        return default_path
    # 拒绝协议相对路径 //evil.com 与反斜杠混淆
    if raw_url.startswith("/") and not raw_url.startswith("//") and "\\" not in raw_url:
        return raw_url
    parsed = urlparse(raw_url)
    if parsed.scheme == "https" and (parsed.hostname or "").lower() in ALLOWED_REDIRECT_HOSTS:
        return raw_url
    return default_path

def verify_cross_ledger_consistency(order_row: dict, payment_row: dict, owner_id: str) -> None:
    if order_row["owner_id"] != owner_id:
        raise PermissionError("order owner mismatch")
    if payment_row["order_id"] != order_row["id"]:
        raise PermissionError("payment order linkage mismatch")
    if payment_row["status"] != "CAPTURED":
        raise PermissionError("payment not captured")
    if payment_row["amount_minor"] != order_row["cash_due_minor"]:
        raise PermissionError("ledger amount divergence detected")

if __name__ == "__main__":
    bd = compute_settlement(gross_minor=10000, coupon_discount_minor=3000, points_balance_minor=5000, requested_points_minor=2000)
    assert bd.cash_paid_minor == 5000
    assert validate_refund_amount(bd, already_refunded_minor=0, request_refund_minor=5000) == 5000
    try:
        validate_refund_amount(bd, already_refunded_minor=0, request_refund_minor=8000)
        raise AssertionError("should block refund exceeding cash paid")
    except PermissionError:
        pass
    assert sanitize_return_url("//evil.com/steal") == "/orders"
    assert sanitize_return_url("https://shop.example.com/done") == "https://shop.example.com/done"
    verify_cross_ledger_consistency(
        {"id": "o1", "owner_id": "u1", "cash_due_minor": 5000},
        {"order_id": "o1", "status": "CAPTURED", "amount_minor": 5000},
        "u1",
    )
    print("payment-logic-defense self-check passed")
```

## 防御工作流

```text
1. 清理测试入口：扫描路由表并下线所有 mock_pay、sandbox_bypass 与未受保护的对账调试端点。
2. 固定结算管线：强制服务端按“原价 -> 单券/规则折扣 -> 积分 -> 实付现金”顺序落库，并记录分项明细。
3. 账务查询参数化：彻底消除 SQL/NoSQL 字符串拼接，对排序字段、状态枚举采用静态映射白名单。
4. 跨账本门禁：发货服务仅认 `payments` 权威实付记录与 `orders.cash_due_minor` 全等匹配，不信前端或缓存状态。
5. 跳转与回调收敛：校验 `return_url` 白名单，禁止跳转携带敏感 token 或订单内部密钥。
```

## 验证与判定标准

- **套利组合拦截**：对 100 元商品使用 30 元券 + 20 元积分后，申请退款上限严格锁定为 50 元现金，超额请求返回 `400/403`。
- **账本分歧阻断**：人为篡改中间态缓存或提交不匹配实付金额的回调，发货校验器立即拦截并触发告警。
- **跳转安全**：`return_url=//evil.com` 或 `https://attacker.tld` 均被回落至默认安全路径 `/orders`。

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 结算与跳转边界探测 | `http_probe` | 验证异常 `return_url`、超额退款与越权订单访问的拦截结果 |
| 关联数据库防线检索 | `kb_router` | 检索 SQLi/NoSQLi 防御与并发锁方案 |
| 配对攻击细节对照 | `kb_read_file` | 对照读取 `ctf-website/12-payment/payment-logic` 复核业务链覆盖度 |
| 支付防御总览 | `kb_catalog` | 检索支付安全全部防御条目 |
