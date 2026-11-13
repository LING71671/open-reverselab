---
id: "ctf-website/12-payment/payment-bypass-defense"
title: "支付绕过纵深防御 — 服务端权威计价、状态机与精度控制"
title_en: "Payment Bypass Defense — Server-Authoritative Pricing, State Machine & Precision Controls"
summary: >
  针对参数篡改、跨语言类型混淆、浮点精度舍入、状态机回退、Mass Assignment 与并发优惠券叠加等支付绕过攻击，
  建立服务端权威计价（Integer Cents / Decimal）、严格 DTO 白名单绑定、单向状态机与跨账本对账防御体系。
summary_en: >
  Defense-in-depth against payment bypass attacks including parameter tampering, cross-language type confusion,
  floating-point precision abuse, state machine rollback, mass assignment, and concurrent coupon stacking via
  server-authoritative integer-cent pricing, strict DTO allowlists, monotonic state machines, and cross-ledger reconciliation.
board: "ctf-website"
category: "12-payment"
signals: ["Payment Bypass", "支付防御", "权威计价", "状态机校验", "精度控制", "DTO白名单", "防重放", "账本一致性"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "kb_catalog"]
keywords: ["支付防御", "payment hardening", "integer cents", "单向状态机", "服务端计价", "类型强校验", "CWE-840", "CWE-472"]
difficulty: "advanced"
tags: ["defense", "blue-team", "hardening", "payment", "state-machine", "precision", "web-security"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/12-payment/payment-bypass", "ctf-website/12-payment/payment-callback-async-defense", "ctf-website/12-payment/payment-race-lost-update-defense", "ctf-website/15-mass-assignment/02-parameter-tampering-defense"]
track: "blue"
defends: "ctf-website/12-payment/payment-bypass"
---
# 支付绕过纵深防御 — 服务端权威计价、状态机与精度控制

> 配对攻击手册：[payment-bypass.md](../../../../red/ctf-website/techniques/12-payment/payment-bypass.md)。防御核心原则：客户端只提交意图（`sku_id`、`quantity`、`coupon_code`、`currency`），金额、折扣、税费、状态转移与发货决策全部由服务端依据持久化账本重新计算并强类型校验。

## 威胁模型与控制映射

| 攻击向量 | 典型利用点 | 根因 | 防御控制措施 |
|---|---|---|---|
| 参数篡改与 SKU 错配 | 修改 `price`/`total`/`tax`/`shipping` 或低价 SKU 携带高价权益 | 信任客户端传入金额或未重查目录价格 | 服务端按 `sku_id` 查主库单价并重算全量账单（含税费/运费） |
| 跨语言类型混淆 | JSON 传 `NaN`/`Infinity`/`"1e-9"`/数组/`"0e123"`/科学计数法 | 弱类型语言隐式转换（`==`、JS `Number()`、`float` 强转） | 严格 Schema 校验（拒绝非有限数、字符串数字、布尔和对象），全链路使用全等与定点数 |
| 浮点精度与舍入滥用 | `0.1 + 0.2` 误差、分币四舍五入归零、负数数量/金额 | 使用 IEEE 754 `float`/`double` 存金额 | 内部统一采用最小货币单位整数（如分 `int`）或 `Decimal` + `ROUND_HALF_UP` 且校验 `amount > 0` |
| 状态机回退与跳步 | 直接传 `status=paid`、从 `refunded` 回退到 `fulfilled` | 缺乏单向状态转换表或直接透传 ORM 字段 | 显式有限状态机（FSM）+ SQL 条件更新 `WHERE id=? AND status=?` |
| 货币与通道降级 | 支付 VND/JPY 充当 USD；沙盒通道充当生产通道 | 订单与网关货币/渠道未强绑定 | 下单时锁定 `currency` 与 `channel`，回调时强制比对 `currency`、`amount_minor`、`merchant_id` |
| 优惠券叠加与超时窗口 | 同一优惠券并发多次核销、负折扣变加钱、超时后仍低价结算 | 先读后写未加锁、允许无互斥标签叠加 | 数据库唯一约束 `(order_id, coupon_id)` + `SELECT ... FOR UPDATE` + 折扣封顶 `max(0, total - discount)` |

## 核心加固实现

### 1. 强类型输入边界与最小货币单位计价

```python
# payment_authoritative_pricing.py — 服务端权威计价与强类型边界校验
from decimal import Decimal, ROUND_HALF_UP, InvalidOperation
from dataclasses import dataclass
from typing import Dict, List

SUPPORTED_CURRENCIES = {"USD": 100, "CNY": 100, "JPY": 1}

@dataclass(frozen=True)
class SkuCatalogItem:
    sku_id: str
    unit_price_minor: int
    currency: str
    active: bool = True

class PricingValidationError(ValueError):
    pass

def strict_positive_int(val, field: str, max_val: int = 1000) -> int:
    # 拒绝 bool (Python 中 isinstance(True, int) 为 True)、float、str、None
    if type(val) is not int:
        raise PricingValidationError(f"{field} must be strict int, got {type(val).__name__}")
    if val <= 0 or val > max_val:
        raise PricingValidationError(f"{field} out of range: {val}")
    return val

def calculate_authoritative_order(
    catalog: Dict[str, SkuCatalogItem],
    items: List[dict],
    requested_currency: str,
    discount_rate_bps: int = 0,  # 基点 0..5000 (最高 50%)
    tax_bps: int = 800,
) -> dict:
    if requested_currency not in SUPPORTED_CURRENCIES:
        raise PricingValidationError("unsupported currency")
    if not isinstance(items, list) or not items:
        raise PricingValidationError("items must be non-empty list")
    if type(discount_rate_bps) is not int or not (0 <= discount_rate_bps <= 5000):
        raise PricingValidationError("invalid discount bps")

    subtotal_minor = 0
    normalized_lines = []
    for raw in items:
        if not isinstance(raw, dict):
            raise PricingValidationError("invalid line item")
        sku_id = raw.get("sku_id")
        if type(sku_id) is not str or sku_id not in catalog:
            raise PricingValidationError("unknown sku")
        sku = catalog[sku_id]
        if not sku.active or sku.currency != requested_currency:
            raise PricingValidationError("sku inactive or currency mismatch")
        qty = strict_positive_int(raw.get("quantity"), "quantity")
        line_total = sku.unit_price_minor * qty
        subtotal_minor += line_total
        normalized_lines.append({"sku_id": sku_id, "qty": qty, "line_minor": line_total})

    discount_minor = (subtotal_minor * discount_rate_bps) // 10000
    discounted = max(subtotal_minor - discount_minor, 0)
    tax_minor = int(
        (Decimal(discounted) * Decimal(tax_bps) / Decimal(10000)).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    )
    grand_total_minor = discounted + tax_minor
    if grand_total_minor <= 0:
        raise PricingValidationError("zero or negative total requires explicit free-tier workflow")

    return {
        "currency": requested_currency,
        "lines": normalized_lines,
        "subtotal_minor": subtotal_minor,
        "discount_minor": discount_minor,
        "tax_minor": tax_minor,
        "grand_total_minor": grand_total_minor,
    }
```

### 2. 单向支付状态机与六账本不变量校验

```python
# payment_fsm_guard.py — 显式状态机与跨账本一致性自检
ALLOWED_TRANSITIONS = {
    "CREATED": {"PENDING_PAYMENT", "CANCELLED", "EXPIRED"},
    "PENDING_PAYMENT": {"PAID", "FAILED", "EXPIRED", "CANCELLED"},
    "PAID": {"FULFILLED", "REFUND_PENDING"},
    "FULFILLED": {"REFUND_PENDING"},
    "REFUND_PENDING": {"REFUNDED", "PAID"},
    "REFUNDED": set(),
    "CANCELLED": set(),
    "EXPIRED": set(),
}

def transition_order_state(current: str, target: str) -> str:
    if current not in ALLOWED_TRANSITIONS:
        raise ValueError(f"unknown state: {current}")
    if target not in ALLOWED_TRANSITIONS[current]:
        raise PermissionError(f"illegal transition: {current} -> {target}")
    return target

def assert_ledger_invariant(order: dict, payment: dict, fulfillment: dict) -> None:
    """在发货前及对账任务中强制执行的不变量检查。"""
    assert order["currency"] == payment["currency"], "currency mismatch across ledgers"
    assert order["grand_total_minor"] == payment["captured_minor"], "captured amount mismatch"
    assert payment["channel"] == order["locked_channel"], "gateway channel downgraded"
    assert payment["is_sandbox"] is False, "sandbox receipt rejected in production"
    assert order["status"] in {"PAID", "FULFILLED"}, f"unpaid order cannot fulfill: {order['status']}"
    assert fulfillment["order_id"] == order["order_id"], "entitlement bound to wrong order"

if __name__ == "__main__":
    # 回归自检：验证类型混淆拒绝、单向状态机与对账不变量
    catalog = {"pro-plan": SkuCatalogItem("pro-plan", 9900, "USD")}
    res = calculate_authoritative_order(catalog, [{"sku_id": "pro-plan", "quantity": 2}], "USD", discount_rate_bps=1000)
    assert res["grand_total_minor"] == 19246  # 19800 - 1980 = 17820; tax 8% = 1426; sum = 19246
    for bad_qty in (0, -1, True, 1.5, "1", "1e2"):
        try:
            strict_positive_int(bad_qty, "quantity")
            raise AssertionError(f"should reject {bad_qty!r}")
        except PricingValidationError:
            pass
    assert transition_order_state("CREATED", "PENDING_PAYMENT") == "PENDING_PAYMENT"
    try:
        transition_order_state("REFUNDED", "PAID")
        raise AssertionError("should block rollback from REFUNDED")
    except PermissionError:
        pass
    assert_ledger_invariant(
        {"order_id": "ord-1", "currency": "USD", "grand_total_minor": 19246, "locked_channel": "stripe_prod", "status": "PAID"},
        {"currency": "USD", "captured_minor": 19246, "channel": "stripe_prod", "is_sandbox": False},
        {"order_id": "ord-1"},
    )
    print("payment-bypass-defense self-check passed")
```

## 防御工作流

```text
1. 边界收口：移除下单与结算 DTO 中的 price/amount/status/discount 等内部计算字段，启用严格类型反序列化。
2. 账本统一：将全链路金额字段迁移为最小货币单位整数（_minor）并绑定 ISO-4217 currency 与商户/环境标识。
3. 状态机锁：在数据访问层落地 ALLOWED_TRANSITIONS 与条件更新（CAS: WHERE status = expected），禁止任意字段写回。
4. 并发防护：为优惠券核销、库存扣减与支付确认增加行级悲观锁或唯一幂等键约束。
5. 对账闭环：在发货前与 T+1 对账任务中运行账本不变量断言，拦截任何金额、币种或沙盒通道异常。
```

## 验证与判定标准

- **输入抗畸变**：对下单接口提交 `amount=0`、负数、`NaN`、布尔 `true`、科学计数法字符串及 `status="paid"` 时，服务端返回 `400/422` 或完全忽略客户端价格，持久化订单仍按服务端目录价生成。
- **状态机单向性**：跳过 `PENDING_PAYMENT` 直接请求发货，或对 `REFUNDED`/`CANCELLED` 订单重放确认接口，均返回 `409 Conflict` 且数据库状态零变更。
- **沙盒与币种隔离**：生产环境拒绝任何 `is_sandbox=true` 凭据或跨币种回调，发货前六账本不变量检查全部通过。

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 结算接口回归探测 | `http_probe` | 验证上线后边界拒绝码（`400/422/409`）与响应一致性 |
| 关联脆弱点检索 | `kb_router` | 检索关联的并发、回调与批量赋值防御文档 |
| 配对攻击细节对照 | `kb_read_file` | 对照读取 `ctf-website/12-payment/payment-bypass` 复核已覆盖向量 |
| 目录能力盘点 | `kb_catalog` | 列出支付与访问控制类防御条目构建加固基线 |
