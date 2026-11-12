---
id: "ctf-website/12-payment/payment-subscription-defense"
title: "订阅与周期计费防御 — 试用反滥用、Proration 校验与 Seat 强绑定"
title_en: "Subscription & Recurring Billing Defense — Trial Anti-Abuse, Proration Verification & Seat Binding"
summary: >
  针对免费试用无限白嫖、计划升降级按比例计费（Proration）负值漏洞、自动续费宽限期状态残留、
  计量计费（Metered Billing）上报伪造、企业 Seat 超配额与 Stripe Webhook 顺序错乱，建立完整订阅风控与状态机防御体系。
summary_en: >
  Protects subscription and recurring billing platforms against trial abuse, proration calculation flaws,
  dunning grace-period entitlement leaks, metered billing tampering, seat limit bypass, and out-of-order
  Stripe webhooks using canonical billing state machines and server-side usage aggregation.
board: "ctf-website"
category: "12-payment"
signals: ["subscription defense", "试用风控", "proration校验", "续费宽限期", "metered billing", "seat配额", "Stripe webhook"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "kb_catalog"]
keywords: ["subscription hardening", "trial abuse prevention", "proration security", "seat enforcement", "Stripe billing defense", "dunning state machine"]
difficulty: "advanced"
tags: ["defense", "blue-team", "hardening", "payment", "subscription", "webhook", "saas"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/12-payment/payment-subscription", "ctf-website/12-payment/payment-callback-async-defense", "ctf-website/14-idor/01-idor-enumeration-defense"]
track: "blue"
defends: "ctf-website/12-payment/payment-subscription"
---
# 订阅与周期计费防御 — 试用反滥用、Proration 校验与 Seat 强绑定

> 配对攻击手册：[payment-subscription.md](./payment-subscription.md)。订阅系统的复杂性在于时间轴与多状态耦合：试用、升降级折算、续费失败宽限（Dunning）、用量计量与团队席位（Seat）必须由服务端单一计费引擎统一仲裁。

## 威胁模型与控制映射

| 攻击向量 | 典型缺陷 | 防御控制措施 |
|---|---|---|
| 免费试用无限滥用 | 仅按邮箱去重（支持 `+alias`/点号变体或临时邮箱）、绑定可注销重领 | 邮箱规范化去重 + 支付方式指纹（Stripe `card.fingerprint`）唯一试用配额 + 域名/设备风控 |
| 计划升降级 Proration 套利 | 允许高频切换计划触发负折算余额、降级立即退差价但保留高阶权益至期末 | 升级立即按天计费并先扣款后开权限；降级统一在当前周期结束（`cancel_at_period_end` / `schedule`）生效，不退现金仅折抵下期账单 |
| 自动续费失败权益残留 | `invoice.payment_failed` 后未降权，或无期限停留在 `past_due` 状态 | 明确 Dunning 状态机：`active -> past_due (限期宽限) -> unpaid/canceled`，到期定时任务强制回收高级权限 |
| 计量计费（Metered Billing）绕过 | 信任客户端上报的用量，或无配额硬熔断 | 用量由服务端 API 网关/后端消费者实时统计；超过套餐硬上限立即触发 `402/429` 拦截 |
| 企业 Seat 席位绕过 | 先并发邀请 100 名成员再校验 `seats_used <= seat_limit`，或踢人瞬间并发保留会话 | 成员邀请/激活在数据库事务内锁定团队行并执行 `CHECK (active_seats <= purchased_seats)`；移出成员立即撤销其 Token/Session |
| Webhook 乱序与伪造 | 未校验 `Stripe-Signature` 时间窗，或旧事件覆盖新周期状态 | 使用官方 SDK `Webhook.construct_event` 验签，并比较事件 `created` / `subscription.current_period_end` 单调推进状态 |

## 核心加固实现

### 1. 订阅 Proration 安全计算与升降级周期治理

```python
# subscription_billing_guard.py — Proration 非负校验与升级/降级策略控制
from dataclasses import dataclass

PLANS = {
    "free": {"monthly_minor": 0, "tier": 0, "max_seats": 1},
    "basic": {"monthly_minor": 1000, "tier": 1, "max_seats": 5},
    "pro": {"monthly_minor": 3000, "tier": 2, "max_seats": 25},
}

@dataclass
class Subscription:
    sub_id: str
    plan: str
    status: str  # active | past_due | canceled
    used_seats: int
    last_event_ts: int
    pending_downgrade_plan: str | None = None

def calculate_upgrade_charge_minor(current_plan: str, target_plan: str, remaining_days: int, cycle_days: int = 30) -> int:
    if current_plan not in PLANS or target_plan not in PLANS:
        raise ValueError("unknown plan")
    if not (0 < remaining_days <= cycle_days):
        raise ValueError("invalid remaining_days")
    cur_cfg, tgt_cfg = PLANS[current_plan], PLANS[target_plan]
    if tgt_cfg["tier"] <= cur_cfg["tier"]:
        raise ValueError("use schedule_downgrade for same or lower tier")

    diff_minor = tgt_cfg["monthly_minor"] - cur_cfg["monthly_minor"]
    charge = (diff_minor * remaining_days) // cycle_days
    return max(charge, 1)  # 升级至少收取最小单位，防止最后几小时免费升档

def schedule_downgrade(sub: Subscription, target_plan: str) -> str:
    if target_plan not in PLANS:
        raise ValueError("unknown plan")
    if PLANS[target_plan]["tier"] >= PLANS[sub.plan]["tier"]:
        raise ValueError("not a downgrade")
    if sub.used_seats > PLANS[target_plan]["max_seats"]:
        raise PermissionError("reduce active seats before scheduling downgrade")
    sub.pending_downgrade_plan = target_plan
    return "scheduled_for_period_end"
```

### 2. 试用卡指纹去重、Seat 原子绑定与 Webhook 单调推进

```python
# subscription_entitlement_guard.py — 试用去重、Seat 上限与事件时序保护
import re

def canonicalize_email_for_trial(email: str) -> str:
    local, _, domain = email.strip().lower().partition("@")
    if not local or not domain:
        raise ValueError("invalid email")
    local = local.split("+", 1)[0]
    if domain in {"gmail.com", "googlemail.com"}:
        local = local.replace(".", "")
    return f"{local}@{domain}"

class TrialRegistry:
    def __init__(self):
        self.used_emails: set[str] = set()
        self.used_card_fingerprints: set[str] = set()

    def claim_trial(self, email: str, card_fingerprint: str) -> bool:
        norm_email = canonicalize_email_for_trial(email)
        if norm_email in self.used_emails or card_fingerprint in self.used_card_fingerprints:
            raise PermissionError("trial quota already consumed for identity or payment instrument")
        self.used_emails.add(norm_email)
        self.used_card_fingerprints.add(card_fingerprint)
        return True

def apply_webhook_state(sub: Subscription, new_status: str, event_ts: int) -> bool:
    if event_ts <= sub.last_event_ts:
        return False  # 丢弃乱序旧事件，避免支付失败旧事件覆盖已续费状态
    if new_status not in {"active", "past_due", "canceled"}:
        raise ValueError("unknown subscription status")
    sub.status = new_status
    sub.last_event_ts = event_ts
    return True

def allocate_seat(sub: Subscription) -> None:
    if sub.status != "active":
        raise PermissionError("subscription not active")
    limit = PLANS[sub.plan]["max_seats"]
    if sub.used_seats + 1 > limit:
        raise PermissionError("seat limit reached")
    sub.used_seats += 1

if __name__ == "__main__":
    assert calculate_upgrade_charge_minor("basic", "pro", 15, 30) == 1000
    reg = TrialRegistry()
    assert reg.claim_trial("Alice.User+promo1@gmail.com", "fp_card_01") is True
    try:
        reg.claim_trial("aliceuser+promo2@gmail.com", "fp_card_02")
        raise AssertionError("should block Gmail alias trial abuse")
    except PermissionError:
        pass
    sub = Subscription("sub_1", "basic", "active", 5, 1000)
    try:
        allocate_seat(sub)
        raise AssertionError("should block 6th seat on basic plan")
    except PermissionError:
        pass
    assert apply_webhook_state(sub, "past_due", 999) is False  # 拒绝乱序旧事件
    assert sub.status == "active"
    print("payment-subscription-defense self-check passed")
```

## 防御工作流

```text
1. 试用风控收敛：结合规范化邮箱、支付卡指纹（card fingerprint）与手机/租户绑定控制单主体试用次数。
2. 计费变更分离：升级即时补差价并先收款后提权；降级延后至周期末切换，彻底消除即时退差套利。
3. Dunning 与过期调度：设置自动续费宽限期上限，过期定时任务强行切换为 `canceled` 并回收 API Token 配额。
4. 席位与用量原子校验：Seat 分配采用数据库行锁约束，Metered 用量由网关后端采集，绝不信任客户端计数。
5. 事件时序护栏：订阅 Webhook 除验签外强制比较事件时间戳 `event_ts > last_event_ts`，防止乱序状态回退。
```

## 验证与判定标准

- **试用防绕过**：使用 `user+1@gmail.com`、`u.s.e.r@gmail.com` 或同张银行卡注销重开账号申请试用，均被返回 `403` 拦截。
- **席位与用量硬限制**：`basic`（5 席）并发邀请第 6 人返回 `402/403`；移除成员后其旧 Session 在下一次请求即失效。
- **Webhook 乱序免疫**：在 `active (ts=2000)` 状态下重放历史 `past_due (ts=1500)` 事件，订阅状态保持 `active`。

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 订阅与试用接口验证 | `http_probe` | 验证试用别名、超额 Seat 邀请与未验签 Webhook 的拒绝状态 |
| 异步回调与支付防线关联 | `kb_router` | 检索 Webhook 验签、幂等性与并发扣减防御条目 |
| 配对攻击细节对照 | `kb_read_file` | 对照读取 `ctf-website/12-payment/payment-subscription` 核查防御覆盖 |
| 知识库模块总览 | `kb_catalog` | 列出支付与 SaaS 业务风控防御文档 |
