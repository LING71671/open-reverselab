---
id: "ctf-website/12-payment/payment-callback-async-defense"
title: "支付回调与异步链路防御 — 验签、幂等锁、Anti-SSRF 与事件因果保护"
title_en: "Payment Callback & Async Defense — Signature Verification, Idempotency, Anti-SSRF & Causal Ordering"
summary: >
  针对支付回调签名绕过、notify_url SSRF 与 DNS Rebinding、Webhook 重放竞态、消息队列投毒乱序及跨通道对账不一致，
  提供恒定时间 HMAC/RSA 验签、幂等唯一键 + 状态机 CAS、出站 IP 固定防重绑定与事件因果校验方案。
summary_en: >
  Defends asynchronous payment pipelines against callback signature bypass, notify_url SSRF and DNS rebinding,
  webhook replay races, MQ message poisoning/reordering, and cross-channel reconciliation drift using constant-time
  verification, idempotency unique keys with CAS, DNS-pinned egress clients, and causal event checks.
board: "ctf-website"
category: "12-payment"
signals: ["payment callback", "回调验签", "幂等性", "Webhook SSRF", "DNS Rebinding", "MQ签名", "异步竞态", "防重放"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "kb_catalog"]
keywords: ["支付回调防御", "webhook verification", "constant time compare", "idempotency key", "anti-ssrf", "DNS rebinding defense"]
difficulty: "advanced"
tags: ["defense", "blue-team", "hardening", "payment", "webhook", "ssrf", "async"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/12-payment/payment-callback-async", "ctf-website/12-payment/payment-bypass-defense", "ctf-website/12-payment/payment-race-lost-update-defense", "ctf-website/22-dos/12-ssrf-dos-defense"]
track: "blue"
defends: "ctf-website/12-payment/payment-callback-async"
---
# 支付回调与异步链路防御 — 验签、幂等锁、Anti-SSRF 与事件因果保护

> 配对攻击手册：[payment-callback-async.md](../../../../red/ctf-website/techniques/12-payment/payment-callback-async.md)。异步支付的安全边界在于：回调仅作为“触发服务端主动向网关反查或验签入账”的信号，绝不可信任未验签参数、客户端可控 `notify_url` 或无序列号的乱序事件。

## 威胁模型与控制映射

| 攻击向量 | 典型缺陷 | 防御控制措施 |
|---|---|---|---|
| 签名绕过与算法降级 | 从参数读取 `sign_type`、允许空签名、使用 `==` 或字符串拼接无分隔符 | 服务端硬编码算法（HMAC-SHA256 / RSA-SHA256），规范化按键名排序拼装，`hmac.compare_digest` 恒定时间比对 |
| 回调重放与并发双花 | 仅依赖 Redis `SETNX` 短期过期，或先查后改无行锁 | 数据库唯一键 `UNIQUE(provider, provider_tx_id)` + `UPDATE orders SET status='PAID' WHERE id=? AND status='PENDING'` |
| `notify_url` SSRF 与 DNS Rebinding | 用户传入回调地址直接由服务端 `requests.post` 请求，或仅校验一次 DNS | 禁止客户端传入 `notify_url`（使用后台预注册白名单域名）；若必须出站，解析后校验非私网 IP 并锁定连接目标 IP |
| 消息队列投毒与乱序 | MQ 消息无认证/无 HMAC、先消费 `refund` 后消费 `paid` 导致状态错乱 | 消息体附带服务端签名与单调 `event_version`/时间戳；消费端校验版本递增并按状态机规则丢弃过期事件 |
| XXE 与 Content-Type 混淆 | 微信 V2 XML 解析未禁外部实体，或 JSON/Form 混用绕过网关校验 | 解析 XML 时强制 `resolve_entities=False, no_network=True, dtd_validation=False`；按接口固定单一 `Content-Type` |
| 客户端轮询与通道错配 | 信任客户端轮询回传的状态，或 A 通道回调用 B 通道密钥验签 | 仅信任服务端与网关的 S2S 确认；订单创建时绑定 `provider_id`，验签密钥严格按订单 `provider_id` 索引 |

## 核心加固实现

### 1. 恒定时间规范化验签与时间戳防重放

```python
# callback_verifier.py — 支付回调恒定时间验签与防重放
import hmac
import hashlib
import time
from typing import Mapping

class CallbackVerifyError(ValueError):
    pass

def canonical_payload(params: Mapping[str, str], exclude_keys=("sign", "sign_type")) -> bytes:
    # 排除签名字段并按字典序拼接，避免参数顺序与拼接歧义
    pairs = []
    for k in sorted(params.keys()):
        if k in exclude_keys:
            continue
        v = params[k]
        if v is None or v == "":
            continue
        # 使用长度前缀或明确分隔符降低拼接碰撞风险
        pairs.append(f"{k}={v}")
    return "&".join(pairs).encode("utf-8")

def verify_payment_callback(
    params: Mapping[str, str],
    secret: bytes,
    expected_merchant_id: str,
    expected_amount_minor: int,
    expected_currency: str,
    max_skew_seconds: int = 300,
    now_ts: int | None = None,
) -> bool:
    sig_hex = params.get("sign", "")
    ts_raw = params.get("timestamp", "")
    if not sig_hex or not ts_raw or not ts_raw.isdigit():
        raise CallbackVerifyError("missing signature or numeric timestamp")

    now = int(time.time()) if now_ts is None else now_ts
    if abs(now - int(ts_raw)) > max_skew_seconds:
        raise CallbackVerifyError("callback timestamp expired")

    # 算法由服务端硬编码，忽略请求中的任何 algorithm/sign_type 参数
    msg = canonical_payload(params)
    expected_sig = hmac.new(secret, msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig_hex.lower(), expected_sig.lower()):
        raise CallbackVerifyError("invalid hmac signature")

    # 强制核对商户、币种与实付金额（防止低价订单回调串用或跨商户重放）
    if params.get("merchant_id") != expected_merchant_id:
        raise CallbackVerifyError("merchant_id mismatch")
    if params.get("currency") != expected_currency:
        raise CallbackVerifyError("currency mismatch")
    if str(expected_amount_minor) != str(params.get("amount_minor")):
        raise CallbackVerifyError("amount_minor mismatch")
    return True
```

### 2. DNS-Pinned Anti-SSRF 出站校验与幂等事务锁

```python
# webhook_egress_guard.py — 出站 Webhook IP 校验（防 DNS Rebinding）与事件因果保护
import ipaddress
import socket
from urllib.parse import urlparse

def resolve_and_validate_egress(url: str, allowed_hosts: set[str]) -> tuple[str, str, int]:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("only https callback allowed")
    host = (parsed.hostname or "").lower()
    if host not in allowed_hosts:
        raise PermissionError("callback host not in allowlist")
    port = parsed.port or 443

    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    pinned_ip = None
    for _, _, _, _, sockaddr in infos:
        ip_obj = ipaddress.ip_address(sockaddr[0])
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            raise PermissionError(f"blocked non-public ip: {ip_obj}")
        if pinned_ip is None:
            pinned_ip = str(ip_obj)
    if not pinned_ip:
        raise ValueError("dns resolution returned no addresses")
    return host, pinned_ip, port

class IdempotentOrderLedger:
    def __init__(self):
        self.seen_events: set[tuple[str, str]] = set()
        self.orders: dict[str, dict] = {}

    def apply_paid_event(self, provider: str, provider_tx_id: str, order_id: str, version: int) -> bool:
        key = (provider, provider_tx_id)
        if key in self.seen_events:
            return False  # 幂等去重：已处理直接确认 ACK，不重复发货
        order = self.orders[order_id]
        if order["status"] != "PENDING_PAYMENT" or version <= order["event_version"]:
            return False  # 因果与状态机拒绝乱序或已终结事件
        self.seen_events.add(key)
        order["status"] = "PAID"
        order["event_version"] = version
        return True

if __name__ == "__main__":
    secret = b"unit-test-hmac-key-material"
    sample = {
        "order_id": "ord-100",
        "merchant_id": "m-01",
        "currency": "USD",
        "amount_minor": "5000",
        "timestamp": "1700000000",
    }
    sample["sign"] = hmac.new(secret, canonical_payload(sample), hashlib.sha256).hexdigest()
    assert verify_payment_callback(sample, secret, "m-01", 5000, "USD", now_ts=1700000010)

    ledger = IdempotentOrderLedger()
    ledger.orders["ord-100"] = {"status": "PENDING_PAYMENT", "event_version": 0}
    assert ledger.apply_paid_event("stripe", "tx_1", "ord-100", 1) is True
    assert ledger.apply_paid_event("stripe", "tx_1", "ord-100", 1) is False  # 重放拦截
    print("payment-callback-async-defense self-check passed")
```

## 防御工作流

```text
1. 验签加固：移除动态签名算法参数，统一 HMAC-SHA256 / 非对称公钥验签并使用恒定时间比较。
2. 账单核对：验签后必须在同一事务内比对 merchant_id、currency、amount_minor 与订单 locked_provider。
3. 幂等落库：以数据库 UNIQUE(provider, provider_tx_id) + 状态机 CAS 作为最终幂等屏障，不依赖易失缓存锁。
4. 出站封堵：禁用任意 notify_url 注入；所有 Webhook 仅向预配置域名发起，并校验解析 IP 非内网且禁用 HTTP 重定向。
5. 异步因果：MQ 事件与 CDC 流携带单调 event_version 与签名，消费前先验因果序再改状态。
```

## 验证与判定标准

- **签名抗降级与抗篡改**：提交空签名、篡改 `sign_type=none` 或改动任意金额字段后，回调接口返回 `401/403` 且订单保持 `PENDING_PAYMENT`。
- **并发重放零双花**：使用 20 个并发线程重放同一已签名的合法回调请求，唯一键与状态机 CAS 保证仅 1 次入账与 1 次发货。
- **SSRF/XXE 免疫**：向回调配置提交内网 IP、DNS 重绑定域名或带 `<!ENTITY` 的 XML 载荷时，解析器与出站网关在连接建立前即阻断。

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 回调接口边界检查 | `http_probe` | 验证异常签名、过期时间戳与错误 Content-Type 的拒绝状态码 |
| 异步竞态与 SSRF 关联 | `kb_router` | 检索并发控制、SSRF 防护与状态机相关防御条目 |
| 配对攻击细节对照 | `kb_read_file` | 对照读取 `ctf-website/12-payment/payment-callback-async` 核查防御覆盖度 |
| 知识库模块总览 | `kb_catalog` | 确认全站异步支付与出站防护文档索引 |
