---
id: "ctf-website/12-payment/payment-digital-goods-defense"
title: "虚拟商品与内购 (IAP) 防御 — 收据服务端直验、防重放与铸币防护"
title_en: "Digital Goods & IAP Defense — Server-Side Receipt Verification, Replay Protection & Minting Guards"
summary: >
  针对 iOS App Store 收据伪造/沙盒混用、Google Play purchaseToken 重放与测试卡逃逸、Steam 微交易绕过、
  弱卡密算法预测、虚拟货币铸币溢出及数字商品重复发货攻击，提供服务端向官方 API 直验、唯一交易账本与密码学卡密生成方案。
summary_en: >
  Protects digital goods and in-app purchases against forged iOS receipts and sandbox confusion, Google Play
  purchaseToken replay and test-card bypass, Steam validation flaws, predictable license keys, virtual currency
  minting overflow, and duplicate fulfillment via official server-to-server verification and cryptographic tokens.
board: "ctf-website"
category: "12-payment"
signals: ["IAP防御", "receipt服务端校验", "purchaseToken去重", "沙盒隔离", "卡密加密生成", "防重复发货", "虚拟货币账本"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "kb_catalog"]
keywords: ["IAP defense", "App Store Server API", "Google Play Developer API", "purchaseToken replay", "license key security", "digital goods hardening"]
difficulty: "advanced"
tags: ["defense", "blue-team", "hardening", "payment", "iap", "digital-goods", "anti-replay"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/12-payment/payment-digital-goods", "ctf-website/12-payment/payment-bypass-defense", "ctf-website/12-payment/payment-race-lost-update-defense"]
track: "blue"
defends: "ctf-website/12-payment/payment-digital-goods"
---
# 虚拟商品与内购 (IAP) 防御 — 收据服务端直验、防重放与铸币防护

> 配对攻击手册：[payment-digital-goods.md](../../../../red/ctf-website/techniques/12-payment/payment-digital-goods.md)。数字商品与游戏内购没有物流缓冲，任何一次漏验或重放都会直接转化为永久资产损失；防御的核心是“官方 S2S 强校验 + 环境绝对隔离 + 交易号全局唯一消费”。

## 威胁模型与控制映射

| 攻击向量 | 典型缺陷 | 防御控制措施 |
|---|---|---|
| iOS 伪造收据与沙盒混用 | 仅在客户端校验、信任自签名 JSON、生产库接受 `Sandbox` 收据（21007 盲目回退） | 使用 App Store Server API (JWS 签名校验 Apple 根证书)；生产环境严禁自动回退 `Sandbox` 发货 |
| Google Play `purchaseToken` 复用与测试卡 | 未校验 `purchaseState == 0` / `consumptionState`、未检查 `purchaseType` 过滤测试订单 | 向 `androidpublisher` 直验后核对 `productId`、`purchaseState==0`、`purchaseType != 0`（拒绝测试卡），并先 `acknowledge`/`consume` 再发权益 |
| 跨账号收据重放 | 同一 `transaction_id`/`purchaseToken` 可给多个业务账号发货 | 数据库建立 `UNIQUE(platform, transaction_id)` 消费账本，并绑定 `obfuscatedAccountId` / `appAccountToken` |
| License Key / 卡密预测 | 使用自增 ID、时间戳、CRC32 或线性同余生成序列号 | 使用 `secrets.token_bytes` 生成 ≥ 128-bit 随机码或服务端 Ed25519 签名载荷；在线兑换严格限速与锁定 |
| 虚拟货币铸币与负余额 | 前端上报金币增量、整除溢出或负值转账 | 禁止客户端传入余额增量；采用不可变复式记账流水表（Ledger Entry）+ 数据库 `CHECK (balance >= 0)` |
| 下载链接与重复发货 | 并发请求发货接口重复发放道具，或静态 URL 无鉴权永久有效 | 发货状态机 CAS + 唯一发货记录表；下载链接采用短时效（≤ 5 分钟）HMAC 预签名 URL 且绑定 `user_id` |

## 核心加固实现

### 1. IAP 官方回执强制校验与全局唯一消费账本

```python
# iap_receipt_guard.py — IAP 环境隔离、字段校验与防跨账号重放
from dataclasses import dataclass

@dataclass(frozen=True)
class VerifiedReceipt:
    platform: str          # "apple" | "google"
    transaction_id: str
    bundle_id: str
    product_id: str
    environment: str       # "Production" | "Sandbox"
    purchase_state: int    # 0 = purchased
    is_test_purchase: bool
    account_binding: str

class IapVerificationError(PermissionError):
    pass

class IapConsumptionLedger:
    def __init__(self, expected_bundle_id: str, allow_sandbox: bool = False):
        self.expected_bundle_id = expected_bundle_id
        self.allow_sandbox = allow_sandbox
        self.consumed_tx: dict[tuple[str, str], str] = {}

    def verify_and_consume(self, receipt: VerifiedReceipt, current_user_id: str, expected_product_id: str) -> bool:
        if receipt.bundle_id != self.expected_bundle_id:
            raise IapVerificationError("bundle_id mismatch")
        if receipt.environment != "Production" and not self.allow_sandbox:
            raise IapVerificationError("sandbox receipt rejected in production")
        if receipt.is_test_purchase and not self.allow_sandbox:
            raise IapVerificationError("test card purchase rejected in production")
        if receipt.purchase_state != 0:
            raise IapVerificationError("purchase not completed")
        if receipt.product_id != expected_product_id:
            raise IapVerificationError("product_id mismatch (SKU swap blocked)")
        if receipt.account_binding and receipt.account_binding != current_user_id:
            raise IapVerificationError("receipt bound to another account")

        key = (receipt.platform, receipt.transaction_id)
        if key in self.consumed_tx:
            raise IapVerificationError("transaction_id already consumed (replay blocked)")

        self.consumed_tx[key] = current_user_id
        return True
```

### 2. 高熵卡密生成、常量时间校验与防铸币账本

```python
# digital_goods_security.py — 密码学安全卡密与防铸币复式记账
import hashlib
import hmac
import secrets

def issue_cryptographic_cdkey(pepper: bytes, batch_id: str) -> tuple[str, str]:
    """返回 (展示给用户的卡密, 仅入库保存的 HMAC-SHA256 摘要)。"""
    raw_token = secrets.token_urlsafe(18)  # 144-bit 熵，不可预测
    code = f"{batch_id}-{raw_token}"
    digest = hmac.new(pepper, code.encode("utf-8"), hashlib.sha256).hexdigest()
    return code, digest

def verify_cdkey_digest(pepper: bytes, submitted_code: str, stored_digest: str) -> bool:
    computed = hmac.new(pepper, submitted_code.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, stored_digest)

def transfer_virtual_currency(balances: dict[str, int], sender: str, receiver: str, amount: int) -> None:
    if type(amount) is not int or amount <= 0:
        raise ValueError("amount must be positive int")
    if sender == receiver:
        raise ValueError("self transfer blocked")
    if balances.get(sender, 0) < amount:
        raise ValueError("insufficient balance")
    balances[sender] -= amount
    balances[receiver] = balances.get(receiver, 0) + amount

if __name__ == "__main__":
    ledger = IapConsumptionLedger(expected_bundle_id="com.example.app", allow_sandbox=False)
    valid = VerifiedReceipt("google", "GPA.1234-5678", "com.example.app", "gem_pack_100", "Production", 0, False, "u_42")
    assert ledger.verify_and_consume(valid, "u_42", "gem_pack_100") is True
    # 测试重放与测试卡拦截
    for bad in (
        valid,  # 重复提交同 tx
        VerifiedReceipt("apple", "tx_99", "com.example.app", "gem_pack_100", "Sandbox", 0, False, "u_42"),
        VerifiedReceipt("google", "GPA.9999", "com.example.app", "gem_pack_100", "Production", 0, True, "u_42"),
    ):
        try:
            ledger.verify_and_consume(bad, "u_42", "gem_pack_100")
            raise AssertionError("should have blocked invalid receipt")
        except IapVerificationError:
            pass
    pepper = b"server-only-cdkey-pepper"
    cdkey, digest = issue_cryptographic_cdkey(pepper, "B2026")
    assert verify_cdkey_digest(pepper, cdkey, digest)
    print("payment-digital-goods-defense self-check passed")
```

## 防御工作流

```text
1. 剔除本地校验：废弃客户端“支付成功即发货”逻辑，强制服务端通过 App Store Server API / Play Developer API 直验。
2. 隔离沙盒与测试卡：生产节点配置显式禁用 Sandbox 自动回退与 test purchase 类型订单。
3. 交易号唯一账本：落库前先插入 `UNIQUE(platform, transaction_id)` 记录，失败立即中止发货。
4. 卡密密码学化：替换所有自增/CRC 算法卡密，改为 128-bit+ CSPRNG 生成并仅在库内存储加盐摘要，兑换接口加 IP+账号双维度限流。
5. 资产防重发：数字资产下载链接使用短期签发 URL（绑定 user_id 与过期时间），发货操作加订单行锁。
```

## 验证与判定标准

- **沙盒与测试订单零通过**：向生产验证接口提交 Sandbox 收据或 `purchaseType=0` 测试卡回执，返回 `403` 且不生成发货记录。
- **跨账号重放零命中**：同一 `transaction_id` 在账号 A 核销后，使用账号 B 并发或串行重放返回 `409 Conflict`。
- **卡密空间不可枚举**：生成的卡密样本满足 ≥ 128-bit 熵且库内不存明文；连续错误兑换 5 次触发锁定或指数退避。

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 内购与兑换接口检查 | `http_probe` | 验证收据重放、SKU 错配与兑换暴力请求拦截响应 |
| 并发与支付防线关联 | `kb_router` | 检索丢失更新防护与速率限制防御文档 |
| 配对攻击细节对照 | `kb_read_file` | 对照读取 `ctf-website/12-payment/payment-digital-goods` 复核防御点 |
| 数字商品防御索引 | `kb_catalog` | 浏览支付与业务安全防御条目 |
