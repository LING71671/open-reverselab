---
id: "apk-reverse/05-network/02-license-verification-bypass-defense"
title: "在线许可证与授权校验加固"
title_en: "Online License Verification Hardening"
summary: >
  针对硬编码 RC4 密钥伪造响应、DNS/hosts 劫持返回 {"code":0}、本地缓存文件检查（access/pm list packages）及单点布尔返回值 Patch 等绕过手法，提供 Ed25519 非对称签名凭证、Challenge-Nonce 绑定、服务端功能授权下发与 Play Integrity 联动方案。
summary_en: >
  Hardening online license verification against hardcoded RC4 forgery, DNS/hosts hijacking returning {"code":0}, local cache/package checks (access/pm list), and boolean return patching. Covers Ed25519 signed license assertions, challenge-nonce binding, server-gated feature delivery, and Play Integrity integration.
board: "apk-reverse"
category: "05-network"
signals:
  - "license verification hardening"
  - "Ed25519 授权签名"
  - "Challenge-Nonce"
  - "Play Integrity"
  - "反 hosts 劫持"
  - "服务端下发配置"
mcp_tools:
  - "android_crypto_unpack_recipe"
  - "android_http_observation_recipe"
  - "ghidra_headless_analyze"
  - "kb_router"
keywords:
  - "在线验证加固"
  - "授权防破解"
  - "Ed25519"
  - "非对称签名"
  - "防hosts劫持"
  - "blue-team"
difficulty: "intermediate"
tags:
  - "defense"
  - "blue-team"
  - "license"
  - "cryptography"
  - "anti-tamper"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "apk-reverse/05-network/02-license-verification-bypass"
  - "apk-reverse/05-network/03-tls-pinning-unpinning-defense"
  - "apk-reverse/08-patch-repack/02-signature-integrity-bypass-defense"
track: "blue"
defends: "apk-reverse/05-network/02-license-verification-bypass"
---
# 在线许可证与授权校验加固

## 防御目标与威胁面

弱在线验证系统的典型脆弱点有三类：
1. **对称加密 + 明文状态码**：客户端硬编码 `appkey` 与 `rc4key`，仅凭服务端返回 `{"code":0}` 决定是否放行。攻击者可通过 `hosts`/DNS 劫持自建服务器或 Frida Hook `httppost` 直接返回成功 JSON。
2. **本地文件系统/包名伪造**：通过 `access("/data/data/.../cache/...")` 或 `system("pm list packages")` 判定外部应用状态，极易被 `touch` 空文件或 Hook `access`/`system` 绕过。
3. **单点纯客户端布尔开关**：验证逻辑集中于单个导出函数（如 `verify()` 返回 `1`/`0`），且解锁的功能代码已全部打包在本地，一处 `RET 1` Patch 即可永久破解。

根治方案在于：**非对称签名授权 + 动态 Challenge 绑定 + TLS Pinning 防劫持 + 核心资源/能力由服务端按会话下发**。

## 核心防御矩阵

| 攻击向量 | 根治控制措施 | 关键实现约束 |
|---|---|---|
| 自建服务器 / DNS 劫持伪造响应 | 服务端使用 Ed25519/ECDSA 私钥签发授权声明，客户端仅内嵌公钥 | 启用 HTTPS + SPKI Pinning，拒绝明文 HTTP 验证端点 |
| 静态重放历史合法响应 | 每次启动由客户端生成随机 `client_nonce` 并要求签名声明回带 | 声明必须绑定 `nonce`、`package_name`、`cert_sha256`、`exp` |
| Hook `httppost` / Patch `verify()` 返回值 | 消除全局单点布尔开关；授权响应直接携带解密密钥碎片或业务配置 | 高价值能力与动态规则在鉴权通过后由服务端下发，不在本地明文留存 |
| 本地 `access()` / `system()` 外部状态校验 | 废弃本地文件/Shell 命令检测，改用服务端 OAuth/API 核验成员身份 | 禁止在客户端调用 `system("pm ...")` 作为信任依据 |
| 伪造连通性检测（如请求第三方 HTTP 页面） | 连通性与时间校准统一走己方带签名的 HTTPS 健康检查接口 | 防止攻击者借助离线假响应绕过过期检查 |

## 加固代码与离线验签示例

以下 Python 示例演示服务端签发带上下文绑定的授权票据，以及客户端无导出对称密钥、仅靠公钥完成 fail-closed 验签的逻辑（使用标准库 `hmac`/`hashlib` 结构化模拟验签骨架，生产环境替换为 `cryptography.hazmat.primitives.asymmetric.ed25519` 或 BoringSSL `ED25519_verify`）：

```python
import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Tuple


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


class LicenseServerSigner:
    """服务端授权票据签发器（生产环境使用 Ed25519 私钥，客户端仅持公钥）。"""

    def __init__(self, server_signing_secret: bytes) -> None:
        self._secret = server_signing_secret

    def issue_ticket(
        self,
        nonce: str,
        package_name: str,
        cert_sha256: str,
        ttl_sec: int = 300,
        now: float | None = None,
    ) -> dict:
        ts = int(now if now is not None else time.time())
        claims = {
            "nonce": nonce,
            "pkg": package_name,
            "cert": cert_sha256,
            "iat": ts,
            "exp": ts + ttl_sec,
            "entitlement": "pro_session",
        }
        payload_b64 = b64u_encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
        # 生产中为 Ed25519_sign(priv_key, payload_b64.encode())
        sig = hmac.new(self._secret, payload_b64.encode(), hashlib.sha256).digest()
        return {"payload": payload_b64, "sig": b64u_encode(sig)}


def client_verify_ticket(
    ticket: dict,
    expected_nonce: str,
    expected_pkg: str,
    expected_cert: str,
    verify_key: bytes,
    now: float | None = None,
) -> Tuple[bool, str]:
    payload_b64 = ticket.get("payload", "")
    sig_b64 = ticket.get("sig", "")
    if not isinstance(payload_b64, str) or not isinstance(sig_b64, str) or not payload_b64 or not sig_b64:
        return False, "malformed_ticket"

    expected_sig = hmac.new(verify_key, payload_b64.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(b64u_decode(sig_b64), expected_sig):
        return False, "invalid_signature"

    claims = json.loads(b64u_decode(payload_b64))
    ts = int(now if now is not None else time.time())
    if claims.get("nonce") != expected_nonce:
        return False, "nonce_mismatch"
    if claims.get("pkg") != expected_pkg or claims.get("cert") != expected_cert:
        return False, "app_identity_mismatch"
    if ts > int(claims.get("exp", 0)):
        return False, "ticket_expired"
    return True, "ok"


if __name__ == "__main__":
    # 演示用密钥仅作本地断言自测；真实部署中客户端仅内嵌 Ed25519 公钥
    signing_key = b"demo-asymmetric-key-placeholder"
    signer = LicenseServerSigner(signing_key)
    nonce = secrets.token_hex(16)
    ticket = signer.issue_ticket(nonce, "com.vendor.app", "aa11bb22", ttl_sec=60, now=1700000000)

    assert client_verify_ticket(ticket, nonce, "com.vendor.app", "aa11bb22", signing_key, now=1700000010) == (True, "ok")
    assert client_verify_ticket(ticket, "wrong-nonce", "com.vendor.app", "aa11bb22", signing_key, now=1700000010) == (False, "nonce_mismatch")
    assert client_verify_ticket(ticket, nonce, "com.repack.app", "aa11bb22", signing_key, now=1700000010) == (False, "app_identity_mismatch")
    assert client_verify_ticket(ticket, nonce, "com.vendor.app", "aa11bb22", signing_key, now=1700000100) == (False, "ticket_expired")
    print("License defense self-check passed.")
```

## 防御工作流

```text
1. 淘汰弱验证：移除本地文件 existence 检查（access/stat）、Shell 包名检查及硬编码 RC4 密钥
2. 服务端签发改造：切换为 HTTPS + Ed25519 非对称签名授权票据，响应携带 nonce/pkg/cert/exp 声明
3. Native 多点核验：在 Native 侧隐藏公钥与验签逻辑，剥离 httppost/verify 等可预测导出符号
4. 业务耦合下沉：将核心算法参数、资源密钥或规则配置改为授权通过后由服务端按会话下发
5. 传输防劫持：绑定证书 Pinning 与 Play Integrity 设备完整性校验，阻断自建假验证站
```

## 验证与判定标准

- **假响应拦截**：通过本地代理或 Hook 返回固定 `{"code":0,"msg":"ok"}` 时，客户端因缺少合法签名与匹配 `nonce` 必须拒绝激活。
- **重打包跨包隔离**：修改包名或签名证书后即使收到合法历史票据，因 `pkg` 或 `cert` 声明不匹配必须校验失败。
- **导出符号检查**：使用 `ghidra_headless_analyze` 检查发布 SO，不得出现明文 `httppost`、`channel_verify`、`rc4key` 等高可读性导出符号。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检查加解密与验签路径 | `android_crypto_unpack_recipe` | 验证是否仍残留硬编码对称密钥或可被轻易替换的返回点 |
| 核查验证请求传输层 | `android_http_observation_recipe` | 确认验证端点全部采用 HTTPS 且无明文状态回落 |
| 检查 Native 符号与分支 | `ghidra_headless_analyze` | 核对验签函数是否已剥离符号并避免单点布尔开关 |
| 关联红蓝文档 | `kb_router` | 对照 [02-license-verification-bypass.md](02-license-verification-bypass.md) 覆盖全部绕过面 |
