---
id: "pe-reverse/10-license-keygen/06-cloud-license-frida-hook-defense"
title: "云端授权查询面防 Hook 与本地状态/试用重置防御"
title_en: "Cloud License Query Surface Hardening and Anti-Trial-Reset Defense"
summary: >
  针对云端授权场景下的三大替代攻击路径（本地授权状态文件伪造、Frida 挂钩授权查询面函数强行返回已激活、
  删除状态文件/注册表键循环重置试用期），提供服务端能力下发与功能解耦、Ed25519 短时签名租约、
  Fail-Closed 试用服务端登记及查询面防篡改架构。
summary_en: >
  Defense against cloud-licensing bypass vectors including local state file forgery, Frida hooking
  of licensing query APIs, and local trial-state deletion resets. Enforces server-authoritative
  capability delivery, short-lived Ed25519 signed leases, server-tracked trial issuance with
  fail-closed local defaults, and query-surface anti-hook hardening.
board: "pe-reverse"
category: "10-license-keygen"
signals:
  - "cloud license defense"
  - "anti-trial-reset"
  - "signed lease"
  - "fail-closed"
  - "能力下发"
  - "查询面加固"
  - "状态伪造防御"
mcp_tools:
  - http_probe
  - procmon_start_capture
  - ghidra_summary_function_detail
  - rizin_strings
  - triage_pe
  - kb_router
keywords:
  - "cloud licensing defense"
  - "anti-trial-reset"
  - "signed offline lease"
  - "fail-closed licensing"
  - "server capability gating"
  - "blue-team"
difficulty: "intermediate"
tags:
  - "defense"
  - "blue-team"
  - "cloud-license"
  - "anti-trial-reset"
  - "signed-lease"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "pe-reverse/10-license-keygen/06-cloud-license-frida-hook"
  - "pe-reverse/10-license-keygen/05-keygen-frida-verification-loop-defense"
  - "pe-reverse/04-dynamic-analysis/08-procmon-patterns-defense"
track: "blue"
defends: "pe-reverse/10-license-keygen/06-cloud-license-frida-hook"
---
# 云端授权查询面防 Hook 与本地状态/试用重置防御

## 防御目标与威胁面

在 [06-cloud-license-frida-hook.md](06-cloud-license-frida-hook.md) 中，攻击者虽然确认云端校验无本地 keygen 公式，但会立刻转向三条替代路线：

1. **本地状态伪造**：侦察 `AppData\Local\TargetApp\License` 下的缓存/会话文件格式并构造“已激活”文件（或 Hook 本地编码函数代为加密）。
2. **授权查询面 Frida Hook**：用 `frida -f` 在启动早期 attach，通过 `Interceptor.attach` 把 `IsLicensed()` / `LicensingService` 查询函数返回值强行改为 `1` 或改写输出结构体。
3. **试用状态重置**：退出进程后备份并删除 `state.dat` 或注册表试用键值，使程序每次冷启动重新进入满额试用期。

根治这三条路径的核心思想是：**客户端本地不拥有“授予授权或颁发试用”的权力，所有权威状态与高价值能力必须由服务端签名下发并 Fail-Closed 执行。**

## 核心防御架构

| 攻击路径 | 防御控制措施 | 关键实现约束 |
|---|---|---|
| 本地授权状态文件伪造 | **Ed25519 服务端签名短时租约（Signed Lease）+ DPAPI 封装** | 客户端绝不持有用于签发状态文件的加密/签名私钥（禁止客户端“自己加密状态文件”）；租约绑定 `device_id + user_id + jti + exp` |
| 删除 `state.dat`/注册表实现试用重置 | **服务端登记试用资格 + 客户端 Fail-Closed 默认未授权** | 本地无状态文件时默认处于“未激活/需登录或联机申请试用”状态，绝不本地自动生成新的 30 天试用 |
| `frida -f` Hook 查询面函数返回值置 `1` | **服务端能力交付（Capability Gating）** + 查询面去布尔化 + CIG/Anti-Frida | 高级功能的核心模型、模板、加密密钥或云算力在验签通过后由服务端下发；本地仅返回 `1` 无法凭空获得有效解密密钥 |
| 多进程架构只加固主进程 | 全工作进程统一激活 CIG 与独立租约验签校验 | 防止攻击者转而注入权限较低但负责授权查询的辅助子进程 |

## 加固实现与检测代码

以下 Python 参考实现展示云端授权系统的**服务端签发短时签名租约 + Fail-Closed 客户端验证器**（包含抗删除重置试用、抗伪造状态文件、抗跨设备重放与防过期租约重用检验）：

```python
"""cloud_lease_verifier.py: 服务端签发 Ed25519 短时租约与 Fail-Closed 抗试用重置验证器"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import time
from typing import Optional, Set, Tuple

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError:  # 无第三方 cryptography 库时的离线自检兼容桩（生产环境必须使用真实 Ed25519）
    class InvalidSignature(Exception):
        pass

    class Ed25519PublicKey:
        def __init__(self, key_bytes: bytes):
            self._k = key_bytes

        def verify(self, sig: bytes, data: bytes) -> None:
            if not hmac.compare_digest(sig, hmac.new(self._k, data, hashlib.sha256).digest() * 2):
                raise InvalidSignature()

    class Ed25519PrivateKey:
        def __init__(self, key_bytes: bytes):
            self._k = key_bytes

        @classmethod
        def generate(cls) -> "Ed25519PrivateKey":
            return cls(os.urandom(32))

        def public_key(self) -> Ed25519PublicKey:
            return Ed25519PublicKey(self._k)

        def sign(self, data: bytes) -> bytes:
            return hmac.new(self._k, data, hashlib.sha256).digest() * 2


class CloudLicenseServer:
    """服务端权威试用发放与短时授权租约签发器。"""

    def __init__(self, priv: Ed25519PrivateKey):
        self._priv = priv
        self._trial_issued_devices: Set[str] = set()

    def request_trial_or_lease(self, device_fp: str, user_id: str, now_ts: int) -> Tuple[bool, str]:
        if user_id == "trial":
            if device_fp in self._trial_issued_devices:
                return False, "trial_already_consumed_for_device"
            self._trial_issued_devices.add(device_fp)
            tier, ttl = "trial", 7 * 86400
        else:
            tier, ttl = "pro", 3600  # 短时租约，定期续签

        claims = {
            "sub": user_id,
            "dev": device_fp,
            "tier": tier,
            "iat": now_ts,
            "exp": now_ts + ttl,
            # 模拟随租约下发受授权保护的会话解封秘钥材料（未持有有效服务端响应则不可伪造）
            "cap_secret": base64.b64encode(f"cap-{tier}-{device_fp}".encode()).decode(),
        }
        payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig = self._priv.sign(b"CLOUD-LEASE-V1\x00" + payload)
        token = base64.urlsafe_b64encode(payload).decode() + "." + base64.urlsafe_b64encode(sig).decode()
        return True, token


def verify_local_lease_fail_closed(
    pub: Ed25519PublicKey,
    local_token: Optional[str],
    current_device_fp: str,
    now_ts: int,
) -> Tuple[bool, dict | str]:
    """Fail-Closed 验证: 缺失本地文件时绝不自动重开试用，必须连线服务端裁决。"""
    if not local_token:
        return False, "missing_state_require_online_check"
    try:
        p_b64, s_b64 = local_token.split(".", 1)
        payload = base64.urlsafe_b64decode(p_b64)
        sig = base64.urlsafe_b64decode(s_b64)
        pub.verify(sig, b"CLOUD-LEASE-V1\x00" + payload)
        claims = json.loads(payload.decode("utf-8"))
    except (ValueError, InvalidSignature, Exception):
        return False, "forged_or_corrupt_lease"

    if claims.get("dev") != current_device_fp:
        return False, "device_fingerprint_mismatch"
    if claims.get("exp", 0) < now_ts:
        return False, "lease_expired_require_renewal"
    return True, claims


if __name__ == "__main__":
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    srv = CloudLicenseServer(sk)

    # 1. 首次试用成功，删本地文件后再次请求试用必须被服务端拒绝
    ok, trial_tok = srv.request_trial_or_lease("dev-abc", "trial", now_ts=1700000000)
    assert ok
    assert verify_local_lease_fail_closed(pk, None, "dev-abc", 1700000100) == (
        False, "missing_state_require_online_check"
    )
    assert srv.request_trial_or_lease("dev-abc", "trial", now_ts=1700000200) == (
        False, "trial_already_consumed_for_device"
    )

    # 2. 跨设备复制与过期拦截
    assert verify_local_lease_fail_closed(pk, trial_tok, "dev-other", 1700000100)[1] == "device_fingerprint_mismatch"
    assert verify_local_lease_fail_closed(pk, trial_tok, "dev-abc", 1800000000)[1] == "lease_expired_require_renewal"
    print("Cloud license & anti-trial-reset defense self-check passed.")
```

## 防御工作流

```text
1. 切断本地试用生成：移除客户端首次启动自动生成本地 state.dat 的逻辑，缺失状态统一进入 Fail-Closed 未激活态
2. 服务端状态签名化：本地缓存必须为服务端私钥签名的短 TTL 租约（绑定设备指纹与单调时间戳），客户端仅做验签
3. 能力与密钥服务端交付：将高级功能的运算或资源解密密钥放在服务端验证租约后下发，使仅 Hook 客户端查询布尔值失去意义
4. 加固进程查询面：所有主进程与子进程均启用 CIG/ACG 与 Anti-Frida 检测，并将查询函数去布尔化
5. 通信链路固定：对激活与租约续签接口启用 TLS 1.3 + SPKI Pinning，防止本地代理伪造服务端 JSON 响应
```

## 验证与判定标准

- **删除状态抗重置验证**：删除客户端本地全部授权与试用文件后断网重启，软件必须提示需联机认证且禁止恢复任何试用天数；联网后同一设备指纹重复请求试用必须被服务端拒绝。
- **伪造状态文件拒绝**：任意构造或局部修改本地状态文件（即使结构合法），`verify_local_lease_fail_closed` 必须返回 `forged_or_corrupt_lease`。
- **查询面 Hook 无效化验证**：强制将本地 `IsLicensed` 内存查询函数返回值覆写为 `1` 时，由于缺乏服务端签发的解密密钥/能力令牌，受保护的高级功能仍无法正常解密或执行。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检查本地状态文件写入与网络激活流 | `procmon_start_capture`、`http_probe` | 验证删除本地状态后不再本地重置试用，且激活流量受强校验保护 |
| 定位并评估查询面是否可被单点布尔 Hook | `ghidra_summary_function_detail`、`rizin_strings` | 排查孤立的 `Licensed`/`Activated` 字符串路径与 `retval=1` 漏洞 |
| 核查二进制进程缓解策略 | `triage_pe` | 确认 CIG/CFG 启用状态 |
| 检索红蓝成对参考 | `kb_router` | 对照 [06-cloud-license-frida-hook.md](06-cloud-license-frida-hook.md) 验证防御完备性 |
