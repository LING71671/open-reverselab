---
id: "pe-reverse/10-license-keygen/05-keygen-frida-verification-loop-defense"
title: "进程内 Hook 替换、标志位篡改与本地配置伪造防护"
title_en: "In-Process Hook Swap, Memory Flag Tampering, and Config Forgery Defense"
summary: >
  针对 Frida 劫持 GetDlgItemTextW/RegGetValueW 实施进程内 key 替换、轮询或篡改全局内存注册标志位
  （如 DAT_1422E9936）、Hook 伪造 MachineGuid 硬件指纹以及直接改写 Preferences.json 等本地配置激活路径，
  提供导入/入口完整性监测、认证密封状态结构、多信号硬件证明与 DPAPI 配置保护方案。
summary_en: >
  Defense against in-process Frida key swapping (GetDlgItemTextW/RegGetValueW), global registration
  flag tampering, MachineGuid hook spoofing, and offline Preferences.json config edits. Covers
  import/API prologue integrity checks, MAC-sealed session state, multi-source hardware binding,
  and DPAPI + signature protection for persisted configs.
board: "pe-reverse"
category: "10-license-keygen"
signals:
  - "Frida 防护"
  - "内存标志位"
  - "MachineGuid"
  - "Preferences.json"
  - "GetDlgItemTextW"
  - "DPAPI"
  - "anti-hook"
  - "状态密封"
mcp_tools:
  - triage_pe
  - ghidra_summary_imports
  - ghidra_summary_function_detail
  - make_yara_stub
  - kb_router
keywords:
  - "in-process swap defense"
  - "anti-Frida"
  - "memory flag protection"
  - "MachineGuid spoofing defense"
  - "DPAPI config protection"
  - "blue-team"
difficulty: "intermediate"
tags:
  - "defense"
  - "blue-team"
  - "anti-Frida"
  - "state-integrity"
  - "DPAPI"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "pe-reverse/10-license-keygen/05-keygen-frida-verification-loop"
  - "pe-reverse/04-dynamic-analysis/05-anti-debug-bypass-defense"
  - "pe-reverse/04-dynamic-analysis/08-procmon-patterns-defense"
track: "blue"
defends: "pe-reverse/10-license-keygen/05-keygen-frida-verification-loop"
---
# 进程内 Hook 替换、标志位篡改与本地配置伪造防护

## 防御目标与威胁面

在 [05-keygen-frida-verification-loop.md](05-keygen-frida-verification-loop.md) 中，攻击者在验证或激活阶段采用四类进程内与本地文件手段绕过校验：

1. **输入 API 进程内替换**：通过 Frida 挂载 `user32!GetDlgItemTextW`、`ReadFile` 或 `RegGetValueW`，把合法输入或读取内容动态偷换成自生成 key。
2. **全局注册标志位篡改**：定位内存中的单一全局字节/整数标志（如 `0=已注册`），直接修改或轮询确认激活生效。
3. **硬件指纹 Hook 欺骗**：拦截 `RegQueryValueExW(MachineGuid)` 或 `DeviceIoControl`，返回固定伪造指纹以实现“一码通杀”。
4. **本地配置直接改写**：程序关闭后改写 `Preferences.json` 中的 `Name`/`Email`/`Key` 明文三键实现冷启动持久激活。

## 核心防御架构

| 攻击向量 | 防御控制措施 | 关键实现约束 |
|---|---|---|
| Frida Hook `GetDlgItemTextW` / `RegQueryValueExW` | 启用 CIG（`ProcessSignaturePolicy`）阻断未签名 `frida-agent` 注入，并在调用前校验目标 API 入口字节是否含跳转 | 检查 `user32!GetDlgItemTextW`、`advapi32!RegQueryValueExW` 首部未被 `E9`/`FF 25` 篡改 |
| 全局单一内存标志位（`u8 g_isRegistered`） | **消除裸全局布尔位**：使用动态分配 + 每会话随机密钥 HMAC 密封的状态对象，多处独立重新核验完整凭证 | 任何直接修改状态字段的操作都会导致 HMAC 失配；标志位不再以固定 RVA 暴露 |
| Hook `RegQueryValueExW` 伪造 `MachineGuid` | **多源交叉硬件绑定 + 服务端签发**：结合 TPM EK 公钥 / 签名凭证 / 多路径硬件特征，并在关键业务中校验完整签发载荷 | 若仅依赖单一可被 Hook 的用户态注册表读取 API，极易被拦截替换 |
| 明文改写 `Preferences.json` 等配置文件 | 本地持久化状态必须携带**服务端非对称签名（Ed25519）**并用 **DPAPI（`CryptProtectData`）** 绑定本机加密封装 | 退出写回配置时不覆盖未通过服务端签名校验的临时状态；启动读取先解封 DPAPI 再验签名 |

## 加固实现与检测代码

以下 Python 参考实现演示**本地配置与运行时状态的双重保护**：使用密封结构体抵抗进程内单字节标志篡改，并用带机器指纹绑定的认证封套阻止离线直接改写 `Preferences.json`；下方附带 C++ 检测输入与注册表 API 是否被 Frida `Interceptor` 劫持的代码：

```python
"""sealed_state_and_config.py: 运行时 MAC 密封状态与抗改写本地配置校验"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
from typing import Tuple


class SealedSessionState:
    """用进程内随机密钥与 HMAC-SHA256 保护运行时授权状态，杜绝裸全局标志位。"""

    def __init__(self, machine_binding: str):
        self._ephemeral_key = os.urandom(32)
        self._machine = machine_binding
        self._blob = b""
        self._mac = b""
        self.update(licensed=False, tier="free", seq=0)

    def update(self, licensed: bool, tier: str, seq: int) -> None:
        payload = json.dumps(
            {"licensed": licensed, "tier": tier, "seq": seq, "hw": self._machine},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self._blob = payload
        self._mac = hmac.new(self._ephemeral_key, payload, hashlib.sha256).digest()

    def verify_and_read(self) -> Tuple[bool, dict | str]:
        expected = hmac.new(self._ephemeral_key, self._blob, hashlib.sha256).digest()
        if not hmac.compare_digest(self._mac, expected):
            return False, "session_state_tampered"
        return True, json.loads(self._blob.decode("utf-8"))


def seal_preferences(prefs: dict, dpapi_machine_secret: bytes, server_sign_key: bytes) -> str:
    """模拟本地配置持久化: 内层带服务端签名/MAC，外层模拟 DPAPI 本机加密绑定。"""
    body = json.dumps(prefs, sort_keys=True, separators=(",", ":")).encode("utf-8")
    srv_tag = hmac.new(server_sign_key, b"SRV-PREF-V1:" + body, hashlib.sha256).hexdigest()
    envelope = json.dumps({"body": prefs, "srv_tag": srv_tag}, separators=(",", ":")).encode("utf-8")
    # 模拟 DPAPI 机器绑定封装校验标签
    dpapi_tag = hmac.new(dpapi_machine_secret, envelope, hashlib.sha256).hexdigest()
    return base64.b64encode(json.dumps({"env": envelope.decode("utf-8"), "dpapi": dpapi_tag}).encode()).decode()


def unseal_preferences(sealed_b64: str, dpapi_machine_secret: bytes, server_verify_key: bytes) -> Tuple[bool, dict | str]:
    try:
        outer = json.loads(base64.b64decode(sealed_b64).decode("utf-8"))
        env_bytes = outer["env"].encode("utf-8")
        expected_dpapi = hmac.new(dpapi_machine_secret, env_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(outer["dpapi"], expected_dpapi):
            return False, "dpapi_binding_mismatch"
        env = json.loads(outer["env"])
        body = json.dumps(env["body"], sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected_srv = hmac.new(server_verify_key, b"SRV-PREF-V1:" + body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(env["srv_tag"], expected_srv):
            return False, "invalid_server_signature"
        return True, env["body"]
    except Exception:
        return False, "malformed_preferences"


if __name__ == "__main__":
    st = SealedSessionState("hw-fp-001")
    assert st.verify_and_read()[1]["licensed"] is False
    # 模拟攻击者直接改写内存状态字节（把 false 改为 true）
    st._blob = st._blob.replace(b"false", b"true ")
    assert st.verify_and_read() == (False, "session_state_tampered")

    dpapi_secret = b"machine-dpapi-master"
    srv_key = b"server-only-signing-key"
    token = seal_preferences({"Name": "Pro", "Email": "u@example.com"}, dpapi_secret, srv_key)
    ok, cfg = unseal_preferences(token, dpapi_secret, srv_key)
    assert ok and cfg["Name"] == "Pro"

    # 模拟攻击者离线篡改或复制到另一台机器
    assert unseal_preferences(token, b"other-machine-dpapi", srv_key)[0] is False
    print("Frida verification loop defense self-check passed.")
```

以下 C++ 片段检查常见输入与指纹读取 API 入口是否被 Frida `Interceptor` 写入跳转跳板：

```cpp
// api_hook_integrity.cpp: 检测关键输入与硬件指纹 API 是否被植入内联 Hook
#include <windows.h>
#include <cstdint>

bool IsExportHooked(const wchar_t* dllName, const char* funcName) {
    HMODULE hMod = GetModuleHandleW(dllName);
    if (!hMod) return false;
    const auto* p = reinterpret_cast<const uint8_t*>(GetProcAddress(hMod, funcName));
    if (!p) return false;

    // 检查常见 x86/x64 inline hook 入口跳板字节
    if (p[0] == 0xE9 || p[0] == 0xEB || p[0] == 0xE8) return true;
    if (p[0] == 0xFF && p[1] == 0x25) return true;
    if (p[0] == 0x48 && p[1] == 0xB8) return true; // mov rax, addr
    if (p[0] == 0x49 && p[1] == 0xBB) return true; // mov r11, addr (Frida Gum 常见跳板)
    return false;
}

bool CheckLicensingSurfaceClean() {
    return !IsExportHooked(L"user32.dll", "GetDlgItemTextW") &&
           !IsExportHooked(L"advapi32.dll", "RegQueryValueExW") &&
           !IsExportHooked(L"kernel32.dll", "ReadFile");
}
```

## 防御工作流

```text
1. 进程加载防线：启用 ProcessSignaturePolicy (CIG) 阻止未签名的 Frida Agent 附加进程
2. API 入口完整性检验：调用 GetDlgItemTextW/RegQueryValueExW/ReadFile 前后检查出口首字节是否存在 E9/FF 25/49 BB 跳板
3. 消除裸全局状态位：将全局注册标志迁移为动态内存的 MAC 密封会话对象，读取时强制验真
4. 配置文件加密与签名：所有持久化授权文件必须经过服务端非对称签名并套用 DPAPI 本机封装，禁止信任明文 JSON 三键
5. 多源硬件绑定：结合 TPM 密钥或交叉系统指纹源并由服务端签发绑定租约，防止单一注册表 API Hook 欺骗
```

## 验证与判定标准

- **Frida 挂钩拦截**：使用 Frida 对 `GetDlgItemTextW` 或 `RegQueryValueExW` 安装 `Interceptor.attach` 后，`IsExportHooked` 必须返回 `true` 并中止激活流程。
- **内存标志位篡改失效**：在进程内存中将状态对象里的授权标志字修改后，`verify_and_read` 必须因 MAC 校验失败而拒绝放行。
- **离线配置文件篡改与跨机失效**：直接手工修改 `Preferences.json` 或将其复制到另一台不同 DPAPI 上下文的主机，`unseal_preferences` 必须返回拒绝错误。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检查目标进程敏感全局与明文配置读写 | `ghidra_summary_function_detail`、`ghidra_summary_imports` | 排查是否存在全局单字节状态标志与裸 JSON 写盘路径 |
| 生成检测 Frida 跳板的内存扫描规则 | `make_yara_stub` | 捕获 `gum-js-loop` 与 `49 BB` 跳板特征 |
| 核查二进制缓解策略基线 | `triage_pe` | 验证 CIG/ACG/CFG 启用状态 |
| 检索红蓝成对参考 | `kb_router` | 对照 [05-keygen-frida-verification-loop.md](05-keygen-frida-verification-loop.md) 验证防御覆盖 |
