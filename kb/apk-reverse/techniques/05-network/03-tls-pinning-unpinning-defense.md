---
id: "apk-reverse/05-network/03-tls-pinning-unpinning-defense"
title: "TLS 证书固定（Pinning）多层加固与防绕过"
title_en: "Multi-Layer TLS Certificate Pinning Hardening and Anti-Unpinning"
summary: >
  针对 OkHttp CertificatePinner Hook、TrustManagerImpl 绕过、network_security_config 用户证书信任、Cronet 本地锚点绕过及 Native SSL_get_verify_result/X509_verify_cert 劫持，提供系统级配置、BoringSSL 自定义回调与指令防 Hook 自检方案。
summary_en: >
  Multi-layer TLS pinning defense countering OkHttp CertificatePinner hooks, TrustManagerImpl bypass, user-CA network_security_config abuse, Cronet bypass hooks, and native SSL_get_verify_result/X509_verify_cert interception. Covers strict Network Security Config, static BoringSSL custom verify callbacks, and prologue hook integrity checks.
board: "apk-reverse"
category: "05-network"
signals:
  - "network_security_config"
  - "CertificatePinner 加固"
  - "BoringSSL SSL_CTX_set_custom_verify"
  - "SPKI SHA-256"
  - "Cronet Pinning"
  - "anti-unpinning"
mcp_tools:
  - "android_http_observation_recipe"
  - "android_crypto_unpack_recipe"
  - "ghidra_headless_analyze"
  - "kb_router"
keywords:
  - "TLS Pinning加固"
  - "防抓包"
  - "BoringSSL"
  - "NetworkSecurityConfig"
  - "SPKI固定"
  - "mTLS"
  - "blue-team"
difficulty: "intermediate"
tags:
  - "defense"
  - "blue-team"
  - "tls"
  - "pinning"
  - "network"
  - "boringssl"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "apk-reverse/05-network/03-tls-pinning-unpinning"
  - "apk-reverse/05-network/01-game-protocol-hook-defense"
  - "apk-reverse/06-dynamic/01-memory-rw-hook-defense"
track: "blue"
defends: "apk-reverse/05-network/03-tls-pinning-unpinning"
---
# TLS 证书固定（Pinning）多层加固与防绕过

## 防御目标与威胁面

单层 Java Pinning（如仅配置 `okhttp3.CertificatePinner`）极易被通用 Frida Unpinning 脚本（Hook `CertificatePinner.check` 或 `TrustManagerImpl.verifyChain`）在几秒内失效；若 `network_security_config.xml` 错误保留了 `<certificates src="user" />`，系统会直接信任设备安装的用户代理 CA；而在 Native 层，若仅依赖动态链接的 `libssl.so` 导出符号（`SSL_get_verify_result`、`X509_verify_cert`），同样会被 `Interceptor.attach` 改写返回值绕过。

有效防御需要**系统配置最小信任**、**Java + Native 独立多层 Pinning**、**静态编译 BoringSSL 无导出校验**以及**mTLS / 应用层加密兜底**。

## 核心防御矩阵

| 攻击向量 | 根治控制措施 | 关键实现约束 |
|---|---|---|
| 安装代理 CA 触发系统信任 | Release 版 `network_security_config.xml` 仅信任 `system` 且禁用明文 | 禁止在 `base-config` 中配置 `user` 信任锚点；主/备 SPKI Pin 至少 2 个 |
| Frida Hook OkHttp / `TrustManagerImpl` | 关键业务通信下沉至静态链接 BoringSSL 的 Native TLS 客户端 | Java 层保留 Pinning 作为第一道防线，不作为唯一可信边界 |
| Frida Hook `CronetEngine$Builder` | 在 Native 初始化 Cronet 参数并锁定 `addPublicKeyPins` | 严禁在 Release 构建调用 `enablePublicKeyPinningBypassForLocalTrustAnchors(true)` |
| Hook `SSL_get_verify_result` / `X509_verify_cert` | 使用静态内联的 `SSL_CTX_set_custom_verify` 校验 SPKI SHA-256 并剥离符号 | 校验前核对函数入口字节是否被改写为跳转指令（Inline Hook 检测） |
| 代理重打包改写 XML 配置 | 结合 APK 签名/资源哈希自检 + 双向 TLS（mTLS）客户端证书 | 客户端私钥受 Android Keystore 硬件保护，MITM 无法代表合法客户端握手 |

## 加固代码与配置校验示例

### 1. 严格生产环境 `res/xml/network_security_config.xml`

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2027-06-01">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

### 2. Native BoringSSL 自定义 SPKI Pinning 与函数前导码完整性检查

```cpp
// native_pinning.cpp — 静态链接 BoringSSL 校验 SPKI SHA-256 并检查函数入口是否被 Hook
#include <cstdint>
#include <cstring>

static bool is_arm64_hooked(const void* fn_addr) {
    const auto* insn = static_cast<const uint32_t*>(fn_addr);
    uint32_t first = insn[0];
    // 检测常见 Frida/Dobby ARM64 跳板前导指令: LDR X16/X17, #8 (0x58000050 / 0x58000051) 或无条件 B (0x14000000)
    if ((first & 0xFF00001F) == 0x58000010 || (first & 0xFC000000) == 0x14000000) {
        return true;
    }
    return false;
}

extern "C" int verify_spki_pin_constant_time(
    const uint8_t* peer_spki_sha256,
    const uint8_t* primary_pin,
    const uint8_t* backup_pin,
    const void* verify_fn_addr
) {
    if (is_arm64_hooked(verify_fn_addr)) {
        return -2;  // 检测到 Inline Hook 跳板
    }
    uint8_t diff_primary = 0;
    uint8_t diff_backup = 0;
    for (int i = 0; i < 32; ++i) {
        diff_primary |= (peer_spki_sha256[i] ^ primary_pin[i]);
        diff_backup |= (peer_spki_sha256[i] ^ backup_pin[i]);
    }
    return (diff_primary == 0 || diff_backup == 0) ? 0 : -1;
}
```

### 3. Python 检查 `network_security_config.xml` 配置隐患

```python
import xml.etree.ElementTree as ET


def check_network_security_config(xml_text: str) -> list[str]:
    root = ET.fromstring(xml_text)
    issues: list[str] = []

    for elem in root.iter():
        if elem.attrib.get("cleartextTrafficPermitted", "").lower() == "true":
            issues.append(f"cleartext_allowed:{elem.tag}")
        if elem.tag == "certificates" and elem.attrib.get("src") == "user":
            issues.append("user_ca_trusted")

    pin_sets = root.findall(".//pin-set")
    if not pin_sets:
        issues.append("missing_pin_set")
    for ps in pin_sets:
        pins = ps.findall("pin")
        if len(pins) < 2:
            issues.append("insufficient_backup_pins")
    return issues


if __name__ == "__main__":
    weak_xml = "<network-security-config><base-config cleartextTrafficPermitted='true'><trust-anchors><certificates src='user'/></trust-anchors></base-config></network-security-config>"
    weak_res = check_network_security_config(weak_xml)
    assert "cleartext_allowed:base-config" in weak_res
    assert "user_ca_trusted" in weak_res
    assert "missing_pin_set" in weak_res

    strong_xml = """<network-security-config>
      <base-config cleartextTrafficPermitted="false"><trust-anchors><certificates src="system"/></trust-anchors></base-config>
      <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2027-06-01">
          <pin digest="SHA-256">AAAA</pin>
          <pin digest="SHA-256">BBBB</pin>
        </pin-set>
      </domain-config>
    </network-security-config>"""
    assert check_network_security_config(strong_xml) == []
    print("TLS pinning config check passed.")
```

## 防御工作流

```text
1. 系统配置锁定：在 Release 启用严格 network_security_config.xml，禁止明文与用户 CA 锚点
2. 多 Pin 与轮换机制：每个域名配置主/备至少两枚 SPKI SHA-256 Pin，设置合理的 expiration
3. 原生静态链接：将核心网络栈编译为静态链接 BoringSSL，采用内联自定义校验回调并剥离符号
4. 入口防 Hook 核验：在关键校验函数执行前检测 ARM64 前导指令是否被篡改为跳板
5. 应用层纵深兜底：关键 API 请求叠加应用层签名/AEAD 与 mTLS 客户端证书，避免单点被破即全盘明文
```

## 验证与判定标准

- **代理抓包拦截测试**：设备安装 Burp/mitmproxy CA 并配置系统代理后，应用所有核心 HTTPS 请求必须握手失败，代理侧不得出现可解密明文请求。
- **通用脚本抗性测试**：仅对 `okhttp3.CertificatePinner` 与 `TrustManagerImpl` 下发标准 Java Unpinning 脚本时，Native TLS 通道仍须阻断中间人证书。
- **配置文件检查**：CI 构建阶段运行 `check_network_security_config` 返回空问题列表，且代码中不存在 `enablePublicKeyPinningBypassForLocalTrustAnchors(true)`。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 验证代理与 HTTP 降级暴露面 | `android_http_observation_recipe` | 确认开启代理与 Java unpin 后核心流量仍受阻 |
| 检查 Native SSL 符号剥离 | `ghidra_headless_analyze` | 确认 Release SO 未导出 `SSL_get_verify_result` 等明文挂钩点 |
| 核查应用层加密兜底 | `android_crypto_unpack_recipe` | 验证在 TLS 之外仍具备会话签名或载荷保护 |
| 检索对应红蓝文档 | `kb_router` | 对照 [03-tls-pinning-unpinning.md](03-tls-pinning-unpinning.md) 逐层复核 |
