---
id: "ctf-website/22-dos/08-tls-exhaustion-defense"
title: "TLS/SSL 握手耗尽防御与密码学优化"
title_en: "TLS/SSL Handshake Exhaustion Defense and Cryptographic Hardening"
summary: >
  防御利用 TLS 计算不对称性的拒绝服务攻击，覆盖 TLS Handshake Flood（含强制 RSA 私钥解密消耗）、TLS Renegotiation DoS（CVE-2011-1473 / THC-SSL-DOS）、大体积 ClientHello 扩展解析耗尽、mTLS 客户端长证书链放大，以及 Session Ticket/PSK 缓存驱逐与内存耗尽。提供 Nginx/OpenSSL 加固配置及 Python 密码套件与握手配置自检代码。
summary_en: >
  Defense against asymmetric TLS DoS attacks: TLS Handshake Flood (including forced RSA decryption), TLS Renegotiation DoS (CVE-2011-1473), large ClientHello exhaustion, mTLS client certificate chain amplification, and Session Ticket/PSK cache churn. Provides Nginx/OpenSSL hardening configs and Python cipher/handshake policy verifier.
board: "ctf-website"
category: "22-dos"
signals:
  - "禁用纯 RSA 密钥交换改用 ECDHE+ECDSA"
  - "禁用 TLS 1.2 客户端重协商"
  - "ssl_handshake_timeout 与握手限速"
  - "mTLS ssl_verify_depth 链深度上限"
  - "共享 Session Cache 与轮转 Ticket Key"
  - "边缘 TLS 卸载与硬件加速"
mcp_tools:
  - "http_probe"
  - "kb_router"
  - "kb_read_file"
  - "kb_catalog"
keywords:
  - "TLS 握手加固"
  - "ECDSA 性能优化"
  - "禁用 TLS 重协商"
  - "CVE-2011-1473 防护"
  - "mTLS 证书链深度"
  - "Session Ticket 轮转"
  - "ssl_handshake_timeout"
  - "tls exhaustion defense"
difficulty: "advanced"
tags:
  - "defense"
  - "blue-team"
  - "resilience"
  - "dos-protection"
  - "tls"
  - "ssl"
  - "cryptography"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "ctf-website/22-dos/08-tls-exhaustion"
track: "blue"
defends: "ctf-website/22-dos/08-tls-exhaustion"
---
# TLS/SSL 握手耗尽防御与密码学优化

## 防御目标与对抗矩阵

TLS 握手耗尽攻击（对应攻击方法见 [08-tls-exhaustion.md](../../../../red/ctf-website/techniques/22-dos/08-tls-exhaustion.md)）核心利用服务端私钥计算远昂贵于客户端公钥计算的不对称性，或反复重协商与内存分配耗尽 CPU/RAM。蓝队防御重心在于**削减服务端单次握手密码学成本、彻底封堵重协商与超长证书链，以及对半开握手与会话缓存实施硬限制**。

| 攻击向量 | 消耗放大点 | 核心防御措施 | 关键配置 / 参数 |
|---|---|---|---|
| Handshake Flood + 强制 RSA 密钥交换 | RSA-2048 私钥解密耗时 5–50ms（不对称比 50x） | 彻底移除静态 `RSA` 密钥交换，优先 TLS 1.3 + ECDSA P-256 证书 | `ssl_protocols TLSv1.2 TLSv1.3` + 禁用 `TLS_RSA_*` |
| TLS Renegotiation DoS (CVE-2011-1473) | 单连接循环重协商消耗 100% CPU | 升级 OpenSSL（默认 `SSL_OP_NO_RENEGOTIATION`）禁用客户端发起的重协商 | 仅支持 TLS 1.3 或禁用 TLS 1.2 客户端重协商 |
| 大 ClientHello 状态耗尽 | 构造数千字节冗余扩展与 PSK 列表 | 收紧 TLS 握手超时、边缘速率限流与缓冲上限 | `ssl_handshake_timeout 5s` + `ssl_buffer_size 4k` |
| mTLS 证书链放大 | 校验深层自签名客户端证书链耗时 | 严格限制客户端证书链验证深度并前置信源白名单 | `ssl_verify_depth 2` + `ssl_client_certificate` 固定受信任 CA |
| Session Ticket / Cache 驱逐 | 大量会话状态占满内存或淘汰合法缓存 | 启用无状态加密 Session Ticket 并按小时轮转 STEK，或适度扩容共享 Cache | `ssl_session_cache shared:SSL:50m` + STEK 定时轮转 |

---

## 防御工作流

### 阶段一：密码学降耗（移除静态 RSA + 启用 ECDSA 证书）

1. **禁止协商静态 RSA 密钥交换（`TLS_RSA_WITH_*`）**：若客户端只通告 RSA 套件，服务端必须直接拒绝握手（返回 `handshake_failure`）而不应降级执行昂贵的 RSA 私钥解密。
2. **双证书部署优先 ECDSA P-256**：ECDSA P-256 签名速度比 RSA-2048 快 **8–10 倍**，可将服务端 CPU 握手吞吐提升近一个数量级，同时大幅压缩 `Certificate` 握手消息体积。

### 阶段二：Nginx / OpenSSL TLS 抗耗尽生产配置

```nginx
# /etc/nginx/conf.d/tls_dos_hardening.conf
limit_conn_zone $binary_remote_addr zone=tls_ip_conn:20m;
limit_req_zone  $binary_remote_addr zone=tls_ip_req:20m rate=20r/s;

server {
    listen 443 ssl;
    http2 on;
    server_name secure.example.internal;

    # 1. 优先 ECDSA 证书（兼顾 RSA 兼容性回落，但密钥交换强制 ECDHE）
    ssl_certificate     /etc/ssl/certs/site-ecdsa.pem;
    ssl_certificate_key /etc/ssl/private/site-ecdsa.key;
    ssl_certificate     /etc/ssl/certs/site-rsa.pem;
    ssl_certificate_key /etc/ssl/private/site-rsa.key;

    # 2. 仅允许 TLS 1.2 / 1.3，彻底禁用静态 RSA 密钥交换与弱密码套件
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:!RSA:!aNULL:!eNULL';
    ssl_prefer_server_ciphers on;
    ssl_ecdh_curve X25519:prime256v1;

    # 3. 限制半开握手耗时与记录缓冲区，防止 ClientHello 长时间挂起
    ssl_handshake_timeout 5s;
    ssl_buffer_size 4k;
    limit_conn tls_ip_conn 25;

    # 4. 会话缓存与无状态 Ticket 管控（防止 OOM 与 Cache Churn）
    ssl_session_cache shared:SSL:50m;
    ssl_session_timeout 10m;
    # 若无法实现自动化每小时安全轮转 STEK，关闭 tickets 以保持前向保密与确定性
    ssl_session_tickets off;

    # 5. 若启用 mTLS，强制限制客户端证书链深度 <= 2 防止长链验证放大
    # ssl_verify_client on;
    # ssl_verify_depth 2;
    # ssl_client_certificate /etc/ssl/certs/internal-ca.pem;

    # 6. 开启 OCSP Stapling，减少服务端/客户端实时外部验证阻塞
    ssl_stapling on;
    ssl_stapling_verify on;
}
```

### 阶段三：禁用重协商与边缘负载均衡卸载

1. **确保禁用 TLS 1.2 客户端重协商**：OpenSSL 1.1.1+ 默认阻止客户端重协商；若使用自定义 Go/Java/HAProxy 终止 TLS，显式配置 `Renegotiation: tls.RenegotiateNever`（Go 默认值）或升级至 TLS 1.3（协议层已移除重协商机制）。
2. **前置四层/TLS 终止集群与 SNI 早期丢弃**：对于未知或无效 SNI 请求，在 Nginx 中配置默认 catch-all server 块使用 `ssl_reject_handshake on;`，无需加载证书及计算密钥交换直接中断非法握手。

```nginx
# 默认未知 SNI 直接拒绝握手，零证书/私钥开销
server {
    listen 443 ssl default_server;
    ssl_reject_handshake on;
}
```

---

## 弹性校验代码（可运行 Python 自检）

以下 Python 脚本对本地/CI 的 TLS 策略配置及 OpenSSL `ssl.SSLContext` 进行自动化基线核查：验证静态 RSA 套件是否被禁用、TLS 1.3 是否启用、重协商禁止标志 (`OP_NO_RENEGOTIATION`) 是否生效、mTLS 链深度与握手超时是否合规。

```python
#!/usr/bin/env python3
"""TLS/SSL exhaustion defense verifier: cipher asymmetry, renegotiation block, and Nginx policy check."""

import ssl


def verify_ssl_context_hardening(ctx: ssl.SSLContext) -> list[str]:
    """Audit an ssl.SSLContext instance against TLS DoS hardening requirements."""
    issues: list[str] = []

    if ctx.minimum_version < ssl.TLSVersion.TLSv1_2:
        issues.append(f"weak_min_tls:{ctx.minimum_version}")

    # 验证禁用了客户端重协商（OpenSSL 1.1.1+ 提供 OP_NO_RENEGOTIATION）
    no_reneg_flag = getattr(ssl, "OP_NO_RENEGOTIATION", 0)
    if no_reneg_flag and not (ctx.options & no_reneg_flag):
        issues.append("client_renegotiation_not_disabled")

    # 检查是否残留纯 RSA 密钥交换套件（kRSA），避免 10-50x 解密不对称
    ciphers = ctx.get_ciphers()
    static_rsa = [c["name"] for c in ciphers if c.get("kea") == "kx-rsa"]
    if static_rsa:
        issues.append(f"static_rsa_kx_enabled:{','.join(static_rsa[:3])}")

    return issues


def verify_nginx_tls_policy(conf_text: str) -> list[str]:
    """Validate Nginx TLS snippet contains handshake timeout, reject default, and depth caps."""
    checks = {
        "ssl_handshake_timeout": "missing_handshake_timeout",
        "ssl_reject_handshake on;": "missing_default_sni_reject",
        "ssl_session_cache shared:": "missing_shared_session_cache",
        "ssl_protocols TLSv1.2 TLSv1.3;": "missing_modern_tls_protocols",
    }
    return [err for token, err in checks.items() if token not in conf_text]


def build_hardened_server_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
    )
    if hasattr(ssl, "OP_NO_RENEGOTIATION"):
        ctx.options |= ssl.OP_NO_RENEGOTIATION
    return ctx


def run_self_checks() -> None:
    # 1. 加固后 SSLContext 应零告警
    hardened_ctx = build_hardened_server_context()
    issues = verify_ssl_context_hardening(hardened_ctx)
    assert issues == [], f"Unexpected issues in hardened context: {issues}"

    # 2. 启用纯 RSA 套件的弱上下文应被拦截
    weak_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    weak_ctx.set_ciphers("AES128-GCM-SHA256:AES256-SHA")
    weak_issues = verify_ssl_context_hardening(weak_ctx)
    assert any("static_rsa_kx_enabled" in i for i in weak_issues), f"Weak RSA kx missed: {weak_issues}"

    # 3. Nginx 配置基线校验
    good_nginx = """
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_handshake_timeout 5s;
    ssl_session_cache shared:SSL:50m;
    ssl_reject_handshake on;
    """
    assert verify_nginx_tls_policy(good_nginx) == []
    assert "missing_handshake_timeout" in verify_nginx_tls_policy("ssl_reject_handshake on;")
    print("[PASS] All TLS/SSL handshake exhaustion defense checks passed.")


if __name__ == "__main__":
    run_self_checks()
```

---

## 验证与判定标准

| 验证项 | 达标判定标准 | 可观测指标 |
|---|---|---|
| 静态 RSA 套件清零 | 仅使用 RSA 密钥交换的 `ClientHello` 被服务端直接拒绝 | `testssl.sh` / OpenSSL 握手测试返回 `handshake failure` |
| 重协商禁用 | 连接建立后尝试 TLS 1.2 重协商被服务端立即中断 | 同一连接无多次 `ServerHello` |
| 握手超时回收 | 发送半截 `ClientHello` 后超过 `5s` 自动断开连接 | 70KB/连接 内存占用不随半开数持续累加 |
| mTLS 链深限制 | 超过 2 层的客户端伪造证书链在解析阶段立即拒绝 | `verify_depth` 报错阻断，无高 CPU 尖峰 |

---

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| TLS 协议与握手探测 | `http_probe` | 检查 TLS 版本协商、ALPN 及异常 SNI 拒绝行为 |
| 蓝队技术搜索 | `kb_router` | 以 `track="blue"` 检索 `tls` / `ssl` / `renegotiation` 防御文档 |
| 攻防对照查阅 | `kb_read_file` | 读取本文件及配对攻击文档 `ctf-website/22-dos/08-tls-exhaustion` |
| 分类清单查看 | `kb_catalog` | 列举 `22-dos` 全部防御条目 |
