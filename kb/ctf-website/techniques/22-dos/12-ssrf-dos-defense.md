---
id: "ctf-website/22-dos/12-ssrf-dos-defense"
title: "SSRF 驱动的拒绝服务防御与出站隔离"
title_en: "SSRF-Driven Denial of Service Defense and Egress Isolation"
summary: >
  系统防御利用服务端请求伪造（SSRF）实施的拒绝服务攻击：包括内网服务洪泛、Gopher/Dict 协议走私向 Redis 注入 FLUSHALL/DEBUG SLEEP、递归 SSRF 自我耗尽、访问云元数据 169.254.169.254 窃取凭证后破坏云资源，以及 file:///dev/random 阻塞。提供出站校验逻辑、NetworkPolicy 隔离与 Redis 加固配置。
summary_en: >
  Defense against SSRF-driven DoS attacks: internal service flooding, Gopher/Dict protocol smuggling into Redis (FLUSHALL/DEBUG SLEEP), recursive SSRF self-exhaustion, cloud metadata 169.254.169.254 credential theft and resource destruction, and file:// blocking (/dev/random, /dev/zero). Covers DNS-pinned egress filtering, Kubernetes NetworkPolicy, Redis hardening, and runnable Python checks.
board: "ctf-website"
category: "22-dos"
signals:
  - "URL Scheme 严格白名单仅限 https"
  - "DNS 解析后校验证书并锁定目标 IP"
  - "阻止环回/私网/链路本地/IPv6 映射地址"
  - "禁用 HTTP 重定向或逐跳重校验"
  - "X-Fetch-Depth 防递归 SSRF 自调用"
  - "IMDSv2 跳数=1 与 Redis 危险命令重命名"
mcp_tools:
  - "http_probe"
  - "kb_router"
  - "kb_read_file"
  - "kb_catalog"
keywords:
  - "SSRF DoS 防御"
  - "Gopher 协议封禁"
  - "DNS Rebinding 防护"
  - "出站网络隔离"
  - "递归 SSRF 防护"
  - "IMDSv2 加固"
  - "Redis 命令禁用"
  - "ssrf dos defense"
difficulty: "advanced"
tags:
  - "defense"
  - "blue-team"
  - "resilience"
  - "dos-protection"
  - "ssrf"
  - "redis"
  - "cloud-metadata"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "ctf-website/22-dos/12-ssrf-dos"
track: "blue"
defends: "ctf-website/22-dos/12-ssrf-dos"
---
# SSRF 驱动的拒绝服务防御与出站隔离

## 防御目标与对抗矩阵

SSRF 驱动的 DoS（对应攻击向量见 [12-ssrf-dos.md](./12-ssrf-dos.md)）借目标服务器的内网信任关系与高带宽，绕过外网限流直击内网数据库、Redis、云元数据或形成自我递归放大。防御必须坚持**应用层强白名单解析 + 传输层防 DNS 重绑定固定连接 + 网络层零信任出站隔离 + 内部服务自身鉴权**。

| 攻击向量 | 破坏链路 | 核心防御手段 | 关键控制点 |
|---|---|---|---|
| 内网服务扫描与洪泛 | 目标服务器并发请求 `10.x/172.16.x/192.168.x` | 严格禁止私有/保留网段 IP、限制出站并发与超时、NetworkPolicy 拒绝业务 Web Pod 访问无关内网 | 出站代理 (`Squid`/`Envoy`) + `ipaddress` 全局校验 |
| Gopher / Dict / File 协议走私 | `gopher://redis:6379` 注入 `FLUSHALL`/`DEBUG SLEEP` 或 `file:///dev/random` 阻塞 | 强制仅允许 `https://`（必要时 `http://`），禁用 `curl`/HTTP 库非 HTTP 协议与重定向，Redis 启用 ACL 与禁用高危命令 | 仅放行 `https` + Redis `rename-command` + 响应体大小/超时硬限 |
| 递归 SSRF 自我攻击 | 请求自身或链式微服务形成死循环耗尽连接池 | 禁用内部回环/自身域名访问 + 出站请求注入防重入标记头 (`X-SSRF-Hop`) | 检测请求头含 `X-SSRF-Hop` 时直接返回 `400` |
| 云元数据凭证与资源破坏 | 读取 `169.254.169.254` 获取 IAM Token 后停服/删库 | 强制 IMDSv2（需 `PUT` + Token）+ `HttpPutResponseHopLimit=1` + 防火墙/NetworkPolicy 封锁 `169.254.169.254/32` | 最小权限 IAM Role（遵循只读/业务最小集合，禁止删除或改安全组） |

---

## 防御工作流

### 阶段一：应用层出站请求全链路守卫

1. **禁止使用原生 `curl` 或默认允许重定向的客户端直接访问用户输入 URL**：在发起任何出站请求前执行严格校验：
   - **Scheme 白名单**：仅允许 `https`（如业务确需支持 `http`，严禁 `gopher`/`dict`/`file`/`ftp`/`ldap`/`jar`）；
   - **端口白名单**：仅允许 `443`（及业务明确需要的 `80`），禁止连接 `6379`、`11211`、`3306`、`5432`、`9200` 等数据库与缓存端口；
   - **目标域名与 IP 解析核查**：解析所有 A/AAAA 记录后校验每一个 IP 必须为公网全球单播地址（拒绝 `is_private`、`is_loopback`、`is_link_local`、`is_multicast`、`is_reserved` 及 IPv4-mapped IPv6 `::ffff:127.0.0.1`）；
   - **固定连接 IP 防 DNS Rebinding**：校验通过后直接将连接目标绑定到已验证的 IP 并传入原 `Host` / SNI，禁止请求库二次独立 DNS 解析；
   - **禁用自动重定向**（`allow_redirects=False`）且设定严苛超时（`connect=2s, read=5s`）与最大响应体上限（`<= 2MB`），防止 `/dev/zero` 或超大响应引发 OOM。
2. **防递归 SSRF 标记头**：出站代理/客户端统一附加 `X-Outbound-Fetch: 1`；服务端对外暴露的抓取/Webhook 测试接口若检测到入站请求携带该头部，立即拒绝。

### 阶段二：基础设施与内部服务纵深加固

1. **Kubernetes 出站隔离（仅允许访问公网非私网地址）**：

```yaml
# k8s-ssrf-egress-isolation.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web-fetcher-egress-shield
  namespace: app-prod
spec:
  podSelector:
    matchLabels:
      role: url-fetcher
  policyTypes: ["Egress"]
  egress:
    # 仅放行 DNS 与外网 443，显式排除全部私网与链路本地元数据网段
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
              - 127.0.0.0/8
              - 169.254.0.0/16
      ports:
        - protocol: TCP
          port: 443
```

2. **内部 Redis 与云主机 IMDS 加固**：即使出站控制意外被旁路，内部 Redis 必须强制密码/ACL 认证并禁用高危指令，云实例强制 IMDSv2：

```conf
# /etc/redis/redis.conf — 阻断通过 SSRF 走私的破坏性指令
bind 127.0.0.1 10.10.2.15
protected-mode yes
requirepass REPLACE_WITH_STRONG_RANDOM_SECRET
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command DEBUG ""
rename-command CONFIG ""
rename-command SHUTDOWN ""
```

```bash
# AWS EC2 强制 IMDSv2 并限制跳数为 1（阻止容器内跨网桥访问元数据）
aws ec2 modify-instance-metadata-options \
  --instance-id i-0123456789abcdef0 \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

---

## 弹性校验代码（可运行 Python 自检）

以下 Python 代码实现完整的 SSRF 防护 URL 与 IP 校验器，覆盖 `gopher://`/`file://`/`dict://` 封禁、端口白名单、IPv4/IPv6 私有/链路本地/映射地址拦截（如 `169.254.169.254`、`::ffff:127.0.0.1`、`10.0.0.1`），以及递归 `X-Outbound-Fetch` 环路阻断。

```python
#!/usr/bin/env python3
"""SSRF-driven DoS defense verifier: scheme/port/IP/IPv6-mapped & recursion-hop guards."""

import ipaddress
from urllib.parse import urlsplit


ALLOWED_SCHEMES = {"https"}
ALLOWED_PORTS = {443}


class SsrfBlockedError(ValueError):
    """Raised when an outbound URL violates SSRF egress policy."""


def validate_ip_public(ip_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Ensure IP is globally routable (reject private, loopback, link-local, and mapped-v4)."""
    ip_obj = ipaddress.ip_address(ip_str)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped
    if not ip_obj.is_global or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_link_local:
        raise SsrfBlockedError(f"non-public IP blocked: {ip_str}")
    return ip_obj


def validate_outbound_url(raw_url: str, resolved_ips: list[str], incoming_headers: dict[str, str] | None = None) -> list[str]:
    """Validate URL scheme, port, recursion header, and all resolved DNS IPs."""
    if incoming_headers and incoming_headers.get("X-Outbound-Fetch"):
        raise SsrfBlockedError("recursive SSRF loop detected via X-Outbound-Fetch")

    parts = urlsplit(raw_url.strip())
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise SsrfBlockedError(f"forbidden scheme: {parts.scheme}")
    if not parts.hostname:
        raise SsrfBlockedError("missing hostname")
    if parts.username or parts.password:
        raise SsrfBlockedError("embedded URL userinfo forbidden")

    port = parts.port or 443
    if port not in ALLOWED_PORTS:
        raise SsrfBlockedError(f"forbidden port: {port}")

    if not resolved_ips:
        raise SsrfBlockedError("empty DNS resolution")
    validated = [str(validate_ip_public(ip)) for ip in resolved_ips]
    return validated


def run_self_checks() -> None:
    # 1. 阻断 Gopher/Dict/File 协议走私
    for evil_url in (
        "gopher://redis:6379/_FLUSHALL",
        "dict://127.0.0.1:6379/info",
        "file:///dev/random",
        "http://169.254.169.254/latest/meta-data/",
    ):
        try:
            validate_outbound_url(evil_url, ["93.184.216.34"])
            raise AssertionError(f"Forbidden URL was allowed: {evil_url}")
        except SsrfBlockedError:
            pass

    # 2. 阻断云元数据、内网与 IPv4-mapped IPv6 地址
    for evil_ip in ("169.254.169.254", "10.0.0.5", "172.16.1.10", "192.168.1.1", "127.0.0.1", "::ffff:127.0.0.1", "fd00::1"):
        try:
            validate_outbound_url("https://rebind.example.com/hook", [evil_ip])
            raise AssertionError(f"Internal IP {evil_ip} was allowed")
        except SsrfBlockedError:
            pass

    # 3. 阻断递归 SSRF
    try:
        validate_outbound_url("https://api.example.com/fetch", ["93.184.216.34"], {"X-Outbound-Fetch": "1"})
        raise AssertionError("Recursive SSRF header was not blocked")
    except SsrfBlockedError:
        pass

    # 4. 放行合规公网 HTTPS 地址
    assert validate_outbound_url("https://example.com/webhook", ["93.184.216.34"]) == ["93.184.216.34"]
    print("[PASS] All SSRF DoS defense checks passed.")


if __name__ == "__main__":
    run_self_checks()
```

---

## 验证与判定标准

| 验证项 | 达标判定标准 | 可观测指标 |
|---|---|---|
| 非法 Scheme 封禁 | `gopher://`、`dict://`、`file://`、`http://` 在解析层即返回 `400` | 出站代理零非 HTTPS 连接建立 |
| 内网与元数据不可达 | `10.x`、`172.16.x`、`192.168.x`、`169.254.169.254` 及映射 IPv6 全部拦截 | `NetworkPolicy` 丢弃计数正常，IMDS 仅支持带 Token 的 IMDSv2 |
| 防递归 SSRF | 携带自环标识或指向自身服务的请求被立即拒绝 | 线程/连接池在递归探测下无上涨 |
| 内部 Redis 抗走私 | 匿名发送 `FLUSHALL` / `DEBUG SLEEP` 返回 `NOAUTH` 或未知命令错误 | 内部缓存可用性 `100%` |

---

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| 出站代理端点校验 | `http_probe` | 验证 Webhook/抓取接口对内网/非法 scheme 的拒绝响应 |
| 蓝队技术搜索 | `kb_router` | 以 `track="blue"` 搜索 `ssrf` / `imds` / `gopher` 防御方案 |
| 攻防文档对照 | `kb_read_file` | 读取本文件及配对攻击文档 `ctf-website/22-dos/12-ssrf-dos` |
| 分类清单查看 | `kb_catalog` | 列举 `22-dos` 下所有蓝队加固条目 |
