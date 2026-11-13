---
id: "ctf-website/04-ssrf/ssrf-defense"
title: "SSRF 纵深防御：协议封堵、DNS Pinning 与云元数据隔离"
title_en: "SSRF Defense-in-Depth: Protocol Allowlisting, DNS Pinning & IMDSv2"
summary: >
  全面防御利用 Gopher/File/Dict 等危险协议接管内网服务（Redis/MySQL/FastCGI）、DNS Rebinding 绕过、IP 进制编码变形、URL 解析差分、302 跳转跟随及云元数据接口（AWS IMDSv1/GCP/Azure/阿里云）窃取凭据的 SSRF 攻击。
summary_en: >
  Defense-in-depth against SSRF attacks including dangerous protocols (gopher://, file://, dict://), DNS rebinding TOCTOU, non-standard IP encodings, URL parser differentials, 302 redirect pivoting, and cloud metadata credential theft. Enforces strict scheme/IP allowlisting, socket-level IP pinning, redirect disabling, and IMDSv2 enforcement.
board: "ctf-website"
category: "04-ssrf"
signals: ["SSRF", "DNS rebinding", "Gopher", "cloud metadata", "IMDSv2", "内网隔离", "SSRF防御"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["SSRF防御", "DNS Pinning", "禁Gopher协议", "禁用重定向", "IMDSv2强制", "内网IP过滤", "出口代理隔离", "blue-team"]
difficulty: "advanced"
tags: ["defense", "blue-team", "ssrf", "cloud-security", "network-isolation", "dns-rebinding"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/04-ssrf/ssrf", "ctf-website/04-ssrf/open-redirect-defense", "ctf-website/10-cloud/aws-iam-privesc-defense"]
track: "blue"
defends: "ctf-website/04-ssrf/ssrf"
---
# SSRF 纵深防御：协议封堵、DNS Pinning 与云元数据隔离

## 防御目标与威胁面

SSRF 能够击穿边界防火墙，将外网入口转化为对内网中间件、云元数据及内部微服务控制面的直接访问通道。核心绕过手法包括：

1. **危险协议滥用**：`gopher://`、`dict://`、`file://`、`ftp://` 向 Redis/Memcached/PHP-FPM/MySQL 发送原生 TCP 字节流。
2. **先校验后请求 TOCTOU（DNS Rebinding）**：校验阶段解析出公网 IP 放行，HTTP 客户端真正建连时重新发起 DNS 解析得到 `127.0.0.1` 或内网地址。
3. **IP 表示变形与解析器差异**：十进制 `2130706433`、十六进制 `0x7f000001`、八进制 `017700000001`、`0.0.0.0/8`、IPv6 映射 `[::ffff:127.0.0.1]`、`user@internal`、反斜杠及 `302 Location` 重定向跳转。
4. **云元数据凭据窃取**：AWS IMDSv1 (`169.254.169.254`)、GCP/Azure/阿里云元数据端点无强上下文认证即可获取实例 IAM 临时密钥。

## 核心防御架构

| 防护层 | 根治控制措施 | 实施要点 |
|---|---|---|
| 协议与端口层 | 仅允许 `https://`（必要时 `http://`）与 `80/443` 端口 | 显式禁用 `gopher`/`file`/`dict`/`ftp`/`jar`/`netdoc` 等所有非常规协议 |
| 解析与连接绑定 | DNS Pinning + Socket 层校验，消除二次解析窗口 | 解析一次得到全部 A/AAAA，用 `ipaddress` 验证非私网/回环/链路本地/未指定地址后，直接以该 IP 建立底层连接并覆盖 `Host`/SNI |
| 重定向与头注入 | 禁用 HTTP 客户端自动跟随重定向（`allow_redirects=False`） | 若业务确需跳转，每一跳均须重新过完整校验；严格拒绝 URL 内 CR/LF 字符 |
| 网络出站隔离 | 将需发起外网抓包的组件置于独立隔离 VPC/出口代理 | 出口网关从网络层面阻断向内网 CIDR 与 `169.254.169.254`/`100.100.100.200` 的路由 |
| 云平台纵深 | 强制 AWS EC2 启用 IMDSv2（`HttpTokens=required`，`HopLimit=1`） | 在容器中限制访问宿主链路本地元数据 IP，并最小化实例角色权限 |

## 加固代码与离线核查示例

以下 Python 实现展示**单次解析 + `ipaddress` 全地址族拦截（覆盖 IPv4-mapped IPv6、`0.0.0.0/8`、链路本地及 CGNAT）+ 禁用重定向 + 固定 IP 连接规划**的安全封装与自检：

```python
import ipaddress
import socket
from urllib.parse import urlparse
from typing import Callable, List, Tuple

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}
CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")


def is_forbidden_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    # 展开 IPv4-mapped IPv6 (如 ::ffff:127.0.0.1 或 ::ffff:169.254.169.254)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (isinstance(ip, ipaddress.IPv4Address) and ip in CGNAT_NET)
    )


def resolve_and_pin_url(
    url: str,
    resolver: Callable[[str, int], List[str]] | None = None,
) -> Tuple[bool, dict]:
    if any(ch in url for ch in ("\r", "\n", "\x00", "\\")):
        return False, {"reason": "forbidden_control_or_backslash"}

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        return False, {"reason": f"forbidden_scheme:{scheme}"}
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        return False, {"reason": "userinfo_forbidden"}

    host = parsed.hostname
    if not host:
        return False, {"reason": "missing_host"}

    port = parsed.port or (443 if scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        return False, {"reason": f"forbidden_port:{port}"}

    # 单次 DNS 解析并在连接前校验全部候选 IP，防止 DNS Rebinding
    if resolver is None:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        ips = list(dict.fromkeys(info[4][0] for info in infos))
    else:
        ips = resolver(host, port)

    if not ips:
        return False, {"reason": "dns_resolution_empty"}

    for ip in ips:
        if is_forbidden_ip(ip):
            return False, {"reason": f"forbidden_ip:{ip}"}

    # 返回固定首 IP 供底层 Socket/HTTPAdapter 直连，禁止客户端二次解析与自动 302 跟随
    return True, {
        "pinned_ip": ips[0],
        "port": port,
        "host_header": parsed.netloc,
        "sni_hostname": host,
        "allow_redirects": False,
    }


if __name__ == "__main__":
    assert resolve_and_pin_url("gopher://127.0.0.1:6379/_PING")[0] is False
    assert resolve_and_pin_url("http://allow.example@127.0.0.1/")[0] is False
    assert resolve_and_pin_url("http://[::ffff:169.254.169.254]/latest/meta-data/", lambda h, p: ["::ffff:169.254.169.254"])[0] is False
    assert resolve_and_pin_url("http://2130706433/", lambda h, p: ["127.0.0.1"])[0] is False
    assert resolve_and_pin_url("http://0.0.0.0/", lambda h, p: ["0.0.0.0"])[0] is False
    assert resolve_and_pin_url("http://100.100.100.200/latest/meta-data/", lambda h, p: ["100.100.100.200"])[0] is False
    ok, plan = resolve_and_pin_url("https://api.public.example/v1/hook", lambda h, p: ["93.184.216.34"])
    assert ok and plan["pinned_ip"] == "93.184.216.34" and plan["allow_redirects"] is False
    print("SSRF defense self-check passed.")
```

## 防御工作流

```text
1. 业务收敛：将任意 URL 抓取改为域名/资源 ID 白名单，非必要不向用户开放自由 URL 输入
2. 协议与入口过滤：仅放行 http/https 与 80/443，剔除 userinfo、反斜杠、CR/LF 与非标准主机格式
3. DNS Pinning 连接：应用层解析一次并校验全部 IP（含 IPv4-mapped IPv6 与 CGNAT），绑定固定 IP 建连并关闭自动重定向
4. 独立出站代理：将外连抓取流量路由至无内网路由权限的独立 Egress Proxy（如 Smokescreen）
5. 云基础设施加固：全量云主机强制开启 IMDSv2 且 HopLimit=1，隔离容器网段访问元数据 IP
```

## 验证与判定标准

- **全变形内网拦截**：针对 `127.0.0.1`、`2130706433`、`0x7f000001`、`[::ffff:127.0.0.1]`、`0.0.0.0`、`169.254.169.254`、`100.100.100.200` 及 `gopher://` 的输入均被前置拦截，不触发任何内网 TCP 连接。
- **重绑定与 302 阻断**：面对 `TTL=0` 切换公/私网 IP 的测试域名及返回 `302 -> http://127.0.0.1` 的外部服务端，出站请求均不落地到内网服务。
- **IMDSv1 失效**：从云主机实例内不带 `X-aws-ec2-metadata-token` 的 `GET /latest/meta-data/` 稳定返回 `401 Unauthorized`。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索 SSRF 与云元数据防御 | `kb_router` | 搜索 `SSRF防御`、`DNS Pinning`、`IMDSv2` |
| 对照高阶绕过矩阵 | `kb_read_file` | 读取 [ssrf.md](../../../../red/ctf-website/techniques/04-ssrf/ssrf.md) 核查各类 IP 变形、Gopher 与解析器差分 |
| 联动云与重定向加固 | `kb_catalog` | 协同查阅 `open-redirect-defense` 与 `aws-iam-privesc-defense` |
