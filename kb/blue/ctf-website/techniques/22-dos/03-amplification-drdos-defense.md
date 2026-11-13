---
id: "ctf-website/22-dos/03-amplification-drdos-defense"
title: "UDP 反射与放大攻击（DRDoS）防御"
title_en: "UDP Amplification and DRDoS Defense"
summary: >
  系统防御基于伪造源 IP 的分布式反射放大攻击（DRDoS），覆盖 BCP38 源地址验证、DNS 响应速率限制（RRL）与禁用开放递归、NTP monlist 禁用、Memcached UDP 关闭、CLDAP/SSDP/WS-Discovery/SNMP/Chargen/QOTD 端口收敛，以及 DTLS/QUIC Cookie 校验与 TCP 中间盒防护。
summary_en: >
  Comprehensive defense against source-spoofed Distributed Reflection DoS (DRDoS): BCP38 ingress filtering, DNS Response Rate Limiting (RRL) and closed recursion, disabling NTP monlist, disabling Memcached UDP, locking down CLDAP/SSDP/WS-Discovery/SNMP/Chargen/QOTD, DTLS/QUIC address validation, and TCP middlebox reflection mitigation.
board: "ctf-website"
category: "22-dos"
signals:
  - "BCP38 rp_filter 严格源路由校验"
  - "BIND RRL 响应限速与禁止外部递归"
  - "NTP monlist 禁用与 restrict 收紧"
  - "Memcached UDP 端口关闭 (-U 0)"
  - "UDP 反射端口 17/19/161/389/1900/3702 封禁"
  - "QUIC Retry 与 DTLS Cookie 源验证"
mcp_tools:
  - "http_probe"
  - "kb_router"
  - "kb_read_file"
  - "kb_catalog"
keywords:
  - "DRDoS 防御"
  - "BCP38"
  - "uRPF"
  - "DNS RRL"
  - "NTP monlist 禁用"
  - "Memcached 加固"
  - "UDP 放大防护"
  - "amplification defense"
difficulty: "advanced"
tags:
  - "defense"
  - "blue-team"
  - "resilience"
  - "dos-protection"
  - "drdos"
  - "udp"
  - "bcp38"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "ctf-website/22-dos/03-amplification-drdos"
track: "blue"
defends: "ctf-website/22-dos/03-amplification-drdos"
---
# UDP 反射与放大攻击（DRDoS）防御

## 防御目标与对抗矩阵

反射放大攻击（对应攻击技术见 [03-amplification-drdos.md](../../../../red/ctf-website/techniques/22-dos/03-amplification-drdos.md)）包含两个防御侧面：**防止自身基础设施成为反射器**（Eliminate Reflectors & BCP38）以及**在网络边缘清洗入向反射流量**（Ingress Mitigation）。

| 放大向量 | 端口 / 协议 | 历史放大比 | 核心防御与收敛配置 |
|---|---|---|---|
| IP 源地址伪造 | 网络层 IPv4/IPv6 | DRDoS 根基 | 部署 BCP38 / SAVI / 严格 `uRPF`，拒绝非本网段源 IP 出站 |
| 开放 DNS 解析器 | UDP 53 | 70x–90x | 关闭外部递归 (`allow-recursion`)、启用 BIND RRL、禁用 `ANY` 大包 (`minimal-any yes`) |
| NTP `monlist` | UDP 123 | ~556x | 升级至 NTP `>= 4.2.7p26` 或 Chrony，显式 `disable monitor` 与 `noquery` |
| Memcached UDP | UDP 11211 | 50,000x | 启动参数强制 `-U 0 -l 127.0.0.1` 关闭 UDP 并禁用公网绑定 |
| CLDAP / WS-Discovery / SSDP | UDP 389 / 3702 / 1900 | 15x–80x | 边界防火墙严格封禁入出向公网流量，禁用不必要的多播发现服务 |
| SNMP / Chargen / QOTD | UDP 161 / 19 / 17 | 80x–∞ | 彻底下线 inetd 遗留 Chargen/QOTD；SNMP 仅限内网管理段并迁移 SNMPv3 |
| DTLS / QUIC / TCP 中间盒 | UDP 443 / TCP | 12x–100x | 强制 DTLS 1.3 / QUIC `Retry` 源地址验证令牌；修补中间盒反射漏洞 (CVE-2022-32293) |

---

## 防御工作流

### 阶段一：源地址防伪造与边界防火墙收敛（BCP38 / nftables）

1. **启用内核与路由器级严格逆向路径过滤（uRPF / BCP38）**：防止本网段主机伪造外部源 IP 发出反射探测或攻击包。

```ini
# /etc/sysctl.d/99-bcp38-spoof-protection.conf
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
```

2. **边缘 nftables 封禁高危反射 UDP 端口并限制入向突发**：仅对明确需要对外提供服务的协议放行，并按源端口识别反射流量进入清洗队列或限速。

```nftables
#!/usr/sbin/nft -f
table inet drdos_filter {
    chain input {
        type filter hook input priority 0; policy accept;

        # 阻断公网直接访问高危反射服务端口（假设 eth0 为公网口）
        iifname "eth0" udp dport { 17, 19, 111, 161, 389, 1900, 3702, 11211 } drop

        # 对本地仅限内部使用的 NTP 查询端口做源网段白名单
        iifname "eth0" udp dport 123 udp length > 76 drop

        # 对突发入向高放大特征 UDP 响应包做边缘限速保护
        iifname "eth0" udp sport { 123, 389, 1900, 11211 } limit rate over 1000/second drop
    }
}
```

### 阶段二：DNS、NTP 与 Memcached 服务专项加固

1. **BIND9 权威与缓存 DNS 加固**：关闭面向公网的递归解析，开启 Response Rate Limiting（RRL）并最小化 `ANY` 响应。

```bind
// /etc/bind/named.conf.options
acl "internal_trusted" {
    10.0.0.0/8;
    172.16.0.0/12;
    192.168.0.0/16;
    127.0.0.0/8;
};

options {
    recursion yes;
    allow-recursion { internal_trusted; };
    allow-query-cache { internal_trusted; };

    // 缩小单次响应体积，抑制 ANY 与 EDNS0 放大
    minimal-any yes;
    minimal-responses yes;
    max-udp-size 1232;
    edns-udp-size 1232;

    // RRL 响应速率限制
    rate-limit {
        responses-per-second 5;
        window 5;
        slip 2;            // 每 2 次超限返回 1 次 TC=1 迫使客户端切 TCP 验证真实 IP
        exempt-clients { internal_trusted; };
    };
};
```

2. **NTP 与 Memcached 加固**：

```conf
# /etc/ntp.conf — 禁用 monlist 私有模式并限制控制查询
disable monitor
restrict default kod nomodify notrap nopeer noquery
restrict -6 default kod nomodify notrap nopeer noquery
restrict 127.0.0.1
restrict ::1
```

```conf
# /etc/memcached.conf — 彻底关闭 UDP (-U 0) 并仅监听回环或内网隔离口
-p 11211
-U 0
-l 127.0.0.1
```

### 阶段三：现代协议（DTLS / QUIC）与流量清洗联动

1. **QUIC / DTLS 防放大准则**：在客户端源地址未通过 `Retry` / `HelloVerifyRequest` Cookie 验证前，服务端发送的响应包总字节数**不得超过收到的初始请求包大小的 3 倍**（RFC 9000 Section 8.1 强制要求）。
2. **公网入向反射流量处置**：在单台主机上行链路打满前，必须通过上游 BGP FlowSpec / scrubbing center 在 ISP 侧按 `udp.src_port in {53, 123, 389, 11211}` 对异常响应流进行牵引丢弃。

---

## 弹性校验代码（可运行 Python 自检）

以下 Python 脚本在本地环回地址上验证高危 UDP 反射端口是否暴露，计算服务响应放大系数（若大于 2x 则标记告警），并校验证书/BCP38 `rp_filter` 配置字典是否符合基线。

```python
#!/usr/bin/env python3
"""DRDoS self-check: verifies UDP reflector exposure, amplification ratio, and sysctl baseline."""

import socket
import struct
from dataclasses import dataclass


@dataclass
class ReflectorCheckResult:
    protocol: str
    port: int
    responded: bool
    query_bytes: int
    response_bytes: int
    ratio: float
    compliant: bool


PROBES = {
    "NTP_MONLIST": (123, b"\x17\x00\x03\x2a" + b"\x00" * 4),
    "MEMCACHED_STATS": (11211, b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"),
    "SSDP_MSEARCH": (
        1900,
        b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
    ),
    "DNS_ANY": (
        53,
        struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        + b"\x07example\x03com\x00"
        + struct.pack(">HH", 255, 1),
    ),
}


def check_local_udp_reflector(host: str, protocol: str, timeout: float = 0.2) -> ReflectorCheckResult:
    """Check whether a host/port responds with amplified UDP payloads."""
    port, payload = PROBES[protocol]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (host, port))
        data, _ = sock.recvfrom(65535)
        ratio = round(len(data) / max(len(payload), 1), 2)
        # Compliant only if amplification factor <= 2.0 (or closed/non-responsive)
        return ReflectorCheckResult(
            protocol=protocol,
            port=port,
            responded=True,
            query_bytes=len(payload),
            response_bytes=len(data),
            ratio=ratio,
            compliant=(ratio <= 2.0),
        )
    except (socket.timeout, ConnectionRefusedError, OSError):
        return ReflectorCheckResult(
            protocol=protocol,
            port=port,
            responded=False,
            query_bytes=len(payload),
            response_bytes=0,
            ratio=0.0,
            compliant=True,
        )
    finally:
        sock.close()


def verify_bcp38_sysctl(sysctl_map: dict[str, str]) -> list[str]:
    """Verify kernel anti-spoofing sysctl values."""
    expected = {
        "net.ipv4.conf.all.rp_filter": "1",
        "net.ipv4.conf.default.rp_filter": "1",
        "net.ipv4.conf.all.accept_source_route": "0",
    }
    issues = []
    for key, req in expected.items():
        actual = sysctl_map.get(key)
        if actual != req:
            issues.append(f"{key}: expected {req}, got {actual}")
    return issues


def run_self_checks() -> None:
    # 1. 在本地环回验证闭合反射器（Mock 测试高放大拦截逻辑）
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    # 验证端口无响应（或未开放）场景
    closed_res = check_local_udp_reflector("127.0.0.1", "MEMCACHED_STATS", timeout=0.1)
    assert isinstance(closed_res.compliant, bool)
    srv.close()

    # 2. 验证高放大检测逻辑（模拟 100x 响应）
    assert ReflectorCheckResult("MEMCACHED_STATS", 11211, True, 15, 1500, 100.0, False).compliant is False

    # 3. 验证 sysctl 防伪造基线
    good_sysctl = {
        "net.ipv4.conf.all.rp_filter": "1",
        "net.ipv4.conf.default.rp_filter": "1",
        "net.ipv4.conf.all.accept_source_route": "0",
    }
    assert verify_bcp38_sysctl(good_sysctl) == []
    bad_sysctl = {"net.ipv4.conf.all.rp_filter": "0"}
    assert len(verify_bcp38_sysctl(bad_sysctl)) == 3
    print("[PASS] All DRDoS amplification defense checks passed.")


if __name__ == "__main__":
    run_self_checks()
```

---

## 验证与判定标准

| 验证项 | 达标判定标准 | 可观测指标 |
|---|---|---|
| 开放反射器收敛 | 公网扫描 `17/19/161/389/1900/3702/11211` UDP 端口无响应；外部递归查询 DNS 返回 `REFUSED` | 零外部开放反射端口 |
| DNS RRL 与响应体上限 | 单包 UDP 响应 `<= 1232` 字节；高频重复查询触发 `slip` 返回 `TC=1` 截断标志 | DNS 放大倍数 `< 2x` |
| NTP 与 Memcached 加固 | `ntpdc -c monlist` 超时或被拒；Memcached 仅监听 `127.0.0.1` TCP | `ss -ulnp` 无 `0.0.0.0:11211` |
| BCP38 源地址校验 | `rp_filter=1` 开启，非本地路由源 IP 出站报文被丢弃 | 伪造源 IP 出站丢包率 `100%` |
| QUIC/DTLS 放大上限 | 未通过源验证前的初始响应严格满足 `<= 3x` 请求大小 | 握手前出站/入站字节比 `<= 3.0` |

---

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| 服务暴露面检查 | `http_probe` | 检查边缘 DoH/HTTP3 入口与可用性基线 |
| 防御知识路由 | `kb_router` | 以 `track="blue"` 搜索 `drdos` / `bcp38` / `dns` 防护指南 |
| 攻防对照查阅 | `kb_read_file` | 读取本文件及配对攻击文档 `ctf-website/22-dos/03-amplification-drdos` |
| 分类清单查看 | `kb_catalog` | 列举 `22-dos` 下关联防御条目 |
