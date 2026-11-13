---
id: "ctf-website/22-dos/06-tcp-state-exhaustion-defense"
title: "TCP 协议栈状态耗尽防御与内核调优"
title_en: "TCP Protocol Stack State Exhaustion Defense and Kernel Tuning"
summary: >
  系统防御针对 TCP 状态机的耗尽攻击，包括 SYN Flood、Sockstress 零窗口连接保持、反向 TIME_WAIT 槽位耗尽、netfilter conntrack 表满、TCP Fast Open（TFO）Cookie 风暴与 Socket Buffer 内存压力攻击。提供 Linux sysctl 调优模板、nftables SYNPROXY/NOTRACK 规则、负载均衡器最小速率配置及 Python 基线检查代码。
summary_en: >
  System-level defense against TCP state exhaustion attacks: SYN Flood, Sockstress zero-window attacks, reverse TIME_WAIT exhaustion, netfilter conntrack table saturation, TCP Fast Open (TFO) cookie storms, and socket buffer memory pressure. Provides Linux sysctl hardening, nftables SYNPROXY/NOTRACK rules, proxy minimum-rate timeouts, and Python baseline verifier.
board: "ctf-website"
category: "22-dos"
signals:
  - "tcp_syncookies=1 抗 SYN Flood"
  - "nftables NOTRACK 与 SYNPROXY"
  - "Sockstress 零窗口超时与最小速率淘汰"
  - "nf_conntrack_max 扩容与超时收紧"
  - "tcp_wmem 与 tcp_orphans 内存边界"
  - "TCP Fast Open 禁用或密钥轮转"
mcp_tools:
  - "http_probe"
  - "kb_router"
  - "kb_read_file"
  - "kb_catalog"
keywords:
  - "SYN Flood 防御"
  - "Sockstress 防护"
  - "conntrack 优化"
  - "TIME_WAIT 调优"
  - "SYNPROXY"
  - "Linux sysctl 加固"
  - "Socket Buffer 防护"
  - "tcp state exhaustion defense"
difficulty: "advanced"
tags:
  - "defense"
  - "blue-team"
  - "resilience"
  - "dos-protection"
  - "tcp"
  - "syn-flood"
  - "conntrack"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "ctf-website/22-dos/06-tcp-state-exhaustion"
track: "blue"
defends: "ctf-website/22-dos/06-tcp-state-exhaustion"
---
# TCP 协议栈状态耗尽防御与内核调优

## 防御目标与对抗矩阵

TCP 状态耗尽攻击（对应攻击方法见 [06-tcp-state-exhaustion.md](../../../../red/ctf-website/techniques/22-dos/06-tcp-state-exhaustion.md)）绕过应用层直接消耗内核队列、连接跟踪表与套接字缓存。防御核心在于**无状态抗半连接洪泛、绕过无必要状态跟踪（NOTRACK）、压缩失效状态回收窗口以及在代理层强制淘汰零窗口死连接**。

| 攻击向量 | 内核消耗面 | 核心防御策略 | 关键配置参数 |
|---|---|---|---|
| SYN Flood | 半连接队列 (`SYN_RECV`) | 开启 SYN Cookie + SYNPROXY 代理握手 + 缩减重传 | `tcp_syncookies=1`、`tcp_synack_retries=2`、`nftables synproxy` |
| Sockstress（零窗口攻击） | 全连接队列与永久挂起套接字 | 代理层检查零窗口/停滞发送超时并主动断连，缩短内核孤儿连接回收 | `tcp_orphan_retries=1`、`send_timeout` + HAProxy `timeout client` |
| TIME_WAIT 槽位耗尽 | 四元组端口与内核 `tw_sock` | 合理复用安全时间戳 `tcp_tw_reuse`、缩小 `fin_timeout` 并前置四层负载均衡 | `tcp_tw_reuse=1`（出向）、`tcp_fin_timeout=15`、`tcp_max_tw_buckets` |
| Conntrack 表耗尽 | `nf_conntrack` 表项（~300B/项） | 对公网无状态服务入向直通使用 `NOTRACK` 绕过状态跟踪，并扩大表上限 | `raw` 表 `notrack`、`nf_conntrack_max=1048576`、缩短 TCP 超时 |
| TCP Fast Open (TFO) 滥用 | SYN+Data Cookie 计算与缓冲区 | 公网边缘默认关闭服务器侧 TFO 或限制未握手数据缓冲区与密钥轮转 | `net.ipv4.tcp_fastopen=0`（面向不可信公网） |
| Socket Buffer 内存压力 | `tcp_wmem` 堆积触发内核内存 OOM | 收紧 `tcp_wmem` 上限、设置合理 `tcp_mem` 压力水位及应用发送超时 | `tcp_wmem="4096 16384 1048576"`、`tcp_retries2=5` |

---

## 防御工作流

### 阶段一：Linux 内核 TCP 协议栈加固（`/etc/sysctl.d/99-tcp-hardening.conf`）

针对 SYN Flood、TIME_WAIT 积累、TFO 滥用和 Socket Buffer 内存挤压，应用以下生产基线参数：

```ini
# /etc/sysctl.d/99-tcp-hardening.conf
# 1. 半连接与全连接队列抗 SYN Flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 16384
net.core.somaxconn = 16384
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2

# 2. 快速回收孤儿连接与零窗口死连接（抗 Sockstress 与 Buffer 挤压）
net.ipv4.tcp_orphan_retries = 1
net.ipv4.tcp_max_orphans = 65536
net.ipv4.tcp_retries2 = 5
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 3

# 3. 限制单连接读写缓冲区上限，防止 Win=0 放大至 GB 级 OOM
net.ipv4.tcp_rmem = 4096 87380 1048576
net.ipv4.tcp_wmem = 4096 16384 1048576
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 262144

# 4. 面向不可信公网关闭 TFO 避免 Cookie CPU 消耗与未握手缓冲占用
net.ipv4.tcp_fastopen = 0

# 5. Netfilter Conntrack 容量与超时收紧（若未做 NOTRACK）
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 15
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
```

### 阶段二：nftables `NOTRACK` 与 `SYNPROXY` 无状态防御

对于无需 NAT 的公网 Web 节点，最彻底的 `nf_conntrack` 防护是**直接免除 80/443 入出向流量的连接跟踪**，同时利用 `SYNPROXY` 在完成三次握手前不向内核或后端分配套接字状态：

```nftables
#!/usr/sbin/nft -f
table inet tcp_shield {
    chain raw_prerouting {
        type filter hook prerouting priority raw; policy accept;
        # 对公网 80/443 TCP SYN 包启用 notrack，使 SYNPROXY 接管或避免打满 conntrack
        tcp dport { 80, 443 } tcp flags syn notrack
    }

    chain filter_input {
        type filter hook input priority filter; policy accept;
        # 无效状态直接丢弃（需配合 conntrack 场景；若全端口 notrack 则按需调整）
        ct state invalid,untracked tcp dport { 80, 443 } synproxy mss 1460 wscale 7 timestamp sack-perm
        ct state invalid drop
    }
}
```

### 阶段三：四/七层代理淘汰 Sockstress 零窗口连接

内核无法区分恶意 `win=0` 与临时网络拥塞，必须在四层/七层反向代理设置**最小发送速率与活跃超时**，强制回收卡在 `persist timer` 的 Sockstress 连接：

```haproxy
# /etc/haproxy/haproxy.cfg — 抗 Sockstress 零窗口占用
defaults
    mode tcp
    timeout connect 3s
    timeout client  15s
    timeout server  15s
    timeout client-fin 5s
    timeout server-fin 5s
    # 防止 HTTP 响应被零窗口长期阻塞在 send buffer
    timeout http-request 5s
    timeout http-keep-alive 10s
    option clitcpka
    option srvtcpka
```

---

## 弹性校验代码（可运行 Python 自检）

以下 Python 脚本校验目标内核配置字典是否满足 SYN Flood、Sockstress、Conntrack 与 Buffer 内存上限基线，并估算最坏情况下 `tcp_wmem` 并发内存消耗是否超出宿主机预算。

```python
#!/usr/bin/env python3
"""TCP stack state exhaustion defense verifier (sysctl baseline + buffer memory budget)."""

from dataclasses import dataclass


@dataclass
class SysctlRule:
    key: str
    op: str  # "eq", "ge", "le"
    expected: int


HARDENED_TCP_RULES = [
    SysctlRule("net.ipv4.tcp_syncookies", "eq", 1),
    SysctlRule("net.ipv4.tcp_max_syn_backlog", "ge", 8192),
    SysctlRule("net.core.somaxconn", "ge", 8192),
    SysctlRule("net.ipv4.tcp_synack_retries", "le", 2),
    SysctlRule("net.ipv4.tcp_orphan_retries", "le", 2),
    SysctlRule("net.ipv4.tcp_fin_timeout", "le", 20),
    SysctlRule("net.ipv4.tcp_fastopen", "eq", 0),
    SysctlRule("net.netfilter.nf_conntrack_max", "ge", 524288),
    SysctlRule("net.netfilter.nf_conntrack_tcp_timeout_syn_recv", "le", 20),
]


def check_tcp_sysctl(config: dict[str, int]) -> list[str]:
    """Validate kernel sysctl integers against TCP DoS hardening thresholds."""
    violations: list[str] = []
    for rule in HARDENED_TCP_RULES:
        if rule.key not in config:
            violations.append(f"missing:{rule.key}")
            continue
        val = config[rule.key]
        ok = (
            (rule.op == "eq" and val == rule.expected)
            or (rule.op == "ge" and val >= rule.expected)
            or (rule.op == "le" and val <= rule.expected)
        )
        if not ok:
            violations.append(f"non_compliant:{rule.key}={val} (expected {rule.op} {rule.expected})")
    return violations


def estimate_zero_window_memory_mb(max_connections: int, tcp_wmem_max_bytes: int) -> float:
    """Compute worst-case send-buffer RAM footprint under Sockstress zero-window holding."""
    return round((max_connections * tcp_wmem_max_bytes) / (1024 * 1024), 2)


def run_self_checks() -> None:
    compliant_cfg = {
        "net.ipv4.tcp_syncookies": 1,
        "net.ipv4.tcp_max_syn_backlog": 16384,
        "net.core.somaxconn": 16384,
        "net.ipv4.tcp_synack_retries": 2,
        "net.ipv4.tcp_orphan_retries": 1,
        "net.ipv4.tcp_fin_timeout": 15,
        "net.ipv4.tcp_fastopen": 0,
        "net.netfilter.nf_conntrack_max": 1048576,
        "net.netfilter.nf_conntrack_tcp_timeout_syn_recv": 15,
    }
    assert check_tcp_sysctl(compliant_cfg) == []

    weak_cfg = dict(compliant_cfg)
    weak_cfg["net.ipv4.tcp_syncookies"] = 0
    weak_cfg["net.ipv4.tcp_fastopen"] = 3
    issues = check_tcp_sysctl(weak_cfg)
    assert len(issues) == 2

    # 校验 tcp_wmem 收紧至 1MB vs 默认 4MB 的内存边界差异
    hardened_mb = estimate_zero_window_memory_mb(max_connections=1000, tcp_wmem_max_bytes=1048576)
    default_mb = estimate_zero_window_memory_mb(max_connections=1000, tcp_wmem_max_bytes=4194304)
    assert hardened_mb == 1000.0 and default_mb == 4000.0
    print("[PASS] All TCP state exhaustion defense checks passed.")


if __name__ == "__main__":
    run_self_checks()
```

---

## 验证与判定标准

| 验证项 | 达标判定标准 | 可观测指标 |
|---|---|---|
| SYN Flood 抗压 | 开启 `tcp_syncookies=1` 与 `SYNPROXY` 后半连接队列零溢出 | `netstat -s` 中 `SYNs to LISTEN` 增量不再上升，合法握手正常 |
| Conntrack 表零打满 | 业务端口免跟踪 (`NOTRACK`) 或表上限扩容配合短超时回收 | `dmesg` 零 `nf_conntrack: table full` 日志，占用 `< 50%` |
| Sockstress / Buffer 防护 | 零窗口连接在 `15s` 超时窗内被代理层主动 RST 释放 | `CLOSE_WAIT` / `tcp_orphans` 稳定，内存使用平稳无 OOM |
| TIME_WAIT 槽位复用 | 主动短连接峰值下四元组端口池无耗尽错误 | `EADDRNOTAVAIL` 报错归零，`TIME_WAIT` 自动控制在预算内 |

---

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| 端口与连接可用性核验 | `http_probe` | 验证边缘 TCP 443/80 在压力基线下的握手延迟与建连成功率 |
| 蓝队技术路由 | `kb_router` | 以 `track="blue"` 检索 `tcp` / `syn_flood` / `conntrack` 防御指南 |
| 攻防文档对照 | `kb_read_file` | 读取本文件及配对攻击文档 `ctf-website/22-dos/06-tcp-state-exhaustion` |
| 分类目录查询 | `kb_catalog` | 列举 `22-dos` 下所有蓝队加固条目 |
