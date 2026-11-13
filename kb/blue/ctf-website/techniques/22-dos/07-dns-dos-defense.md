---
id: "ctf-website/22-dos/07-dns-dos-defense"
title: "DNS 拒绝服务与缓存投毒防御"
title_en: "DNS Denial of Service and Cache Poisoning Defense"
summary: >
  防御针对权威 DNS 与递归解析器自身的拒绝服务攻击，涵盖 Water Torture 随机子域攻击、NXDOMAIN Flood、Phantom Domain 静默丢弃耗尽递归器、DNS Cache Poisoning（CVE-2008-1447）导致的解析中断，以及 DNSSEC 自身放大耗尽。提供 BIND9/Unbound/dnsdist 加固配置及 Python 熵值与 NXDOMAIN 异常检测脚本。
summary_en: >
  Defense for authoritative DNS servers and recursive resolvers against Water Torture random subdomain floods, NXDOMAIN Floods, Phantom Domain resolver stalls, DNS Cache Poisoning (CVE-2008-1447) DoS, and DNSSEC self-amplification. Includes BIND9, Unbound, and dnsdist configurations plus runnable Python entropy and NXDOMAIN detection code.
board: "ctf-website"
category: "22-dos"
signals:
  - "子域香农熵与 NXDOMAIN 比例告警"
  - "RFC 8198 NSEC 否定缓存合成"
  - "BIND fetches-per-zone 限制"
  - "Unbound 0x20-bit 与端口随机化"
  - "Anycast 多节点分散承载"
  - "dnsdist 动态规则拦截随机子域"
mcp_tools:
  - "http_probe"
  - "kb_router"
  - "kb_read_file"
  - "kb_catalog"
keywords:
  - "DNS Water Torture 防御"
  - "Phantom Domain 防护"
  - "NXDOMAIN Flood 缓解"
  - "DNS 缓存投毒防御"
  - "RFC 8198"
  - "dnsdist 限流"
  - "BIND9 加固"
  - "dns dos defense"
difficulty: "advanced"
tags:
  - "defense"
  - "blue-team"
  - "resilience"
  - "dos-protection"
  - "dns"
  - "dnssec"
  - "cache-poisoning"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "ctf-website/22-dos/07-dns-dos"
track: "blue"
defends: "ctf-website/22-dos/07-dns-dos"
---
# DNS 拒绝服务与缓存投毒防御

## 防御目标与对抗矩阵

针对 DNS 基础设施自身的 DoS（对应攻击技术见 [07-dns-dos.md](../../../../red/ctf-website/techniques/22-dos/07-dns-dos.md)）同时威胁权威服务器与递归解析器。防御必须覆盖**边缘高熵随机子域清洗、否定缓存主动合成、递归并发配额隔离及加密校验加固**。

| 攻击向量 | 受害节点 | 核心防御机制 | 关键配置 / 标准 |
|---|---|---|---|
| Water Torture（水刑随机子域） | 权威 DNS + 递归解析器 | 边缘 `dnsdist` 动态限速高熵/NXDOMAIN 子域 + 限制每域并发拉取 | `fetches-per-zone` + `dnsdist` 动态封禁 + Anycast |
| NXDOMAIN Flood | 权威 DNS | 启用 RFC 8198（基于 NSEC/NSEC3 在递归层合成否定缓存）+ 合理负缓存 SOA TTL | `synth-from-dnssec yes` + SOA `minimum >= 300s` |
| Phantom Domain 攻击 | 递归解析器 outgoing 池 | 对无响应权威域名实施退避惩罚（Infra Cache RTT 降级）、严格限制每域/每服并发与超时 | BIND `fetches-per-server`、Unbound `infra-cache-min-rtt` |
| DNS Cache Poisoning (CVE-2008-1447) | 递归缓存与全站可达性 | 启用源端口随机化 + 0x20 大小写随机化 + DNSSEC 强验证 + DoT/DoH 上游 | Unbound `use-caps-for-id: yes`、`dnssec-validation auto` |
| DNSSEC 自身带宽放大 | 权威 DNS 出口带宽 | 关闭/最小化 `ANY` 响应（RFC 8482）、采用 ECDSA P-256 签名缩减 RRSIG 体积 | `minimal-any yes` + ECDSA 密钥（比 RSA-2048 小约 4x） |

---

## 防御工作流

### 阶段一：权威 DNS 加固（Anycast + RRL + ECDSA + 最小化 `ANY`）

1. **采用 Anycast 分布与多权威供应商隔离**：避免单点权威 IP 被直接打穿，确保关键域名具备独立的次级权威托管。
2. **收缩 DNSSEC 响应体积**：将 DNSSEC 签名算法从 RSA-2048 迁移至 ECDSA P-256（Algorithm 13），单条 `RRSIG` 从 ~256 字节降至 ~64 字节，显著降低自身带宽消耗，同时按 RFC 8482 对 `ANY` 查询仅返回 `HINFO` 占位记录。

```bind
// /etc/bind/named.conf.options — 权威与递归防 DoS 关键指令
options {
    // 1. 抑制 DNSSEC 与 ANY 带宽放大
    minimal-any yes;
    minimal-responses yes;
    max-udp-size 1232;

    // 2. 启用 RFC 8198 否定响应合成，大幅削减 NXDOMAIN 穿透至权威
    synth-from-dnssec yes;

    // 3. 限制对单一域或单一失联权威（Phantom Domain）的并发探测
    fetches-per-zone 40 drop;
    fetches-per-server 100 drop;
    max-recursion-depth 7;
    max-recursion-queries 64;

    // 4. RRL 对高频重复/NXDOMAIN 响应限流
    rate-limit {
        responses-per-second 5;
        nxdomains-per-second 5;
        errors-per-second 5;
        window 5;
        slip 2;
    };
};
```

### 阶段二：递归解析器抗 Phantom Domain 与防缓存投毒（Unbound）

Unbound 通过基础设施缓存（Infra Cache）自动追踪上游权威服务器的丢包率与延迟；配合 0x20 位随机化与 `serve-expired` 策略，可在上游权威遭攻击或存在幽灵域名时维持本地可用性：

```yaml
# /etc/unbound/unbound.conf.d/dos-hardening.conf
server:
  # 1. 防缓存投毒：随机化源端口、TXID 及查询名大小写 0x20 bit
  outgoing-port-avoid: 0-1024
  use-caps-for-id: yes
  harden-glue: yes
  harden-dnssec-stripped: yes
  harden-below-nxdomain: yes
  aggressive-nsec: yes        # RFC 8198 本地合成 NXDOMAIN，拦截 Water Torture

  # 2. 抗 Phantom Domain：限制单查询最大重试与上游退避
  infra-host-ttl: 900
  infra-cache-min-rtt: 50
  num-queries-per-thread: 4096
  jostle-timeout: 200         # 队列满时优先淘汰超时慢查询（幽灵域），保护正常查询
  ratelimit: 1000
  ratelimit-below-domain: 100 # 按父域限速，直接遏制随机子域穿透

  # 3. 优雅降级：权威短时不可达时返回过期缓存同时异步预取
  prefetch: yes
  serve-expired: yes
  serve-expired-ttl: 86400
```

### 阶段三：边缘 `dnsdist` 动态拦截 Water Torture

在权威或递归前置部署 `dnsdist`，基于父域名维度的 `NXDOMAIN` 与随机子域 QPS 统计自动触发丢弃或强制转 TCP（`TC=1`）：

```lua
-- /etc/dnsdist/dnsdist.conf
local dbr = dynBlockRulesGroup()
-- 单源 IP 10 秒内 NXDOMAIN 超过 50/s 直接封禁 60 秒
dbr:setRCodeRate(DNSRCode.NXDOMAIN, 50, 10, "Excessive NXDOMAIN (Water Torture)", 60)
-- 单源 IP 总 QPS 超过 200/s 截断返回 TC=1 迫使切 TCP
dbr:setQueryRate(200, 10, "High QPS TC fallback", 60, DNSAction.Truncate)
function maintenance()
  dbr:apply()
end
```

---

## 弹性校验代码（可运行 Python 自检）

以下 Python 脚本实现双层校验：（1）基于子域标签香农熵（Shannon Entropy）与窗口内 NXDOMAIN 比例的水刑攻击/随机子域实时识别器；（2）BIND/Unbound 防御指令基线合规检查器。

```python
#!/usr/bin/env python3
"""DNS DoS defense verifier: Water Torture entropy/NXDOMAIN detector & resolver config check."""

import math
from collections import Counter


def shannon_entropy(label: str) -> float:
    """Compute Shannon entropy of a DNS leftmost subdomain label."""
    if not label:
        return 0.0
    counts = Counter(label)
    total = len(label)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def detect_water_torture_batch(queries: list[tuple[str, str]], entropy_threshold: float = 3.2,
                               nxdomain_ratio_threshold: float = 0.75) -> tuple[bool, dict]:
    """Detect random-subdomain Water Torture floods from (qname, rcode) telemetry."""
    if not queries:
        return False, {"count": 0}
    nx_count = sum(1 for _, rcode in queries if rcode == "NXDOMAIN")
    unique_qnames = len({q for q, _ in queries})
    entropies = [shannon_entropy(q.split(".", 1)[0]) for q, _ in queries]
    avg_entropy = sum(entropies) / len(entropies)
    nx_ratio = nx_count / len(queries)
    unique_ratio = unique_qnames / len(queries)

    flagged = (
        nx_ratio >= nxdomain_ratio_threshold
        and avg_entropy >= entropy_threshold
        and unique_ratio >= 0.8
    )
    return flagged, {
        "nx_ratio": round(nx_ratio, 3),
        "avg_entropy": round(avg_entropy, 3),
        "unique_ratio": round(unique_ratio, 3),
    }


def verify_unbound_hardening(conf_text: str) -> list[str]:
    """Verify required Unbound directives against Water Torture, Phantom Domain, and poisoning."""
    required = [
        "use-caps-for-id: yes",
        "aggressive-nsec: yes",
        "harden-dnssec-stripped: yes",
        "jostle-timeout:",
        "ratelimit-below-domain:",
        "serve-expired: yes",
    ]
    return [item for item in required if item not in conf_text]


def run_self_checks() -> None:
    # 1. 模拟正常查询样本（重复域名 + 低 NXDOMAIN）
    normal_batch = [("www.example.com", "NOERROR"), ("api.example.com", "NOERROR")] * 10
    flagged, _ = detect_water_torture_batch(normal_batch)
    assert not flagged, "Normal traffic triggered false positive"

    # 2. 模拟 Water Torture 高熵唯一随机子域 + NXDOMAIN 洪泛
    attack_batch = [
        (f"x9k2m{i:04x}q7z.example.com", "NXDOMAIN") for i in range(40)
    ]
    flagged, metrics = detect_water_torture_batch(attack_batch)
    assert flagged, f"Water Torture batch missed: {metrics}"

    # 3. 校验 Unbound 配置完整性
    good_conf = "\n".join([
        "use-caps-for-id: yes",
        "aggressive-nsec: yes",
        "harden-dnssec-stripped: yes",
        "jostle-timeout: 200",
        "ratelimit-below-domain: 100",
        "serve-expired: yes",
    ])
    assert verify_unbound_hardening(good_conf) == []
    assert "aggressive-nsec: yes" in verify_unbound_hardening("use-caps-for-id: yes")
    print("[PASS] All DNS DoS & cache poisoning defense checks passed.")


if __name__ == "__main__":
    run_self_checks()
```

---

## 验证与判定标准

| 验证项 | 达标判定标准 | 可观测指标 |
|---|---|---|
| Water Torture 抑制 | 边缘 `dnsdist` 与 `aggressive-nsec` 阻断随机子域穿透至权威节点 | 权威 `NXDOMAIN` 穿透 QPS 下降 `> 90%` |
| Phantom Domain 隔离 | 静默丢弃的上游域名被 `jostle-timeout` 快速淘汰，不阻塞其他域名解析 | 递归器正常域 P99 延迟维持 `< 100ms` |
| 防缓存投毒开启 | 抓包验证源端口随机、0x20 大小写混合及 DNSSEC 校验生效 | 无效签名响应返回 `SERVFAIL` 不入缓存 |
| DNSSEC 带宽优化 | 已切 ECDSA P-256 且 `ANY` 查询返回精简响应 | 单包响应大小 `< 1232` 字节，无放大瓶颈 |

---

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| DoH / 边缘 DNS 服务探测 | `http_probe` | 验证 DoH 网关与状态页面在负载下的可用性 |
| 蓝队技术路由 | `kb_router` | 以 `track="blue"` 搜索 `dns` / `water_torture` / `cache_poisoning` |
| 攻防文档对照 | `kb_read_file` | 读取本文件及配对攻击文档 `ctf-website/22-dos/07-dns-dos` |
| 分类清单查看 | `kb_catalog` | 列举 `22-dos` 下所有蓝队防御指南 |
