---
id: "ctf-website/11-dos/01-valkey-resp-dos-defense"
title: "Valkey RESP 协议状态机 DoS 防御：版本升级、状态重置补丁与边界接入控制（CVE-2026-27623）"
title_en: "Valkey RESP Protocol Pre-Auth DoS Defense: Upgrade, State Reset Patch & Perimeter Access Control (CVE-2026-27623)"
summary: >
  针对 CVE-2026-27623（Valkey 9.0.0–9.0.2 在处理空 multibulk 请求 *0\r\n 后未清零 c->reqtype，导致同一 TCP 缓冲内后续 inline 命令触发断言失败进程 abort 的预认证 DoS）的蓝队防御与加固方案。覆盖升级基线（>= 9.0.3）、上游补丁 2c311dd7 原理解析、TLS/mTLS 与网段白名单收敛预认证接触面、进程高可用守卫，以及 Python 协议回归校验脚本。
summary_en: >
  Blue-team defense guide for CVE-2026-27623 (Valkey 9.0.0–9.0.2 pre-auth RESP state machine DoS caused by uncleared c->reqtype after empty multibulk *0\r\n). Covers upgrade baseline (>= 9.0.3), upstream patch 2c311dd7 analysis, TLS/mTLS and network perimeter isolation to shrink pre-auth reachability, process supervision, and a Python RESP state-machine verification check.
board: "ctf-website"
category: "11-dos"
signals: ["CVE-2026-27623", "Valkey DoS defense", "RESP state machine", "reqtype reset", "pre-auth DoS mitigation", "Valkey 9.0.3"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog", "http_probe"]
keywords: ["CVE-2026-27623防御", "Valkey DoS加固", "RESP状态机补丁", "reqtype清零", "Valkey 9.0.3升级", "预认证网络隔离", "mTLS接入"]
difficulty: "intermediate"
tags: ["defense", "blue-team", "dos", "cve", "valkey", "protocol-security"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/11-dos/01-valkey-resp-dos", "ctf-website/09-cve/02-redis-zipmap-rce-defense"]
track: "blue"
defends: "ctf-website/11-dos/01-valkey-resp-dos"
---
# Valkey RESP 协议状态机 DoS 防御：版本升级、状态重置补丁与边界接入控制（CVE-2026-27623）

## 1. 威胁模型与漏洞根因回顾

CVE-2026-27623 影响 Valkey `9.0.0` 至 `9.0.2`，属于无需任何认证即可触发的服务端进程崩溃（Pre-Auth DoS）：
- 在单次 `read()` 缓冲中同时包含空 multibulk 请求与后续 inline 命令（如 `*0\r\nPING\r\n`）时，第一段 `*0\r\n` 返回 `READ_FLAGS_PARSING_NEGATIVE_MBULK_LEN`。
- `handleParseResults` 调用 `resetClient(c)` 清理参数，但旧代码漏掉了 `c->reqtype = 0;`。
- 循环继续解析紧随其后的 `PING\r\n` 时，由于 `c->reqtype` 仍残留为 `PROTO_REQ_MULTIBULK`，直接进入 `parseMultibulk` 并触发 `networking.c` 断言 `c->querybuf[c->qb_pos] == '*'` 失败，导致 `valkey-server` 直接 `abort` 退出。

由于该缺陷发生在命令认证之前（解析阶段即崩），单纯配置 `requirepass` 或业务层 ACL 无法阻止已经建立 TCP 连接的客户端打崩进程。

## 2. 分层防御与缓解措施

| 防线层级 | 控制措施 | 目标对象 | 缓解效果 |
|---|---|---|---|
| 官方升级（根治） | 升级 Valkey 至 `>= 9.0.3`（包含提交 `2c311dd7173ffc715a3d61266fdede6096a097de`） | 所有 Valkey 9.0.x 节点 | 处理完空/负长度 multibulk 后重置 `c->reqtype = 0` |
| 预认证网络收敛 | 严禁 `protected-mode no` 或公网监听；仅允许受信任应用 VPC/子网访问 `6379`/`16379` | 防火墙 / 安全组 / NetworkPolicy | 在传输层阻断非授权源建立 TCP 连接 |
| mTLS 双向认证 | 对跨主机缓存访问启用 `tls-port` + `tls-auth-clients yes`，关闭明文端口 `port 0` | `valkey.conf` | 未持有受信任客户端证书的 TCP 连接在 TLS 握手阶段即被拒绝，无法触及 RESP 解析器 |
| 高可用与监控告警 | 配置 `systemd` 自动拉起 + Sentinel/Cluster 故障转移；监控 `ASSERTION FAILED` 日志 | 进程托管与告警 | 缩短极端情况下的故障恢复时间（RTO）并精准溯源恶意连接源 IP |

### 上游补丁核心逻辑（`src/networking.c`）

```c
// handleParseResults 中处理空/负长度 multibulk 分支
if (flags & READ_FLAGS_PARSING_NEGATIVE_MBULK_LEN) {
    resetClient(c);
    c->reqtype = 0;  // 关键修复：清除协议类型状态，使后续流水线数据重新判定 inline/multibulk
    return PARSE_OK;
}
```

### `valkey.conf` 传输层与预认证隔离配置基线

```conf
# 关闭明文端口，强制 TLS 双向证书认证以阻断未授权 TCP 直达 RESP 解析器
port 0
tls-port 6379
tls-auth-clients yes
tls-cert-file /etc/valkey/certs/server.crt
tls-key-file /etc/valkey/certs/server.key
tls-ca-cert-file /etc/valkey/certs/ca.crt

protected-mode yes
bind 10.10.20.15
maxclients 5000
```

## 防御工作流

1. **版本区间快速定位**：收集集群内所有 Valkey 实例版本，精确锁定处于 `9.0.0` – `9.0.2` 区间的节点。
2. **网络与认证边界止血**：在补丁窗口前，立即核查安全组与 `valkey.conf`，确保关闭 `protected-mode no` 与公网开放，优先启用 `tls-auth-clients yes` 阻断未知来源触达 RESP 状态机。
3. **滚动升级至 `>= 9.0.3`**：按从节点优先、主从切换、最后原主节点的顺序滚动升级集群二进制或容器镜像至 `9.0.3+`。
4. **状态机回归核验**：运行下方协议状态机检查脚本与版本基线验证，确认空 multibulk 串联 inline 请求时进程保持存活并正常响应 `+PONG`。

## 3. Python 版本基线与 RESP 状态机回归校验脚本

```python
#!/usr/bin/env python3
"""CVE-2026-27623 Valkey 版本基线判断与安全 RESP 状态机模拟校验工具。"""

from dataclasses import dataclass


@dataclass
class RespParserState:
    reqtype: int = 0  # 0=unset, 1=inline, 2=multibulk
    patched: bool = True

    def feed_pipeline(self, segments: list[str]) -> list[str]:
        outputs: list[str] = []
        for seg in segments:
            if self.reqtype == 0:
                self.reqtype = 2 if seg.startswith("*") else 1
            if self.reqtype == 2:
                if not seg.startswith("*"):
                    raise AssertionError("networking.c: querybuf[qb_pos] == '*' failed (DoS crash)")
                if seg == "*0":
                    # 消费空 multibulk；补丁版必须重置 reqtype = 0
                    if self.patched:
                        self.reqtype = 0
                    outputs.append("EMPTY_MBULK_CONSUMED")
                    continue
                self.reqtype = 0
                outputs.append("MBULK_OK")
            else:
                self.reqtype = 0
                outputs.append("+PONG" if seg == "PING" else "+OK")
        return outputs


def is_vulnerable_valkey_version(ver: str) -> bool:
    parts = tuple(int(x) for x in ver.strip().split(".")[:3])
    return (9, 0, 0) <= parts <= (9, 0, 2)


if __name__ == "__main__":
    assert is_vulnerable_valkey_version("9.0.2")
    assert not is_vulnerable_valkey_version("9.0.3")

    # 未打补丁状态机遇到 [*0, PING] 触发断言异常
    unpatched = RespParserState(patched=False)
    try:
        unpatched.feed_pipeline(["*0", "PING"])
        raise RuntimeError("expected assertion failure on unpatched state machine")
    except AssertionError as exc:
        print("unpatched simulated abort:", exc)

    # 打补丁后状态机正确清零 reqtype，PING 返回 +PONG
    patched = RespParserState(patched=True)
    res = patched.feed_pipeline(["*0", "PING"])
    print("patched pipeline response:", res)
    assert res == ["EMPTY_MBULK_CONSUMED", "+PONG"]
```

## 验证与判定标准

| 检查项 | 判定为已加固（PASS） | 判定为存在风险（FAIL） | 验证方式 |
|---|---|---|---|
| Valkey 版本 | `>= 9.0.3`（或已合入 `2c311dd7` 补丁的发行版包） | `9.0.0` – `9.0.2` 且无上游状态重置补丁 | `INFO server` 检查 `valkey_version` |
| 流水线解析稳定性 | 在测试环境发送空 multibulk + `PING` 保持连接并返回 `+PONG`，PID 不变 | 连接重置、进程退出或日志出现 `ASSERTION FAILED` | 隔离测试实例回归前后对比进程 PID |
| 预认证暴露面 | 开启 `protected-mode yes`，仅内网白名单可连接且启用 `tls-auth-clients yes` | 公网可达或非信任网段可建立明文 TCP 连接 | 端口策略复核与 TLS 握手检查 |
| 日志与进程守护 | 具备 `ASSERTION FAILED` 告警规则与自动故障切换机制 | 无崩溃告警或单点崩溃不可自动恢复 | 检查 systemd/k8s 探针与日志规则 |

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索 Valkey DoS 防护 | `kb_router` | 按 `CVE-2026-27623` / `Valkey` / `RESP` 搜索 |
| 核对触发序列与版本 | `kb_read_file` | 读取 `ctf-website/11-dos/01-valkey-resp-dos` 核对状态机细节 |
| 端口暴露收敛检查 | `http_probe` | 辅助核查对外边缘网关未意外暴露缓存端口 |
