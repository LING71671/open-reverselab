---
id: "ctf-website/08-infra/http2-attacks-defense"
title: "HTTP/2 协议栈防御：HPACK 限额、CONTINUATION 封堵与 H2C 禁用"
title_en: "HTTP/2 Protocol Hardening: HPACK Limits, CONTINUATION Bounds & H2C Disabling"
summary: >
  防御 HTTP/2 HPACK Bomb (CVE-2025-53020)、HPACK 索引放大与窗口停滞炸弹 (CVE-2026-49975)、CONTINUATION Flood (CVE-2024-28182)、H2C Upgrade 走私及流多路复用滥用，通过边缘网关升级、严格头部数量/总解码体积限制、流空闲超时与明文 H2C 阻断实现协议层韧性加固。
summary_en: >
  Hardening HTTP/2 infrastructure against HPACK Bomb (CVE-2025-53020), HPACK indexed-reference amplification with stalled flow-control windows (CVE-2026-49975), CONTINUATION Flood (CVE-2024-28182), H2C upgrade smuggling, and stream multiplexing abuse. Covers patched runtimes, header count/size ceilings, stream idle timeouts, and H2C blocking.
board: "ctf-website"
category: "08-infra"
signals: ["HTTP/2", "HPACK", "CONTINUATION", "H2C", "CVE-2026-49975", "CVE-2024-28182", "HTTP/2防御"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["HTTP2防御", "HPACK Bomb防护", "CONTINUATION Flood防御", "H2C禁用", "CVE-2026-49975缓解", "流控超时", "协议层加固", "blue-team"]
difficulty: "advanced"
tags: ["defense", "blue-team", "http2", "dos-mitigation", "infrastructure", "cve"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/08-infra/http2-attacks", "ctf-website/08-infra/race-cache-smuggling-defense"]
track: "blue"
defends: "ctf-website/08-infra/http2-attacks"
---
# HTTP/2 协议栈防御：HPACK 限额、CONTINUATION 封堵与 H2C 禁用

## 防御目标与威胁面

HTTP/2 在连接复用与 HPACK 压缩上引入了非对称资源消耗面，低带宽攻击者即可耗尽代理或源站内存与 CPU：

1. **HPACK Bomb / 索引引用放大（CVE-2025-53020、CVE-2026-49975）**：客户端发送海量独立不重复 Header 撑爆动态表，或以极短 1 字节索引引用反复触发服务端分配完整解码头副本，并配合零/极小 `WINDOW_UPDATE` 长期钉住已分配内存。
2. **CONTINUATION Flood（CVE-2024-28182）**：持续发送不设 `END_HEADERS` 标志的 `CONTINUATION` 帧，迫使服务端不断缓冲未完成头部块直到 OOM 或 CPU 打满。
3. **H2C Upgrade Smuggling**：前端仅按 HTTP/1.1 解析并放行 `Upgrade: h2c` 与 `HTTP2-Settings` 头，使攻击者直接与支持 H2C 的后端建立明文 HTTP/2 隧道，完全绕过边缘鉴权与路径过滤。
4. **Stream 多路复用与快速重置滥用**：单连接并发大量未完成流或异常 `RST_STREAM` 消耗后端工作线程。

## 核心防御架构

| 攻击向量 | 根治控制措施 | 关键参数与版本目标 |
|---|---|---|
| HPACK 放大与内存膨胀 | 升级到修复版本并显式限制单请求最大 Header 数量、单头大小及解码后总字节数 | Nginx ≥ `1.29.8` (`http2_max_field_size`/`http2_max_header_size`/`max_headers`)；Apache `mod_http2` ≥ `2.0.41`；Envoy ≥ 2026-06 补丁 |
| 窗口停滞钉死内存 | 配置严格头部接收超时、最小流吞吐速率限制与零窗口停滞回收 | 对持续发送零/极小 `WINDOW_UPDATE` 且长期未完成帧交互的连接直接发送 `GOAWAY` 并断开 |
| CONTINUATION Flood | 限制单流连续 `CONTINUATION` 帧数量上限与头部块接收超时 | 未在限定帧数/毫秒内收到 `END_HEADERS` 即触发 `ENHANCE_YOUR_CALM` (`0x0b`) 关闭连接 |
| H2C 明文升级走私 | 边缘与上游全链路禁用明文 H2C 升级，严格剥离 `Upgrade`/`HTTP2-Settings` 逐跳头 | HTTP/2 仅通过 TLS ALPN `h2` 协商；前后端统一规范化 `Connection` 头 |
| 流并发泛洪 | 收紧 `SETTINGS_MAX_CONCURRENT_STREAMS` 与单连接最大请求数 | 公网边缘建议限制单连接并发流 ≤ 100 并启用连接速率熔断 |

## 加固配置与离线核查示例

Nginx 与 Envoy 关键防线配置参考：

```nginx
# Nginx 边缘层：收紧 HTTP/2 资源配额并阻断 H2C 升级走私
http2_max_concurrent_streams 64;
http2_recv_timeout 10s;
client_header_timeout 10s;
large_client_header_buffers 4 8k;

# 上游代理清除逐跳升级头，阻止 H2C Smuggling
proxy_http_version 1.1;
proxy_set_header Upgrade "";
proxy_set_header Connection "";
```

以下 Python 协议策略核查器用于在上线前验证 HTTP/2 网关配置（动态表上限、解码头部总字节、最大头字段数、CONTINUATION 帧上限、流空闲超时及 H2C 禁用状态）：

```python
from typing import Dict, List


def evaluate_http2_hardening(cfg: Dict[str, object]) -> Dict[str, object]:
    findings: List[str] = []

    if cfg.get("allow_h2c_upgrade", True):
        findings.append("h2c_upgrade_must_be_disabled")
    if int(cfg.get("max_concurrent_streams", 9999)) > 128:
        findings.append("max_concurrent_streams_too_high")
    if int(cfg.get("max_header_list_size_bytes", 1048576)) > 65536:
        findings.append("max_header_list_size_too_large")
    if int(cfg.get("max_header_count", 1000)) > 100:
        findings.append("max_header_count_too_high")
    if int(cfg.get("max_continuation_frames", 999)) > 10:
        findings.append("continuation_frame_limit_missing_or_high")
    if int(cfg.get("hpack_dynamic_table_size", 65536)) > 4096:
        findings.append("hpack_table_size_above_4k")
    if int(cfg.get("stream_idle_timeout_sec", 300)) > 30:
        findings.append("stream_idle_timeout_too_long")

    return {"compliant": len(findings) == 0, "findings": findings}


if __name__ == "__main__":
    weak = {
        "allow_h2c_upgrade": True,
        "max_concurrent_streams": 1000,
        "max_header_list_size_bytes": 262144,
        "max_header_count": 500,
        "max_continuation_frames": 100,
        "hpack_dynamic_table_size": 65536,
        "stream_idle_timeout_sec": 120,
    }
    res_weak = evaluate_http2_hardening(weak)
    assert res_weak["compliant"] is False and len(res_weak["findings"]) == 7

    strong = {
        "allow_h2c_upgrade": False,
        "max_concurrent_streams": 64,
        "max_header_list_size_bytes": 32768,
        "max_header_count": 64,
        "max_continuation_frames": 5,
        "hpack_dynamic_table_size": 4096,
        "stream_idle_timeout_sec": 15,
    }
    assert evaluate_http2_hardening(strong) == {"compliant": True, "findings": []}
    print("HTTP/2 defense self-check passed.")
```

## 防御工作流

```text
1. 组件升级：将 Nginx/Apache/Envoy/Node/Go HTTP/2 协议栈升级至修复 CVE-2024-28182、CVE-2025-53020 与 CVE-2026-49975 的安全版本
2. 头部配额：设置解码后最大头部字节（≤ 32KB~64KB）、最大字段数（≤ 64~100）及连续 CONTINUATION 帧上限
3. 停滞熔断：启用流空闲超时、头部接收超时与零窗口/RST_STREAM 异常连接断开阈值
4. 协议清边界：所有反代清除 Upgrade: h2c 与 HTTP2-Settings 头，上游禁止明文 H2C
5. 进程监控：为边缘网关设置单进程 RSS 告警与优雅重启阈值，防止单连接内存异常驻留
```

## 验证与判定标准

- **CONTINUATION 与 HPACK 爆破即时断连**：发送超过配额的连续 `CONTINUATION` 帧或高密度索引引用头块时，服务端在毫秒~秒级返回 `GOAWAY`/`RST_STREAM` (`ENHANCE_YOUR_CALM`)，工作进程 RSS 不出现阶跃式泄漏。
- **H2C 走私失效**：发送带 `Upgrade: h2c` 与 `HTTP2-Settings` 的 HTTP/1.1 请求到边缘代理时，不透传至后端且无法切换为 H2 帧会话。
- **停滞流自动回收**：建立连接发送 `WINDOW_UPDATE(0)` 并挂起流后，到达配置的 `stream_idle_timeout` 时服务端主动释放关联内存并关闭连接。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索 HTTP/2 协议防御条目 | `kb_router` | 搜索 `HTTP2防御`、`HPACK`、`CONTINUATION`、`H2C禁用` |
| 对照攻击机理与受影响版本 | `kb_read_file` | 读取 [http2-attacks.md](../../../../red/ctf-website/techniques/08-infra/http2-attacks.md) 核查补丁版本矩阵 |
| 联动基础设施走私防御 | `kb_catalog` | 协同查阅 `race-cache-smuggling-defense` 防范 H2.CL/H2.TE 降级 |
