---
id: "ctf-website/09-cve/06-nginx-rewrite-heapoverflow-defense"
title: "NGINX rewrite 模块堆溢出防御：版本升级、指令安全重构与运行缓解（CVE-2026-42945）"
title_en: "NGINX rewrite Module Heap Overflow Defense: Version Upgrade, Directive Refactoring & Runtime Hardening (CVE-2026-42945)"
summary: >
  针对 CVE-2026-42945（NGINX 0.6.27–1.30.0 rewrite 带 ? 内部跳转结合 set $var $1 导致长度估算与 URI 转义复制语义错配引发堆溢出）的蓝队防御与加固方案。覆盖升级基线（1.30.1+ / 1.31.0+）、规避带查询串 rewrite + set 捕获组模式、ASLR/PIE/Hardened Malloc 等二进制运行缓解，以及自动化 nginx.conf 危险模式检查脚本。
summary_en: >
  Blue-team defense guide for CVE-2026-42945 (NGINX 0.6.27–1.30.0 rewrite with ? combined with set directive capture copy causing URI escape length mismatch heap overflow). Covers upgrade baselines (1.30.1+ / 1.31.0+), safe nginx.conf refactoring, ASLR/PIE/Hardened Malloc runtime mitigations, and an automated nginx.conf pattern checker.
board: "ctf-website"
category: "09-cve"
signals: ["CVE-2026-42945", "NGINX defense", "rewrite set mismatch", "heap overflow mitigation", "nginx.conf hardening", "ASLR PIE"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog", "http_probe"]
keywords: ["CVE-2026-42945防御", "NGINX堆溢出防护", "rewrite配置加固", "set指令风险", "nginx.conf检查", "ASLR", "1.30.1升级"]
difficulty: "advanced"
tags: ["defense", "blue-team", "cve", "nginx", "memory-corruption", "config-hardening"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/09-cve/06-nginx-rewrite-heapoverflow"]
track: "blue"
defends: "ctf-website/09-cve/06-nginx-rewrite-heapoverflow"
---
# NGINX rewrite 模块堆溢出防御：版本升级、指令安全重构与运行缓解（CVE-2026-42945）

## 1. 威胁模型与漏洞根因回顾

CVE-2026-42945 影响 NGINX Open Source `0.6.27` 至 `1.30.0`。漏洞发生在 `ngx_http_rewrite_module` 同时存在以下组合配置时：
1. `rewrite` 指令将 URI 改写到包含 `?` 的目标路径（使内部处理进入需要参数转义的状态）。
2. 同级上下文中紧随 `set $var $1`（或包含正则捕获组、需要重新计算转义长度的变量赋值）。
3. 内存分配阶段按 `$1` 原始长度申请堆缓冲区，而数据拷贝阶段按 URI 转义规则展开字符（例如大量 `+` 被扩展为 3 字节 `%2B`），导致写入超出堆块边界。在关闭 ASLR 或可延迟释放请求对象（堆整理）的环境中，可进一步演化为相邻堆结构体覆盖乃至 RCE。

## 2. 分层防御与配置重构策略

| 防线层级 | 控制措施 | 目标对象 | 缓解效果 |
|---|---|---|---|
| 官方补丁升级 | 升级至 NGINX `>= 1.30.1` 或 `>= 1.31.0`（含 OpenResty/Ingress 对应同步补丁） | NGINX 二进制 | 统一长度估算与转义复制阶段的长度计算逻辑 |
| 配置安全重构 | 先执行 `set` 或用 `map` / `$request_uri` 替代“带 `?` 的 `rewrite` 后再 `set $1`” | `nginx.conf` | 在未升级前消除触发路径 |
| 请求体积与字符收口 | 限制 `large_client_header_buffers` 与单路径长度，阻断超长重复 `+` URI | 边界 WAF / NGINX | 降低触发越界扩容及堆喷射成功率 |
| 二进制与系统缓解 | 强制开启系统 ASLR（`randomize_va_space=2`）、PIE、Full RELRO 与 Hardened Allocator | OS / 容器运行环境 | 破坏硬编码地址利用链与堆布局可预测性 |
| 异常监控 | 监控 worker `SIGSEGV` / `SIGABRT` 核心转储及异常多 `+` 字符长 URI 请求 | 运维监控 / SIEM | 第一时间告警异常崩溃与探测流量 |

### 危险配置与安全重构对照

```nginx
# 存在风险的模式：rewrite 带 '?' 触发转义状态，随后 set 引用正则捕获组
location ~ ^/api/(.*)$ {
    rewrite ^/api/(.*)$ /internal?migrated=true;
    set $original_endpoint $1;
}
```

重构方案：将正则捕获赋值移至修改 URI 查询串的 `rewrite` 之前，或改用 `map` 预先映射，并限制异常长 URI 与连续 `+` 数量：

```nginx
# 加固方案：先于带 '?' rewrite 保存捕获变量，或仅通过参数显式传递
location ~ ^/api/([^?\s]{1,256})$ {
    set $original_endpoint $1;
    rewrite ^/api/(.*)$ /internal?migrated=true break;
    proxy_set_header X-Original-Endpoint $original_endpoint;
    proxy_pass http://app_backend;
}
```

### 系统与容器运行时加固要求

- 检查宿主机与容器内 `/proc/sys/kernel/randomize_va_space` 必须为 `2`（Full ASLR），严禁在生产入口使用 `setarch -R` 启动服务。
- 校验 `nginx` 二进制安全编译选项（PIE、NX、Stack Canary、Full RELRO），并配置 `worker_rlimit_core` 与受限 `ulimit` 避免敏感内存转储泄露。

## 防御工作流

1. **全量 NGINX 版本盘点**：覆盖反向代理、API 网关、Ingress Controller 与 Sidecar 中的 NGINX 二进制版本号。
2. **配置文件模式排查**：扫描所有 `nginx.conf` 及 `conf.d/*.conf`，定位同时出现带 `?` 的 `rewrite` 与后置 `set ... $1` 的 `location` 块。
3. **快速配置改写与版本升级**：优先重构危险 `rewrite`/`set` 顺序并重载生效，随后分批将 NGINX 升级至 `1.30.1+` / `1.31.0+`。
4. **运行时缓解与回归检查**：验证 ASLR 开启、URI 长度上限生效，并在测试实例确认异常长 `+` URI 不触发 worker 崩溃。

## 3. Python `nginx.conf` 危险组合检测与 ASLR 基线检查脚本

```python
#!/usr/bin/env python3
"""CVE-2026-42945 nginx.conf 危险 rewrite+set 组合检查与版本基线核验工具。"""

from pathlib import Path
import re

REWRITE_QUERY_RE = re.compile(r"^\s*rewrite\s+\S+\s+\S*\?\S*", re.IGNORECASE)
SET_CAPTURE_RE = re.compile(r"^\s*set\s+\$\w+\s+.*\$[1-9]", re.IGNORECASE)


def parse_nginx_version(ver_str: str) -> tuple[int, int, int]:
    parts = [int(x) for x in ver_str.strip().split(".")[:3]]
    return tuple(parts)  # type: ignore[return-value]


def is_patched_nginx(ver_str: str) -> bool:
    v = parse_nginx_version(ver_str)
    if v[0] > 1:
        return True
    if v[1] == 30:
        return v >= (1, 30, 1)
    if v[1] >= 31:
        return True
    return v < (0, 6, 27)


def scan_nginx_conf(conf_text: str) -> list[dict[str, object]]:
    """检查同一代码块中是否存在 rewrite ... ? 之后出现 set $var ... $1 的高危顺序。"""
    findings = []
    seen_query_rewrite_line: int | None = None
    brace_depth = 0
    for lineno, line in enumerate(conf_text.splitlines(), start=1):
        stripped = line.split("#", 1)[0].strip()
        if not stripped:
            continue
        if "{" in stripped:
            brace_depth += stripped.count("{")
            seen_query_rewrite_line = None
        if REWRITE_QUERY_RE.match(stripped):
            seen_query_rewrite_line = lineno
        elif seen_query_rewrite_line is not None and SET_CAPTURE_RE.match(stripped):
            findings.append({
                "rewrite_line": seen_query_rewrite_line,
                "set_line": lineno,
                "statement": stripped,
                "risk": "rewrite-with-query followed by set capture group",
            })
        if "}" in stripped:
            brace_depth = max(0, brace_depth - stripped.count("}"))
            seen_query_rewrite_line = None
    return findings


if __name__ == "__main__":
    sample_bad = """
    location ~ ^/api/(.*)$ {
        rewrite ^/api/(.*)$ /internal?migrated=true;
        set $original_endpoint $1;
    }
    """
    sample_good = """
    location ~ ^/api/(.*)$ {
        set $original_endpoint $1;
        rewrite ^/api/(.*)$ /internal?migrated=true break;
    }
    """
    bad_hits = scan_nginx_conf(sample_bad)
    good_hits = scan_nginx_conf(sample_good)
    print("bad_hits:", bad_hits)
    print("good_hits:", good_hits)
    assert len(bad_hits) == 1
    assert len(good_hits) == 0
    assert not is_patched_nginx("1.30.0")
    assert is_patched_nginx("1.30.1")
    assert is_patched_nginx("1.31.0")
```

## 验证与判定标准

| 检查项 | 判定为已加固（PASS） | 判定为存在风险（FAIL） | 验证方式 |
|---|---|---|---|
| NGINX 版本 | `>= 1.30.1`（稳定分支）或 `>= 1.31.0`（主线分支） | `0.6.27` – `1.30.0` 且无厂商回port补丁 | `nginx -v` 输出核对 |
| 配置文件语法组合 | `scan_nginx_conf` 无 `rewrite-with-query` 后紧随 `set $capture` 命中 | 存在 `rewrite ... ?` 后再 `set $var $1` | 对所有站点配置运行检查脚本 |
| 运行环境内存缓解 | 内核 `randomize_va_space == 2`，二进制启用 PIE 与 RELRO | 启动脚本含 `setarch -R` 或关闭 ASLR | `cat /proc/sys/kernel/randomize_va_space` 与 `checksec` |
| 异常输入稳定性 | 发送含重复 `+` 的超长路径返回 `400`/`414`/`403` 且 worker PID 不变 | error.log 出现 `worker process exited on signal 11` | 受控测试环境对比 reload 前后 worker PID |

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 搜索 NGINX 加固文档 | `kb_router` | 按 `CVE-2026-42945` / `NGINX` / `rewrite` 检索 |
| 核对触发配置样本 | `kb_read_file` | 读取 `ctf-website/09-cve/06-nginx-rewrite-heapoverflow` 比对配置 |
| 网关响应回归验证 | `http_probe` | 验证超长畸形 URI 被正常拦截且服务维持存活 |
