---
id: "ctf-website/08-infra/race-cache-smuggling-defense"
title: "并发竞态原子化、缓存键隔离与 HTTP 走私防御"
title_en: "Concurrency Atomicity, Cache Key Isolation & HTTP Request Smuggling Defense"
summary: >
  防御高并发条件竞争（优惠券重复核销、余额双花、状态机越权、上传窗口）、Unkeyed Header 缓存投毒（X-Forwarded-Host/Origin 污染共享缓存）以及 HTTP 请求走私（CL.TE、TE.CL、TE.TE 混淆与 H2.CL/H2.TE 降级），提供数据库原子锁、幂等令牌、缓存键标准化及严格 HTTP 报文规范化方案。
summary_en: >
  Defense against infrastructure-layer concurrency race conditions (coupon double-spend, lost updates, state-machine races), unkeyed-header cache poisoning, and HTTP request smuggling (CL.TE, TE.CL, TE.TE, H2.CL/H2.TE). Implements DB atomic conditional updates, idempotency keys, cache key canonicalization, and strict HTTP framing enforcement.
board: "ctf-website"
category: "08-infra"
signals: ["race condition", "cache poisoning", "request smuggling", "CL.TE", "TE.CL", "H2.CL", "竞态防御", "请求走私防御"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["条件竞争防御", "原子更新", "幂等性设计", "缓存投毒防御", "Unkeyed Header隔离", "HTTP请求走私防御", "禁用H2降级", "blue-team"]
difficulty: "advanced"
tags: ["defense", "blue-team", "race-condition", "cache-poisoning", "request-smuggling", "infrastructure"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/08-infra/race-cache-smuggling", "ctf-website/08-infra/web-cache-deception-defense", "ctf-website/02-auth/host-header-defense"]
track: "blue"
defends: "ctf-website/08-infra/race-cache-smuggling"
---
# 并发竞态原子化、缓存键隔离与 HTTP 走私防御

## 防御目标与威胁面

基础设施层的三大顽疾——条件竞争、缓存投毒与请求走私——分别攻击状态机时间窗、共享缓存边界与代理链路报文定界：

1. **条件竞争 (Race Condition)**：读取-判断-写入分离（Check-Then-Act）导致并发请求穿透一次核销、转账扣款、投票限额或临时上传扫描窗，引发 Lost Update 与双花。
2. **缓存投毒 (Cache Poisoning)**：后端读取未纳入 CDN Cache Key 的头字段（`X-Forwarded-Host`、`X-Forwarded-Scheme`、`X-Original-URL`、`Origin`）动态生成重定向或脚本链接并被共享缓存持久化分发给其他用户。
3. **请求走私 (Request Smuggling)**：前后端代理对 `Content-Length` 与 `Transfer-Encoding` 优先级、畸形 TE 头（`Transfer-Encoding : chunked`、`Transfer-Encoding:\tchunked`）或 HTTP/2 降级 HTTP/1.1 时的长度解析产生分歧，导致请求边界被越界拼接。

## 核心防御架构

| 领域 | 根治控制措施 | 实施要点 |
|---|---|---|
| 并发竞态 | 数据库条件原子更新 + 唯一约束 + 强制幂等键 | 扣款/核销用单条 `UPDATE ... SET balance = balance - ? WHERE id = ? AND balance >= ?` 或 `INSERT ... ON CONFLICT DO NOTHING`；关键写接口强制 `Idempotency-Key` + 分布式锁 |
| 缓存投毒 | 剥离未入 Key 的影响性转发头 + `Vary` 显式对齐 + 动态页禁公共缓存 | 边缘网关丢弃外部 `X-Forwarded-Host`/`X-Original-URL`；所有能改变响应体的 Header 必须纳入 Cache Key 或声明在 `Vary` 中；`4xx/5xx` 错误页禁用 CDN 缓存 |
| 请求走私 | 全链路原生 HTTP/2 + 严格 RFC 9112 报文校验 + 禁用上游连接复用降级 | 同一请求同时出现 `Content-Length` 与 `Transfer-Encoding`、或存在多个 `CL`/非法字符空白的 `TE` 时，边缘直接返回 `400` 并关闭 TCP 连接 |

## 加固代码与离线核查示例

以下 Python 示例整合了**原子条件扣减与幂等防重（SQLite 事务模拟）**以及**HTTP 报文定界与缓存头安全检查器**：

```python
import sqlite3
from typing import Dict, List, Tuple


def atomic_redeem_coupon(conn: sqlite3.Connection, code: str, user_id: int) -> bool:
    """单条条件更新 + 唯一约束，彻底消除 Check-Then-Act 并发双花。"""
    cur = conn.cursor()
    cur.execute("BEGIN IMMEDIATE")
    cur.execute(
        "UPDATE coupons SET remaining = remaining - 1 WHERE code = ? AND remaining > 0",
        (code,),
    )
    if cur.rowcount != 1:
        conn.rollback()
        return False
    try:
        cur.execute(
            "INSERT INTO coupon_redemptions(code, user_id) VALUES (?, ?)",
            (code, user_id),
        )
    except sqlite3.IntegrityError:
        conn.rollback()
        return False
    conn.commit()
    return True


def check_http_framing_and_cache_safety(raw_headers: List[Tuple[str, str]]) -> Tuple[bool, str]:
    """严格按 RFC 9112 拦截走私歧义头与危险未键控重写头。"""
    cl_values = []
    te_values = []
    for raw_name, raw_val in raw_headers:
        # 禁止 header name 末尾带空格/制表符（如 'Transfer-Encoding :'）
        if raw_name != raw_name.strip() or any(c.isspace() for c in raw_name):
            return False, f"obs_fold_or_space_in_header_name:{raw_name!r}"
        name = raw_name.lower()
        if "\r" in raw_val or "\n" in raw_val:
            return False, f"crlf_in_header:{name}"
        if name == "content-length":
            if not raw_val.strip().isdigit():
                return False, "invalid_content_length"
            cl_values.append(int(raw_val.strip()))
        elif name == "transfer-encoding":
            te_values.append(raw_val.strip().lower())
        elif name in {"x-original-url", "x-rewrite-url"}:
            return False, f"untrusted_routing_header:{name}"

    if cl_values and te_values:
        return False, "both_cl_and_te_present"
    if len(set(cl_values)) > 1 or len(cl_values) > 1:
        return False, "duplicate_content_length"
    if te_values and te_values != ["chunked"]:
        return False, f"non_canonical_te:{te_values}"
    return True, "ok"


if __name__ == "__main__":
    # 1. 原子扣减测试：剩余 1 次的券连续两次兑换仅成功 1 次
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE coupons (code TEXT PRIMARY KEY, remaining INTEGER NOT NULL)")
    db.execute("CREATE TABLE coupon_redemptions (code TEXT, user_id INTEGER, UNIQUE(code, user_id))")
    db.execute("INSERT INTO coupons VALUES ('ONCE', 1)")
    db.commit()
    assert atomic_redeem_coupon(db, "ONCE", 101) is True
    assert atomic_redeem_coupon(db, "ONCE", 102) is False

    # 2. HTTP 走私歧义报文测试
    assert check_http_framing_and_cache_safety([("Content-Length", "6"), ("Transfer-Encoding", "chunked")]) == (False, "both_cl_and_te_present")
    assert check_http_framing_and_cache_safety([("Transfer-Encoding ", "chunked")]) == (False, "obs_fold_or_space_in_header_name:'Transfer-Encoding '")
    assert check_http_framing_and_cache_safety([("Transfer-Encoding", "chunked, x")]) == (False, "non_canonical_te:['chunked, x']")
    assert check_http_framing_and_cache_safety([("Host", "app.example"), ("Content-Length", "12")]) == (True, "ok")
    print("Race / Cache Poisoning / Smuggling defense self-check passed.")
```

## 防御工作流

```text
1. 事务原子化：梳理所有扣款、兑换、领券、库存、状态流转接口，改造成带条件 WHERE 的原子 SQL 或分布式互斥锁 + 幂等键
2. 缓存隔离：在 CDN/Nginx 剥离未纳入 Cache Key 的转发头（X-Forwarded-Host/Scheme/Original-URL），动态及错误响应显式置 Cache-Control: no-store
3. 走私拦截：升级并加固边缘反代，开启严格 HTTP 解析模式，对同时含 CL+TE、多 CL 或混淆 TE 直接返回 400 并断连
4. 协议端到端对齐：CDN 到源站采用全链路 HTTP/2 或独立连接池，避免 H2->H1.1 降级复用引发走私
```

## 验证与判定标准

- **高并发零超发**：使用 50 并发同时触发同一单次优惠券或全额转账时，数据库流水仅写入 1 笔成功记录且余额绝不为负。
- **Unkeyed Header 零毒化**：携带 `X-Forwarded-Host: attacker.example` 请求静态化或缓存路径后，紧接的无头常规请求响应体不包含 `attacker.example`。
- **走私探针全返回 `400`**：发送 `CL.TE`、`TE.CL`、`Transfer-Encoding : chunked` 畸形请求时，边缘层直接拒收并断开连接，后续正常请求不受任何前缀污染。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索基础设施层防御 | `kb_router` | 搜索 `条件竞争防御`、`缓存投毒防御`、`HTTP请求走私防御` |
| 对照竞态与走私矩阵 | `kb_read_file` | 读取 [race-cache-smuggling.md](race-cache-smuggling.md) 检查覆盖点 |
| 联动缓存欺骗防御 | `kb_catalog` | 协同查阅 `web-cache-deception-defense` 完善 CDN 边界 |
