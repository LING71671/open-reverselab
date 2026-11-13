---
id: "ctf-website/03-injection/graphql-defense"
title: "GraphQL 防御与安全架构加固"
title_en: "GraphQL Defense and Hardening"
summary: >
  针对 GraphQL API 的纵深防御指南，覆盖传输层收敛（禁用 GET 变更与匿名 APQ）、生产环境关闭 Introspection 与 Field Suggestions、基于 AST 的深度/别名/复杂度限额、字段级与跨类型关联解析器鉴权、Subscription 握手与事件重验，以及底层 SQL/NoSQL/SSTI 强类型参数化防护。
summary_en: >
  Defense-in-depth guide for GraphQL APIs covering transport hardening (disabling GET mutations and anonymous APQ registration), disabling production introspection and field suggestions, AST-based depth/alias/cost limits, field-level and nested resolver authorization, WebSocket subscription re-validation, and strongly-typed parameterization against underlying injection.
board: "ctf-website"
category: "03-injection"
signals: ["GraphQL防御", "introspection禁用", "query complexity", "depth limit", "field authorization", "APQ白名单", "field suggestion关闭"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog", "http_probe"]
keywords: ["GraphQL防御", "AST复杂度限制", "字段级鉴权", "禁用Introspection", "关闭Field Suggestion", "Batch限流", "APQ安全", "Subscription鉴权"]
difficulty: "advanced"
tags: ["defense", "blue-team", "injection", "graphql", "api-hardening"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/03-injection/graphql", "ctf-website/14-idor/01-idor-enumeration", "ctf-website/15-mass-assignment/01-mass-assignment", "ctf-website/24-database/02-sqli-advanced", "ctf-website/07-client/websocket"]
track: "blue"
defends: "ctf-website/03-injection/graphql"
---

# GraphQL 防御与安全架构加固

GraphQL 的风险来自“单一入口暴露完整对象图谱”与“HTTP 层限流/鉴权和 AST 解析器语义脱节”。防御必须落在传输层收敛、AST 解析前限额、每个 Resolver 的上下文鉴权与底层强类型边界四道防线上，而非仅靠网关 WAF 或关闭 Introspection。

## 防御工作流

```text
收敛传输层入口（仅 POST JSON，关 GET/Batch/匿名 APQ）
  → 编译与验证层关闭 Introspection 与 Field Suggestions
  → 执行前计算 AST 深度、别名数、Fragment 展开后总节点成本
  → 顶层、子字段、Interface/Union 及 Subscription 逐层校验租户与角色权限
  → filter/where/orderBy/Upload 统一强类型白名单并参数化入库
```

## 1. 传输层与 APQ 入口收敛

GraphQL 常因同时开放 `POST JSON`、`GET`、`Batch Array`、`Multipart Upload` 与 `APQ` 而导致过滤器被旁路。网关与服务端必须对传输入口实行统一收口：

| 入口风险面 | 加固措施 | 关键配置要点 |
|---|---|---|
| GET 触发 Mutation/CSRF | 禁止 GET 执行任何操作或仅放行只读持久化查询 | 对 `GET /graphql` 返回 `405` 或强制校验 `Content-Type: application/json` |
| Batch Array 绕过速率限制 | 关闭数组批量请求或按总 AST Cost 扣减配额 | Apollo Server 设置 `allowBatchedHttpRequests: false` |
| Multipart File Upload | 禁用非必要 `Upload` scalar，校验扩展名、MIME 与体积上限 | 强制携带 CSRF Header（如非简单请求校验） |
| APQ 匿名注册与缓存投毒 | 禁用客户端动态写入未注册 Hash，仅查预编译静态白名单 | 缓存 Key 必须包含 `sha256Hash + variablesHash + tenantId + role` |

## 2. 关闭 Introspection 与 Field Suggestions

攻击者在禁用 `__schema` 后仍常通过 `Field Suggestions`（`Did you mean ...`）与 `__type` 枚举拼出全量 Schema：

1. **生产环境禁用内省**：在验证规则中注入 `NoSchemaIntrospectionCustomRule`，同时拦截 `__schema` 与 `__type` 元字段（仅保留可选的 `__typename`）。
2. **抑制字段拼写提示**：覆盖 GraphQL 引擎格式化错误逻辑，或启用禁用 `fieldSuggestions` 的补丁/中间件，在出现 `GRAPHQL_VALIDATION_FAILED` 时统一返回泛化错误码，不回显候选字段名。
3. **关闭堆栈与调试字段**：生产环境剥离 `errors[].extensions.exception` 与底层数据库报错文本，避免通过 `Cannot return null` 或类型报错反推字段存在性。

## 3. AST 复杂度、深度与 Alias/Fragment 防护

按 HTTP 请求次数限流无法阻挡单个请求内塞入上千个别名（如 `verifyOtp` 暴力枚举）或深层递归查询（`users -> posts -> comments -> author`），也无法防止同名 Fragment 复用（`...f ...f ...f`）绕过简单的正则字段计数：

- **递归深度限制**：设置 `depthLimit(6)`，在解析阶段直接拒绝超深嵌套查询。
- **展开 Fragment 计费**：复杂度分析器必须先递归展开 `FragmentSpread` 与 `InlineFragment`，按实际执行字段数、列表乘法因子（`limit`/`first` 参数）与单个操作内同名 `Alias` 上限计算总 Cost，超过阈值（如 `maxCost = 500`）拒绝解析。
- **敏感 Mutation 单例隔离**：对认证、OTP 核验、邀请码生成等敏感操作限制单次请求仅允许出现 1 个节点，并绑定账户级滑动窗口限流。
- **Token 数量与解析超时**：限制单个 Query 文本长度（如 `<= 16 KB`）与 AST Token 上限（`maxTokens <= 1000`），避免解析器自身耗尽 CPU。

## 4. 字段级授权、关联路径与 Variables 边界

顶层查询 `user(id: 1)` 鉴权通过后，子字段 `posts.comments.author.email` 或 `... on Admin { secretKey }` 常因缺少子级检查而发生越权，且 `Variable` 默认值与类型包装可能绕过前置校验：

- **Resolver 内置上下文鉴权**：在每个敏感字段（`email`、`secretKey`、`order.amount`、`payment.provider`）及 `Interface`/`Union` 解析器中检查 `ctx.currentUser` 与记录所属 `ownerId`/`tenantId`，不要将权限判断留在网关或顶层 Query。
- **Schema 指令统一声明权限**：通过 `@auth(requires: ADMIN)` 或 `@ownerOnly` Schema Directive 强制兜底，未显式声明策略的敏感字段默认拒绝（Fail-Closed）。
- **Input 白名单与默认值锁定**：`MutationInput` 使用专用窄 DTO 类型（剔除 `role`、`isAdmin`、`status`、`amount`、`ownerId`），禁止把请求对象直接透传 ORM；校验逻辑必须作用于 GraphQL 强制类型转换与默认值填充之后。

## 5. Subscription 与底层注入防护

- **WebSocket Subscription 加固**：握手阶段严格校验 `Origin` 白名单并验证会话票据；在 `connection_init`、`subscribe` 两个阶段以及会话权限变更/吊销时同步校验并断开未授权订阅。
- **底层 SQLi / NoSQLi / SSTI 防护**：`filter`、`where`、`orderBy` 参数禁用自由字符串或透传 MongoDB 操作符（`$regex`、`$ne`），一律映射为受限 `Enum` 与强类型标量，后端使用参数化查询；错误响应纯 JSON 序列化输出，不进入服务端模板渲染。

## 6. 硬化配置与策略校验脚本

以下可运行 Python 脚本用于在 CI 或网关前置阶段校验 GraphQL 查询策略：模拟检测内省查询、深度超限、别名/Fragment 展开后配额超标、批量请求数组与 GET 变更拦截效果：

```python
#!/usr/bin/env python3
"""GraphQL 查询策略与 AST 防护校验器（无外部依赖）。"""
import json
import re
from dataclasses import dataclass


@dataclass
class Policy:
    max_depth: int = 6
    max_aliases: int = 8
    max_fields: int = 40
    allow_introspection: bool = False
    allow_batch: bool = False


def inspect_graphql_request(method: str, content_type: str, raw_body: str, policy: Policy) -> tuple[bool, str]:
    if method.upper() != "POST":
        return False, "reject: only POST is allowed"
    if "application/json" not in content_type.lower():
        return False, "reject: Content-Type must be application/json"

    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError:
        return False, "reject: invalid JSON payload"

    if isinstance(payload, list):
        if not policy.allow_batch:
            return False, "reject: batch array queries are disabled"
        return False, "reject: unexpected batch"
    if not isinstance(payload, dict):
        return False, "reject: payload must be JSON object"

    query = payload.get("query", "")
    ext = payload.get("extensions") or {}
    if "persistedQuery" in ext and query:
        # 禁止客户端同一请求携带未授权 query 覆盖或注册 APQ
        return False, "reject: dynamic APQ registration is disabled"
    if not isinstance(query, str) or not query.strip():
        return False, "reject: empty query"

    # 1. 禁止内省元字段
    if not policy.allow_introspection and re.search(r"\b__(?:schema|type)\b", query):
        return False, "reject: introspection is disabled in production"

    # 2. 统计括号最大嵌套深度与别名数
    depth = 0
    max_depth = 0
    for ch in query:
        if ch == "{":
            depth += 1
            max_depth = max(max_depth, depth)
        elif ch == "}":
            depth -= 1
    if max_depth > policy.max_depth:
        return False, f"reject: query depth {max_depth} exceeds limit {policy.max_depth}"

    aliases = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\s*:\s*[A-Za-z_]", query)
    if len(aliases) > policy.max_aliases:
        return False, f"reject: alias count {len(aliases)} exceeds limit {policy.max_aliases}"

    # 3. 检查 Fragment 定义展开放大风险
    frag_defs = dict(re.findall(r"fragment\s+([A-Za-z_][A-Za-z0-9_]*)\s+on\s+[A-Za-z_][A-Za-z0-9_]*\s*\{([^}]*)\}", query, re.S))
    spreads = re.findall(r"\.\.\.([A-Za-z_][A-Za-z0-9_]*)", query)
    expanded_fields = len(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", query))
    for sp in spreads:
        if sp in frag_defs:
            expanded_fields += len(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", frag_defs[sp]))
    if expanded_fields > policy.max_fields:
        return False, f"reject: expanded node cost {expanded_fields} exceeds {policy.max_fields}"

    return True, "allow"


if __name__ == "__main__":
    pol = Policy()
    cases = [
        ("GET", "application/json", '{"query":"mutation{deleteAll{ok}}"}', False),
        ("POST", "application/json", '[{"query":"{__typename}"},{"query":"{__typename}"}]', False),
        ("POST", "application/json", '{"query":"{__schema{types{name}}}"}', False),
        ("POST", "application/json", '{"query":"{a{b{c{d{e{f{g{id}}}}}}}}"}', False),
        ("POST", "application/json", '{"query":"query{u1:user{id} u2:user{id} u3:user{id} u4:user{id} u5:user{id} u6:user{id} u7:user{id} u8:user{id} u9:user{id}}"}', False),
        ("POST", "application/json", '{"query":"query($id:ID!){user(id:$id){id name}}","variables":{"id":"101"}}', True),
    ]
    for method, ct, body, expected in cases:
        ok, reason = inspect_graphql_request(method, ct, body, pol)
        assert ok == expected, f"unexpected result for {body}: {ok} ({reason})"
        print(f"[PASS] expected={expected} actual={ok} -> {reason}")
```

## 验证与判定标准

| 验证项 | 预期加固表现 | 阻断失败标志 |
|---|---|---|
| 传输入口测试 | `GET /graphql`、Batch Array 与匿名 APQ 注册均被拒绝（`400`/`405`） | `GET` 仍可执行 Mutation 或 Batch 数组返回结果数组 |
| 内省与建议测试 | `__schema`/`__type` 返回统一策略拦截错误；拼写错误字段不返回 `Did you mean` | 响应泄露类型列表或任何候选字段名 |
| 复杂度与别名限制 | 深度超过阈值或高频别名/重复 Fragment 在进入 Resolver 前被拒绝 | 嵌套递归引发高耗时，或单请求完成批量 OTP/ID 枚举 |
| 字段级与关联鉴权 | 非特权账号访问 `admin`/`email`/`secretKey` 或跨租户子字段返回 `FORBIDDEN` | 顶层对象返回后，子字段或 `... on Admin` 仍吐出敏感值 |
| Subscription 校验 | 跨站 Origin 或未授权 `subscribe` 立即关闭连接并返回错误帧 | 仅在 `connection_init` 检查，后续越权订阅仍收广播 |

## MCP 工具映射

| 防御环节 | MCP 工具 | 说明 |
|---|---|---|
| 防御知识路由 | `kb_router` | 按 `graphql`、`introspection`、`complexity`、`idor` 检索配对攻防文档 |
| 读取关联知识 | `kb_read_file` | 查阅配对进攻文档 `ctf-website/03-injection/graphql` 及 IDOR/Mass Assignment 策略 |
| 浏览目录索引 | `kb_catalog` | 列出 `03-injection` 与关联防御条目进行覆盖核对 |
| 入口基线核验 | `http_probe` | 切换到 `red` 或 `both` 轨道后验证目标端点对 GET/Batch/Introspection 的实际响应 |
