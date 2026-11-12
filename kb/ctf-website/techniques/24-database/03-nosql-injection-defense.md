---
id: "ctf-website/24-database/03-nosql-injection-defense"
title: "NoSQL Injection Defense — MongoDB/Redis/ES/CouchDB/Memcached 全栈防御"
title_en: "NoSQL Injection & Unauthorized Access Defense"
summary: >
  全面防御 MongoDB、Redis、Elasticsearch、CouchDB 与 Memcached 的注入与未授权利用：阻断 Express/PHP 嵌套对象与 $ne/$regex/$where 操作符注入、禁用 MongoDB 服务端 JS 与正则 ReDoS；实施 Redis 6+ ACL 禁用 CONFIG/SLAVEOF/MODULE 并加密签名会话键；关闭 ES 动态脚本并收敛 _cat/_mapping 访问；消除 CouchDB Admin Party 与 Memcached UDP/未授权缓存暴露。
summary_en: >
  Comprehensive defense against NoSQL injection and unauthorized access across MongoDB, Redis, Elasticsearch, CouchDB, and Memcached: enforcing scalar type validation and key sanitization against $ne/$regex/$where operator injection, disabling server-side JS, applying Redis ACLs against CONFIG/SLAVEOF/MODULE RCE while signing session keys, locking down ES scripting and cluster endpoints, patching CouchDB Admin Party, and restricting Memcached.
board: "ctf-website"
category: "24-database"
signals:
  - "MongoDB $操作符清洗与标量类型强校验"
  - "MongoDB javascriptEnabled false 禁用 $where"
  - "Redis ACL 禁用 CONFIG SLAVEOF MODULE"
  - "Elasticsearch 禁用动态脚本与 query_string 收敛"
  - "CouchDB require_valid_user 与版本升级"
  - "Memcached 127.0.0.1 绑定与禁用 UDP"
mcp_tools:
  - "kb_router"
  - "kb_read_file"
  - "kb_catalog"
  - "http_probe"
keywords:
  - "NoSQL 注入防御"
  - "MongoDB 防护"
  - "Redis ACL"
  - "Elasticsearch 安全"
  - "CouchDB 加固"
  - "Memcached 隔离"
  - "操作符过滤"
  - "类型校验"
  - "会话签名"
  - "禁用服务端JS"
difficulty: "advanced"
tags:
  - "defense"
  - "blue-team"
  - "database-security"
  - "nosql"
  - "mongodb"
  - "redis"
  - "elasticsearch"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/24-database/03-nosql-injection", "ctf-website/24-database/04-config-exposure-defense", "ctf-website/24-database/01-sqli-fundamentals-defense"]
track: "blue"
defends: "ctf-website/24-database/03-nosql-injection"
---
# NoSQL Injection Defense — MongoDB/Redis/ES/CouchDB/Memcached 全栈防御

> NoSQL 风险常源自“框架将字符串参数解析为查询对象”或“内存/文档服务裸奔”。防御重心在于输入标量强类型校验、操作符键清洗、禁用服务端脚本与内网服务认证隔离。

## 1. 多引擎攻击面与防御矩阵

对照 [03-nosql-injection.md](03-nosql-injection.md)，五大 NoSQL 组件必须同时收紧应用查询层与实例网络/权限层：

| 组件 | 核心风险向量 | 应用层防御 | 实例与网络层防御 |
|---|---|---|---|
| **MongoDB** | `[$ne]`/`$gt`/`$regex` 认证绕过、点号键越权、`$where` JS 执行 | 强制标量类型（`string`），剔除 `$` 开头与含 `.` 的键，转义正则 | `javascriptEnabled: false`、开启 SCRAM-SHA-256 认证、限制 `maxTimeMS` |
| **Redis** | 未授权 `CONFIG SET` 写 Webshell/SSH/Cron、`SLAVEOF`+`MODULE LOAD`、伪造 `session:*` | 禁止用户输入直接拼入 Redis 命令；会话与队列载荷加 HMAC/AEAD 签名 | `bind 127.0.0.1`、`protected-mode yes`、Redis ACL 禁用高危命令、启用 TLS |
| **Elasticsearch** | Groovy/动态脚本 RCE、`query_string` 注入、`/_cat`/`/_mapping` 泄露 | 改用 `term`/`match` 结构化 DSL，禁止前端传入原始 `query_string` | `script.allowed_types: none`、开启 X-Pack/OpenSearch RBAC、反代屏蔽管理端点 |
| **CouchDB** | 未授权 `/_all_dbs`/`/_users`、CVE-2017-12635/CVE-2018-8007 RCE | 校验文档结构与角色字段不可由客户端写入 | 升级至修复版本、`require_valid_user = true`、禁用 Admin Party |
| **Memcached** | `stats items`/`cachedump` 拖取缓存与会话令牌 | 缓存键值仅存不可预测哈希或加密密文 | 仅监听内网/本机、禁用 UDP (`-U 0`)、开启 SASL 认证与防火墙隔离 |

## 2. 分引擎加固基线

### 2.1 MongoDB：强类型校验、键清洗与禁用 `$where`

很多 MongoDB 注入并非数据库自身缺陷，而是 Express (`qs`)、PHP 或框架将 `username[$ne]=1` 解析成了嵌套字典 `{username: {"$ne": "1"}}`。
- **认证与查询前必须做严格标量断言**（如 Pydantic `StrictStr`、Zod `z.string()`），禁止对象或数组进入字符串字段。
- **键值递归清洗**：拒绝任何以 `$` 开头或包含 `.` 的键名；对搜索场景使用 `re.escape()` 并限制正则长度与 `maxTimeMS(1000)` 防止正则盲注与 ReDoS。
- **实例禁用 JS 引擎**（`/etc/mongod.conf`）：

```yaml
security:
  authorization: enabled
  javascriptEnabled: false
net:
  bindIp: 127.0.0.1
  tls:
    mode: requireTLS
```

### 2.2 Redis：ACL 最小权限、防写盘/主从 RCE 与业务键签名

为避免未授权访问或 SSRF Gopher 打入导致 `CONFIG SET` 落盘与主从复制加载 `.so` 模块：

```text
# /etc/redis/redis.conf 核心加固基线
bind 127.0.0.1
protected-mode yes
port 0
tls-port 6379

# 禁用默认高权限账号，为应用创建仅可操作指定 key 前缀的 ACL 账号
user default off
user app_web on >STRONG_RANDOM_REDIS_SECRET ~session:* ~cart:* ~order:* +@read +@write -@dangerous -CONFIG -SLAVEOF -REPLICAOF -MODULE -BGSAVE -SAVE -FLUSHALL -FLUSHDB -EVAL -EVALSHA
```

- **业务键保护**：对于 `session:*`、`laravel:*`、`flask_session:*`、`queue:*`、`captcha:*` 等业务键，必须在应用层采用服务端密钥签名（如 HMAC-SHA256 或 AES-GCM 封装），防止缓存内网越权篡改 `role`/`uid` 或反序列化伪造。

### 2.3 Elasticsearch：结构化 DSL 替代与管理端点收口

1. **禁止动态脚本与原始 `query_string`**：

```yaml
# config/elasticsearch.yml
xpack.security.enabled: true
script.allowed_types: none
```

2. **安全查询构建**：用户输入仅作为 `match` 或 `term` 的字符串值传入，禁止让用户输入控制 `query_string`、`_source` 字段清单或 `sort` 任意内部字段（同样采用服务端允许字段集合映射）。
3. **反代隔离**：Nginx 严禁将 `9200` 端口或 `/_cat/*`、`/_nodes/*`、`/_mapping`、`/_field_caps` 暴露给外网用户。

### 2.4 CouchDB 与 Memcached 基线

- **CouchDB**（`/opt/couchdb/etc/local.ini`）：确保版本高于 `2.1.2`/`1.7.2`（消除 CVE-2017-12635/CVE-2018-8007），配置：

```ini
[chttpd]
bind_address = 127.0.0.1
require_valid_user = true

[couch_httpd_auth]
require_valid_user = true
```

- **Memcached**（`/etc/memcached.conf`）：禁用 UDP 端口以防放大与未授权读写，启用 SASL 并仅绑定本机/内网安全组：

```text
-l 127.0.0.1
-p 11211
-U 0
-S
```

## 3. 可运行防御自检脚本

以下 Python 脚本可本地直接执行，用于校验：（1）MongoDB 输入清洗与认证载荷强类型拦截（阻断 `$ne`/`$regex`/`$where`/嵌套数组/点号键）；（2）安全正则转义；（3）Redis/Mongo/ES 配置基线核对：

```python
#!/usr/bin/env python3
"""Self-check for NoSQL payload sanitization, type validation, and config hardening."""
import re


class NoSQLInputError(ValueError):
    pass


def assert_scalar_str(value: object, field: str, max_len: int = 128) -> str:
    if not isinstance(value, str):
        raise NoSQLInputError(f"field {field!r} must be scalar str, got {type(value).__name__}")
    if len(value) > max_len:
        raise NoSQLInputError(f"field {field!r} exceeds max length {max_len}")
    return value


def sanitize_mongo_doc(obj: object) -> object:
    if isinstance(obj, dict):
        cleaned = {}
        for k, v in obj.items():
            if not isinstance(k, str) or k.startswith("$") or "." in k:
                raise NoSQLInputError(f"forbidden MongoDB key: {k!r}")
            cleaned[k] = sanitize_mongo_doc(v)
        return cleaned
    if isinstance(obj, list):
        return [sanitize_mongo_doc(item) for item in obj]
    return obj


def build_safe_mongo_login_filter(body: dict) -> dict[str, str]:
    # 拒绝 {"username": {"$ne": None}}, ["admin", {"$ne": None}], {"username[$ne]": "x"} 等变体
    for key in body:
        if "[" in key or "]" in key or key.startswith("$") or "." in key:
            raise NoSQLInputError(f"suspicious parameter name: {key!r}")
    username = assert_scalar_str(body.get("username"), "username", 64)
    password = assert_scalar_str(body.get("password"), "password", 128)
    return {"username": username, "password": password}


def safe_regex_prefix(user_input: str) -> str:
    scalar = assert_scalar_str(user_input, "search", 64)
    return "^" + re.escape(scalar)


def check_redis_acl_line(acl_line: str) -> list[str]:
    required_denies = ("-CONFIG", "-SLAVEOF", "-MODULE", "-BGSAVE")
    return [cmd for cmd in required_denies if cmd not in acl_line]


def run_self_check() -> None:
    # 1. MongoDB 操作符与嵌套对象注入拦截
    attack_payloads = [
        {"username": {"$ne": None}, "password": {"$ne": None}},
        {"username": {"$regex": "^admin"}, "password": {"$ne": None}},
        {"username[$ne]": "x", "password[$ne]": "x"},
        {"username": ["admin", {"$ne": None}], "password": "123"},
    ]
    for p in attack_payloads:
        try:
            build_safe_mongo_login_filter(p)
            raise AssertionError(f"attack payload was not blocked: {p}")
        except NoSQLInputError:
            pass

    assert build_safe_mongo_login_filter({"username": "alice", "password": "pw"}) == {
        "username": "alice",
        "password": "pw",
    }

    # 2. 点号键与 $where 拦截
    try:
        sanitize_mongo_doc({"$where": "sleep(5000)"})
        raise AssertionError("$where should be rejected")
    except NoSQLInputError:
        pass
    try:
        sanitize_mongo_doc({"profile.role": "admin"})
        raise AssertionError("dotted key should be rejected")
    except NoSQLInputError:
        pass

    # 3. 正则元字符安全转义
    assert safe_regex_prefix("a.*+?^$") == r"^a\.\*\+\?\^\$"

    # 4. Redis ACL 基线检查
    good_acl = "user app_web on >pass ~session:* +@read +@write -@dangerous -CONFIG -SLAVEOF -MODULE -BGSAVE"
    assert check_redis_acl_line(good_acl) == []
    print("[PASS] NoSQL injection defense self-check succeeded.")


if __name__ == "__main__":
    run_self_check()
```

## 防御工作流

```text
1. 在所有认证、搜索与更新接口强制校验输入为标量类型（str/int/bool），禁止隐式解析为嵌套对象或数组
2. 开启 MongoDB 键名递归过滤（拦截 $ 前缀与点号路径），实例层设置 javascriptEnabled: false
3. 为 Redis 启用 TLS、protected-mode 与 ACL 账号，禁用 CONFIG/SLAVEOF/MODULE/BGSAVE 并在应用层对会话与队列载荷签名
4. 将 Elasticsearch 切换为结构化 term/match 查询，关闭动态脚本并屏蔽 /_cat /_mapping /_nodes 外部暴露
5. 升级并锁定 CouchDB require_valid_user=true，绑定 Memcached 至内网并关闭 UDP，运行自检脚本验证拦截生效
```

## 验证与判定标准

| 服务组件 | 校验方式 | 通过标准 | 失败信号 |
|---|---|---|---|
| MongoDB | 提交 `{"$ne": null}`、`[$ne]` 与 `$where` 载荷 | 全部在应用反序列化/校验层返回 HTTP 400，实例禁用 JS | 触发登录绕过、返回 `unknown operator` 或出现执行延时 |
| Redis | 检查 `CONFIG GET` 与非特权 ACL 账号命令矩阵 | 公网不可达；应用账号执行 `CONFIG`/`SLAVEOF`/`MODULE` 返回权限拒绝 | 返回 `+PONG` 且可执行 `CONFIG SET` 或主从同步 |
| Elasticsearch | 请求 `/_cat/indices`、`/_mapping` 与内联脚本查询 | 未授权返回 401/403，动态脚本被引擎拒绝 | 暴露索引元数据或允许 `query_string` 拖取敏感字段 |
| CouchDB / Memcached | 端口扫描与 `/_all_dbs`、`stats cachedump` 检查 | 外部端口不可达或强制认证拒绝 | 匿名可读 `/_users` 或 `stats items` 缓存键 |
| 业务会话/队列 | 修改 Redis/Memcached 内缓存值测试应用解析 | 签名校验失败并自动丢弃/重建会话 | 篡改缓存字段后直接提权或伪造订单状态 |

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索 NoSQL 防御指南 | `kb_router` | 按 `MongoDB sanitize`、`Redis ACL`、`Elasticsearch script` 搜索文档 |
| 对照攻击载荷 | `kb_read_file` | 读取 [03-nosql-injection.md](03-nosql-injection.md) 核对各引擎攻击向量 |
| 目录索引查阅 | `kb_catalog` | 确认数据库防御系列覆盖完整度 |
| 端点连通与拦截测试 | `http_probe` | 在 `red`/`both` 模式下确认 JSON/表单操作符载荷均返回 400 拦截 |

## 关联技术

- [03-nosql-injection.md](03-nosql-injection.md) — 配对攻击面：NoSQL 注入攻击
- [04-config-exposure-defense.md](04-config-exposure-defense.md) — Redis/Mongo 连接串与配置防泄露
- [01-sqli-fundamentals-defense.md](01-sqli-fundamentals-defense.md) — SQL 参数化查询与账号隔离基线
