---
id: "ctf-website/14-idor/01-idor-enumeration-defense"
title: "IDOR 纵深防御 — 对象级授权 (BOLA)、多租户隔离与不可预测标识"
title_en: "IDOR Defense — Broken Object Level Authorization (BOLA), Tenant Isolation & Opaque IDs"
summary: >
  针对可预测 ID（自增/UUID v1/Hashids）枚举、多步间接 IDOR 链、SaaS 跨租户访问、GraphQL 别名批量越权
  与 REST 批量端点越权，建立中心化对象所有权策略（Policy Enforcement Point）、强制租户作用域查询与不透明间接引用映射。
summary_en: >
  Defends against predictable ID enumeration (auto-increment, UUID v1, Hashids), multi-step IDOR chains,
  cross-tenant SaaS leakage, GraphQL alias batching, and REST batch endpoint BOLA using centralized object-level
  authorization, tenant-scoped queries, opaque random IDs (UUID v4/ULID), and query complexity caps.
board: "ctf-website"
category: "14-idor"
signals: ["IDOR防御", "BOLA", "对象级授权", "多租户隔离", "UUID v4", "GraphQL防批量", "CWE-639"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "kb_catalog"]
keywords: ["IDOR defense", "BOLA prevention", "object level authorization", "multi-tenant isolation", "GraphQL alias limit", "CWE-639"]
difficulty: "advanced"
tags: ["defense", "blue-team", "hardening", "idor", "bola", "access-control", "graphql", "multi-tenant"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/14-idor/01-idor-enumeration", "ctf-website/14-idor/02-bac-business-logic-defense", "ctf-website/12-payment/payment-email-bounce-idor-defense"]
track: "blue"
defends: "ctf-website/14-idor/01-idor-enumeration"
---
# IDOR 纵深防御 — 对象级授权 (BOLA)、多租户隔离与不可预测标识

> 配对攻击手册：[01-idor-enumeration.md](../../../../red/ctf-website/techniques/14-idor/01-idor-enumeration.md)。IDOR（OWASP API1 Broken Object Level Authorization）的根本原因不是“ID 可猜测”，而是“服务端未验证当前已认证主体对目标对象及其父级租户是否拥有访问权限”。UUID v4 只是纵深缓解，不能替代授权校验。

## 威胁模型与控制映射

| 攻击向量 | 脆弱根因 | 防御控制措施 |
|---|---|---|
| 自增 ID / UUID v1 / Hashids 枚举 | 使用顺序主键或含时间戳的 UUID v1，且未在接口校验归属 | 外部暴露 ID 改用 CSPRNG 128-bit（UUID v4 / 加密随机盐 HMAC 引用映射），并在每条查询注入 `owner_id` 过滤 |
| 跨租户 IDOR (SaaS Multi-Tenant) | 接口仅按 `order_id` 查表，或直接信任请求体里的 `tenant_id` | 从服务端签名的 JWT/Session Claims 提取 `tenant_id`，启用 PostgreSQL RLS 或 ORM 全局 Tenant Scope |
| GraphQL 别名（Alias）批量越权 | 每个 Resolver 未单独鉴权，且允许单次 query 包含上百个 alias | **每个节点/Resolver 强制执行所有权校验** + 设置 GraphQL 查询深度、别名数量与复杂度上限（Query Cost Analysis） |
| REST 批量端点越权 (`/batch?ids=...`) | 仅检查列表首元素或忽略 `ids[]` 中的非当前用户 ID | 对批量入参集合执行全量过滤：`WHERE id IN (:ids) AND tenant_id = :tid AND owner_id = :uid`；若存在越权 ID 则整批拒绝或仅返授权子集 |
| 多步间接 IDOR 与参数源混淆 | Step1 泄露关联外键，或 JSON 与 Form 混传导致鉴权读会话而业务读请求体 | 统一在网关/中间件层剥离客户端伪造的身份参数，所有关联对象沿“当前主体 -> 租户 -> 父对象 -> 子对象”整链验证 |

## 核心加固实现

### 1. 中心化对象级策略守卫与租户作用域查询

```python
# bola_policy_guard.py — 中心化对象级授权、批量过滤与跨租户防护
from dataclasses import dataclass
from typing import Iterable

@dataclass(frozen=True)
class Principal:
    user_id: str
    tenant_id: str
    role: str  # "member" | "tenant_admin"

@dataclass(frozen=True)
class ResourceObject:
    obj_id: str
    owner_id: str
    tenant_id: str
    shared_with: frozenset[str] = frozenset()

class AuthorizationDenied(PermissionError):
    pass

def authorize_object_access(principal: Principal, resource: ResourceObject, action: str) -> None:
    # 1. 强制多租户边界隔离（无论角色，跨租户一律拒绝）
    if resource.tenant_id != principal.tenant_id:
        raise AuthorizationDenied("cross-tenant boundary violation")
    # 2. 对象归属与显式共享矩阵
    if action == "read":
        if principal.role == "tenant_admin":
            return
        if resource.owner_id == principal.user_id or principal.user_id in resource.shared_with:
            return
    elif action in {"write", "delete"}:
        if principal.role == "tenant_admin" or resource.owner_id == principal.user_id:
            return
    raise AuthorizationDenied(f"principal {principal.user_id} denied {action} on {resource.obj_id}")

def fetch_batch_authorized(
    store: dict[str, ResourceObject],
    principal: Principal,
    requested_ids: Iterable[str],
    max_batch_size: int = 50,
) -> list[ResourceObject]:
    ids = list(dict.fromkeys(requested_ids))
    if len(ids) > max_batch_size:
        raise ValueError("batch size limit exceeded")
    authorized: list[ResourceObject] = []
    for oid in ids:
        obj = store.get(oid)
        if obj is None:
            continue
        # 逐对象强制授权，绝不因批量而跳过单条检查
        authorize_object_access(principal, obj, "read")
        authorized.append(obj)
    return authorized
```

### 2. GraphQL 别名/复杂度限制与随机标识符校验

```python
# graphql_alias_guard.py — 限制 GraphQL Alias 批量枚举与 UUID v1 检测
import re
import uuid

ALIAS_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\s*:\s*[A-Za-z_][A-Za-z0-9_]*\s*\(")

def validate_graphql_query_limits(query: str, max_aliases: int = 5, max_depth: int = 4) -> None:
    aliases = ALIAS_RE.findall(query)
    if len(aliases) > max_aliases:
        raise PermissionError(f"too many graphql aliases: {len(aliases)} > {max_aliases}")
    depth = 0
    peak = 0
    for ch in query:
        if ch == "{":
            depth += 1
            peak = max(peak, depth)
        elif ch == "}":
            depth -= 1
    if peak > max_depth:
        raise PermissionError(f"graphql depth exceeded: {peak} > {max_depth}")

def ensure_opaque_uuid4(raw_id: str) -> str:
    parsed = uuid.UUID(raw_id)
    if parsed.version != 4:
        raise ValueError(f"predictable UUID v{parsed.version} rejected; require UUID v4")
    return str(parsed)

if __name__ == "__main__":
    store = {
        "inv_1": ResourceObject("inv_1", "u_alice", "tenant_a"),
        "inv_2": ResourceObject("inv_2", "u_bob", "tenant_a"),
        "inv_3": ResourceObject("inv_3", "u_alice", "tenant_b"),
    }
    alice = Principal("u_alice", "tenant_a", "member")
    assert len(fetch_batch_authorized(store, alice, ["inv_1"])) == 1
    for bad_id in ("inv_2", "inv_3"):
        try:
            fetch_batch_authorized(store, alice, ["inv_1", bad_id])
            raise AssertionError(f"should deny {bad_id}")
        except AuthorizationDenied:
            pass
    bad_gql = "{ " + " ".join(f"u{i}: user(id:{i}) {{ email }}" for i in range(10)) + " }"
    try:
        validate_graphql_query_limits(bad_gql, max_aliases=5)
        raise AssertionError("should block alias batching")
    except PermissionError:
        pass
    ensure_opaque_uuid4(str(uuid.uuid4()))
    print("01-idor-enumeration-defense self-check passed")
```

## 防御工作流

```text
1. 鉴权收口：建立全局策略决策点（PDP/PEP），禁止控制器直接通过 `Model.find(id)` 读取对象，统一封装 `findForPrincipal(id, currentPrincipal)`。
2. 强制租户隔离：在 ORM 全局拦截器或 PostgreSQL RLS 中绑定 `current_setting('app.tenant_id')`，彻底根除跨租户漏加 `WHERE`。
3. 替换可预测 ID：对外接口将自增整型、UUID v1 与可逆 Hashids 替换为 UUID v4 或服务端映射的不透明令牌。
4. 批量与 GraphQL 限流：限制单次 REST 批量大小与 GraphQL Alias/深度，并确保 Field Resolver 各自触发对象鉴权。
5. 统一错误响应：对未授权与不存在的对象返回一致的状态码与错误体（如 `404` 或统一 `403`），避免存在性侧信道。
```

## 验证与判定标准

- **全路径 BOLA 拦截**：使用账号 A Token 遍历账号 B 的单个 ID、嵌套子资源 ID 及不同租户 ID，全部返回 `403/404`。
- **批量与 GraphQL 免疫**：批量接口混入 1 个他人的 ID 时整批拒绝或被严格剔除；超过 5 个别名的 GraphQL 查询直接被拒绝。
- **ID 空间不可预测**：新创建资源的外部标识符符合 UUID v4（版本号为 `4` 且高熵随机）。

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 越权边界回归检查 | `http_probe` | 使用双会话对比验证 REST/GraphQL 对象及批量端点返回拒绝状态 |
| 功能权限与参数防线关联 | `kb_router` | 检索 BAC、Mass Assignment 与退信越权防御条目 |
| 配对攻击细节对照 | `kb_read_file` | 对照读取 `ctf-website/14-idor/01-idor-enumeration` 复核全部枚举面 |
| 知识库模块总览 | `kb_catalog` | 列出访问控制类全量防御文档 |
