---
id: "ctf-website/15-mass-assignment/01-mass-assignment-defense"
title: "批量赋值与属性注入防御 — DTO 白名单绑定、禁危险函数与 GraphQL 类型收敛"
title_en: "Mass Assignment Defense — Strict DTO Allowlists, Safe Binding & GraphQL Input Types"
summary: >
  针对 Laravel、Rails、Django、Spring Boot 的模型属性自动绑定注入、PHP extract/parse_str/$$ 变量覆盖、
  嵌套属性（Nested Attributes）越权改写及 GraphQL Mutation 字段注入，提供显式 DTO 白名单、只读字段隔离与静态模式检查方案。
summary_en: >
  Prevents mass assignment and attribute injection across Laravel, Rails, Django, Spring Boot, PHP functions
  (extract/parse_str/$$), nested attributes, and GraphQL mutations by enforcing explicit input DTO allowlists,
  separating domain entities from API payloads, and blocking dynamic variable assignment.
board: "ctf-website"
category: "15-mass-assignment"
signals: ["mass assignment防御", "DTO白名单", "$fillable", "strong_parameters", "禁用extract", "GraphQL Input校验", "CWE-915"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "kb_catalog"]
keywords: ["mass assignment defense", "DTO allowlist", "CWE-915", "Spring WebDataBinder", "Rails strong parameters", "Django serializer fields"]
difficulty: "advanced"
tags: ["defense", "blue-team", "hardening", "mass-assignment", "framework", "graphql", "cwe-915"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/15-mass-assignment/01-mass-assignment", "ctf-website/15-mass-assignment/02-parameter-tampering-defense", "ctf-website/14-idor/02-bac-business-logic-defense"]
track: "blue"
defends: "ctf-website/15-mass-assignment/01-mass-assignment"
---
# 批量赋值与属性注入防御 — DTO 白名单绑定、禁危险函数与 GraphQL 类型收敛

> 配对攻击手册：[01-mass-assignment.md](../../../../red/ctf-website/techniques/15-mass-assignment/01-mass-assignment.md)。Mass Assignment（CWE-915）的根源在于直接将外部 HTTP/GraphQL 请求载荷绑定到持久化领域模型（ORM Entity），使攻击者能够注入 `role`、`is_admin`、`balance`、`tenant_id` 或嵌套关联对象属性。

## 威胁模型与框架级控制映射

| 框架 / 场景 | 常见脆弱写法 | 推荐加固写法 |
|---|---|---|
| Laravel (PHP) | `$guarded = []` 或 `User::create($request->all())` | 控制器强制使用 `$request->only(['name', 'bio'])` 或 FormRequest `validated()`，模型显式定义最小 `$fillable` |
| Ruby on Rails | `params.permit!` 或在 `permit` 中开放 `role_id` / `*_attributes` | 精确枚举 `params.require(:user).permit(:display_name, :avatar)`，嵌套属性仅允许白名单子键且校验父对象归属 |
| Django / DRF | `fields = "__all__"` 或仅 `exclude = ('is_staff',)` | 显式定义 `fields = ('username', 'email')` 与 `read_only_fields`，敏感状态单独走业务 Service 方法 |
| Spring Boot (Java) | 控制器直接接收 `@ModelAttribute UserEntity` 或未设 `WebDataBinder.setAllowedFields` | 接收层与 Entity 彻底解耦：仅用专用 `UpdateProfileRequest` DTO（`record` / Bean）+ Jackson `FAIL_ON_UNKNOWN_PROPERTIES=true` |
| PHP 原生函数 | `extract($_POST)`、`parse_str($qs)` 无第二参数、`$$key = $val` | 严禁对不可信输入使用 `extract` 与可变变量 `$$`；`parse_str($qs, $arr)` 后再按固定键读取 |
| GraphQL Mutation | 普通用户与管理员复用同一 `UserInput` 类型（含 `role` / `verified`） | 按角色拆分最小化 `Input` 类型（如 `UpdateSelfProfileInput` 仅含 `nickname`），服务端拒绝未定义字段 |

## 核心加固实现

### 1. Spring Boot / DRF 边界加固示例

```java
// Spring Boot: 使用不可变 Request DTO + @InitBinder 双重收口
public record UpdateProfileRequest(
    @NotBlank @Size(max = 64) String displayName,
    @Size(max = 200) String bio
) {}

@ControllerAdvice
public class GlobalBindingHardening {
    @InitBinder
    public void configureBinder(WebDataBinder binder) {
        // 禁止 Spring 内部路径及常见敏感字段被绑定
        binder.setDisallowedFields("class.*", "Class.*", "*.class.*", "role", "roles", "isAdmin", "balance", "tenantId");
    }
}
```

### 2. Python 严格 DTO 过滤与未知/敏感字段阻断器

```python
# strict_dto_binder.py — 显式字段白名单绑定、嵌套深度控制与敏感字段告警
from dataclasses import dataclass

FORBIDDEN_SENSITIVE_FIELDS = {
    "role", "roles", "is_admin", "is_staff", "is_superuser",
    "balance", "credit", "paid", "status", "tenant_id", "owner_id",
}

class MassAssignmentBlocked(PermissionError):
    pass

@dataclass(frozen=True)
class StrictBindingPolicy:
    allowed_fields: frozenset[str]
    reject_unknown: bool = True

def bind_payload(payload: dict, policy: StrictBindingPolicy) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")

    bound = {}
    for key, value in payload.items():
        if not isinstance(key, str):
            raise MassAssignmentBlocked("non-string key rejected")
        if key in FORBIDDEN_SENSITIVE_FIELDS and key not in policy.allowed_fields:
            raise MassAssignmentBlocked(f"sensitive field injection blocked: {key}")
        if key not in policy.allowed_fields:
            if policy.reject_unknown:
                raise MassAssignmentBlocked(f"unknown field rejected: {key}")
            continue
        # 拒绝嵌套字典/列表越权修改关联关系（除非模型显式允许并单独绑定）
        if isinstance(value, (dict, list)):
            raise MassAssignmentBlocked(f"nested attribute injection blocked on {key}")
        bound[key] = value
    return bound

if __name__ == "__main__":
    profile_policy = StrictBindingPolicy(allowed_fields=frozenset({"display_name", "bio"}))
    clean = bind_payload({"display_name": "Alice", "bio": "Engineer"}, profile_policy)
    assert clean == {"display_name": "Alice", "bio": "Engineer"}

    for attack in (
        {"display_name": "Alice", "is_admin": True},
        {"display_name": "Alice", "role": "admin"},
        {"display_name": "Alice", "tenant_id": "other_org"},
        {"display_name": {"nested": "override"}},
        {"display_name": "Alice", "extra_field": 123},
    ):
        try:
            bind_payload(attack, profile_policy)
            raise AssertionError(f"should block mass assignment: {attack}")
        except MassAssignmentBlocked:
            pass
    print("01-mass-assignment-defense self-check passed")
```

## 防御工作流

```text
1. 实体与 DTO 解耦：所有外部接口一律禁止直接接收 ORM Entity/Model，统一通过专用输入 DTO 进行反序列化。
2. 反序列化严格模式：开启 `FAIL_ON_UNKNOWN_PROPERTIES`（Jackson）或 Pydantic `extra="forbid"`，收到额外字段直接返回 400 并记录告警。
3. 清理框架危险配置：检查仓库并移除 Laravel `$guarded = []`、DRF `fields = "__all__"`、Rails `permit!` 及 PHP `extract()`。
4. 嵌套与 GraphQL 收敛：为不同权限角色提供独立 Mutation Input 类型，关闭嵌套属性自动创建/覆写关联外键的能力。
5. 字段级回归测试：对所有用户更新、注册、下单接口自动附加敏感字段（`role`, `is_admin`, `status`, `balance`）并确认持久化记录零篡改。
```

## 验证与判定标准

- **敏感字段注入零生效**：在注册或资料更新请求中附加 `is_admin=true`、`role=admin`、`balance=99999`、`tenant_id=other`，服务端返回 `400/422` 或持久化后字段保持默认值不变。
- **嵌套关系零篡改**：提交 `user[company_attributes][id]=1` 或 `profile.role` 等嵌套载荷被严格模式拒绝。
- **源码零危险原语**：代码静态扫描无 `extract($_...)`、`permit!`、`fields = "__all__"` 与 `$guarded = []`。

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 额外字段与注入边界验证 | `http_probe` | 验证接口向更新/注册端点提交多余敏感字段返回 `400/422` |
| 关联权限与参数防线 | `kb_router` | 检索 BAC 与参数篡改防御条目 |
| 配对攻击细节对照 | `kb_read_file` | 对照读取 `ctf-website/15-mass-assignment/01-mass-assignment` 核查框架覆盖面 |
| 知识库模块总览 | `kb_catalog` | 列出框架绑定与访问控制防御文档 |
