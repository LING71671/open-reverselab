---
id: "ctf-website/14-idor/02-bac-business-logic-defense"
title: "功能级访问控制 (BAC) 防御 — 默认拒绝、防方法覆写与流程状态锁"
title_en: "Broken Access Control (BAC) Defense — Default-Deny RBAC, Anti-Method-Override & Workflow State Locking"
summary: >
  针对管理端点暴露、HTTP 方法覆写（X-HTTP-Method-Override）、API 版本鉴权漂移（/v1 vs /v2）、
  多步业务跳步及 Spring Boot Actuator 信息泄露，建立默认拒绝（Default-Deny）集中式鉴权中间件、多步签名状态令牌与运营端口隔离方案。
summary_en: >
  Hardens applications against broken function-level access control (BAC) including exposed admin/Actuator
  endpoints, HTTP method override bypass, API version authorization drift, and multi-step workflow skipping
  using default-deny RBAC middleware, signed workflow state tokens, and management-plane isolation.
board: "ctf-website"
category: "14-idor"
signals: ["BAC防御", "默认拒绝", "RBAC矩阵", "防方法覆写", "Actuator加固", "多步流程锁", "CWE-862"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "kb_catalog"]
keywords: ["BAC defense", "default deny access control", "method override bypass defense", "Spring Actuator hardening", "workflow state token", "CWE-862"]
difficulty: "advanced"
tags: ["defense", "blue-team", "hardening", "bac", "access-control", "rbac", "spring-boot"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/14-idor/02-bac-business-logic", "ctf-website/14-idor/01-idor-enumeration-defense", "ctf-website/17-api-attacks/01-api-discovery-leak-defense"]
track: "blue"
defends: "ctf-website/14-idor/02-bac-business-logic"
---
# 功能级访问控制 (BAC) 防御 — 默认拒绝、防方法覆写与流程状态锁

> 配对攻击手册：[02-bac-business-logic.md](./02-bac-business-logic.md)。功能级访问控制缺失（OWASP API5）往往发生在“网关放行了某个新版本路由或管理端点，而后端控制器默认假设到达这里的都是管理员”。必须坚持 **Default-Deny（未显式声明允许即拒绝）**。

## 威胁模型与控制映射

| 攻击向量 | 典型缺陷 | 防御控制措施 |
|---|---|---|
| 隐藏管理端点与 Source Map 泄露 | `/admin/export` 未挂鉴权中间件，仅靠前端隐藏按钮或 `robots.txt` | **全局 Default-Deny 鉴权守卫**：所有路由必须显式标注 `@RequiresRole` 或 `@PublicEndpoint`，构建产物禁用生产 `.map` |
| HTTP 方法覆写绕过 | 网关仅拦截 `DELETE /users`，后端框架解析 `X-HTTP-Method-Override: DELETE` 后放行 | 在反向代理层剥离 `X-HTTP-Method-Override`/`X-Method-Override`/`_method` 头；鉴权判断放在路由分发**之后**的最终处理器上 |
| API 版本鉴权漂移 (`/api/v1` vs `/api/v2`) | `/v2` 加了新权限校验，遗留 `/v1` 或 `/internal` 仍保持旧无鉴权逻辑 | 下线废弃 API 版本；所有版本共享同一套集中式权限策略引擎与集成回归测试矩阵 |
| 多步流程跳步（Step Skipping） | Step 3 仅检查入参存在性，未检查前序步骤（如实名/风控/支付）已在服务端完成 | 服务端持久化工作流状态机（或 HMAC 签名不可伪造阶段令牌），每一步先验证 `current_step == expected_prev_step` |
| Spring Boot Actuator 暴露 | 公网暴露 `/actuator/env`、`/actuator/heapdump`、`/actuator/mappings` | `management.endpoints.web.exposure.include=health`；管理端口 `management.server.port` 绑定内网回环并加独立身份认证 |

## 核心加固实现

### 1. 默认拒绝（Default-Deny）路由策略与防方法覆写过滤

```python
# bac_default_deny_guard.py — 默认拒绝 RBAC 路由守卫与方法覆写清洗
from dataclasses import dataclass

OVERRIDE_HEADERS = {
    "x-http-method-override",
    "x-method-override",
    "x-http-method",
}

@dataclass(frozen=True)
class RoutePolicy:
    method: str
    path: str
    allowed_roles: frozenset[str]  # 空集合表示公开端点（需显式注册）
    is_public: bool = False

class DefaultDenyRouter:
    def __init__(self, policies: list[RoutePolicy]):
        self.policies = {(p.method.upper(), p.path): p for p in policies}

    def authorize_request(self, method: str, path: str, headers: dict[str, str], user_roles: set[str]) -> bool:
        # 1. 拒绝携带方法覆写头（防止代理与后端视图不一致）
        lowered = {k.lower() for k in headers}
        if lowered & OVERRIDE_HEADERS:
            raise PermissionError("method override headers are forbidden")

        # 2. 规范化路径后查策略表，未显式登记一律默认拒绝
        norm_path = "/" + "/".join(seg for seg in path.split("/") if seg)
        policy = self.policies.get((method.upper(), norm_path))
        if policy is None:
            raise PermissionError(f"default-deny: unregistered route {method} {norm_path}")

        if policy.is_public:
            return True
        if not (user_roles & policy.allowed_roles):
            raise PermissionError(f"role denied for {method} {norm_path}")
        return True
```

### 2. 多步业务防跳步状态机与 Spring Actuator 安全配置

```yaml
# application-prod.yml — Spring Boot Actuator 最小暴露与隔离配置
management:
  server:
    address: 127.0.0.1
    port: 8081
  endpoints:
    enabled-by-default: false
    web:
      exposure:
        include: health
  endpoint:
    health:
      enabled: true
      show-details: never
```

```python
# workflow_step_lock.py — 多步业务防跳步状态机自检
WORKFLOW_ORDER = ["INIT", "IDENTITY_VERIFIED", "PAYMENT_CONFIRMED", "PROVISIONED"]

class WorkflowEngine:
    def __init__(self):
        self.sessions: dict[str, str] = {}

    def start(self, flow_id: str) -> None:
        self.sessions[flow_id] = "INIT"

    def advance(self, flow_id: str, required_current: str, next_state: str) -> str:
        cur = self.sessions.get(flow_id)
        if cur != required_current:
            raise PermissionError(f"step skip blocked: expected {required_current}, actual {cur}")
        if WORKFLOW_ORDER.index(next_state) != WORKFLOW_ORDER.index(cur) + 1:
            raise PermissionError("non-sequential transition blocked")
        self.sessions[flow_id] = next_state
        return next_state

if __name__ == "__main__":
    router = DefaultDenyRouter([
        RoutePolicy("GET", "/api/v2/health", frozenset(), is_public=True),
        RoutePolicy("DELETE", "/api/v2/users", frozenset({"admin"})),
    ])
    assert router.authorize_request("GET", "/api/v2/health", {}, set()) is True
    for bad_call in (
        ("DELETE", "/api/v2/users", {}, {"member"}),
        ("POST", "/api/v2/users", {"X-HTTP-Method-Override": "DELETE"}, {"admin"}),
        ("GET", "/api/v1/users", {}, {"admin"}),  # 未注册遗留版本默认拒绝
        ("GET", "/actuator/heapdump", {}, {"admin"}),
    ):
        try:
            router.authorize_request(*bad_call)
            raise AssertionError(f"should deny {bad_call}")
        except PermissionError:
            pass

    wf = WorkflowEngine()
    wf.start("f1")
    try:
        wf.advance("f1", "PAYMENT_CONFIRMED", "PROVISIONED")
        raise AssertionError("should block step skipping")
    except PermissionError:
        pass
    print("02-bac-business-logic-defense self-check passed")
```

## 防御工作流

```text
1. 启用 Default-Deny 中间件：除明确标记 `@Public` 的登录/健康检查外，所有端点与 API 版本强制要求角色声明，未声明路由启动失败或默认返回 403。
2. 消除解析差异：在 Ingress/Nginx 层丢弃 `X-HTTP-Method-Override`、`_method` 与尾部斜杠/大小写混淆路径，统一鉴权与路由解析视图。
3. 多步状态强绑定：将流程进度保存在服务端数据库或 Redis，每步接口只推进相邻下一状态，严禁前端通过 `step=3` 或隐藏表单跳转。
4. 运行时管理面隔离：将 Actuator、Swagger、Metrics 与调试控制台绑定内网管理端口并由零信任网关保护，外网仅暴露 `/health`。
5. 角色矩阵自动化回归：CI 阶段自动遍历全量路由表对“匿名/普通用户/客服/管理员”四类身份执行权限矩阵验证。
```

## 验证与判定标准

- **角色矩阵零越权**：普通用户与匿名身份请求管理路由、旧版 `/v1/` 接口及方法覆写变体，100% 返回 `401/403`。
- **多步流程零跳步**：直接调用最终开通/领奖接口而不经过前序校验步骤，返回 `409/403` 且业务状态无变更。
- **管理端点零公网泄露**：公网探测 `/actuator/env`、`/actuator/heapdump`、`/actuator/mappings` 及 `*.js.map` 全部返回 `404/403`。

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 角色矩阵与方法覆写回归 | `http_probe` | 验证各类低权限身份与覆写头部对敏感端点的拒绝码 |
| API 暴露与 IDOR 关联 | `kb_router` | 检索 API 发现暴露面收口与对象级授权防御文档 |
| 配对攻击细节对照 | `kb_read_file` | 对照读取 `ctf-website/14-idor/02-bac-business-logic` 复核全部 BAC 向量 |
| 知识库防御索引 | `kb_catalog` | 浏览访问控制与业务逻辑安全防御条目 |
