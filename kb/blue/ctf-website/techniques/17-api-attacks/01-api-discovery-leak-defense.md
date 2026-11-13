---
id: "ctf-website/17-api-attacks/01-api-discovery-leak-defense"
title: "API 发现与信息泄露防御 — 生产文档收敛、GraphQL 内省禁用、Source Map 隔离与版本治理"
title_en: "API Discovery & Information Disclosure Defense — Spec Gating, GraphQL Introspection Hardening, Source Map Isolation & Version Governance"
summary: >
  针对 Swagger/OpenAPI 文档暴露、GraphQL Introspection 与错误字段猜测、JS Source Map 反解、APK 硬编码端点提取、
  Postman 集合泄露、WSDL/XXE 及 API 多版本漂移问题，提供生产构建剥离、网关默认拒绝、GraphQL 字段建议抑制与统一鉴权加固方案，并附可运行自检代码。
summary_en: >
  Blue-team hardening against Swagger/OpenAPI exposure, GraphQL introspection and error-based field discovery,
  JS Source Map leaks, mobile APK endpoint extraction, Postman collection exposure, WSDL XXE, and API version drift.
  Includes gateway rules, GraphQL suggestion suppression, build pipeline stripping, and runnable verification tests.
board: "ctf-website"
category: "17-api-attacks"
signals: ["OpenAPI exposure", "GraphQL introspection", "Source Map leak", "WSDL XXE", "API version drift", "actuator exposure", "default-deny gateway"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "kb_catalog"]
keywords: ["API防御", "禁用Swagger", "GraphQL内省禁用", "Source Map隔离", "API版本治理", "网关鉴权", "Postman防泄露", "WSDL安全"]
difficulty: "advanced"
tags: ["defense", "blue-team", "hardening", "api", "graphql", "source-map", "openapi"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/17-api-attacks/01-api-discovery-leak", "ctf-website/17-api-attacks/02-api-key-leak-defense"]
track: "blue"
defends: "ctf-website/17-api-attacks/01-api-discovery-leak"
---

# API 发现与信息泄露防御 — 生产文档收敛、GraphQL 内省禁用、Source Map 隔离与版本治理

## 威胁模型与防御目标

前后端分离与微服务架构下，暴露的契约文件与构建产物往往成为攻击者绘制攻击面的第一手地图。对照 [01-api-discovery-leak.md](../../../../red/ctf-website/techniques/17-api-attacks/01-api-discovery-leak.md)，蓝队的核心原则是：**永远不把“接口未公开”当作安全边界（Security through Obscurity），同时切断外部对内部结构、调试符号与旧版本路由的非必要测绘通道**：

| 信息泄露面 | 攻击利用方式 | 防御控制 |
|---|---|---|
| Swagger / OpenAPI / Redoc / WSDL | 枚举管理端点、未鉴权路径、参数结构及 WSDL 外部 Schema XXE | 生产环境关闭文档路由或置于 VPN/mTLS 内网；禁止 SOAP/XML 解析器加载外部 DTD/Schema |
| GraphQL Introspection 与报错提示 | `__schema`/`__type` 导出全量图谱，或借助 `Did you mean ...` 猜出隐藏字段 | 生产禁用内省与字段拼写建议；强制查询深度/复杂度限制与每个字段/Resolver 独立鉴权 |
| JS Source Map（`.js.map`）与 SSR 初始状态 | 从生产 JS 反解未发布路由、内部函数名、管理端点及调试开关 | 构建使用 `hidden-source-map` 并仅上传至私有错误平台；边缘拦截 `.map` 并清除 `sourceMappingURL` 注释 |
| APK / 客户端 BFF 与 Postman 集合 | 从移动包字符串/Retrofit 注解或公开 Postman 工作区获取内部网关与历史接口 | 移动端只连独立公网 BFF，剥离内网域名与调试路由；Postman 环境变量禁止存真实主机与凭据 |
| `/actuator`、`/debug`、`.env`、`.git`、`robots.txt` | 直接拉取环境变量、路由表或通过 `Disallow` 列表定位后台入口 | 管控端口绑定 `127.0.0.1`/内网；边缘规则显式拦截敏感文件前缀；不将内部后台路径写入 `robots.txt` |
| API 版本漂移（`/v1` vs `/v2`） | 旧版本未同步新版鉴权、对象归属检查或批量赋值白名单 | API 网关实施默认拒绝（Default-Deny）；通过契约网关下线过期 `/v1` 路径并共享同一鉴权中间件 |

## 架构加固配置

### 1. Nginx / 边缘网关收敛配置

在边缘层统一封堵文档路径、Source Map 文件、Actuator/Debug 路由以及敏感配置文件：

```nginx
# /etc/nginx/conf.d/api_surface_hardening.conf

# 1. 生产环境禁止外部下载任何 JS/CSS Source Map
location ~* \.map$ {
    return 404;
}

# 2. 阻断常见开发文档、配置与版本控制路径
location ~* ^/(?:\.env|\.git|swagger|swagger-ui|api-docs|v[23]/api-docs|openapi\.(?:json|ya?ml)|redoc|actuator|debug) {
    # 如需内部访问，改为 allow 10.0.0.0/8; deny all;
    return 404;
}

# 3. 禁止暴露服务器技术栈与内部错误细节
server_tokens off;
proxy_intercept_errors on;
```

### 2. 前端打包与 GraphQL 生产加固

**前端构建（Vite / Webpack）**：仅生成不带引用注释的 `hidden` Source Map，并在上传至私有错误监控系统后于发布包内删除 `.map` 文件：

```javascript
// vite.config.ts (生产构建片段)
export default {
  build: {
    // 'hidden' 生成 .map 但不在 JS 末尾追加 //# sourceMappingURL=
    sourcemap: "hidden",
  },
};
```

**GraphQL 生产策略**：
1. 注册 `NoSchemaIntrospection` 校验规则，同时屏蔽 `__schema` 与 `__type` 元字段查询。
2. 关闭 `didYouMean` 字段纠错提示，将未知字段统一归一为通用校验错误 `{"errors": [{"message": "Invalid query"}]}`，阻断 Clairvoyance 类字典推断。
3. 在每个敏感 `Query` / `Mutation` Resolver 入口强制调用统一的 RBAC 与对象所有权检查，不依赖隐藏字段名提供安全性。

### 3. API 契约网关：版本收敛、默认拒绝与响应净化

下面的 Python 实现演示了一个轻量级 API 防护策略引擎，用于在网关层拦截：
- 生产环境未授权的文档/调试/Source Map/配置文件探测；
- GraphQL Introspection 元字段及错误信息中的字段猜测提示；
- 已废弃旧版本 API（如 `/v1/` 遗留高危路径）与未在活跃路由契约白名单中的接口；
- HTML/JSON 初始状态中的内部路径或调试字段泄露。

```python
import re
from dataclasses import dataclass, field


BLOCKED_SURFACE_PATTERNS = (
    re.compile(r"\.js\.map$", re.I),
    re.compile(r"^/(?:swagger(?:-ui(?:\.html)?)?|openapi\.(?:json|ya?ml)|v[23]/api-docs|api-docs|redoc)(?:/|$)", re.I),
    re.compile(r"^/(?:\.env|\.git|actuator|debug|__debug__)(?:/|$)", re.I),
    re.compile(r"\?wsdl$", re.I),
)

GRAPHQL_META_FIELD_RE = re.compile(r"\b(?:__schema|__type)\b")
FIELD_SUGGESTION_RE = re.compile(r"Did you mean [^?]+\?", re.I)


@dataclass
class APISurfaceGuard:
    """生产环境 API 攻击面收敛与契约路由守卫。"""

    environment: str = "production"
    deprecated_prefixes: tuple[str, ...] = ("/api/v1/",)
    allowed_routes: set[tuple[str, str]] = field(default_factory=set)
    allow_introspection: bool = False

    def inspect_http_request(self, method: str, full_path: str, role: str) -> tuple[int, dict]:
        path_only = full_path.split("?", 1)[0]

        # 1. 生产环境阻断文档、Source Map、Actuator 与 WSDL
        if self.environment == "production":
            for pat in BLOCKED_SURFACE_PATTERNS:
                if pat.search(full_path) or pat.search(path_only):
                    return 404, {"error": "not_found"}

        # 2. 阻止已下线旧版本路由继续绕过新版鉴权
        for dep in self.deprecated_prefixes:
            if path_only.startswith(dep):
                return 410, {"error": "api_version_retired"}

        # 3. 显式白名单：未登记的路由默认拒绝（防止幽灵/隐藏端点暴露）
        route_key = (method.upper(), path_only)
        if route_key not in self.allowed_routes:
            return 404, {"error": "not_found"}

        # 4. 写操作与管理路由强制非匿名角色
        if (method.upper() in {"POST", "PUT", "PATCH", "DELETE"} or path_only.startswith("/api/admin")) and role == "anon":
            return 401, {"error": "authentication_required"}

        return 200, {"status": "allowed"}

    def sanitize_graphql_request_and_error(self, query: str, raw_error: str | None = None) -> tuple[bool, str | None]:
        if not self.allow_introspection and GRAPHQL_META_FIELD_RE.search(query):
            return False, "Introspection is disabled in production"

        if raw_error:
            # 抹除 "Did you mean 'secretField'?" 字段枚举提示
            cleaned = FIELD_SUGGESTION_RE.sub("", raw_error).strip()
            if "Cannot query field" in cleaned:
                return True, "Invalid GraphQL query"
            return True, cleaned
        return True, None


def strip_sourcemap_comment(js_bundle: str) -> str:
    """清除 JS 打包产物末尾残留的 sourceMappingURL 注释。"""
    return re.sub(r"//[#@]\s*sourceMappingURL=.*$", "", js_bundle, flags=re.M).rstrip()
```

### 4. WSDL / SOAP 与移动端 BFF 收敛

- **XML/WSDL 解析禁止外部实体与外部 Schema**：在 `defusedxml` / `lxml` / `DocumentBuilderFactory` 中关闭 `external-general-entities`、`external-parameter-entities` 与 `load-external-dtd`，阻断通过 WSDL `schemaLocation` 发起的 XXE 与 SSRF。
- **移动端 BFF 隔离**：移动 App 仅与专属 BFF 域名通信，不在客户端代码中保留未上线的管理路由、调试开关或内部服务域名；CI 发布流自动扫描 APK strings/Retrofit 接口是否出现非公网允许域。

## 防御工作流

1. **清点与下线暴露契约**：检查线上与测试环境的所有 `.js.map`、`/swagger*`、`/openapi*`、`/api-docs`、`/?wsdl`、`/actuator`、`robots.txt` 与公开 Postman 工作区，移除生产访问入口或迁入内网鉴权。
2. **GraphQL 运行时加固**：禁用 `__schema`/`__type` 内省与字段纠错建议，叠加查询深度（如 `depth <= 6`）与别名数量限制，并核查每个 Mutation 的角色校验。
3. **版本收敛与默认拒绝**：整理 `/v1` 与 `/v2` 路由矩阵，在 API 网关关闭未注册路由的透传，统一由网关注入认证与 RBAC/对象权限上下文后下线旧版本。
4. **构建流水线门禁**：在 CI/CD 中强制开启 `sourcemap: "hidden"` 与注释剥离、校验 `X-Content-Type-Options: nosniff`，并在构建产物上传私有平台后清除发布包内 `.map` 文件。
5. **周期性自检回归**：使用下方的自检代码验证高危发现面在生产策略下均返回统一 `404`/`410`/`401` 且无 Schema 泄露。

## 验证与判定标准

运行下方自检脚本，确认 API 攻击面收敛策略对所有常见发现手段生效：

```python
def run_self_checks() -> None:
    guard = APISurfaceGuard(
        environment="production",
        deprecated_prefixes=("/api/v1/",),
        allowed_routes={
            ("GET", "/api/v2/profile"),
            ("POST", "/api/v2/orders/refund"),
            ("GET", "/api/admin/metrics"),
        },
        allow_introspection=False,
    )

    # 1. 文档、Source Map、Actuator 与 WSDL 在生产环境全部返回 404
    for path in (
        "/static/app.a1b2c3.js.map",
        "/swagger-ui.html",
        "/v3/api-docs",
        "/openapi.json",
        "/actuator/env",
        "/.env",
        "/soap?wsdl",
    ):
        code, body = guard.inspect_http_request("GET", path, role="user")
        assert code == 404 and body["error"] == "not_found", f"Leaked surface: {path}"

    # 2. 旧版本路由返回 410 Gone，杜绝版本漂移绕过
    code_v1, _ = guard.inspect_http_request("POST", "/api/v1/orders/refund", role="user")
    assert code_v1 == 410

    # 3. 未登记端点默认拒绝，管理与写端点拒绝匿名访问
    assert guard.inspect_http_request("GET", "/api/v2/internal_debug", role="user")[0] == 404
    assert guard.inspect_http_request("POST", "/api/v2/orders/refund", role="anon")[0] == 401
    assert guard.inspect_http_request("GET", "/api/admin/metrics", role="anon")[0] == 401
    assert guard.inspect_http_request("GET", "/api/v2/profile", role="user")[0] == 200

    # 4. GraphQL 内省被拦截，且错误提示中不泄露隐藏字段名
    ok, msg = guard.sanitize_graphql_request_and_error("query { __schema { types { name } } }")
    assert ok is False and "disabled" in (msg or "")

    ok2, msg2 = guard.sanitize_graphql_request_and_error(
        "query { usr { id } }",
        raw_error="Cannot query field 'usr' on type 'Query'. Did you mean 'userSecretConfig'?",
    )
    assert ok2 is True and "userSecretConfig" not in (msg2 or "") and msg2 == "Invalid GraphQL query"

    # 5. JS Bundle 中的 sourceMappingURL 注释被彻底剥离
    cleaned_js = strip_sourcemap_comment("console.log('app');\n//# sourceMappingURL=app.js.map\n")
    assert "sourceMappingURL" not in cleaned_js
    print("[PASS] All API discovery & disclosure defense checks passed.")


if __name__ == "__main__":
    run_self_checks()
```

判定通过标准：
- 所有 Swagger/OpenAPI、`.js.map`、`/actuator`、`/.env`、`/?wsdl` 探测均返回统一 `404`，不暴露框架差异；
- 废弃版本 `/api/v1/*` 统一返回 `410` 并在网关注销，无新旧版本鉴权差异；
- GraphQL 请求拒绝 `__schema` 与 `__type` 查询，错误响应中不含任何 `Did you mean ...` 候选字段提示；
- 前端发布目录无 `.map` 文件且 JS 正文不包含 `sourceMappingURL` 指令。

## MCP 工具映射

| 防御阶段 | MCP 工具 | 用途说明 |
|---|---|---|
| 文档与 Map 暴露探测 | `http_probe` | 核查生产域名是否仍对 `.js.map`、`/openapi.json`、`/swagger-ui.html`、`/graphql` 返回 `200` |
| 关联防御知识检索 | `kb_router` | 按 `API discovery defense`、`GraphQL hardening`、`Source Map` 检索指南 |
| 读取技术细节 | `kb_read_file` | 结合攻击文档 [01-api-discovery-leak.md](../../../../red/ctf-website/techniques/17-api-attacks/01-api-discovery-leak.md) 逐项核对暴露面 |
| 知识目录定位 | `kb_catalog` | 浏览 `17-api-attacks` 下全部防御与攻击文档 |
