---
id: "ctf-website/09-cve/05-litellm-privesc-defense"
title: "LiteLLM 权限提升防御：RBAC 路由边界与 API Key 授权隔离（CVE-2026-47101）"
title_en: "LiteLLM Privilege Escalation Defense: RBAC Route Boundary & API Key Authorization Isolation (CVE-2026-47101)"
summary: >
  针对 CVE-2026-47101（LiteLLM < 1.83.14 因 /key/generate 未校对 allowed_routes 与请求者角色边界、路由授权回退至 key allowed_routes、且 /user/update 允许自修改 user_role 导致的自提权漏洞）的蓝队防御与加固方案。覆盖升级基线（1.83.14+）、RBAC 与 API Key 授权解耦、管理路由反向代理隔离、以及 Python 授权策略矩阵自检脚本。
summary_en: >
  Blue-team defense guide for CVE-2026-47101 (LiteLLM < 1.83.14 self-privilege escalation via unvalidated allowed_routes in /key/generate, route authorization fallback, and self user_role update in /user/update). Covers upgrade baseline (1.83.14+), RBAC and API-key scope decoupling, reverse-proxy admin route isolation, and a Python authorization matrix check script.
board: "ctf-website"
category: "09-cve"
signals: ["CVE-2026-47101", "LiteLLM defense", "allowed_routes bypass", "RBAC enforcement", "proxy_admin isolation", "API key scope hardening"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog", "http_probe"]
keywords: ["CVE-2026-47101防御", "LiteLLM加固", "allowed_routes校验", "proxy_admin隔离", "LLM网关安全", "RBAC防提权", "自修改角色拦截"]
difficulty: "intermediate"
tags: ["defense", "blue-team", "cve", "privilege-escalation", "api-security", "rbac"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/09-cve/05-litellm-privesc"]
track: "blue"
defends: "ctf-website/09-cve/05-litellm-privesc"
---
# LiteLLM 权限提升防御：RBAC 路由边界与 API Key 授权隔离（CVE-2026-47101）

## 1. 威胁模型与三层授权失效根因

CVE-2026-47101 影响 LiteLLM `< 1.83.14`，使低权限 `internal_user` 可在无需管理员凭据的情况下自我提权至 `proxy_admin`：
1. **第一层缺失（权限授予越界）**：`POST /key/generate` 未校验申请者提交的 `allowed_routes`（如 `["/*"]`）是否落在其自身角色允许集合内。
2. **第二层缺失（鉴权回退倒置）**：管理路由在角色校验失败时错误回退到 API Key 的 `allowed_routes` 匹配逻辑，导致通配符 Key 绕过角色守卫。
3. **第三层缺失（自修改角色）**：`POST /user/update` 允许非管理员携带该 Key 修改自身 `user_role` 为 `proxy_admin`，从而接管 `/user/list`、模型路由、预算及上游 LLM 凭据。

## 2. 分层防御与网关加固措施

| 防线层级 | 控制措施 | 针对缺陷层 | 落地标准 |
|---|---|---|---|
| 官方升级 | 升级 LiteLLM Proxy 至 `>= 1.83.14` | 全部三层 | 固定镜像 tag 与 `requirements.txt` 下限版本 |
| 角色与 Key 范围严格交集 | Key 实际可用路由 = `role_allowed_routes ∩ key.allowed_routes`，禁止通配符扩大权限 | 第一、二层 | `internal_user` 仅允许推理类端点（`/v1/chat/completions` 等） |
| 不可自变更高权字段 | `/user/update` 仅允许 `proxy_admin` 修改 `user_role`、预算与组织归属 | 第三层 | 显式白名单限制普通用户可更新字段 |
| 管理面与推理面网关分离 | Nginx / Envoy 在代理层隔离 `/key/generate`、`/user/*`、`/team/*` 等管理路由 | 暴露面收敛 | 管理 API 仅限内网管理 VPN + 独立 Admin Ingress 访问 |
| 密钥与用户基线清理 | 核查现有 Key 表与 `user_role` 变更日志，吊销含 `/*` 的非管理员 Key | 事后排查 | 检查数据库 `LiteLLM_VerificationToken` 与 `LiteLLM_UserTable` |

### 反向代理管理面隔离配置（Nginx）

```nginx
# 推理数据面：仅开放标准 OpenAI 兼容推理接口给业务应用
location ~ ^/v1/(chat/completions|completions|embeddings|models)$ {
    proxy_pass http://litellm_backend;
}

# 管理控制面：禁止普通业务出口访问，仅允许运维内网网段
location ~ ^/(user|key|team|organization|config|health)/ {
    allow 10.20.0.0/16;
    deny all;
    proxy_pass http://litellm_backend;
}
```

### LiteLLM Proxy 配置加固要点

- 使用强随机 `LITELLM_MASTER_KEY` 注入环境变量，禁止使用默认演示密钥或写入仓库。
- 在 `general_settings` 中关闭普通用户自助签发高权 Key 能力，并定期轮换 `LITELLM_SALT_KEY`。
- 将数据库中的管理变更事件接入 SIEM，重点监控 `user_role` 从 `internal_user` 变为 `proxy_admin` 以及 `allowed_routes` 包含 `*` 的记录。

## 防御工作流

1. **版本与配置盘点**：核查运行中 LiteLLM 版本是否 `< 1.83.14`，以及 `/key/generate`、`/user/update` 是否暴露在业务公网域名下。
2. **现网存量 Key 与角色排查**：查询数据库是否存在非 `proxy_admin` 用户持有的通配符 `allowed_routes`（如 `/*`、`*`）及异常新增的 `proxy_admin` 账号，立即吊销并轮换相关密钥。
3. **版本升级与网关隔离**：升级容器镜像至 `>= 1.83.14`，并在反向代理或 API 网关将推理路由与管理路由拆分为独立策略域。
4. **策略回归检验**：运行授权边界校验脚本验证低权限用户无法申请管理路由通配符 Key，且无法调用 `/user/update` 变更角色。

## 3. Python RBAC 路由交集与自提权拦截验证脚本

```python
#!/usr/bin/env python3
"""CVE-2026-47101 LiteLLM RBAC 路由边界与 Key 授权交集校验工具。"""

from dataclasses import dataclass
import fnmatch

ROLE_MAX_ROUTES: dict[str, tuple[str, ...]] = {
    "internal_user": ("/v1/chat/completions", "/v1/completions", "/v1/embeddings", "/v1/models"),
    "internal_user_viewer": ("/v1/models", "/key/info"),
    "proxy_admin": ("/*",),
}
ADMIN_ONLY_ROUTES = ("/user/update", "/user/new", "/user/list", "/key/generate", "/config/*")


@dataclass
class KeyRequest:
    actor_role: str
    requested_routes: list[str]


def authorize_key_generation(req: KeyRequest) -> tuple[bool, str]:
    allowed_for_role = ROLE_MAX_ROUTES.get(req.actor_role, ())
    if req.actor_role != "proxy_admin":
        for route in req.requested_routes:
            if "*" in route or any(fnmatch.fnmatch(route, admin_r) for admin_r in ADMIN_ONLY_ROUTES):
                return False, f"denied: role {req.actor_role} cannot request {route}"
            if not any(fnmatch.fnmatch(route, pat) for pat in allowed_for_role):
                return False, f"denied: {route} outside role boundary"
    return True, "authorized"


def authorize_route_access(actor_role: str, key_routes: list[str], target_route: str) -> bool:
    """严禁回退到 key_routes 覆盖角色限制：必须同时满足角色与 Key 双重交集。"""
    role_patterns = ROLE_MAX_ROUTES.get(actor_role, ())
    role_ok = any(fnmatch.fnmatch(target_route, pat) for pat in role_patterns)
    key_ok = any(fnmatch.fnmatch(target_route, pat) for pat in key_routes)
    return role_ok and key_ok


def authorize_role_change(actor_role: str, target_role: str) -> bool:
    return actor_role == "proxy_admin" and target_role in ROLE_MAX_ROUTES


if __name__ == "__main__":
    ok_gen, msg_gen = authorize_key_generation(KeyRequest("internal_user", ["/*"]))
    print("wildcard key gen:", ok_gen, msg_gen)
    assert not ok_gen

    # 即使历史遗留了通配符 key，交集检查仍阻止 internal_user 访问管理路由
    assert not authorize_route_access("internal_user", ["/*"], "/user/update")
    assert authorize_route_access("internal_user", ["/v1/chat/completions"], "/v1/chat/completions")
    assert not authorize_role_change("internal_user", "proxy_admin")
    assert authorize_role_change("proxy_admin", "internal_user")
```

## 验证与判定标准

| 检查项 | 判定为已加固（PASS） | 判定为存在风险（FAIL） | 验证方式 |
|---|---|---|---|
| LiteLLM 版本 | `>= 1.83.14` | `< 1.83.14` | 镜像 tag / `pip show litellm` |
| `/key/generate` 越权申请 | `internal_user` 提交 `allowed_routes: ["/*"]` 返回 `403` | 成功签发通配符 Key | 隔离环境使用低权账号发合规负向请求 |
| `/user/update` 自改角色 | 非 `proxy_admin` 请求变更 `user_role` 返回 `403` | 角色被修改为 `proxy_admin` 且 `/user/list` 返回用户列表 | 回归测试与数据库表检查 |
| 管理接口暴露面 | `/user/*`、`/key/*` 仅内网管理口可达，推理网关拦截 | 业务公网域名可直接访问 `/user/update` | `http_probe` 检查管理路由返回 `403` |

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索 LLM 网关防御指南 | `kb_router` | 按 `CVE-2026-47101` / `LiteLLM` / `RBAC` 搜索 |
| 对照提权调用链 | `kb_read_file` | 读取 `ctf-website/09-cve/05-litellm-privesc` 核对接口链路 |
| 管理路由可达性检查 | `http_probe` | 确认公网推理域名对 `/user/list`、`/key/generate` 返回拒绝状态 |
