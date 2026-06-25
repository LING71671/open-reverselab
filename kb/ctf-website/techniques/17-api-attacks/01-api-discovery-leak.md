# API 发现与信息泄露 — Swagger、GraphQL、Source Map 与移动端提取

## 场景

现代 Web 应用的前后端分离架构导致 API 端点大量暴露。攻击者通过 Swagger/OpenAPI 文档、GraphQL Introspection、JS Source Map 反解、APK 逆向等手段发现未文档化、过时版本或内部使用的 API 端点。每个新端点都是一个潜在的攻击面。

## 输入信号

- 页面 HTML 中包含 `window.__INITIAL_STATE__` 或 `window.__DATA__` 等包含 API 路径的 JS 变量
- JS Source Map 文件存在（`.js.map` 后缀）
- 浏览器 DevTools Network 标签中可见大量 API 调用
- API 返回 JSON 格式数据，但无文档说明
- Swagger UI 页面存在（`/swagger-ui.html`、`/swagger/index.html`）
- GraphQL 端点返回 Introspection 查询结果
- `/api-docs`、`/openapi.json`、`/v2/api-docs`、`/v3/api-docs` 等路径返回 200
- 移动应用 APK 中包含硬编码的 API 端点
- Postman/Insomnia 集合在公开仓库中泄露

## 核心方法论

### 1. Swagger / OpenAPI 文档枚举

```python
# swagger_enum.py — Swagger/OpenAPI 文档发现与利用

SWAGGER_PATHS = [
    # Swagger UI
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger/index.html",
    "/swagger-ui/", "/swagger-resources",
    "/swagger-resources/configuration/ui",
    "/swagger-resources/configuration/security",

    # OpenAPI JSON/YAML
    "/swagger.json", "/swagger.yaml", "/swagger.yml",
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/api/swagger.json", "/api/openapi.json",

    # Springfox / Springdoc
    "/v2/api-docs",
    "/v3/api-docs",
    "/v3/api-docs/swagger-config",
    "/api-docs",

    # .NET Swashbuckle
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",

    # Redoc / Scalar
    "/redoc", "/docs",

    # DRF (Django REST Framework)
    "/api/docs/",
    "/api/schema/",
    "/api/schema/swagger-ui/",

    # FastAPI
    "/docs", "/redoc", "/openapi.json",

    # Common alternative paths
    "/.well-known/openapi.json",
    "/api/.well-known/openapi.json",
    "/documentation",
    "/api/documentation",
]

def discover_api_docs(base_url: str) -> dict:
    """API 文档发现"""
    docs_found = {}
    s = requests.Session()
    for path in SWAGGER_PATHS:
        url = f"{base_url.rstrip('/')}{path}"
        try:
            r = s.get(url, timeout=10, allow_redirects=False)
            if r.status_code == 200:
                content_type = r.headers.get("content-type", "")
                size = len(r.text)
                docs_found[path] = {
                    "status": 200,
                    "type": "json" if "json" in content_type else "html",
                    "size": size,
                    "snippet": r.text[:300],
                }
        except:
            continue
    return docs_found

def parse_swagger_to_endpoints(swagger_json: dict) -> list:
    """从 Swagger JSON 中提取所有端点和参数"""
    endpoints = []
    paths = swagger_json.get("paths", {})
    for path, methods in paths.items():
        for method, details in methods.items():
            endpoint = {
                "path": path,
                "method": method.upper(),
                "summary": details.get("summary", ""),
                "parameters": [],
                "security": details.get("security", []),
            }
            # 提取参数
            for param in details.get("parameters", []):
                endpoint["parameters"].append({
                    "name": param.get("name"),
                    "in": param.get("in"),       # query, path, header, body
                    "required": param.get("required", False),
                    "type": param.get("schema", {}).get("type", "string"),
                })
            endpoints.append(endpoint)
    return endpoints
```

### 2. GraphQL Introspection 深挖

#### 2.1 内省查询

```python
# graphql_introspection.py — GraphQL 内省查询

GRAPHQL_INTROSPECTION_QUERIES = {
    # 完整 schema 内省
    "full_introspection": """
    query FullIntrospection {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              name
              type { kind name ofType { kind name } }
            }
            type { kind name ofType { kind name } }
          }
        }
        directives { name description locations }
      }
    }
    """,

    # 仅查询类型
    "queries_only": """
    query {
      __schema {
        queryType { fields { name description } }
      }
    }
    """,

    # 仅 mutation 类型 (最有用: 发现写操作)
    "mutations_only": """
    query {
      __schema {
        mutationType { fields { name description } }
      }
    }
    """,

    # 通过 introspection 绕过限制 (如果 disabling introspection 不彻底)
    # 使用 __type 元字段:
    "type_by_type": """
    query {
      __type(name: "Query") {
        fields { name description }
      }
    }
    """,
}

# 配合 clairvoyance 工具: 即使 introspection 关闭也能暴力推断 endpoint
# npx clairvoyance -e https://target.com/graphql -o schema.json

def test_graphql_introspection(base_url, endpoint="/graphql"):
    """测试 GraphQL introspection 是否开启"""
    url = f"{base_url.rstrip('/')}{endpoint}"
    s = requests.Session()

    results = {}
    for name, query in GRAPHQL_INTROSPECTION_QUERIES.items():
        r = s.post(url, json={"query": query}, timeout=10)
        try:
            data = r.json()
            introspection_open = "data" in data and data["data"] is not None
            if introspection_open:
                results[name] = {
                    "open": True,
                    "types_count": len(data.get("data", {}).get("__schema", {}).get("types", [])),
                }
        except:
            results[name] = {"open": False}
    return results
```

#### 2.2 Error-based Field Discovery

即使 introspection 关闭，GraphQL 的 error 消息通常包含有用信息：

```python
# graphql_error_discovery.py — 基于错误的 GraphQL 字段发现

def graphql_error_field_discovery(base_url, endpoint="/graphql"):
    """
    利用 GraphQL error 消息发现字段名
    原理: 即使 introspection 关闭, 查询不存在的字段返回错误:
    "Cannot query field 'xxx' on type 'Query'
    "
    → 可以用"这字段不存在"的反面来推断"这字段存在"
    """
    s = requests.Session()
    url = f"{base_url}{endpoint}"

    # 常见字段名字典
    common_fields = [
        "user", "users", "order", "orders", "product", "products",
        "account", "accounts", "profile", "profiles", "payment", "payments",
        "transaction", "transactions", "invoice", "invoices", "admin", "admins",
        "config", "configuration", "settings", "secret", "flag",
        "me", "self", "viewer", "node", "query",
        "login", "register", "logout", "refresh",
    ]

    found = []
    for field in common_fields:
        # 测试简单查询: { field } 或 { field { id } }
        for query in [
            f"query {{ {field} {{ id }} }}",
            f"query {{ {field}(id: 1) {{ id }} }}",
            f"query {{ {field}(first: 1) {{ edges {{ node {{ id }} }} }} }}",
        ]:
            r = s.post(url, json={"query": query})
            if r.status_code == 200:
                data = r.json()
                # 如果有 data 且不是 null → field 存在
                if data.get("data") and data["data"].get(field) is not None:
                    found.append(field)
                    break
                # 如果错误消息包含 "Field 'xxx' is not defined"
                # → 排除, 继续
    return found
```

### 3. JavaScript Source Map 反解

```python
# sourcemap_extract.py — JS Source Map 反解

import re, requests, json, base64, zlib
from urllib.parse import urljoin

class SourceMapExtractor:
    """
    JS Source Map 提取 API 端点
    
    原理: 生产环境 JS bundle 附带 source map
    .js.map 文件包含原始源码的映射
    从中可以提取:
    - API 端点路径
    - 内部函数名
    - 管理/隐藏路由
    - API key 和 secret (粗心放置)
    - 注释中的隐藏功能
    """

    def __init__(self, base_url):
        self.base = base_url.rstrip('/')
        self.s = requests.Session()

    def find_js_bundles(self, html: str = None) -> list:
        """在页面 HTML 中查找 JS bundle URL"""
        if not html:
            r = self.s.get(self.base)
            html = r.text

        # 查找 <script src="...">
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html)
        # 查找 webpack runtime
        webpack = re.findall(r'/[a-f0-9]{20}\.js', html)
        return scripts + webpack

    def find_source_maps(self, js_urls: list) -> dict:
        """对每个 JS 文件查找 .map 文件"""
        maps = {}
        for js_url in js_urls:
            full_url = urljoin(self.base, js_url)
            r = self.s.get(full_url)
            if r.status_code != 200:
                continue

            # 方法 1: 在 JS 末尾查找 sourceMappingURL
            mapping = re.findall(r'sourceMappingURL=([^\s]+)', r.text)
            if mapping:
                map_url = mapping[-1]
                if map_url.startswith("data:"):
                    # inline source map
                    try:
                        _, encoded = map_url.split(",", 1)
                        decoded = base64.b64decode(encoded)
                        maps[js_url] = json.loads(zlib.decompress(decoded))
                    except:
                        pass
                else:
                    map_full = urljoin(full_url, map_url)
                    r2 = self.s.get(map_full)
                    if r2.status_code == 200:
                        maps[js_url] = r2.json()

            # 方法 2: 直接尝试 js_url + ".map"
            if js_url not in maps:
                map_url = js_url + ".map"
                map_full = urljoin(self.base, map_url)
                r2 = self.s.get(map_full)
                if r2.status_code == 200:
                    maps[js_url] = r2.json()

        return maps

    def extract_endpoints_from_map(self, source_map: dict) -> dict:
        """
        从 source map 的 sources 和 sourcesContent 提取 API 端点
        """
        endpoints = {
            "paths": set(),
            "functions": set(),
            "api_keys": set(),
            "interesting": [],
        }

        sources = source_map.get("sources", [])
        contents = source_map.get("sourcesContent", [])

        # 从 source 文件名
        for src in sources:
            # 提取路径
            paths = re.findall(r'(?:/api|/admin|/v[12]/|/internal)(?:/[a-zA-Z0-9_.-]+)+', src)
            for p in paths:
                endpoints["paths"].add(p)

        # 从 source 内容
        for content in contents:
            if not content:
                continue
            # API 端点字符串
            paths = re.findall(r"['\"`]((?:/api|/admin|/internal|/private|/manage|/debug)(?:/[a-zA-Z0-9_.-]+)+)['\"`]", content)
            for p in paths:
                endpoints["paths"].add(p)
            # fetch/axios 调用
            urls = re.findall(r"(?:fetch|axios|ajax|get|post|put|delete)\s*\(\s*['\"`]([^'\"`]+)['\"`]", content, re.IGNORECASE)
            for u in urls:
                if u.startswith('/') or 'api' in u.lower():
                    endpoints["paths"].add(u)
            # 函数名
            funcs = re.findall(r'(?:function|const|let|var)\s+(\w+)\s*[=(]', content)
            for f in funcs:
                if any(kw in f.lower() for kw in ['admin', 'secret', 'internal', 'hidden', 'debug']):
                    endpoints["functions"].add(f)
            # 硬编码密钥
            keys = re.findall(r'(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"`]([A-Za-z0-9_\-=]{16,})['\"`]', content, re.IGNORECASE)
            for k in keys:
                endpoints["api_keys"].add(k)

        return {k: list(v) for k, v in endpoints.items()}

    def run(self) -> dict:
        """完整流程: 获取页面→找 JS→找 source map→提取端点"""
        r = self.s.get(self.base)
        html = r.text

        js_bundles = self.find_js_bundles(html)
        print(f"Found {len(js_bundles)} JS bundles")

        source_maps = self.find_source_maps(js_bundles)
        print(f"Found {len(source_maps)} source maps")

        all_endpoints = {"paths": set(), "functions": set(), "api_keys": set()}
        for js_url, sm in source_maps.items():
            extracted = self.extract_endpoints_from_map(sm)
            all_endpoints["paths"].update(extracted.get("paths", []))
            all_endpoints["functions"].update(extracted.get("functions", []))
            all_endpoints["api_keys"].update(extracted.get("api_keys", []))

        return {k: sorted(v) for k, v in all_endpoints.items()}
```

### 4. APK → API 端点提取

```python
# apk_api_extraction.py — 从 APK 提取 API 端点

class APKAPIExtractor:
    """
    从 Android APK 中提取 API 端点
    
    提取源:
    1. DEX 字节码中的字符串常量
    2. AndroidManifest.xml 中的 intent-filter / URL
    3. 硬编码的 API key / token
    4. OkHttp / Retrofit 接口定义
    5. WebView 中加载的 URL
    6. Firebase / FCM 配置
    """

    @staticmethod
    def extract_from_dex_strings(dex_path: str) -> list:
        """从 DEX 文件提取字符串常量"""
        # 使用 strings 命令提取所有字符串
        # strings classes.dex | grep -E 'https?://'
        pass

    @staticmethod
    def extract_from_smali(smali_dir: str) -> list:
        """
        从 smali 代码提取 API 端点
        
        常见模式:
        - const-string v0, "https://api.target.com/v2/"
        - invoke-virtual {…}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
        - 字符串拼接: new StringBuilder → "https://" + "api." + "target.com"
        """
        import os
        endpoints = []
        api_patterns = [
            r'https?://[a-zA-Z0-9./_-]+api[a-zA-Z0-9./_-]*',
            r'https?://[a-zA-Z0-9./_-]+\.com/(?:api|v[12]|rest|graphql)',
            r'https?://\d+\.\d+\.\d+\.\d+(?::\d+)?/(?:api|v[12])',
        ]

        for root, dirs, files in os.walk(smali_dir):
            for f in files:
                if not f.endswith('.smali'):
                    continue
                path = os.path.join(root, f)
                with open(path, 'r', errors='ignore') as fp:
                    content = fp.read()
                    for pattern in api_patterns:
                        matches = re.findall(pattern, content)
                        endpoints.extend(matches)

        return list(set(endpoints))

    @staticmethod
    def extract_retrofit_interfaces(smali_dir: str) -> list:
        """
        从 Retrofit 接口提取 API 端点
        Retrofit 使用 @GET/@POST/@PUT/@DELETE 注解
        在 smali 中: annotation value="api/users/{id}"
        """
        endpoints = []
        retrofit_patterns = [
            r'value="([^"]*)"',  # @GET("api/users")
            r'Lretrofit2/http/(?:GET|POST|PUT|DELETE);',
        ]
        # ... 具体实现
        return endpoints
```

### 5. Postman 集合泄露

```python
# postman_leak.py — Postman 集合泄露检测

def search_postman_collections(target_domain: str) -> list:
    """
    搜索公开 Postman 集合
    来源: postman.com, github, gitlab, 公开云存储
    """
    import requests

    results = []
    
    # 方法 1: 搜索 Postman 公开 API
    # GET https://www.postman.com/_api/workspaces?q=target.com
    
    # 方法 2: GitHub 搜索
    # search: "target.com" "postman" "collection"
    # search: "target" "apiKey" "postman"
    
    # 方法 3: Google dork
    # site:postman.com target.com api
    # site:github.com "target.com" "postman_collection"
    
    # 方法 4: 检查常见的 Postman 导出文件名
    common_names = [
        "postman_collection.json",
        "api_collection.json",
        "target.postman_collection.json",
        "postman/schema.json",
        "Postman/${env}.postman_collection.json",
        "collection.json",
        "api-tests.postman_collection.json",
    ]

    for name in common_names:
        for subdomain in ["", "api.", "dev.", "admin.", "cdn."]:
            url = f"https://{subdomain}{target_domain}/{name}"
            try:
                r = requests.get(url, timeout=10)
                if r.status_code == 200 and "info" in r.text:
                    results.append(url)
            except:
                continue

    return results
```

### 6. SOAP WSDL 发现与利用

```python
# wsdl_discovery.py — SOAP WSDL 端点发现

WSDL_PATHS = [
    "/?wsdl",
    "/wsdl",
    "/service.wsdl",
    "/services/",
    "/soap/",
    "/soap?wsdl",
    "/api/soap?wsdl",
    "/v2/soap?wsdl",
    "/endpoint.wsdl",
    "/ws/",
    "/webservice/soap",
    "/services/wsdl",
    "/*/wsdl/",
    "/.wsdl",
    "/ws/Service.svc?wsdl",
    "/Service.svc?wsdl",
    "/Service.asmx?wsdl",
    "/api/Service.asmx?wsdl",
]

def discover_wsdl(base_url):
    """发现 WSDL 端点并提取 SOAP 操作"""
    results = {}
    for path in WSDL_PATHS:
        url = f"{base_url.rstrip('/')}{path}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200 and "wsdl:definitions" in r.text[:500]:
            # 提取所有操作
            operations = re.findall(r'name="(\w+)"', r.text)
            results[path] = operations

            # 检查 XXE 潜力
            if "schema" in r.text and "import" in r.text:
                results[path].append("POSSIBLE_XXE: external schema import")
    return results
```

### 7. 自动化 API 端点收割机

```python
# api_harvester.py — 全自动 API 端点发现

import concurrent.futures, itertools

class APIHarvester:
    """多源 API 端点自动收集"""

    def __init__(self, base_url):
        self.base = base_url
        self.endpoints = set()

    def harvest_all(self) -> dict:
        """从所有来源收集 API 端点"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
            futures = {
                ex.submit(self._from_swagger): "swagger",
                ex.submit(self._from_graphql_introspection): "graphql",
                ex.submit(self._from_source_maps): "source_maps",
                ex.submit(self._from_common_paths): "common_paths",
                ex.submit(self._from_robots): "robots",
            }

            for fut in concurrent.futures.as_completed(futures):
                source_name = futures[fut]
                try:
                    result = fut.result()
                    self.endpoints.update(result)
                    print(f"[+] {source_name}: {len(result)} endpoints")
                except Exception as e:
                    print(f"[-] {source_name}: {e}")

        return {
            "total_endpoints": len(self.endpoints),
            "endpoints": sorted(self.endpoints),
        }

    def _from_swagger(self) -> set:
        eps = set()
        for path in SWAGGER_PATHS:
            r = requests.get(f"{self.base}{path}", timeout=5)
            if r.status_code == 200 and "paths" in r.text:
                try:
                    spec = r.json()
                    eps.update(spec.get("paths", {}).keys())
                except:
                    pass
        return eps

    def _from_common_paths(self) -> set:
        eps = set()
        COMMON_API_PATHS = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/rest", "/rest/v1",
            "/graphql", "/graph",
            "/.env", "/.git/config",
            "/admin", "/administrator",
        ]
        for path in COMMON_API_PATHS:
            for method in ["GET", "OPTIONS"]:
                r = requests.request(method, f"{self.base}{path}", timeout=5)
                if r.status_code not in (404,):
                    eps.add(path)
        return eps

    def _from_robots(self) -> set:
        eps = set()
        r = requests.get(f"{self.base}/robots.txt", timeout=5)
        if r.status_code == 200:
            disallows = re.findall(r'Disallow:\s*(/\S+)', r.text)
            eps.update(disallows)
        return eps

    def _from_source_maps(self) -> set:
        extractor = SourceMapExtractor(self.base)
        result = extractor.run()
        return set(result.get("paths", []))

    def _from_graphql_introspection(self) -> set:
        eps = set()
        result = test_graphql_introspection(self.base)
        if any(r.get("open") for r in result.values()):
            eps.add("/graphql")
        return eps
```

## 攻击链

```
Phase 1 — API 端点发现
  ├── Swagger/OpenAPI 文档枚举 (10+ 路径)
  ├── GraphQL introspection 测试
  ├── JS Source Map 下载和反解
  ├── robots.txt / sitemap.xml 分析
  └── 字典枚举 (dirsearch/gobuster)

Phase 2 — 端点分析
  ├── 从文档提取参数、认证方式、请求/响应格式
  ├── 识别管理端点、内部端点、调试端点
  ├── 分析 API 版本差异 (v1 vs v2 vs v3)
  └── 标记高危操作 (DELETE / admin / config)

Phase 3 — 移动端提取 (如果适用)
  ├── APK 反编译 (jadx / apktool)
  ├── 字符串提取 API 端点
  ├── 硬编码密钥和 token
  └── Retrofit/OkHttp 接口分析

Phase 4 — 利用
  ├── 通过未文档化的管理端点提权
  ├── 利用过时 API 版本绕过鉴权
  ├── GraphQL mutation 注入
  └── 硬编码密钥外部服务利用
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动检测上述漏洞：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| HTTP 探测 API 文档 | `http_probe` | 枚举 Swagger/OpenAPI/GraphQL 端点路径 |
| 按信号查知识库 | `kb_router` | 搜索 API discovery / source map leak 相关技术文件 |
| 阅读技术细节 | `kb_read_file` | 读取本文档获取完整攻击链 |
| 运行扫描工具 | `run_ctf_tool` | 使用 dirsearch/jwt_tool 扫描端点 |

## 参考资料

- OWASP API Security Top 10 (2023): API1 — Broken Object Level Authorization; API3 — Broken Object Property Level Authorization
- OWASP: GraphQL Introspection & Field Suggestions
- PortSwigger Research: "Source code disclosure via exposed source maps"
- Clairvoyance: GraphQL Schema Brute-forcing Tool
- Jason Haddix: "The Bug Hunter's Methodology" — API Discovery Section

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 从全新 session/重置状态最小化重放，记录依赖、并发参数、时间窗口及失败样本。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
