---
id: "ctf-website/01-recon/version-fingerprinting"
title: "版本指纹识别"
title_en: "Version Fingerprinting"
summary: >
  介绍从 HTTP Header、HTML Meta、JS Bundle、静态文件 Hash、错误页面到锁文件的多层次版本指纹识别方法。包含 Wappalyzer 级指纹数据库和 fingerprint-to-CVE 联动工作流，用于精确识别目标技术栈及已知漏洞版本。
summary_en: >
  A multi-layered approach to version fingerprinting covering HTTP headers, HTML meta tags, JS bundle analysis, static file hashes, error pages, and lock files. Includes a Wappalyzer-style fingerprint database and fingerprint-to-CVE correlation workflow for precise technology stack identification.
board: "ctf-website"
category: "01-recon"
signals: ["fingerprint", "版本识别", "Server header", "favicon hash", "JS framework", "Wappalyzer", "CVE lookup", "technology stack"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file"]
keywords: ["版本指纹", "fingerprinting", "技术栈识别", "favicon hash", "CVE", "nuclei", "whatweb", "wappalyzer", "JS框架"]
difficulty: "beginner"
tags: ["recon", "fingerprinting", "cve", "web-security", "technology-stack", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: []
---

# 版本指纹识别

## 一句话原则

> 不要信前端注释，信运行时行为。从 header → HTML → JS → 错误 → 文件 递进收束。

## 输入信号

- Header、cookie、HTML meta、JS bundle、favicon、错误页出现产品或框架痕迹
- `package-lock.json`, `composer.lock`, `go.sum`, `requirements.txt` 可读
- API 文档、sourcemap、静态资源路径暴露版本号
- 错误页包含栈帧、模块路径、依赖版本或默认主题

## 0. 置信度矩阵

| 证据 | 置信度 | 用法 | 失败样本 |
|------|--------|------|----------|
| lockfile / package manifest | 高 | 直接提依赖版本 | 构建产物不是当前部署 |
| 错误栈 module path | 高 | 精确框架/库版本 | 错误页被代理替换 |
| JS sourcemap | 高 | 还原源码和 API | sourcemap 过期 |
| favicon hash | 中 | 产品族识别 | 多产品共用默认图标 |
| Header `Server` | 中 | Web server 粗指纹 | CDN/反代覆盖 |
| HTML 注释/meta | 低 | 辅助线索 | 模板未更新 |
| Wappalyzer 单点命中 | 低 | 作为候选 | 同类前端库误判 |

指纹至少要两个独立来源交叉：例如 `laravel_session` + `.env` 路径 + `composer.lock`，或 `JSESSIONID` + Spring 错误栈 + `/actuator`。

## 速查指纹矩阵

```python
# fingerprinter.py — 一键收集所有指纹
import requests, hashlib, re

def fingerprint_all(target: str) -> dict:
    r = requests.get(target, timeout=10)
    results = {}

    # 1. HTTP Headers
    results["server"] = r.headers.get("Server", "")
    results["x_powered_by"] = r.headers.get("X-Powered-By", "")
    results["x_generator"] = r.headers.get("X-Generator", "")
    results["set_cookie"] = r.headers.get("Set-Cookie", "")

    # 2. HTML meta tags
    meta_gen = re.findall(r'<meta[^>]*name="generator"[^>]*content="([^"]*)"', r.text)
    results["generator_meta"] = meta_gen

    # 3. JS bundle 特征 (正则扫版本号)
    js_patterns = {
        "jquery": r'jQuery v(\d+\.\d+\.\d+)',
        "react": r'React v(\d+\.\d+\.\d+)',
        "vue": r'Vue\.js v(\d+\.\d+\.\d+)',
        "angular": r'Angular v(\d+\.\d+\.\d+)',
        "bootstrap": r'Bootstrap v(\d+\.\d+\.\d+)',
        "webpack": r'webpack v?(\d+\.\d+\.\d+)',
        "next": r'next@(\d+\.\d+\.\d+)',
        "nuxt": r'nuxt@(\d+\.\d+\.\d+)',
    }
    results["js_frameworks"] = {}
    for name, pat in js_patterns.items():
        m = re.search(pat, r.text)
        if m:
            results["js_frameworks"][name] = m.group(1)

    # 4. 静态文件 hash → 版本
    FAVICON_HASHES = {
        "b3c1cb2d4672b757886b2b56cbf5f3fa": "Apache Tomcat",
        "9c7e1d563d9c2a91e2e7e0b1f0c9a5e3": "Spring Boot (default)",
        "d41d8cd98f00b204e9800998ecf8427e": "Empty file (many)",
    }
    fav = requests.get(target + "/favicon.ico")
    if fav.status_code == 200:
        h = hashlib.md5(fav.content).hexdigest()
        results["favicon_hash"] = h
        if h in FAVICON_HASHES:
            results["favicon_product"] = FAVICON_HASHES[h]

    # 5. 错误页指纹
    r_err = requests.get(target + "/nonexistent_404_test", allow_redirects=False)
    results["404_status"] = r_err.status_code
    results["404_server"] = r_err.headers.get("Server", "")

    return results
```

## 锁文件探测

```python
# 常见版本锁文件
LOCK_FILES = [
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.lock", "Gemfile.lock", "Pipfile.lock",
    "poetry.lock", "requirements.txt", "go.sum",
    "Cargo.lock", "pubspec.lock", "packages.lock.json",
    ".npmrc", ".yarnrc",
]

def probe_lock_files(target: str):
    for lf in LOCK_FILES:
        r = requests.get(f"{target}/{lf}")
        if r.status_code == 200 and len(r.text) > 50:
            print(f"[!] Found: {lf} ({len(r.text)} bytes)")
            # 从 lock 文件解析版本
            if lf.endswith(".json"):
                try:
                    data = r.json()
                    deps = data.get("dependencies", {}) or data.get("packages", {})
                    for pkg, info in list(deps.items())[:10]:
                        ver = info if isinstance(info, str) else info.get("version", "?")
                        print(f"    {pkg}: {ver}")
                except: pass
```

## 从报错推断版本

```python
# 故意触发异常，从报错提取版本
ERROR_PROBES = [
    # Spring Boot
    ("/api/../admin", "actuator"),
    # Django
    ("/admin/login/?next=/x", "django"),
    # Laravel
    ("/nonexistent_route_404_test", "laravel"),
    # Express
    ("/%FF%FF", "express"),
    # Flask (debug)
    ("/console", "werkzeug"),
    # PHP
    ("/index.php/..%5c..%5c", "php"),
]

def error_fingerprint(target: str):
    for path, hint in ERROR_PROBES:
        r = requests.get(target + path)
        text = r.text[:2000]

        # 框架特征正则
        patterns = {
            "Spring Boot": r"org\.springframework",
            "Django": r"django\.(core|http|urls)",
            "Laravel": r"laravel|Illuminate\\",
            "Express": r"at .*?node_modules/express",
            "Flask/Werkzeug": r"Werkzeug|werkzeug",
            "PHP": r"PHP (Fatal|Warning|Parse|Notice)",
            "Tomcat": r"Apache Tomcat/([\d.]+)",
            "Jetty": r"Jetty\(([\d.]+)",
            "Struts": r"struts2|org\.apache\.struts",
            "Thymeleaf": r"org\.thymeleaf",
        }
        for fw, pat in patterns.items():
            m = re.search(pat, text, re.I)
            if m:
                print(f"  {path}: {fw} → {m.group(0)[:80]}")

        # 精确版本号提取
        versions = re.findall(r'([\w.-]+)[/ ](\d+\.\d+\.\d+)', text)
        for name, ver in versions[:5]:
            print(f"    {name}: {ver}")
```

## Swagger/OpenAPI 暴露

```bash
# 常见 API 文档路径
for path in /swagger-ui.html /api-docs /v2/api-docs /v3/api-docs \
  /api/swagger /openapi.json /api/openapi.json /swagger.json \
  /docs /api/docs /redoc /api/redoc; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$path")
  [[ $code == "200" ]] && echo "[!] $path ($code)"
done
```

## 指纹 → CVE 联动

```bash
# 拿到产品和版本后，直接查 CVE
python scripts/ctf-website/cve_lookup.py --product "spring-boot" --version "2.7.0"
python scripts/ctf-website/cve_lookup.py --product "django" --version "4.1"
```

## Wappalyzer 级指纹数据库

```python
# 扩充指纹 — 按响应特征匹配
WAPP_FINGERPRINTS = {
    # Cookie 特征
    "JSESSIONID":            "Java (Tomcat/Jetty/Spring)",
    "PHPSESSID":             "PHP",
    "laravel_session":       "Laravel",
    "csrftoken":             "Django",
    "ASP.NET_SessionId":     "ASP.NET",
    "_rails_session":        "Ruby on Rails",
    "PLAY_SESSION":          "Play Framework (Scala/Java)",
    "ring-session":          "Ring/Clojure",
    # HTML meta
    '<meta name="generator" content="WordPress': "WordPress",
    '<meta name="generator" content="Drupal': "Drupal",
    '<meta name="generator" content="Joomla': "Joomla",
    # JS 全局变量
    "window.__NEXT_DATA__":  "Next.js",
    "window.__NUXT__":       "Nuxt.js",
    "window.__INITIAL_STATE__": "Vue SSR / Nuxt",
    "ReactDOM.render":       "React (SPA)",
    "angular.module":        "AngularJS",
    "ng-version":            "Angular",
    # 文件路径
    "/wp-content/":          "WordPress",
    "/sites/default/":       "Drupal",
    "/static/version":       "Magento",
    "/skin/frontend/":       "Magento",
    "/shopify/":             "Shopify",
}
```

## 快速扫描集成

```bash
# 一键指纹收集
python3 fingerprinter.py https://target.com > fingerprints.json

# nuclei 模板扫描
nuclei -u https://target.com -t technologies/ -o tech_report.json

# whatweb 批量
whatweb https://target.com -a 3 --log-json=whatweb.json

# wappalyzer CLI
wappalyzer https://target.com

# 从 JS bundle 提取依赖
curl -s https://target.com/main.js | grep -oP '"[^"]+"' | grep -E '^"[@a-z]' | sort -u
```

## 指纹归并与下一跳

```python
import json
import re
from collections import defaultdict

NEXT_HOP = {
    "Laravel": ["04-config-exposure", "payment-php", "deserialization"],
    "Spring": ["ssti", "general/protocol/03-grpc-protobuf", "kubernetes-container"],
    "WordPress": ["payment-php", "file-upload-xxe-lfi"],
    "Magento": ["payment-php", "graphql"],
    "Redis": ["03-nosql-injection", "ssrf"],
    "phpMyAdmin": ["04-config-exposure", "01-sqli-fundamentals"],
}

def merge_fingerprints(items):
    scores = defaultdict(int)
    evidence = defaultdict(list)
    for item in items:
        src = item.get("source", "")
        text = json.dumps(item, ensure_ascii=False)
        weight = 3 if re.search(r"lock|error|sourcemap", src, re.I) else 1
        for product in NEXT_HOP:
            if re.search(product, text, re.I):
                scores[product] += weight
                evidence[product].append(item)
    return [
        {"product": p, "score": s, "next": NEXT_HOP[p], "evidence": evidence[p][:3]}
        for p, s in sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    ]
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| HTTP 版本/服务器指纹收集 | `http_probe` | HTTP GET 探测，收集 Server/Header 指纹 |
| 指纹 → CVE 联动搜索 | `kb_router` | 按指纹信号查相关 CVE 技术 |
| 知识库检索 | `kb_read_file` | 读取知识库技术文件内容 |

## 工作流

建立 HTTP baseline → 枚举路由/参数/版本信号 → 交叉验证指纹 → `kb_router` 选技术分支 → 最小 probe → 证据落盘。


## Evidence

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 固定 session、输入、并发参数和时间窗口重放，记录成功响应、失败样本和下一跳。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
- `fingerprints.json`: source、product、version、confidence、raw evidence。
- `fingerprint-next-hop.json`: 产品/版本、置信度、关联 CVE/KB 文档、复测结果。
- 成功样本: 两个以上独立信号指向同一产品/版本，且对应端点/行为可复测。
- 失败样本: Header 与应用行为冲突、静态资源缓存旧版本、CDN 默认错误页误导。
