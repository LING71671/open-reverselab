# 版本指纹识别

## 一句话原则

> 不要信前端注释，信运行时行为。从 header → HTML → JS → 错误 → 文件 递进收束。

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
