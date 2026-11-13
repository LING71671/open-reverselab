---
id: "ctf-website/24-database/01-sqli-fundamentals-defense"
title: "SQL Injection Core Defense — SQL 注入基础防御与参数化体系"
title_en: "SQL Injection Core Defense — Parameterization & Baseline Hardening"
summary: >
  针对基础 SQL 注入全类型（联合查询 UNION、报错注入、布尔盲注、时间盲注、文件读写、GBK 宽字节注入与 WAF 绕过）的纵深防御体系：强制预编译参数化查询、关闭模拟预处理并统一 utf8mb4 字符集、标识符白名单、错误响应收敛、数据库查询超时与最小权限隔离，以及支付核心表访问边界加固。
summary_en: >
  Defense-in-depth against foundational SQL injection vectors (UNION SELECT, error-based, boolean/time-based blind, file read/write, GBK wide-byte, and WAF bypasses): mandatory parameterized queries, native prepared statements with unified utf8mb4 encoding, identifier allowlists, error suppression, execution timeouts, least-privilege DB accounts, and payment table isolation.
board: "ctf-website"
category: "24-database"
signals:
  - "参数化查询 Prepared Statement 防注入"
  - "关闭 ATTR_EMULATE_PREPARES 与 utf8mb4 统一"
  - "ORDER BY LIMIT IN 标识符白名单"
  - "secure_file_priv 与 FILE 权限回收"
  - "SQL 错误详情屏蔽与通用错误页"
  - "max_execution_time statement_timeout 抗时间盲注"
mcp_tools:
  - "kb_router"
  - "kb_read_file"
  - "kb_catalog"
  - "http_probe"
keywords:
  - "SQL 注入防御"
  - "参数化查询"
  - "Prepared Statement"
  - "宽字节防御"
  - "utf8mb4"
  - "secure_file_priv"
  - "标识符白名单"
  - "查询超时"
  - "最小权限"
  - "错误信息收敛"
difficulty: "advanced"
tags:
  - "defense"
  - "blue-team"
  - "database-security"
  - "sql-injection"
  - "parameterized-queries"
  - "mysql"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/24-database/01-sqli-fundamentals", "ctf-website/24-database/02-sqli-advanced-defense", "ctf-website/24-database/04-config-exposure-defense"]
track: "blue"
defends: "ctf-website/24-database/01-sqli-fundamentals"
---
# SQL Injection Core Defense — SQL 注入基础防御与参数化体系

> 从 SQL 语法树根因切断注入：以原生预编译参数化为核心，配合统一字符集、标识符白名单、错误收敛、超时限制与最小权限隔离，全面抵御联合查询、报错、盲注与文件读写攻击。

## 1. 攻击面与根因映射

对应攻击文档 [01-sqli-fundamentals.md](../../../../red/ctf-website/techniques/24-database/01-sqli-fundamentals.md) 中的 8 类核心手法，防御必须落在“数据与代码分离”及“运行时边界收敛”上，而非依赖关键词黑名单或 WAF 规则：

| 攻击向量 | 典型利用特征 | 根因缺陷 | 对应防御控制项 |
|---|---|---|---|
| 整数/字符串/LIKE 注入 | `'`, `1 AND 1=2`, `%'` | 用户输入直接拼接进入 SQL 字面量 | 原生预编译参数化查询 + `LIKE` 通配符转义 |
| `UNION SELECT` 数据抽取 | `ORDER BY N`, `UNION SELECT ...` | 查询条件可逃逸并追加联合结果集 | 参数化绑定 + 数据库账号隔离 `information_schema` 访问 |
| 报错注入 | `extractvalue`, `updatexml`, `CAST/CONVERT` | 语法拼接 + 应用向前端回显数据库异常详情 | 参数化 + 全局异常拦截（仅返回请求追踪 ID） |
| 布尔与时间盲注 | `SUBSTR/ASCII`, `SLEEP()`, `pg_sleep()`, `WAITFOR` | 无回显但语句语义被篡改且无执行超时 | 参数化 + 语句超时上限 + 异常频次限流 |
| 文件读写与命令执行 | `LOAD_FILE()`, `INTO OUTFILE`, `xp_cmdshell` | 数据库进程拥有高危文件/系统权限 | `secure_file_priv=NULL` + 回收 `FILE` 权限 + 禁用 `xp_cmdshell` |
| GBK 宽字节注入 | `%bf%27`, `%df%27` | 客户端与数据库连接编码不一致导致转义符被吞 | 全链路强制 `utf8mb4` + 禁用客户端模拟预处理 |
| `ORDER BY` / `LIMIT` / `IN` 注入 | `CASE WHEN(...)`, 动态排序列名 | SQL 标识符/结构位无法直接参数绑定 | 严格枚举映射白名单 + 整数区间强约束 |
| WAF 关键字绕过 | `SeLeCt`, `/**/ `, `/*!50000*/`, HPP | 仅在边缘做正则黑名单过滤 | 放弃黑名单依赖，统一在数据访问层做 AST 级参数绑定 |

## 2. 核心防御实现

### 2.1 原生参数化查询与字符集一致性（消除拼接与宽字节）

1. **PHP (PDO)**：必须禁用模拟预处理（`ATTR_EMULATE_PREPARES => false`）并在 DSN 显式指定 `charset=utf8mb4`，防止本地转义与服务端 GBK 解码产生宽字节逃逸（`0xbf5c`）：

```php
<?php
$dsn = 'mysql:host=127.0.0.1;port=3306;dbname=shop_db;charset=utf8mb4';
$pdo = new PDO($dsn, $dbUser, $dbPass, [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_EMULATE_PREPARES   => false,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);

// 安全：原生预编译，输入不会改变 SQL 语法树
$stmt = $pdo->prepare('SELECT id, out_trade_no, status, amount FROM orders WHERE id = :id AND user_id = :uid');
$stmt->execute([
    ':id'  => filter_var($_GET['id'] ?? 0, FILTER_VALIDATE_INT),
    ':uid' => $currentUserId,
]);
$order = $stmt->fetch();
```

2. **Python (SQLAlchemy / DB-API)**：禁止使用 f-string、`%`、`.format()` 或 `+` 构造 SQL，统一使用绑定占位符；`LIKE` 查询必须转义 `%`、`_` 与转义符自身：

```python
def escape_like(term: str, escape_char: str = "\\") -> str:
    return (
        term.replace(escape_char, escape_char * 2)
        .replace("%", escape_char + "%")
        .replace("_", escape_char + "_")
    )
```

3. **Node.js / Java**：分别使用 `mysql2`/`pg` 参数数组（`pool.execute('SELECT ... WHERE id = ?', [id])`）与 JDBC `PreparedStatement`，禁止在 MyBatis 中对业务值使用 `${}`（必须用 `#{}`, 且动态排序列使用代码层白名单映射）。

### 2.2 不可参数化位置的严格白名单（ORDER BY / LIMIT / IN / JSON）

SQL 预编译占位符不能绑定列名、排序方向或关键字。必须通过“枚举字典映射 + 有界整数校验”处理：

```python
SORT_COLUMN_MAP = {
    "created": "created_at",
    "amount": "amount",
    "id": "id",
}
SORT_DIR_MAP = {"asc": "ASC", "desc": "DESC"}

def build_safe_order_limit(sort_key: str, direction: str, page: int, page_size: int) -> tuple[str, int, int]:
    col = SORT_COLUMN_MAP.get(sort_key, "id")
    order_dir = SORT_DIR_MAP.get(direction.lower(), "DESC")
    safe_limit = max(1, min(int(page_size), 100))
    safe_offset = max(0, (max(1, int(page)) - 1) * safe_limit)
    return f"ORDER BY {col} {order_dir} LIMIT ? OFFSET ?", safe_limit, safe_offset
```

### 2.3 数据库引擎与操作系统边界加固

在 MySQL/PostgreSQL/MSSQL 配置层切断报错通道、时间盲注窗口与文件读写能力：

```ini
# /etc/mysql/mysql.conf.d/hardening.cnf
[mysqld]
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci
# 禁止 LOAD_FILE 与 INTO OUTFILE/DUMPFILE 读写任意文件
secure_file_priv = NULL
# 禁止客户端 LOCAL INFILE 读取应用服务器本地文件
local_infile = 0
# 限制单条 SELECT 最长执行时间（毫秒），压缩时间盲注与笛卡尔积拒绝服务窗口
max_execution_time = 2000
```

数据库权限最小化 SQL 基线：

```sql
-- 为业务应用创建最小权限账号，仅授予目标库 CRUD，不授予 FILE / SUPER / PROCESS / GRANT
CREATE USER 'app_orders'@'10.10.0.%' IDENTIFIED BY 'STRONG_RANDOM_PASSWORD_PLACEHOLDER';
GRANT SELECT, INSERT, UPDATE ON shop_db.orders TO 'app_orders'@'10.10.0.%';
GRANT SELECT, INSERT ON shop_db.pay_log TO 'app_orders'@'10.10.0.%';
REVOKE FILE ON *.* FROM 'app_orders'@'10.10.0.%';
FLUSH PRIVILEGES;
```

PostgreSQL 与 MSSQL 补充基线：
- PostgreSQL：设置 `ALTER ROLE app_orders SET statement_timeout = '2000ms';`，禁止普通应用账号使用 `COPY ... FROM PROGRAM`（不授予 `pg_execute_server_program`）。
- MSSQL：确认 `EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;`，禁止应用账号拥有 `sysadmin` 角色，查询超时由连接串/命令 `CommandTimeout` 限制在 2~5 秒。

### 2.4 错误收敛与业务核心表保护

- **关闭调试回显**：生产环境设置 PHP `display_errors = Off`，Spring Boot / Django / Flask 关闭栈追踪与 SQL 原始语句回显，统一返回 `{"error": "invalid_request", "trace_id": "..."}`。
- **支付与敏感表隔离**：`config`、`cards`/`kami`、`wallet`、`pay_log` 与公开检索查询分库或分账号隔离；前端商品检索账号绝不具备读写 `orders`、`cards` 与 `settings` 表的权限。

## 3. 可运行防御自检脚本

以下 Python 脚本可直接在本地运行，用于验证（1）SQLite 参数化查询对常见注入载荷的免疫性；（2）`ORDER BY` / `LIMIT` 白名单构造器的抗注入能力；（3）代码片段中危险 SQL 字符串拼接模式的静态检出：

```python
#!/usr/bin/env python3
"""Self-check for parameterized queries, allowlists, and unsafe SQL concatenation."""
import re
import sqlite3

UNSAFE_SQL_PATTERNS = [
    re.compile(r"""(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\n]*(?:\{\w+\}|%s|%d|\+\s*\w+)""", re.I),
    re.compile(r"""execute\(\s*f["']""", re.I),
]

ALLOWED_SORT = {"id": "id", "price": "price"}
ALLOWED_DIR = {"asc": "ASC", "desc": "DESC"}


def safe_query_order(conn: sqlite3.Connection, raw_id: str, sort_key: str, sort_dir: str, limit: int):
    if sort_key not in ALLOWED_SORT:
        raise ValueError(f"disallowed sort column: {sort_key}")
    if sort_dir.lower() not in ALLOWED_DIR:
        raise ValueError(f"disallowed sort direction: {sort_dir}")
    bounded_limit = max(1, min(int(limit), 50))
    sql = (
        f"SELECT id, item, price FROM orders WHERE id = ? "
        f"ORDER BY {ALLOWED_SORT[sort_key]} {ALLOWED_DIR[sort_dir.lower()]} LIMIT ?"
    )
    return conn.execute(sql, (raw_id, bounded_limit)).fetchall()


def scan_unsafe_sql_lines(code: str) -> list[str]:
    hits = []
    for idx, line in enumerate(code.splitlines(), 1):
        if any(rx.search(line) for rx in UNSAFE_SQL_PATTERNS):
            hits.append(f"line {idx}: {line.strip()}")
    return hits


def run_self_check() -> None:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE orders (id TEXT, item TEXT, price INTEGER)")
    conn.executemany(
        "INSERT INTO orders VALUES (?, ?, ?)",
        [("1", "basic_plan", 100), ("2", "pro_plan", 500)],
    )

    # 1. 参数化查询免疫经典布尔/联合载荷
    assert safe_query_order(conn, "1' OR '1'='1", "id", "asc", 10) == []
    assert safe_query_order(conn, "-1 UNION SELECT 1,2,3--", "id", "asc", 10) == []
    assert safe_query_order(conn, "1", "price", "desc", 10) == [("1", "basic_plan", 100)]

    # 2. ORDER BY 白名单拦截注入表达式
    try:
        safe_query_order(conn, "1", "(CASE WHEN 1=1 THEN id ELSE price END)", "asc", 10)
        raise AssertionError("expected ValueError for unsafe sort column")
    except ValueError:
        pass

    # 3. 静态拼接检测
    bad_sample = 'cur.execute(f"SELECT * FROM users WHERE name=\'{user}\'")'
    good_sample = 'cur.execute("SELECT * FROM users WHERE name = ?", (user,))'
    assert len(scan_unsafe_sql_lines(bad_sample)) == 1
    assert len(scan_unsafe_sql_lines(good_sample)) == 0
    print("[PASS] SQLi fundamentals defense self-check succeeded.")


if __name__ == "__main__":
    run_self_check()
```

## 防御工作流

```text
1. 盘点所有 SQL 入口：Web 参数、Cookie、Header、JSON/XML 字段及后台脚本
2. 替换全部字符串拼接/f-string/sprintf SQL 为原生预编译参数化占位符
3. 统一数据库、连接驱动与页面编码为 utf8mb4，并关闭模拟预处理（如 PDO ATTR_EMULATE_PREPARES=false）
4. 对 ORDER BY / GROUP BY / LIMIT / 表名列名建立代码层枚举白名单与数值边界
5. 加固数据库引擎：配置 secure_file_priv=NULL、禁用 xp_cmdshell、启用查询执行超时、回收高危权限
6. 收敛 HTTP 错误输出并按业务域拆分最小权限数据库账号，运行参数化与拼接检出回归脚本
```

## 验证与判定标准

| 控制维度 | 判定指标 | 通过标准 | 失败信号 |
|---|---|---|---|
| 查询构建 | 全代码库 SQL 执行点检查 | 100% 业务值使用参数化绑定，动态标识符使用枚举映射 | 存在 `f"SELECT ... {x}"`、`${param}` 或未校验拼接 |
| 字符集与预处理 | 数据库连接与驱动配置 | 全链路 `utf8mb4` 且原生预处理开启（非模拟转义） | 混用 `GBK` 与 `addslashes` 或开启模拟预处理 |
| 错误与盲注收敛 | 异常页面与超时配置 | 畸形 SQL 输入返回统一通用错误码；超时上限 `<= 3s` | 响应暴露 `SQLSTATE`/`You have an error` 或 `SLEEP(5)` 完整阻塞 |
| 文件与系统边界 | 数据库权限与实例配置 | `secure_file_priv` 为 `NULL`/空，`FILE`/`xp_cmdshell` 已禁用 | 应用账号拥有 `FILE`、`SUPER` 或 `sysadmin` 权限 |
| 核心账本隔离 | 数据库账号授权表 | 前台查询账号对 `cards`/`config`/`mysql` 表无读写权限 | 单一高权限 `root`/`sa` 账号支撑全部业务模块 |

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 防御知识检索 | `kb_router` | 按 `SQLi defense`、`parameterized`、`utf8mb4` 搜索对应蓝队指南 |
| 规则与条目查阅 | `kb_read_file` | 读取 [01-sqli-fundamentals.md](../../../../red/ctf-website/techniques/24-database/01-sqli-fundamentals.md) 对照待消减的攻击向量 |
| 知识目录遍历 | `kb_catalog` | 列出 `24-database` 目录下的全部攻防配对文档 |
| 边界回归验证 | `http_probe` | 在 `red`/`both` 模式下对测试环境接口发送边界输入确认无回显与延时 |

## 关联技术

- [01-sqli-fundamentals.md](../../../../red/ctf-website/techniques/24-database/01-sqli-fundamentals.md) — 配对攻击面：SQL 注入基础与全类型覆盖
- [02-sqli-advanced-defense.md](02-sqli-advanced-defense.md) — 高级 SQLi、二阶注入与 OOB 防御
- [04-config-exposure-defense.md](04-config-exposure-defense.md) — 数据库配置与凭证保护
