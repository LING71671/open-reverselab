---
id: "ctf-website/22-dos/13-database-dos-defense"
title: "数据库层拒绝服务防御与查询资源治理"
title_en: "Database Layer Denial of Service Defense and Query Resource Governance"
summary: >
  系统防御针对 PostgreSQL、MySQL 与 MongoDB 的数据库层拒绝服务攻击，涵盖慢查询注入（笛卡尔积、递归 CTE、正则 ReDoS、ORDER BY random()、SLEEP/BENCHMARK）、行锁/表锁与死锁构造、连接池与 idle-in-transaction 耗尽、WAL/Binlog 日志膨胀写满磁盘、索引退化与全库全文搜索放大。提供生产级数据库配置与 Python SQL 复杂模式拦截脚本。
summary_en: >
  Comprehensive defense against database-layer DoS on PostgreSQL, MySQL, and MongoDB: slow query injection (Cartesian joins, recursive CTEs, regex ReDoS, ORDER BY random(), SLEEP/BENCHMARK), row/table locks and deadlocks, connection pool and idle-in-transaction exhaustion, WAL/Binlog disk exhaustion, index bloat, and full-text search amplification. Includes production DB configs and runnable Python SQL guard checks.
board: "ctf-website"
category: "22-dos"
signals:
  - "statement_timeout 与 lock_timeout 强约束"
  - "idle_in_transaction_session_timeout 回收"
  - "PgBouncer 事务级池化隔离"
  - "max_wal_size 与 temp_file_limit 磁盘护栏"
  - "参数化查询与 ORM 复杂度/行数硬限"
  - "MongoDB noscripting 与 maxTimeMS"
mcp_tools:
  - "http_probe"
  - "kb_router"
  - "kb_read_file"
  - "kb_catalog"
keywords:
  - "数据库 DoS 防御"
  - "PostgreSQL 超时加固"
  - "PgBouncer 连接池"
  - "行锁与死锁防护"
  - "WAL 磁盘保护"
  - "慢查询拦截"
  - "MongoDB 加固"
  - "database dos defense"
difficulty: "advanced"
tags:
  - "defense"
  - "blue-team"
  - "resilience"
  - "dos-protection"
  - "database"
  - "postgresql"
  - "mysql"
  - "connection-pool"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "ctf-website/22-dos/13-database-dos"
track: "blue"
defends: "ctf-website/22-dos/13-database-dos"
---
# 数据库层拒绝服务防御与查询资源治理

## 防御目标与对抗矩阵

数据库层拒绝服务（对应攻击技术见 [13-database-dos.md](../../../../red/ctf-website/techniques/22-dos/13-database-dos.md)）通过单次高代价 SQL/NoSQL 操作或长期占锁耗尽全部后端服务共享的存储与连接资源。防御核心在于**彻底参数化消除注入、数据库内核级执行超时与锁超时、事务级连接池收敛，以及存储/WAL 写爆护栏**。

| 攻击向量 | 消耗目标 | 核心防御手段 | 关键参数 / 策略 |
|---|---|---|---|
| 慢查询注入（笛卡尔积/递归 CTE/ReDoS/`SLEEP`） | CPU 100%、工作内存 OOM | 全链路参数化防注入 + `statement_timeout` 硬超时 + 限制 CTE 深度/禁止 `CROSS JOIN` 与 `ORDER BY random()` | PG `statement_timeout=5s`、MySQL `max_execution_time=5000`、Mongo `--noscripting` |
| 行锁 / 间隙锁 / 表锁 / 死锁构造 | 业务事务长期阻塞与持续回滚 | 设置 `lock_timeout` + 禁止长时间跨网络持有事务 + 事务内按固定主键序加锁消除死锁环 | PG `lock_timeout=2s`、MySQL `innodb_lock_wait_timeout=3`、应用角色禁 `LOCK TABLE` |
| 连接池与 `idle in transaction` 耗尽 | `max_connections` 槽位满导致全站 503 | 部署 PgBouncer 事务级连接池 + 内核回收空闲事务 + 业务/管理账号独立连接配额 | `idle_in_transaction_session_timeout=10s` + 保留 `superuser_reserved_connections=5` |
| WAL / Binlog 磁盘写爆 | 日志写满存储触发数据库 PANIC | 限制单个事务临时磁盘溢出 + 设置 `max_wal_size` / `binlog_expire_logs_seconds` + 写入速率限流与存储独立挂载 | `temp_file_limit=512MB`、WAL 与数据目录挂载分离并配置 80% 磁盘只读告警 |
| 索引退化与统计失真 | 查询从 `O(log n)` 退化为 `O(n)` SeqScan | 针对 JSONB/表达式建 GIN 与函数索引（如 `LOWER(email)`）+ 调优 `autovacuum` 阈值抑制死元组膨胀 | 降低 `autovacuum_vacuum_scale_factor=0.02` + 定期 `pg_repack` |
| 全库全文搜索放大 | 广泛 OR 条件与 `ts_rank_cd` 计算 | 词元数上限校验 + 强制分页 `LIMIT` + 迁移专业搜索引擎并关闭通配符全扫描 | 查询词项 `<= 8` 个、禁止单字母高频停用词检索 |

---

## 防御工作流

### 阶段一：PostgreSQL / MySQL / MongoDB 内核级硬超时与磁盘护栏

为应用连接角色与实例全局配置强超时，确保任何 `pg_sleep(3600)`、递归 CTE 炸弹或未提交行锁事务在秒级被内核强制终止回滚：

```ini
# /etc/postgresql/16/main/conf.d/99-dos-hardening.conf
# 1. 语句与锁硬超时（也可按业务账号 ALTER ROLE app_user SET ... 差异化配置）
statement_timeout = '5s'
lock_timeout = '2s'
idle_in_transaction_session_timeout = '10s'
idle_session_timeout = '5min'

# 2. 防止慢排序与窗口函数写爆临时磁盘
temp_file_limit = '512MB'
work_mem = '16MB'

# 3. 限制 MySQL 风格等价参数与 WAL 上限保护
max_wal_size = '4GB'
min_wal_size = '1GB'
wal_keep_size = '512MB'
superuser_reserved_connections = 5

# 4. 抑制高频增删改引起的索引膨胀与统计失真
autovacuum_vacuum_scale_factor = 0.02
autovacuum_analyze_scale_factor = 0.01
```

```ini
# /etc/mysql/mysql.conf.d/99-dos-hardening.cnf
[mysqld]
max_execution_time = 5000
innodb_lock_wait_timeout = 3
innodb_deadlock_detect = ON
max_binlog_size = 256M
binlog_expire_logs_seconds = 259200
max_connections = 300
```

```yaml
# /etc/mongod.conf — 彻底禁用 $where 服务端 JS 执行防阻塞
security:
  javascriptEnabled: false
net:
  maxIncomingConnections: 500
```

### 阶段二：PgBouncer 事务级连接池收敛与权限最小化

1. **事务级连接复用**：在应用与 PostgreSQL 之间部署 PgBouncer（`pool_mode = transaction`），使成百上千前端连接复用几十个真实后端 DB 连接，并配置 `query_wait_timeout = 3` 防止排队雪崩。
2. **回收应用层危险 SQL 权限**：应用账号禁止执行 `LOCK TABLE`、禁用 `pg_sleep` 或创建无界自定义函数（在应用连接层拦截），所有动态字段（排序列、过滤条件）走严格白名单映射而非字符串拼接。

```ini
# /etc/pgbouncer/pgbouncer.ini
[pgbouncer]
pool_mode = transaction
max_client_conn = 1000
default_pool_size = 40
reserve_pool_size = 10
reserve_pool_timeout = 2
query_timeout = 5
query_wait_timeout = 3
idle_transaction_timeout = 10
```

### 阶段三：ORM 层查询复杂度与锁顺序治理

1. **禁止无界查询与危险写法**：所有列表查询强制注入 `LIMIT <= 100`；禁止使用 `ORDER BY random()`（改用业务层随机 ID 区间采样）；对 JSONB 字段建立 GIN 索引并仅允许白名单操作符查询；限制全文检索关键词个数及最小字符长度。
2. **统一资源加锁顺序消除死锁**：涉及多行更新（如订单/库存 ID 列表）时，应用层必须先按主键升序排序（`SELECT ... WHERE id = ANY($1) ORDER BY id FOR UPDATE`），从根本上破坏循环等待死锁条件。

---

## 弹性校验代码（可运行 Python 自检）

以下 Python 脚本实现 SQL 危险高复杂度模式静默检查器（拦截 `SLEEP`/`pg_sleep`/`BENCHMARK`、无限递归 CTE 缺省上限、`CROSS JOIN`/多表无条件连接、`ORDER BY random()`、缺失 `LIMIT` 以及高频全表通配 `LIKE`），并核验 PostgreSQL 超时基线配置。

```python
#!/usr/bin/env python3
"""Database DoS defense verifier: SQL complexity/injection-DoS guard & DB config check."""

import re


DANGEROUS_SQL_RULES = [
    ("time_delay_fn", re.compile(r"\b(?:pg_sleep|sleep|benchmark|waitfor\s+delay)\s*\(", re.I)),
    ("random_full_sort", re.compile(r"\border\s+by\s+(?:random|rand)\s*\(", re.I)),
    ("cartesian_cross_join", re.compile(r"\bcross\s+join\b", re.I)),
    ("table_lock_stmt", re.compile(r"\block\s+tables?\b", re.I)),
    ("leading_wildcard_like", re.compile(r"\blike\s+'%[^']*%'", re.I)),
    ("regex_operator_risk", re.compile(r"\s~\*?\s+'[^']*\([^)]*[+*][^)]*\)[+*]", re.I)),
]


def check_sql_dos_risk(sql: str, require_limit: bool = True) -> list[str]:
    """Static guard rejecting high-complexity or blocking SQL patterns before execution."""
    issues: list[str] = []
    normalized = " ".join(sql.strip().split())

    for label, pattern in DANGEROUS_SQL_RULES:
        if pattern.search(normalized):
            issues.append(label)

    # 检查递归 CTE 是否缺少深度/数值上限条件
    if re.search(r"\bwith\s+recursive\b", normalized, re.I):
        if not re.search(r"\b(?:where\s+\w+\s*<\s*\d+|limit\s+\d+)\b", normalized, re.I):
            issues.append("unbounded_recursive_cte")

    # 检查 SELECT 是否强制携带 LIMIT 上限
    if require_limit and re.match(r"^select\b", normalized, re.I):
        limit_match = re.search(r"\blimit\s+(\d+)\b", normalized, re.I)
        if not limit_match:
            issues.append("missing_select_limit")
        elif int(limit_match.group(1)) > 500:
            issues.append(f"excessive_select_limit:{limit_match.group(1)}")

    return issues


def verify_pg_hardening_conf(conf_text: str) -> list[str]:
    """Verify PostgreSQL configuration includes statement/lock/idle timeouts and temp_file_limit."""
    required = [
        "statement_timeout",
        "lock_timeout",
        "idle_in_transaction_session_timeout",
        "temp_file_limit",
        "max_wal_size",
    ]
    return [key for key in required if key not in conf_text]


def run_self_checks() -> None:
    # 1. 拦截各类慢查询 DoS 模式
    assert "time_delay_fn" in check_sql_dos_risk("SELECT pg_sleep(30) LIMIT 1")
    assert "random_full_sort" in check_sql_dos_risk("SELECT id FROM events ORDER BY random() LIMIT 10")
    assert "cartesian_cross_join" in check_sql_dos_risk("SELECT * FROM a CROSS JOIN b LIMIT 10")
    assert "unbounded_recursive_cte" in check_sql_dos_risk(
        "WITH RECURSIVE r AS (SELECT 1 UNION ALL SELECT 1 FROM r) SELECT * FROM r", require_limit=False
    )
    assert "missing_select_limit" in check_sql_dos_risk("SELECT id, name FROM users WHERE org_id = $1")

    # 2. 放行合规参数化带限流查询
    safe_sql = "SELECT id, name FROM users WHERE org_id = $1 AND id > $2 ORDER BY id ASC LIMIT 50"
    assert check_sql_dos_risk(safe_sql) == []

    # 3. 校验 PostgreSQL 配置项完整性
    good_pg_conf = "\n".join([
        "statement_timeout = '5s'",
        "lock_timeout = '2s'",
        "idle_in_transaction_session_timeout = '10s'",
        "temp_file_limit = '512MB'",
        "max_wal_size = '4GB'",
    ])
    assert verify_pg_hardening_conf(good_pg_conf) == []
    assert "lock_timeout" in verify_pg_hardening_conf("statement_timeout = '5s'")
    print("[PASS] All database-layer DoS defense checks passed.")


if __name__ == "__main__":
    run_self_checks()
```

---

## 验证与判定标准

| 验证项 | 达标判定标准 | 可观测指标 |
|---|---|---|
| 慢查询硬超时生效 | 执行 `SELECT pg_sleep(30)` 或笛卡尔积查询在 `<= 5s` 内被内核取消报错 | `pg_stat_activity` 无运行超过 5s 的应用查询 |
| 行锁与空闲事务回收 | 未提交事务在 `10s` 被强制终止释放行锁，锁等待在 `2s` 失败返回 | `idle in transaction` 长期占比 `0%` |
| 连接池抗饱和 | 突发并发慢操作被 PgBouncer 隔离拦截，核心健康检查接口保留连接配额 | 连接池排队等待 `< 3s`，`superuser_reserved_connections` 可用 |
| WAL 与存储防爆 | 单查询临时排序溢出达 `512MB` 自动中断，WAL 磁盘使用率可控 | 磁盘空间报警线 `< 70%`，零 PANIC 停机 |

---

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| 接口超时与报错行为检验 | `http_probe` | 验证高耗时搜索/排序参数是否在 5s 内被截断并返回受控错误码 |
| 蓝队技术搜索 | `kb_router` | 以 `track="blue"` 检索 `database` / `postgresql` / `connection_pool` 防御 |
| 攻防文档对照 | `kb_read_file` | 读取本文件及配对攻击文档 `ctf-website/22-dos/13-database-dos` |
| 分类清单查看 | `kb_catalog` | 列举 `22-dos` 全部防御文档 |
