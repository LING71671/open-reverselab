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

## 7. 关联技术

- [[04-config-exposure]] — 配置文件泄露
- [[01-sqli-fundamentals]] — 数据库连接后的利用
- [[06-card-platform]] — 发卡平台实战
- [[file-upload-xxe-lfi]] — 文件读取
