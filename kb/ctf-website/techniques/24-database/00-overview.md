# Database Attack Surface — 数据库攻击全景与决策树

> 数据库是 Web 应用的核心资产——SQL 注入、NoSQL 滥用、配置泄露、备份暴露、发卡平台 CDK 泄露。本指南提供系统化的攻击面导航与决策路径。

## 关键词

`SQL注入` `NoSQL注入` `数据库脱库` `数据泄露` `SQLi` `blind injection` `error-based` `time-based` `OOB` `WAF绕过` `宽字节注入` `二次注入` `order by注入` `load_file` `into outfile` `默认密码` `数据库备份` `连接字符串泄露` `ORM注入` `PDO` `MySQL` `PostgreSQL` `MongoDB` `Redis` `Elasticsearch`

## 攻击面全景

```
数据库攻击面:
┌──────────────────────────────────────────────────────┐
│  应用层                                              │
│  ├─ SQL 注入 (SELECT/INSERT/UPDATE/DELETE/ORDER BY)  │
│  ├─ NoSQL 注入 (MongoDB/Redis/CouchDB)               │
│  ├─ ORM 注入 (HQL/JPQL/DQL)                          │
│  ├─ 二阶注入 (Stored XSS → SQLi)                     │
│  └─ 盲注 (Boolean/Time/Error/OOB)                    │
├──────────────────────────────────────────────────────┤
│  配置层                                              │
│  ├─ 数据库端口暴露 (3306/5432/27017/6379)             │
│  ├─ 默认凭证 (root:root/sa:sa/admin:admin)           │
│  ├─ 连接字符串泄露 (.env/config.php/web.config)      │
│  └─ 弱密码 + 暴力破解                                 │
├──────────────────────────────────────────────────────┤
│  运维层                                              │
│  ├─ 备份文件暴露 (.sql/.dump/.tar.gz/.zip)           │
│  ├─ phpMyAdmin/Adminer 未授权访问                     │
│  ├─ 日志泄露 (SQL query log/general_log)              │
│  └─ 安装文件残留 (install.sql/install.lock)          │
├──────────────────────────────────────────────────────┤
│  数据层                                              │
│  ├─ 数据库内网可达 (SSRF → RDS)                       │
│  ├─ 数据库复制/订阅泄露                               │
│  ├─ 存储过程/函数滥用 (xp_cmdshell/LOAD_FILE)         │
│  └─ 数据库链接/外部表 (dblink/postgres_fdw)          │
└──────────────────────────────────────────────────────┘
```

## 文档索引

| 文档 | 内容 |
|------|------|
| [01-sqli-fundamentals.md](01-sqli-fundamentals.md) | SQL 注入基础：类型、探测、利用 |
| [02-sqli-advanced.md](02-sqli-advanced.md) | 高级 SQLi：WAF绕过、二阶注入、OOB |
| [03-nosql-injection.md](03-nosql-injection.md) | NoSQL 注入：MongoDB、Redis、Elasticsearch |
| [04-config-exposure.md](04-config-exposure.md) | 数据库配置泄露与默认凭证 |
| [05-backup-log-leak.md](05-backup-log-leak.md) | 备份/日志文件暴露 |
| [06-card-platform.md](06-card-platform.md) | 发卡平台数据库攻击实战 |

## 速查决策树

```
发现数据库相关信号:
├─ URL 参数/表单出现 SQL 错误 → [01] SQL 注入基础
│  ├─ 有详细报错 → Error-based 注入
│  ├─ 无报错但页面行为变化 → Boolean blind
│  └─ 无任何可见变化 → Time-based blind / OOB
├─ WAF 拦截 SQL 关键词 → [02] WAF 绕过技术
├─ 发现 NoSQL 端点 → [03] NoSQL 注入
├─ 发现 .env/config.php 可读 → [04] 配置泄露
├─ 发现 .sql/.dump 文件 → [05] 备份暴露
└─ 发卡/电商平台 → [06] 平台专项攻击
```

## 关联技术

- [[sqli-nosqli]] — SQL/NoSQL 注入
- [[01-idor-enumeration]] — IDOR 与数据库枚举
- [[payment-php]] — PHP 支付与数据库交互
- [[file-upload-xxe-lfi]] — 文件读写与数据库配置
