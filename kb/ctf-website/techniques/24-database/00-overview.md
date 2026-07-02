---
id: "ctf-website/24-database/00-overview"
title: "Database Attack Surface — 数据库攻击全景与决策树"
title_en: "Database Attack Surface — Overview & Decision Tree"
summary: >
  数据库攻击全景导航：覆盖应用层SQL/NoSQL注入与ORM注入、配置层默认凭证与连接字符串泄露、运维层备份文件暴露与日志泄露、数据层SSRF内网数据库可达等四大攻击面。提供快速决策树路线：SQL错误→注入基础、WAF拦截→绕过技术、NoSQL端点→NoSQL注入等。
summary_en: >
  Database attack surface navigation covering four layers: application (SQL/NoSQL/ORM injection), configuration (default credentials, connection string leaks), operations (backup file exposure, log leaks), and data (SSRF to internal databases). Includes quick decision tree routing from signals to specific technique documents.
board: "ctf-website"
category: "24-database"
signals:
  - "SQL 注入 injection"
  - "NoSQL 注入 MongoDB Redis"
  - "默认密码 default credentials"
  - "备份文件 .sql .dump"
  - "phpMyAdmin Adminer 未授权"
  - "连接字符串泄露 .env"
  - "SSRF 内网数据库"
  - "ORM 注入 HQL JPQL"
mcp_tools:
  - "kb_router"
  - "kb_read_file"
keywords:
  - "数据库攻击"
  - "SQL 注入"
  - "NoSQL 注入"
  - "数据库配置泄露"
  - "备份文件暴露"
  - "database attack surface"
  - "default credentials"
  - "connection string leak"
  - "MySQL PostgreSQL MongoDB"
  - "phpMyAdmin"
difficulty: "beginner"
tags:
  - "database"
  - "sql-injection"
  - "nosql"
  - "configuration"
  - "backup"
  - "overview"
language: "zh-CN"
last_updated: "2026-06-25"
related_articles: []
---
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

## 攻击链 / 工作流

```
1. 资产枚举：域名、目录、API、管理后台、数据库端口、备份文件名
2. 信号分类：SQL 报错 / NoSQL 参数 / 配置文件 / 备份日志 / 平台特征
3. 路由文档：按信号进入 01-07 对应技术文档，不在概览页直接深挖
4. 低风险验证：只确认可控表达式、布尔差异、文件可读性或未授权访问
5. 证据固化：保存请求、响应、时间差、错误栈、文件哈希和脱敏字段样例
6. 横向关联：配置泄露 → 数据库登录；备份泄露 → 表结构；SQLi → 文件读写
7. 收敛结论：写入 notes/reports，明确影响面、利用条件和修复优先级
```

## Evidence

| 证据类型 | 记录内容 |
|----------|----------|
| HTTP 证据 | URL、参数、请求方法、状态码、关键响应片段 |
| 数据库指纹 | DBMS 类型、版本、报错函数、时间函数差异 |
| 文件泄露 | 文件路径、大小、哈希、脱敏字段样例 |
| 权限边界 | 未授权/低权限/管理员权限的对比请求 |
| 影响面 | 可读表、可枚举订单、可下载备份、可访问管理工具 |

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 按信号路由 | `kb_router` | 输入 SQLi、NoSQL、备份、配置泄露等信号 |
| 读取技术文档 | `kb_read_file` | 打开对应 24-database 子文档 |
| HTTP 探测 | `http_probe` | 验证端点、状态码、响应差异 |
| 执行 Web 工具 | `run_ctf_tool` | 调用 sqlmap、git-dumper、目录枚举等工具 |
| 证据记录 | `workspace_write_text` | 写入 notes/reports 的复现证据 |

## 关联技术

- [[sqli-nosqli]] — SQL/NoSQL 注入
- [[01-idor-enumeration]] — IDOR 与数据库枚举
- [[payment-php]] — PHP 支付与数据库交互
- [[file-upload-xxe-lfi]] — 文件读写与数据库配置
