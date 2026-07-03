# 24-database — 数据库攻击技术

## 文档索引

| 文件 | 内容 | 难度 |
|------|------|------|
| [00-overview.md](00-overview.md) | 数据库攻击全景、证据路由与决策树 | 进阶 |
| [01-sqli-fundamentals.md](01-sqli-fundamentals.md) | SQL 注入上下文、DBMS 指纹、盲注抽取 | 进阶 |
| [02-sqli-advanced.md](02-sqli-advanced.md) | 高级 SQLi：WAF绕过、二阶、OOB | 进阶 |
| [03-nosql-injection.md](03-nosql-injection.md) | NoSQL：Mongo 参数解析、Redis/ES/CouchDB | 进阶 |
| [04-config-exposure.md](04-config-exposure.md) | 配置泄露：.env/config.php/默认凭证 | 基础 |
| [05-backup-log-leak.md](05-backup-log-leak.md) | 备份候选生成、日志提取、dump 解析 | 进阶 |
| [06-card-platform.md](06-card-platform.md) | 发卡平台实战：CDK泄露+IDOR+XSS | 综合 |

## 快速入口

- 刚接触数据库攻击 → [00-overview.md](00-overview.md)
- 发现 SQL 注入点 → [01-sqli-fundamentals.md](01-sqli-fundamentals.md)
- WAF 拦截了注入 → [02-sqli-advanced.md](02-sqli-advanced.md)
- MongoDB/Redis 未授权 → [03-nosql-injection.md](03-nosql-injection.md)
- 发现了 .env 或 config.php → [04-config-exposure.md](04-config-exposure.md)
- 想找数据库备份文件 → [05-backup-log-leak.md](05-backup-log-leak.md)
- 打发卡/电商平台 → [06-card-platform.md](06-card-platform.md)
