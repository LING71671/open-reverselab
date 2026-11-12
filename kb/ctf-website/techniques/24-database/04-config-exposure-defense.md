---
id: "ctf-website/24-database/04-config-exposure-defense"
title: "Database Config Exposure Defense — 数据库配置与凭证防泄露"
title_en: "Database Config Exposure Defense — Secrets & Surface Hardening"
summary: >
  防止数据库凭证、连接字符串与支付密钥从应用配置、备份残留、版本控制目录、PHP 源码读取、调试端点与默认弱口令泄露：推行 Web 根目录隔离与 KMS/环境变量注入，Nginx 阻断点文件与备份扩展名，禁用 php://filter 与路径遍历风险点，关闭 phpinfo/Spring Actuator/Django-Flask Debug，淘汰默认密码并最小化凭证作用域。
summary_en: >
  Preventing database credential, DSN, and payment key leaks across configuration files, editor/backup remnants, VCS metadata (.git/.svn), PHP wrapper/LFI reads, debug endpoints (phpinfo, Spring Actuator, Django/Flask debug), and default passwords: webroot isolation with secret-manager injection, reverse-proxy deny rules, open_basedir/allow_url_include hardening, debug shutdown, and credential scoping.
board: "ctf-website"
category: "24-database"
signals:
  - "Webroot 隔离 .env 与 config.php 外移"
  - "Nginx 阻断 .git .svn .bak .swp 访问"
  - "禁用 allow_url_include 与收紧 open_basedir"
  - "关闭 phpinfo Spring Actuator env 与 Debug 模式"
  - "消除默认凭证 root sa postgres 空密码"
  - "数据库凭证与支付密钥独立作用域"
mcp_tools:
  - "kb_router"
  - "kb_read_file"
  - "kb_catalog"
  - "http_probe"
keywords:
  - "配置防泄露"
  - ".env 隔离"
  - "Nginx 阻断"
  - "Git 泄露防护"
  - "phpinfo 关闭"
  - "Actuator 加固"
  - "Debug 模式关闭"
  - "默认密码清理"
  - "密钥管理"
  - "Webroot 隔离"
difficulty: "advanced"
tags:
  - "defense"
  - "blue-team"
  - "database-security"
  - "configuration"
  - "credentials"
  - "secrets-management"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/24-database/04-config-exposure", "ctf-website/24-database/05-backup-log-leak-defense", "ctf-website/24-database/03-nosql-injection-defense"]
track: "blue"
defends: "ctf-website/24-database/04-config-exposure"
---
# Database Config Exposure Defense — 数据库配置与凭证防泄露

> 数据库连接串、`.env`、VCS 元数据或调试端点一旦对外可读，攻击者无需任何注入即可直连核心账本与支付回调。防御的核心是“凭证不入 Web 根目录、配置不随静态资源分发、调试面生产默认关闭”。

## 1. 泄露面与防御控制矩阵

对照 [04-config-exposure.md](04-config-exposure.md) 列举的配置与凭证泄露通道，需在架构、Web 服务器、运行时与账号四层同时收口：

| 泄露入口 | 典型文件/路径 | 根因缺陷 | 防御措施 |
|---|---|---|---|
| Webroot 配置文件 | `.env`, `config/database.php`, `settings.py`, `appsettings.json`, `web.config` | 源码与配置同置于 `DOCUMENT_ROOT`，或未启用解析隔离 | 唯一对外目录设为 `/public`；配置移出 Webroot 并改用 KMS/Secrets 注入 |
| 编辑器与临时备份 | `.bak`, `~`, `.save`, `.swp`, `.old`, `.orig` | 运维/编辑器在生产目录直接编辑留存明文副本 | 禁止在生产容器/Web 目录直接编辑；反代全局拦截敏感后缀 |
| VCS 元数据泄露 | `.git/HEAD`, `.svn/entries`, `.DS_Store` | 使用 `git clone` 直接部署到 Web 目录 | CI/CD 构建产物剥离 `.git`/`.svn`；反代对 `^\.` 路径直接返回 404 |
| PHP 文件读取/LFI | `php://filter/...`, `?page=../../.env`, `....//` | 动态包含/读取未做映射校验，且未限制 `open_basedir` | 改用固定路由表 ID 映射；锁定 `open_basedir` 与 `allow_url_include=Off` |
| Debug 与管理端点 | `phpinfo()`, `/actuator/env`, `DEBUG=True`, Flask PIN | 生产环境遗留调试开关或 Actuator 暴露全量环境变量 | 构建流水线强校验关闭 Debug；Actuator 仅绑定内网管理端口并仅开 `health` |
| 默认弱凭证 | `root:root`, `postgres:postgres`, `sa:sa`, 无密码 Redis | 沿用镜像/安装包默认初始账号 | 启动前注入随机强密码，移除匿名与空口令账号，禁止公网监听 |

## 2. 纵深加固配置

### 2.1 Web 服务器与反向代理拦截基线（Nginx）

确保即使部署包意外遗留点文件或备份文件，对外 HTTP 层也一律拒绝返回（返回 `404` 以避免暴露路径存在性）：

```nginx
# /etc/nginx/conf.d/security-deny.conf
# 1. 阻断所有隐藏文件与目录（.env, .git, .svn, .htaccess, .DS_Store）
location ~ /\.(?!well-known) {
    return 404;
}

# 2. 阻断配置文件、编辑器临时文件、数据库脚本与源码备份后缀
location ~* \.(?:env|ini|conf|cfg|yml|yaml|properties|toml|lock|bak|old|orig|save|swp|swo|tmp|sql|sqlite|db|log)$ {
    return 404;
}

# 3. 限制 Spring Boot Actuator 仅允许内网管理网段访问
location ^~ /actuator {
    allow 127.0.0.1;
    allow 10.0.0.0/8;
    deny all;
}
```

### 2.2 目录隔离与运行时加固（PHP / Java / Python）

1. **目录结构隔离**：Nginx `root` 仅指向 `/srv/app/public`，而 `.env`、`config/`、`vendor/` 位于 `/srv/app/` 上级目录；`.dockerignore` 显式排除 `.git`、`.env*`、`*.bak`、`*.swp`。
2. **PHP 运行时 (`php.ini`)**：

```ini
display_errors = Off
log_errors = On
expose_php = Off
allow_url_fopen = Off
allow_url_include = Off
open_basedir = /srv/app/public:/srv/app/src:/tmp
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,phpinfo
```

3. **Spring Boot (`application-prod.yml`)**：

```yaml
management:
  server:
    address: 127.0.0.1
    port: 18080
  endpoints:
    web:
      exposure:
        include: health,info
  endpoint:
    env:
      show-values: NEVER
```

4. **Django / Flask**：生产配置强制 `DEBUG = False`，通过 `os.environ` 从秘密管理服务读取 `DATABASE_URL`、`STRIPE_SECRET`、`ALIPAY_PRIVATE_KEY` 等，禁止将其写入版本库或打包进前端静态资源。

### 2.3 凭证作用域收敛与网络绑定

- **按服务拆分凭证**：MySQL/PostgreSQL、Redis、支付网关密钥与对象存储 AK/SK 各自独立，严禁跨环境复用同一密码。
- **网络绑定**：数据库与缓存仅监听容器内网或本地 Unix Socket；云 RDS 开启白名单仅放行应用节点安全组。

## 3. 可运行防御自检脚本

以下 Python 脚本可在 CI/CD 发布前扫描待部署目录，自动检出（1）Web 根目录内暴露的 `.env`/`.git`/`.swp`/`.bak`/`phpinfo` 残留；（2）Python/PHP/YAML 配置中开启的 `DEBUG=True`/`APP_DEBUG=true` 或 Actuator 全量暴露；（3）配置文件中存在的默认弱口令 DSN：

```python
#!/usr/bin/env python3
"""Pre-deploy checker for config exposure, VCS leaks, debug flags, and default credentials."""
import re
import tempfile
from pathlib import Path

FORBIDDEN_FILES = {
    ".env", ".env.local", ".env.production", ".ds_store",
    "phpinfo.php", "info.php", "web.config", "appsettings.json",
}
FORBIDDEN_SUFFIXES = (".bak", ".old", ".orig", ".save", ".swp", ".swo", ".tmp")
FORBIDDEN_DIRS = {".git", ".svn"}

DEBUG_PATTERNS = [
    re.compile(r"^\s*DEBUG\s*=\s*True\b", re.M),
    re.compile(r"^\s*APP_DEBUG\s*=\s*true\b", re.I | re.M),
    re.compile(r"display_errors\s*=\s*On\b", re.I),
    re.compile(r"exposure:\s*\n\s*include:\s*['\"]?\*", re.M),
    re.compile(r"phpinfo\s*\(", re.I),
]

WEAK_DSN_PATTERN = re.compile(
    r"(?:mysql|postgres|postgresql|mssql)://(?:root:(?:root)?|postgres:postgres|sa:(?:sa)?)@",
    re.I,
)


def scan_webroot(root: Path) -> list[str]:
    findings: list[str] = []
    for item in root.rglob("*"):
        rel = item.relative_to(root).as_posix()
        if any(part in FORBIDDEN_DIRS for part in item.parts):
            findings.append(f"vcs_artifact:{rel}")
            continue
        if not item.is_file():
            continue
        low_name = item.name.lower()
        if low_name in FORBIDDEN_FILES or low_name.endswith(FORBIDDEN_SUFFIXES):
            findings.append(f"sensitive_file:{rel}")
        if item.suffix.lower() in {".php", ".py", ".env", ".yml", ".yaml", ".ini", ".properties", ".conf"}:
            text = item.read_text(encoding="utf-8", errors="ignore")
            for rx in DEBUG_PATTERNS:
                if rx.search(text):
                    findings.append(f"debug_enabled:{rel}")
                    break
            if WEAK_DSN_PATTERN.search(text):
                findings.append(f"default_credential_dsn:{rel}")
    return sorted(set(findings))


def run_self_check() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        (base / ".git").mkdir()
        (base / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        (base / "config.php.bak").write_text("<?php // backup", encoding="utf-8")
        (base / "settings.py").write_text(
            "DEBUG = True\nDATABASE_URL = 'postgres://postgres:postgres@db:5432/app'\n",
            encoding="utf-8",
        )
        hits = scan_webroot(base)
        assert "vcs_artifact:.git" in hits
        assert "sensitive_file:config.php.bak" in hits
        assert "debug_enabled:settings.py" in hits
        assert "default_credential_dsn:settings.py" in hits

        clean = Path(tmp) / "clean_public"
        clean.mkdir()
        (clean / "index.php").write_text("<?php echo 'ok';", encoding="utf-8")
        assert scan_webroot(clean) == []
    print("[PASS] Config exposure defense self-check succeeded.")


if __name__ == "__main__":
    run_self_check()
```

## 防御工作流

```text
1. 重构部署目录：仅将前端静态入口放入 Web 根目录（/public），配置文件与源码置于上级不可直接路由目录
2. 在构建产物与容器镜像中通过 .dockerignore / 构建脚本剥离 .git、.svn、.env 与编辑器备份文件
3. 配置 Nginx 统一对点文件及 .bak/.swp/.env/.yml/.properties/.log 后缀返回 404
4. 关闭生产环境调试入口：移除 phpinfo、关闭 APP_DEBUG/DEBUG、隔离 Spring Boot Actuator 至内网端口
5. 消除所有数据库默认空口令与弱密码，按最小作用域为每个组件分配独立随机凭证与网络白名单
6. 将 pre-deploy 扫描脚本接入 CI 门禁，阻断含残留配置或默认口令的构建上线
```

## 验证与判定标准

| 检查项 | 验证方法 | 合格标准 | 失败信号 |
|---|---|---|---|
| 配置与备份阻断 | 请求 `/.env`、`/config.php.bak`、`/.git/HEAD` | HTTP 网关统一返回 404（非 403/200）且无文件下载 | 返回 200 明文配置或暴露目录结构 |
| 调试与诊断接口 | 访问 `/actuator/env`、`/info.php` 并触发错误输入 | 管理端点公网不可达，错误页不输出路径、环境变量或堆栈 | 暴露 `DOCUMENT_ROOT`、DSN 或调试 PIN |
| PHP 文件读取防护 | 传入 `php://filter` 及 `../../.env` 路径参数 | 输入被映射表拦截，`open_basedir` 与 `allow_url_include=Off` 生效 | 可通过伪协议或目录穿越读回源码 |
| 凭证强度与隔离 | 核对环境注入与数据库用户权限表 | 无 `root:root`/`sa:sa`/`postgres:postgres`，支付密钥与 DB 账号隔离 | 数据库或支付密钥以默认密码或明文写死在仓库 |

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索配置加固策略 | `kb_router` | 按 `config exposure`、`env isolation`、`actuator hardening` 搜索 |
| 对照高危配置清单 | `kb_read_file` | 读取 [04-config-exposure.md](04-config-exposure.md) 核对各语言框架敏感路径 |
| 浏览数据库防御集 | `kb_catalog` | 查看 `24-database` 系列全量防御文档 |
| 线上路径回归检测 | `http_probe` | 在 `red`/`both` 模式下验证 `.env`/`.git`/`.bak`/`/actuator` 返回 404 |

## 关联技术

- [04-config-exposure.md](04-config-exposure.md) — 配对攻击面：数据库配置泄露
- [05-backup-log-leak-defense.md](05-backup-log-leak-defense.md) — 备份归档、日志掩码化与管理面板隔离
- [03-nosql-injection-defense.md](03-nosql-injection-defense.md) — Redis/MongoDB 认证与内网绑定加固
