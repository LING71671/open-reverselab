---
id: "ctf-website/01-recon/fofa-hunting-defense"
title: "公网资产收敛与测绘暴露面防御"
title_en: "External Attack Surface Reduction & Cyberspace Exposure Defense"
summary: >
  防御攻击者利用 FOFA/Shodan/Censys 等网络空间测绘引擎按 org、ASN、证书、响应头和默认指纹批量定位数据库端口、管理后台、配置泄露及脆弱版本组件，建立基于零公网管理面、口令策略、Banner 最小化与持续资产发现的闭环收敛体系。
summary_en: >
  Mitigating automated target discovery via FOFA, Shodan, and Censys across org, ASN, TLS cert, header, and default fingerprint queries. Establishes attack surface reduction through zero public admin/DB exposure, banner minimization, credential hardening, and automated exposure checks.
board: "ctf-website"
category: "01-recon"
signals: ["FOFA", "Shodan", "资产测绘", "暴露面收敛", "数据库端口暴露", "Banner 隐藏", "默认后台"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["暴露面收敛", "资产测绘防御", "FOFA防御", "端口收敛", "零信任接入", "配置泄露防护", "Banner最小化", "blue-team"]
difficulty: "beginner"
tags: ["defense", "blue-team", "attack-surface", "recon-defense", "hardening", "web-security"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/01-recon/fofa-hunting", "ctf-website/01-recon/version-fingerprinting-defense"]
track: "blue"
defends: "ctf-website/01-recon/fofa-hunting"
---
# 公网资产收敛与测绘暴露面防御

## 防御目标与威胁面

网络空间测绘引擎（FOFA、Shodan、Censys、Hunter）持续全网扫描，一旦企业 IP 段、域名或证书关联的脆弱资产上公网暴露，数分钟内就会进入自动化弱口令爆破与 1-day 批量利用队列。高危暴露集中在四类目标：

1. **高危协议直曝公网**：MySQL (`3306`)、Redis (`6379`)、MongoDB (`27017`)、PostgreSQL (`5432`)、MSSQL (`1433`)、SSH (`22`)、RDP (`3389`)、Docker (`2375`) 直接监听公网且未启用双向认证或安全组隔离。
2. **后台与调试面无保护**：`phpMyAdmin`、`Adminer`、`Swagger/OpenAPI`、`Actuator`、`phpinfo()`、企业 OA 管理入口暴露于公网并保留默认/弱口令。
3. **敏感配置与源码目录泄露**：`.git/`、`.env`、`Index of /` 目录列表、`.sql`/`.zip` 备份包、报错详情中的 `DB_PASSWORD` 被测绘爬虫直接抓取索引。
4. **强标识关联拓展**：`Server` / `X-Powered-By` 精确版本号、特定产品 Favicon/Body 指纹、统一 SSL 证书 SAN 与 ICP/Org 归属使同组织全量 C 段资产被一键联动关联。

## 核心防御架构

| 暴露类别 | 根治控制措施 | 目标态基线 |
|---|---|---|
| 数据库/中间件端口 | 严格禁止公网监听，绑定内网 VPC + 隧道/堡垒机接入 | 外网扫描仅开放必要的 `80/443` 网关端口 |
| 管理后台与 API 文档 | 迁入 Zero Trust / VPN / mTLS 网关，生产默认关闭 Swagger 与 Actuator 敏感端点 | 公网访问管理路径直接返回 `404` 或重定向统一 SSO |
| 静态泄露文件 | Web 服务器显式拦截点文件与备份后缀；CI/CD 禁止将 `.env`/`.git` 打入镜像 | 所有 `/.git*`、`/.env*`、`*.bak`/`*.sql` 统一返回 `404` |
| 弱口令与匿名访问 | 禁用匿名 FTP/Redis/MongoDB 无密码模式，强制密钥登录与复杂高熵口令 | 密码认证失败触发账号/IP 渐进退避锁定 |
| 指纹与证书关联 | 清理非必要 Banner 与框架特征头；独立隔离测试与生产环境证书 | 响应不携带 `X-Powered-By` 与精确补丁版本 |

## 加固配置与离线核查示例

Nginx 阻止配置/版本库/备份文件泄露及关闭目录索引配置片段：

```nginx
autoindex off;
server_tokens off;

location ~* /(\.git|\.svn|\.hg|\.env|\.npmrc|\.yarnrc|composer\.(json|lock)|package-lock\.json) {
    return 404;
}

location ~* \.(sql|bak|old|swp|tar\.gz|zip|dump|log)$ {
    return 404;
}
```

以下 Python 策略校验器用于离线检查导出资产清单，自动标记违反暴露面收敛基线的端口、管理路径与指纹信号：

```python
import re
from typing import List, Dict

FORBIDDEN_PUBLIC_PORTS = {21, 22, 1433, 2375, 2379, 3306, 3389, 5432, 6379, 9200, 27017}
SENSITIVE_BODY_PATTERNS = [
    (re.compile(r"Index of /", re.I), "directory_listing_enabled"),
    (re.compile(r"DB_PASSWORD|APP_ENV=|jdbc:mysql://", re.I), "config_leak_exposed"),
    (re.compile(r"\[core\]\s+repositoryformatversion", re.I), "git_metadata_exposed"),
    (re.compile(r"phpinfo\(\)|PHP Version \d+\.\d+", re.I), "debug_page_exposed"),
    (re.compile(r"swagger-ui|openapi\"\s*:", re.I), "api_docs_exposed"),
]


def check_asset_exposure(assets: List[Dict[str, object]]) -> List[Dict[str, object]]:
    violations = []
    for asset in assets:
        issues = []
        port = int(asset.get("port", 0))
        if port in FORBIDDEN_PUBLIC_PORTS and not asset.get("vpn_only", False):
            issues.append(f"forbidden_public_port:{port}")
        banner = str(asset.get("header", "")) + "\n" + str(asset.get("body", ""))
        for rx, tag in SENSITIVE_BODY_PATTERNS:
            if rx.search(banner):
                issues.append(tag)
        if re.search(r"X-Powered-By:\s*\S+", banner, re.I):
            issues.append("version_header_exposed")
        if issues:
            violations.append({"target": f"{asset.get('ip')}:{port}", "issues": issues})
    return violations


if __name__ == "__main__":
    sample_assets = [
        {"ip": "198.51.100.10", "port": 6379, "header": "", "body": "-NOAUTH", "vpn_only": False},
        {"ip": "198.51.100.11", "port": 443, "header": "X-Powered-By: PHP/7.4.3", "body": "DB_PASSWORD=123"},
        {"ip": "198.51.100.12", "port": 443, "header": "Server: edge", "body": "<html>ok</html>"},
    ]
    res = check_asset_exposure(sample_assets)
    assert len(res) == 2
    assert res[0]["issues"] == ["forbidden_public_port:6379"]
    assert set(res[1]["issues"]) == {"config_leak_exposed", "version_header_exposed"}
    print("Asset exposure defense self-check passed.")
```

## 防御工作流

```text
1. 资产清点：汇总组织 ASN、公网 IP 段、域名与证书列表建立唯一资产台账
2. 端口收敛：下线或向内网迁移所有数据库、缓存、管理协议及未授权调试端口
3. 网关拦截：在边缘 WAF 与 Web Server 层统一封堵 /.git、/.env、备份后缀及目录浏览
4. 认证升级：为保留的管理与运维面接入 SSO + MFA 零信任网关，淘汰弱口令与匿名访问
5. 周期自检：每次变更发布后复跑资产端口与 HTTP 特征基线检查，确保零新增高危暴露
```

## 验证与判定标准

- **高危端口公网不可达**：外部探测资产列表中所有 `FORBIDDEN_PUBLIC_PORTS` 均处于阻塞或内网隔离状态。
- **敏感路径返回统一 `404`**：对 `/.git/HEAD`、`/.env`、`/swagger.json`、`/actuator/env`、`/phpinfo.php` 的公网请求均返回统一无特征 `404`。
- **Banner 最小化**：响应头不泄露 `X-Powered-By` 与中间件精确小版本号。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索资产暴露面防御文档 | `kb_router` | 搜索 `暴露面收敛`、`FOFA防御`、`端口收敛` |
| 对照攻击方测绘模式 | `kb_read_file` | 读取 [fofa-hunting.md](../../../../red/ctf-website/techniques/01-recon/fofa-hunting.md) 核查四类高频暴露语法 |
| 关联版本指纹隐藏 | `kb_catalog` | 联动 `version-fingerprinting-defense` 收敛技术栈特征 |
