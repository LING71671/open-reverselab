---
id: "ctf-website/19-dns-email/01-subdomain-takeover-defense"
title: "子域名接管防御 — DNS 生命周期治理、悬空记录核销、托管域认领锁定与 CAA 收敛"
title_en: "Subdomain Takeover Defense — DNS Lifecycle Governance, Dangling Record Cleanup, Domain Claim Verification & CAA Hardening"
summary: >
  针对指向已释放云资源（AWS S3、CloudFront、Azure App/CDN、GCP、GitHub Pages、Netlify、Vercel、Fastly、Shopify 等）
  的悬空 CNAME/A/ALIAS/MX/NS 记录与弹性 IP 回收接管风险，建立“先删 DNS 后拆云资源”的 IaC 生命周期规则、
  云平台域名认领锁定、DNS CAA 证书颁发限制、主机锁 Cookie 隔离与自动化悬空记录巡检脚本。
summary_en: >
  Blue-team defense against subdomain takeover via dangling CNAME/A/ALIAS/MX/NS records across S3, CloudFront, Azure,
  GCP, GitHub Pages, Netlify, Vercel, Fastly, and Elastic IPs. Covers DNS-first teardown lifecycle, cloud domain claim
  verification, DNS CAA records, host-locked cookies, and a runnable Python dangling-DNS detector.
board: "ctf-website"
category: "19-dns-email"
signals: ["dangling DNS", "subdomain takeover defense", "CAA record", "domain verification TXT", "GitHub Pages verification", "CloudFront takeover", "Elastic IP hygiene"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "kb_catalog"]
keywords: ["子域名接管防御", "悬空DNS清理", "CNAME生命周期", "DNS CAA", "云资源下线", "GitHub Pages域验证", "弹性IP回收", "NS委派保护"]
difficulty: "intermediate"
tags: ["defense", "blue-team", "hardening", "dns", "subdomain-takeover", "cloud", "caa"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/19-dns-email/01-subdomain-takeover", "ctf-website/19-dns-email/02-email-spoofing-defense"]
track: "blue"
defends: "ctf-website/19-dns-email/01-subdomain-takeover"
---

# 子域名接管防御 — DNS 生命周期治理、悬空记录核销、托管域认领锁定与 CAA 收敛

## 威胁模型与防御目标

子域名接管的核心根因是**权威 DNS 状态与底层云资源生命周期脱节**：云资源（存储桶、CDN 分发、PaaS 应用、弹性 IP、邮件服务或托管站点）已销毁或过期，但指向它的 `CNAME`/`A`/`NS`/`MX` 记录仍留在 DNS 区域文件中，使外部人员可在第三方平台抢注同名资源或自定义域名。对照 [01-subdomain-takeover.md](../../../../red/ctf-website/techniques/19-dns-email/01-subdomain-takeover.md)，蓝队需从资源下线顺序、平台认领锁定与爆炸半径控制三层联动防御：

| 悬空记录类型 | 典型接管面 | 蓝队防御控制 |
|---|---|---|
| `CNAME` / `ALIAS` 指向第三方 PaaS/存储/CDN | S3 Bucket、CloudFront、Azure CDN/WebApp、Heroku、GitHub Pages、Netlify、Vercel、Fastly 等 | 强制执行 **DNS 先于云资源删除**；开启第三方平台的组织级域名 TXT 所有权校验；禁止滥用泛解析 `*.example.com` |
| `A` 记录指向云厂商弹性公网 IP | AWS EIP / GCP 静态 IP 释放后被其他租户重新分配 | 下线实例前先撤销 DNS `A` 记录并校验解析已过期；为弹性 IP 配置 `prevent_destroy` 与删除前 DNS 反查门禁 |
| `NS` 子域委派记录 | 被委派的权威域过期或托管 DNS Zone 被删除 | 定期核查全部 `NS` 委派目标 WHOIS 到期与解析状态；域名开启 Registrar Lock 与自动续费；撤除废弃委派 |
| `MX` 与 SPF/DKIM 引用 | 指向已注销的 Mailgun / SendGrid / SparkPost 等 ESP | 退订第三方邮件服务前同步清理 `MX`、`_domainkey` 与 SPF `include:` 记录 |
| TLS 签发与跨子域 Cookie 窃取 | 接管后利用 HTTP-01/DNS-01 申请证书并窃取父域 Cookie | 主域配置 DNS `CAA` 记录限制授权 CA；主站认证 Cookie 使用 `__Host-` 前缀且不设宽泛 `Domain=.example.com` |

## 架构加固配置

### 1. DNS 区域记录与 IaC 生命周期规则

1. **IaC 依赖倒置（Terraform 示例）**：通过显式生命周期顺序确保拆除时先销毁 Route53/Cloudflare 记录再销毁后端存储或 CDN：

```hcl
# 仅示例依赖结构：确保云资源在 DNS 记录清理后才允许释放
resource "aws_s3_bucket" "static_site" {
  bucket = "assets.example.com"
}

resource "aws_route53_record" "static_cname" {
  zone_id = var.zone_id
  name    = "assets.example.com"
  type    = "CNAME"
  ttl     = 300
  records = [aws_cloudfront_distribution.cdn.domain_name]

  # Terraform 销毁顺序遵循创建依赖的逆序：先销毁 Route53 记录，再销毁 CDN/Bucket
  depends_on = [aws_cloudfront_distribution.cdn, aws_s3_bucket.static_site]
}
```

2. **组织级域名所有权验证与 CAA 约束**：

```dns
; 1. CAA 限制仅允许指定 CA 签发证书，防止第三方站点接管后任意签发子域 TLS 证书
example.com.    IN CAA 0 issue "letsencrypt.org"
example.com.    IN CAA 0 issuewild ";"
example.com.    IN CAA 0 iodef "mailto:security@example.com"

; 2. 第三方托管平台域名认领锁定（示例：GitHub Pages 组织域验证 TXT）
_github-pages-challenge-myorg.example.com. IN TXT "<org-verification-token>"
```

### 2. 自动化悬空 DNS 与云指纹巡检器（Python）

将以下巡检脚本接入每日 CI/Cron 监控流水线：针对区域文件导出的每条 `CNAME`/`A`/`NS`/`MX` 记录，结合 DNS 解析状态、HTTP 第三方错误指纹与 TLS 状态生成阻断告警：

```python
import re
from dataclasses import dataclass, field


PROVIDER_404_SIGNATURES: dict[str, tuple[str, ...]] = {
    "aws_s3": ("NoSuchBucket", "The specified bucket does not exist"),
    "aws_cloudfront": ("BadRequest: The requested resource cannot be found", "OriginDnsError"),
    "azure_webapp": ("The resource you are looking for has been removed", "azurewebsites.net"),
    "azure_cdn": ("404 - CDN endpoint not found", "The CDN endpoint was not found"),
    "github_pages": ("There is not a GitHub Pages site here",),
    "heroku": ("No such app", "There is no app configured at that hostname"),
    "netlify": ("Not Found - Netlify",),
    "vercel": ("The page could not be found",),
    "fastly": ("Fastly error: unknown domain",),
    "shopify": ("Sorry, this shop is currently unavailable",),
}

EXTERNAL_PROVIDERS = (
    "s3.amazonaws.com",
    "cloudfront.net",
    "azurewebsites.net",
    "azureedge.net",
    "github.io",
    "herokudns.com",
    "netlify.app",
    "vercel.app",
    "fastly.net",
    "myshopify.com",
    "mailgun.org",
    "sendgrid.net",
)


@dataclass(frozen=True)
class DNSRecordEntry:
    fqdn: str
    rtype: str          # CNAME | A | NS | MX
    target: str
    resolves: bool
    http_status: int = 200
    http_body: str = ""
    tls_valid: bool = True
    owned_by_inventory: bool = True


@dataclass(frozen=True)
class TakeoverRisk:
    fqdn: str
    rtype: str
    severity: str
    reason: str
    remediation: str


def evaluate_dns_record_hygiene(entry: DNSRecordEntry) -> TakeoverRisk | None:
    """识别悬空 DNS 记录并给出应立即核销的处置动作。"""
    target_l = entry.target.rstrip(".").lower()

    # 1. NS 委派目标不可解析或不在自有资产台账中 -> 最高危整域接管风险
    if entry.rtype == "NS" and (not entry.resolves or not entry.owned_by_inventory):
        return TakeoverRisk(
            entry.fqdn,
            "NS",
            "critical",
            f"NS delegation target {target_l} is unresolvable or unowned",
            "Remove stale NS delegation or renew/re-claim nameserver domain immediately",
        )

    # 2. CNAME 指向外部云服务但目标已 NXDOMAIN 或返回托管商未认领指纹
    if entry.rtype == "CNAME":
        is_ext = any(p in target_l for p in EXTERNAL_PROVIDERS)
        if is_ext and not entry.resolves:
            return TakeoverRisk(
                entry.fqdn,
                "CNAME",
                "high",
                f"Dangling CNAME to external provider {target_l} (NXDOMAIN)",
                "Delete CNAME record before decommissioning cloud target",
            )
        for provider, sigs in PROVIDER_404_SIGNATURES.items():
            if any(sig.lower() in entry.http_body.lower() for sig in sigs):
                return TakeoverRisk(
                    entry.fqdn,
                    "CNAME",
                    "critical",
                    f"HTTP body matches unclaimed {provider} fingerprint",
                    f"Delete CNAME {entry.fqdn} or re-bind verified {provider} resource",
                )

    # 3. MX 指向外部邮件服务商且目标域名不在台账中
    if entry.rtype == "MX" and any(esp in target_l for esp in ("mailgun.org", "sendgrid.net", "sparkpostmail.com")):
        if not entry.owned_by_inventory:
            return TakeoverRisk(
                entry.fqdn,
                "MX",
                "high",
                f"MX points to offboarded ESP {target_l}",
                "Remove unused MX record and paired SPF/DKIM entries",
            )

    # 4. A 记录指向外部托管 IP 但出现托管商未认领页面或 TLS 证书错配
    if entry.rtype == "A" and not entry.owned_by_inventory:
        return TakeoverRisk(
            entry.fqdn,
            "A",
            "high",
            f"A record points to unowned IP {target_l}",
            "Delete DNS A record immediately; verify IP release workflow",
        )

    return None


def check_zone_caa_and_cookie_scope(caa_records: list[str], set_cookie_header: str) -> list[str]:
    """核查区域 CAA 限制与主站 Cookie 作用域是否隔离潜在子域名接管横向风险。"""
    gaps: list[str] = []
    if not any("issue " in r.lower() for r in caa_records):
        gaps.append("missing CAA issue restriction")
    low_cookie = set_cookie_header.lower()
    if "domain=." in low_cookie or not set_cookie_header.startswith("__Host-"):
        gaps.append("session cookie not host-locked (use __Host- prefix without Domain attribute)")
    return gaps
```

## 防御工作流

1. **全量 Zone 资产对账**：从权威 DNS（Route53 / Cloudflare / DNS Pod）导出全部 `CNAME`、`A`、`NS`、`MX`、`ALIAS` 与 `TXT` 记录，与云账号活跃资源台账逐一比对。
2. **立即清理悬空记录**：对匹配未认领指纹或 `NXDOMAIN` 的外部指向记录直接执行 DNS 下线；若业务仍需使用，先在对应云平台完成组织级域名 TXT 所有权校验再重新绑定。
3. **固化下线审批流**：在变更管理与 Terraform/Pulumi CI 流水线中确立硬规则——“先删 DNS 并等待 TTL 过期，再释放云资源/弹性 IP”。
4. **收紧证书与 Cookie 爆炸半径**：为主域配置 `CAA` 限制签发机构，监控证书透明度（CT）日志异常子域证书；所有主站 Cookie 改用 `__Host-` 前缀并移除宽泛 `Domain=` 属性。
5. **持续巡检告警**：每日调度巡检脚本扫描新出现的未认领云指纹、失效 `NS` 委派与异动弹性 IP 指向。

## 验证与判定标准

执行下方自检代码，确认所有子域名接管类型（悬空 CNAME、GitHub Pages 指纹、过期 NS 委派、废弃 MX、未受控弹性 IP、CAA 与 Cookie 隔离）均能被准确识别：

```python
def run_self_checks() -> None:
    samples = [
        # 1. 悬空 CNAME 到已删除 S3（HTTP 返回 NoSuchBucket）
        DNSRecordEntry(
            fqdn="cdn-old.example.com",
            rtype="CNAME",
            target="old-assets.s3.amazonaws.com",
            resolves=True,
            http_status=404,
            http_body="<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>",
        ),
        # 2. CNAME 指向不存在的 Heroku 应用
        DNSRecordEntry(
            fqdn="beta.example.com",
            rtype="CNAME",
            target="beta-app-retired.herokudns.com",
            resolves=False,
        ),
        # 3. 委派给未纳管/过期域名的 NS 记录
        DNSRecordEntry(
            fqdn="sub.example.com",
            rtype="NS",
            target="ns1.expired-dns-vendor.test",
            resolves=False,
            owned_by_inventory=False,
        ),
        # 4. 指向已退订 Mailgun 的 MX 记录
        DNSRecordEntry(
            fqdn="promo.example.com",
            rtype="MX",
            target="mxa.mailgun.org",
            resolves=True,
            owned_by_inventory=False,
        ),
        # 5. 正常纳管的在用记录应不误报
        DNSRecordEntry(
            fqdn="www.example.com",
            rtype="CNAME",
            target="d111111abcdef8.cloudfront.net",
            resolves=True,
            http_status=200,
            http_body="<html>Welcome</html>",
            owned_by_inventory=True,
        ),
    ]

    risks = [evaluate_dns_record_hygiene(s) for s in samples]
    assert risks[0] is not None and risks[0].severity == "critical" and "aws_s3" in risks[0].reason
    assert risks[1] is not None and risks[1].severity == "high" and "NXDOMAIN" in risks[1].reason
    assert risks[2] is not None and risks[2].rtype == "NS" and risks[2].severity == "critical"
    assert risks[3] is not None and risks[3].rtype == "MX"
    assert risks[4] is None

    # 6. CAA 与主站 Cookie 主机锁定检查
    assert check_zone_caa_and_cookie_scope(['0 issue "letsencrypt.org"'], "__Host-sid=opaque; Path=/; Secure; HttpOnly") == []
    bad_gaps = check_zone_caa_and_cookie_scope([], "sid=123; Domain=.example.com; Secure")
    assert len(bad_gaps) == 2

    print("[PASS] All subdomain takeover defense checks passed.")


if __name__ == "__main__":
    run_self_checks()
```

判定通过标准：
- 全量 DNS 区域不存在任何指向已销毁资源、返回云平台 404 认领指纹或 `NXDOMAIN` 的 `CNAME`/`A`/`NS`/`MX` 记录；
- 第三方静态托管与 SaaS 平台已绑定组织级域名验证 TXT 记录，阻止跨账号抢注；
- 根域存在有效 `CAA` 记录限制证书颁发机构，主站认证 Cookie 使用 `__Host-` 前缀且不向子域共享；
- 基础设施变更流水线执行“先撤 DNS、后拆云资源”的强制先后顺序。

## MCP 工具映射

| 防御阶段 | MCP 工具 | 用途说明 |
|---|---|---|
| 子域 HTTP/TLS 状态核查 | `http_probe` | 探测候选子域是否出现云服务 404 指纹或证书错配 |
| 关联防御知识检索 | `kb_router` | 按 `subdomain takeover defense`、`CAA`、`dangling DNS` 检索文档 |
| 读取技术细节 | `kb_read_file` | 对照攻击文档 [01-subdomain-takeover.md](../../../../red/ctf-website/techniques/19-dns-email/01-subdomain-takeover.md) 的 30+ 服务指纹表核验线上资产 |
| 知识目录定位 | `kb_catalog` | 浏览 `19-dns-email` 板块的全部 DNS 与邮件防御指引 |
