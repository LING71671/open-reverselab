---
id: "ctf-website/01-recon/cloudflare-bypass-defense"
title: "CDN / Cloudflare 源站隐藏与防直连加固"
title_en: "Origin Server Hiding & Anti-CDN-Bypass Hardening"
summary: >
  防御通过历史 DNS 记录、TLS 证书 SAN/CN 搜索、子域名漏网解析、外发邮件头、SPF 记录及恶意转发头（CF-Connecting-IP/X-Forwarded-For）定位并直连源站的攻击，构建 Authenticated Origin Pulls、源站 IP 轮换、防火墙白名单与安全邮件出站架构。
summary_en: >
  Hardening origin servers against CDN/Cloudflare bypass via DNS history, certificate transparency searches, unproxied subdomains, outbound mail headers, SPF records, and forged forwarding headers. Implements Authenticated Origin Pulls (mTLS), origin IP rotation, edge allowlisting, and isolated outbound relays.
board: "ctf-website"
category: "01-recon"
signals: ["Cloudflare", "origin IP", "mTLS", "Authenticated Origin Pulls", "源站隐藏", "CDN加固", "CF-Connecting-IP"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["源站隐藏", "Cloudflare加固", "AOP mTLS", "源站白名单", "TLS证书隔离", "外发邮件隔离", "防直连", "blue-team"]
difficulty: "intermediate"
tags: ["defense", "blue-team", "cdn", "cloudflare", "network-security", "tls"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/01-recon/cloudflare-bypass", "ctf-website/02-auth/host-header-defense"]
track: "blue"
defends: "ctf-website/01-recon/cloudflare-bypass"
---
# CDN / Cloudflare 源站隐藏与防直连加固

## 防御目标与威胁面

部署 Cloudflare 等 CDN/WAF 后，若源站仍可被直接探测或连接，边缘防护将形同虚设。攻击者主要通过五类渠道定位并绕过边缘层：

1. **网络边界未封闭**：源站 `80/443` 对 `0.0.0.0/0` 开放，未限制仅允许 CDN 节点 IP 段入站。
2. **TLS 证书特征泄露**：源站直接配置含真实域名的公共 CA 证书（如 Let's Encrypt），被 Censys/Shodan/crt.sh 反查并匹配 `Host` 直连。
3. **历史 DNS 与旁路子域名**：迁移 CDN 前的旧 A 记录仍在历史库中可用，或 `dev`/`mail`/`direct` 子域名未开启代理（Gray Cloud）暴露同网段或同主机。
4. **外发邮件头与 SPF 泄露**：业务服务器直接外发注册/找回密码邮件，`Received` 头或 SPF `ip4:` 直接泄露源站公网 IP。
5. **可信代理头伪造**：源站盲信 `CF-Connecting-IP`、`X-Forwarded-For`、`X-Originating-IP` 等请求头，未校验流量是否真正来自 CDN 边缘节点。

## 核心防御架构

| 暴露途径 | 根治控制措施 | 实施要点 |
|---|---|---|
| 公网直连 80/443 | 云安全组/防火墙严格白名单 + mTLS | 仅放行 Cloudflare 官方 CIDR，并在 Nginx 启用 Authenticated Origin Pulls (AOP) |
| 证书反查关联 | 源站使用 Cloudflare Origin CA 私有证书 | 仅被 Cloudflare 边缘节点信任，公网扫码无公共 SAN 指纹关联 |
| 历史 IP 未失效 | 迁入 CDN 后立即更换源站公网 IP | 旧 IP 彻底释放或销毁，避免历史 DNS 命中 |
| 旁路子域名同驻 | 非代理服务与核心 Web 源站完全物理/VPC 隔离 | 禁用 DNS AXFR 域传送，管理后台迁入 Zero Trust / VPN |
| 邮件与 SPF 暴露 | 外发邮件通过独立第三方中继（SES/Postmark） | 源站不直接连 SMTP 25 端口，SPF 不含源站业务 IP |
| 伪造转发头 | 源站仅对受信任 CDN CIDR 启用 `set_real_ip_from` | 非 CDN 来源剥离或拒绝 `CF-Connecting-IP` |

## 加固配置与离线核查示例

Nginx 源站强隔离配置（启用 Cloudflare AOP 双向 TLS 校验 + 可信真实 IP 提取 + 拒绝未知 Host）：

```nginx
server {
    listen 443 ssl http2;
    server_name app.example.com;

    # 使用 Cloudflare Origin CA 签发的源站证书（非公共 CT 日志证书）
    ssl_certificate     /etc/ssl/origin/origin-cert.pem;
    ssl_certificate_key /etc/ssl/origin/origin-key.pem;

    # 强制启用 Authenticated Origin Pulls (mTLS)，没有 CDN 客户端证书直接 TLS 握手失败
    ssl_client_certificate /etc/ssl/origin/cloudflare-origin-pull-ca.pem;
    ssl_verify_client on;

    # 仅信任 Cloudflare IPv4/IPv6 CIDR 覆盖客户端 IP（需配合自动化脚本定期同步）
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 103.21.244.0/22;
    real_ip_header CF-Connecting-IP;
}

# 默认虚拟主机直接断开非法 Host / IP 直连探测
server {
    listen 80 default_server;
    listen 443 ssl default_server;
    ssl_certificate     /etc/ssl/origin/fallback-selfsigned.pem;
    ssl_certificate_key /etc/ssl/origin/fallback-selfsigned.key;
    return 444;
}
```

以下 Python 检查脚本用于校验源站暴露面基线（安全组 CIDR 范围、mTLS 开启状态及 SPF/AXFR 风险检查）：

```python
import ipaddress
import re
from typing import List, Dict

CLOUDFLARE_SAMPLE_CIDRS = [
    ipaddress.ip_network("173.245.48.0/20"),
    ipaddress.ip_network("103.21.244.0/22"),
    ipaddress.ip_network("104.16.0.0/13"),
]


def evaluate_origin_exposure(
    ingress_cidrs: List[str],
    nginx_conf: str,
    spf_record: str,
    origin_public_ip: str,
) -> Dict[str, object]:
    findings = []

    # 1. 检查防火墙入站规则是否包含 0.0.0.0/0 或非 CDN 网段
    for raw in ingress_cidrs:
        net = ipaddress.ip_network(raw, strict=False)
        if net.prefixlen == 0 or not any(net.subnet_of(cf) for cf in CLOUDFLARE_SAMPLE_CIDRS):
            findings.append(f"non_cdn_ingress_allowed:{raw}")

    # 2. 检查 Nginx 是否开启强制 mTLS 客户端证书校验
    if not re.search(r"ssl_verify_client\s+on\s*;", nginx_conf):
        findings.append("missing_origin_mtls")

    # 3. 检查 SPF 记录是否泄露源站真实公网 IP
    if origin_public_ip in spf_record:
        findings.append("spf_leaks_origin_ip")

    return {"compliant": len(findings) == 0, "findings": findings}


if __name__ == "__main__":
    good_conf = "ssl_verify_client on;\nset_real_ip_from 104.16.0.0/13;"
    res_bad = evaluate_origin_exposure(["0.0.0.0/0"], "listen 443 ssl;", "v=spf1 ip4:203.0.113.10 -all", "203.0.113.10")
    assert res_bad["compliant"] is False
    assert set(res_bad["findings"]) == {"non_cdn_ingress_allowed:0.0.0.0/0", "missing_origin_mtls", "spf_leaks_origin_ip"}

    res_good = evaluate_origin_exposure(["104.16.0.0/16"], good_conf, "v=spf1 include:_spf.mailrelay.example -all", "203.0.113.10")
    assert res_good == {"compliant": True, "findings": []}
    print("Origin hiding defense self-check passed.")
```

## 防御工作流

```text
1. 边缘隔离：源站云安全组清零 0.0.0.0/0 对 80/443 的放行，仅保留 CDN 官方 CIDR 或内网通道
2. 双向认证：源站安装 CDN Origin CA 证书，并强制开启 ssl_verify_client on (mTLS)
3. 历史清理：在完成 CDN 切换与规则生效后，对已存在历史 DNS 记录中的旧源站 IP 执行替换轮换
4. 外发剥离：业务邮件统一切换至外部 SMTP 中继，清理 DNS TXT/SPF 中的源站 IP 片段并关闭 AXFR
5. 可信头限制：网关与源站同步更新 real_ip CIDR 列表，拒绝来自非边缘节点的可信代理头
```

## 验证与判定标准

- **直连不可达**：从非 CDN 公网主机向源站 IP 的 `80/443` 发起 TCP/TLS 请求时，连接被防火墙丢弃或因缺少客户端证书而在 TLS 握手阶段直接中断。
- **证书零公开关联**：使用目标源站 IP 握手返回的证书不含公开有效域名 SAN，且公网 CT 日志中不存在指向当前源站新 IP 的服务。
- **外发与 DNS 零暴露**：抽样注册/重置密码邮件 `Received` 头及域名 SPF 记录均不包含源站实际 IP，DNS `AXFR` 请求返回 `Refused`。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索 CDN 与源站防御知识 | `kb_router` | 以 `Cloudflare`、`origin IP`、`mTLS` 检索蓝队加固条目 |
| 对照攻击面技术细节 | `kb_read_file` | 读取 [cloudflare-bypass.md](cloudflare-bypass.md) 检查所有绕过途径 |
| 浏览侦察防御目录 | `kb_catalog` | 获取 `01-recon` 板块完整红蓝对照表 |
