---
id: "ctf-website/19-dns-email/02-email-spoofing-defense"
title: "邮件伪造防御 — SPF/DKIM/DMARC 严格对齐、显示名同形字过滤与 SMTP/iCal 注入阻断"
title_en: "Email Spoofing Defense — Strict SPF/DKIM/DMARC Alignment, Homograph Filtering & SMTP/iCal Injection Prevention"
summary: >
  针对 SPF 宽松策略与 10 次查询溢出、DKIM 弱密钥及 l= 截断签名、DMARC p=none 与迁移 TTL 窗口、
  显示名/IDN 同形字/零宽字符伪装、Reply-To 与 X-Original-To 劫持、表单 SMTP 头注入及 .ics 日历投毒，
  给出严格 DNS 记录模板、结构化 MIME 发送封装、入站异形发件人检测与可运行验证脚本。
summary_en: >
  Comprehensive defense against email spoofing and injection: strict SPF (-all, <=10 lookups), 2048-bit DKIM without
  l= body truncation, strict DMARC (p=reject, sp=reject, adkim=s, aspf=s), TTL-aware migration, homograph and zero-width
  display-name detection, Reply-To/X-Original-To hardening, and safe MIME/iCal builders with runnable Python checks.
board: "ctf-website"
category: "19-dns-email"
signals: ["SPF -all", "DKIM 2048-bit", "DMARC p=reject", "strict alignment", "SMTP header injection", "iCal injection", "homograph spoofing"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "kb_catalog"]
keywords: ["邮件伪造防御", "SPF严格配置", "DKIM加固", "DMARC p=reject", "显示名伪造检测", "SMTP头注入防御", "iCal安全", "同形字过滤"]
difficulty: "intermediate"
tags: ["defense", "blue-team", "hardening", "email", "spf", "dkim", "dmarc", "smtp"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/19-dns-email/02-email-spoofing", "ctf-website/19-dns-email/01-subdomain-takeover-defense"]
track: "blue"
defends: "ctf-website/19-dns-email/02-email-spoofing"
---

# 邮件伪造防御 — SPF/DKIM/DMARC 严格对齐、显示名同形字过滤与 SMTP/iCal 注入阻断

## 威胁模型与防御目标

邮件伪造并非单一配置疏漏，而是横跨**DNS 认证（SPF/DKIM/DMARC 对齐）**、**邮件客户端渲染（显示名与 Unicode 混淆）**以及**应用发信接口（SMTP 头注入与 `.ics` 日历投毒）**的组合攻击面。对照 [02-email-spoofing.md](02-email-spoofing.md)，蓝队需同步加固出站认证、入站检测与应用层发信代码：

| 攻击向量 | 漏洞根因 | 蓝队加固控制 |
|---|---|---|
| SPF 失效（`+all`/`?all`/`~all`/超 10 次 DNS 查询/宽泛 `include:`） | 软失败或 `permerror` 导致收件方跳过拦截，或共享云商 `include` 允许他租户代发 | 使用 `-all` 硬失败；控制 DNS 查找总数 `<= 8`（保留余量）；移除 `ptr` 与宽泛网段；专用发信子域隔离 |
| DKIM 弱密钥、`t=y` 测试模式与 `l=` 截断签名 | `<1024` 位 RSA 可被分解；`l=` 允许正文尾部追加恶意内容；`t=y` 被接收端忽略 | 升级 >=2048 位 RSA 或 Ed25519；严禁配置 `l=` 与 `t=y`；双 selector 轮换且私钥托管于 KMS |
| DMARC `p=none`/`pct<100`/宽松对齐/子域未覆盖/高 TTL 迁移窗口 | 未拦截伪造邮件，或允许子域宽松对齐及迁移期长达数天的 DNS 缓存窗口 | 强制 `p=reject; sp=reject; pct=100; adkim=s; aspf=s; rua=...`；迁移前先降 TTL 至 `300s`；停发域发布 `v=spf1 -all` + `p=reject` |
| 显示名伪造、IDN 同形字与零宽字符、`Reply-To` / `X-Original-To` 劫持 | 客户端仅展示显示名，或 MTA 信任入站 `X-Original-To` 路由头 | 入站网关剥离外部 `X-Original-To`；检测零宽字符/混合脚本显示名仿冒 VIP；对外部发件人标注醒目横幅并部署 BIMI |
| 联系表单 SMTP 头注入与 `.ics` 日历邀请注入 | 用户输入直接拼接进邮件头或未转义注入 iCalendar 属性与外部 `ATTENDEE` | 拒绝含 `\r`/`\n`/`\x00` 的头字段，使用 `EmailMessage` 结构化构造；转义 iCal 换行/HTML，禁止不可信输入生成外部 `ATTENDEE` |

## 架构加固配置

### 1. 生产域与停发域 DNS 记录基线

```dns
; === 生产发信域 ===
; SPF：仅允许专用发信 IP 与经过租户隔离认证的渠道，严禁 +all/~all/?all 与 ptr
example.com.          IN TXT "v=spf1 ip4:198.51.100.10/32 include:_spf.mailvendor.example -all"

; DKIM：2048-bit RSA（或 Ed25519），严禁设置 l= 与 t=y，通过 selector 年月轮换
s202611._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."

; DMARC：主域与子域均强制 reject，启用严格对齐 (adkim=s; aspf=s) 并接收聚合报告
_dmarc.example.com.   IN TXT "v=DMARC1; p=reject; sp=reject; pct=100; adkim=s; aspf=s; fo=1; rua=mailto:dmarc-rua@example.com"

; === 非发信/停放子域（防止被借壳发信） ===
assets.example.com.   IN TXT "v=spf1 -all"
_dmarc.assets.example.com. IN TXT "v=DMARC1; p=reject; sp=reject; pct=100; adkim=s; aspf=s;"
```

### 2. DNS 策略评估 + 入站同形字检测 + 安全发信与 `.ics` 构造器（Python）

以下 Python 模块可直接用于 **DNS 基线校验**、**入站钓鱼发件人识别** 与 **应用表单发信/日历导出防护**：

```python
import re
import unicodedata
from email.message import EmailMessage


ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")
HEADER_CRLF_RE = re.compile(r"[\r\n\x00]")
EMAIL_ADDR_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


def audit_email_dns_posture(
    spf_record: str | None,
    dkim_records: list[dict],
    dmarc_record: str | None,
    spf_lookup_count: int = 1,
) -> list[str]:
    """核查 SPF/DKIM/DMARC 配置是否满足严格防伪造基线。"""
    issues: list[str] = []

    if not spf_record or not spf_record.startswith("v=spf1"):
        issues.append("missing valid SPF record")
    else:
        tokens = spf_record.split()
        if not tokens or tokens[-1] != "-all":
            issues.append("SPF must terminate with hard fail (-all)")
        if "ptr" in tokens:
            issues.append("SPF contains deprecated ptr mechanism")
        if spf_lookup_count > 10:
            issues.append(f"SPF DNS lookup count {spf_lookup_count} exceeds RFC 7208 limit (10)")
        for tok in tokens:
            if tok.startswith("ip4:") and "/" in tok and int(tok.split("/", 1)[1]) <= 16:
                issues.append(f"SPF ip4 CIDR overly broad: {tok}")

    if not dkim_records:
        issues.append("no active DKIM selector configured")
    for rec in dkim_records:
        txt = rec.get("record", "")
        bits = rec.get("key_bits", 0)
        if bits < 2048:
            issues.append(f"DKIM selector {rec.get('selector')} key_bits={bits} (<2048)")
        if re.search(r"(?:^|;\s*)l=", txt):
            issues.append(f"DKIM selector {rec.get('selector')} uses dangerous l= body length tag")
        if re.search(r"(?:^|;\s*)t=y\b", txt):
            issues.append(f"DKIM selector {rec.get('selector')} still in test mode (t=y)")

    if not dmarc_record or not dmarc_record.startswith("v=DMARC1"):
        issues.append("missing valid DMARC record")
    else:
        required_tags = ("p=reject", "sp=reject", "adkim=s", "aspf=s")
        for tag in required_tags:
            if tag not in dmarc_record:
                issues.append(f"DMARC missing strict tag: {tag}")
        pct_match = re.search(r"\bpct=(\d+)", dmarc_record)
        if pct_match and int(pct_match.group(1)) < 100:
            issues.append("DMARC pct must be 100")
        if "rua=" not in dmarc_record:
            issues.append("DMARC missing rua= reporting URI")

    return issues


def detect_display_name_and_homograph_spoof(
    display_name: str,
    sender_address: str,
    org_domain: str,
    protected_names: set[str],
) -> list[str]:
    """识别入站邮件中的零宽字符、混合脚本 IDN 同形字与外部假冒内部显示名。"""
    alerts: list[str] = []
    if ZERO_WIDTH_RE.search(display_name) or ZERO_WIDTH_RE.search(sender_address):
        alerts.append("zero-width-unicode-obfuscation")

    local, _, domain = sender_address.rpartition("@")
    is_external = domain.lower() != org_domain.lower()

    # 检查非 ASCII 同形字符（例如西里尔 'а' / 'ƒ' 混入拉丁域名或本地部分）
    if any(ord(ch) > 127 for ch in sender_address):
        alerts.append("non-ascii-homograph-in-address")

    norm_display = unicodedata.normalize("NFKC", display_name).strip().casefold()
    if is_external and norm_display in {n.casefold() for n in protected_names}:
        alerts.append("external-sender-impersonating-protected-display-name")

    return alerts


def build_safe_contact_email(
    sender_from: str,
    reply_to_input: str,
    recipient_to: str,
    subject_input: str,
    body_text: str,
) -> EmailMessage:
    """使用结构化 EmailMessage 并严格拒绝 CRLF/Null 注入，杜绝 SMTP 头注入。"""
    for field_name, val in (("reply_to", reply_to_input), ("subject", subject_input)):
        if HEADER_CRLF_RE.search(val):
            raise ValueError(f"CRLF or null byte detected in {field_name}")

    cleaned_reply = reply_to_input.strip()
    if not EMAIL_ADDR_RE.fullmatch(cleaned_reply):
        raise ValueError("invalid reply-to email format")

    msg = EmailMessage()
    msg["From"] = sender_from  # 固定为本域受信任发件地址，不由用户输入覆盖
    msg["To"] = recipient_to
    msg["Reply-To"] = cleaned_reply
    msg["Subject"] = subject_input.strip()[:150]
    msg.set_content(body_text)
    return msg


def _escape_ical_text(value: str) -> str:
    """按 RFC 5545 转义文本并剔除换行控制符，防止 iCal 属性注入。"""
    cleaned = re.sub(r"[\r\n\x00]", " ", value)
    cleaned = re.sub(r"<[^>]+>", "", cleaned)  # 剥离 HTML 钓鱼链接标签
    return cleaned.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,")


def build_safe_ics_invite(uid: str, summary: str, description: str, organizer_email: str) -> str:
    """生成不可注入额外 ATTENDEE/CN 属性的安全 .ics 日历文本。"""
    if HEADER_CRLF_RE.search(organizer_email) or not EMAIL_ADDR_RE.fullmatch(organizer_email):
        raise ValueError("invalid organizer email")
    return "\r\n".join([
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//SecureApp//Calendar//EN",
        "BEGIN:VEVENT",
        f"UID:{_escape_ical_text(uid)}",
        f"SUMMARY:{_escape_ical_text(summary)}",
        f"DESCRIPTION:{_escape_ical_text(description)}",
        f"ORGANIZER:mailto:{organizer_email}",
        "END:VEVENT",
        "END:VCALENDAR",
        "",
    ])
```

## 防御工作流

1. **清点发信来源与 DNS 查找预算**：列出所有合法第三方邮件网关，合并并精简 `include:` 链，确保 SPF DNS 解析次数低于 10 次且以 `-all` 结尾，停发子域统一设置 `v=spf1 -all`。
2. **升级 DKIM 签名规范**：淘汰 1024 位以下旧密钥，切换为 2048 位 RSA 或 Ed25519，移除 `l=`（防止尾部正文拼接）与 `t=y`，开启定期轮换。
3. **平滑收紧 DMARC 至严格拒绝**：迁移前先将 `_dmarc` TTL 降至 `300s`，观测 `rua=` 聚合报告确认全部业务邮件 SPF+DKIM 对齐通过后，切换至 `p=reject; sp=reject; pct=100; adkim=s; aspf=s;` 再恢复常规 TTL。
4. **入站网关防钓鱼强化**：在邮件网关剥离外部传入的 `X-Original-To` 路由头，对外部发件人显示醒目标识，开启零宽字符、IDN 同形字与 VIP 显示名撞库拦截，并为品牌域部署 BIMI。
5. **应用发信与 `.ics` 出口改造**：禁止直接字符串拼接 SMTP 头部；在表单发信前强制执行 CRLF/Null 校验并固定 `From` 为本域系统邮箱；所有用户可控 `.ics` 邀请剥离 HTML 并按 RFC 5545 转义。

## 验证与判定标准

运行下方回归脚本，验证严格 DNS 策略判定、同形字/零宽字符识别、SMTP 头注入拦截与 `.ics` 注入转义：

```python
def run_self_checks() -> None:
    # 1. 合规 DNS 基线零告警，弱配置精确告警
    good_issues = audit_email_dns_posture(
        spf_record="v=spf1 ip4:198.51.100.10/32 -all",
        dkim_records=[{"selector": "s202611", "key_bits": 2048, "record": "v=DKIM1; k=rsa; p=MIIBIj..."}],
        dmarc_record="v=DMARC1; p=reject; sp=reject; pct=100; adkim=s; aspf=s; rua=mailto:dmarc@example.com",
        spf_lookup_count=2,
    )
    assert good_issues == []

    bad_issues = audit_email_dns_posture(
        spf_record="v=spf1 ip4:10.0.0.0/8 ~all",
        dkim_records=[{"selector": "old", "key_bits": 1024, "record": "v=DKIM1; k=rsa; l=100; t=y; p=MIGf..."}],
        dmarc_record="v=DMARC1; p=none; pct=50;",
        spf_lookup_count=12,
    )
    assert len(bad_issues) >= 7

    # 2. 零宽字符、IDN 同形字与 VIP 显示名仿冒检测
    alerts1 = detect_display_name_and_homograph_spoof(
        "Admin",
        "a\u200bdmin@evil.example",
        "example.com",
        {"Admin", "Support"},
    )
    assert "zero-width-unicode-obfuscation" in alerts1
    assert "external-sender-impersonating-protected-display-name" in alerts1

    alerts2 = detect_display_name_and_homograph_spoof(
        "Billing",
        "in\u0192o@example.com",
        "example.com",
        {"Admin"},
    )
    assert "non-ascii-homograph-in-address" in alerts2

    # 3. SMTP 头注入（CRLF / Bcc）必须抛出 ValueError
    try:
        build_safe_contact_email(
            "noreply@example.com",
            "attacker@evil.example\r\nBcc: victim@example.com",
            "support@example.com",
            "Hello",
            "Body",
        )
        raise AssertionError("Expected ValueError on CRLF header injection")
    except ValueError:
        pass

    safe_msg = build_safe_contact_email(
        "noreply@example.com",
        "user@partner.example",
        "support@example.com",
        "Support Inquiry",
        "Need help.",
    )
    assert safe_msg["From"] == "noreply@example.com" and safe_msg["Reply-To"] == "user@partner.example"

    # 4. .ics 注入换行与 HTML 链接必须被中和，不可产生新 ATTENDEE 行
    ics = build_safe_ics_invite(
        "evt-1",
        "Team Sync\r\nATTENDEE:mailto:victim@example.com",
        'Join <a href="https://evil.example">here</a>; details',
        "calendar@example.com",
    )
    assert "\r\nATTENDEE:" not in ics
    assert "<a " not in ics and "\\;" in ics

    print("[PASS] All email spoofing defense checks passed.")


if __name__ == "__main__":
    run_self_checks()
```

判定通过标准：
- `SPF` 仅以 `-all` 结尾且 DNS 查询数 `<= 10`，停发域均配置 `v=spf1 -all`；
- `DKIM` 全部使用 >=2048 位密钥，不含 `l=` 与 `t=y` 标记；
- `DMARC` 强制 `p=reject; sp=reject; pct=100; adkim=s; aspf=s;` 并完整配置 `rua=` 监控；
- 表单发信与 `.ics` 导出严格拒绝 CRLF 注入，对非预期地址与同形字告警生效。

## MCP 工具映射

| 防御阶段 | MCP 工具 | 用途说明 |
|---|---|---|
| 发信表单与 HTTP 端点核查 | `http_probe` | 检查联系表单、`.ics` 下载端点对异常换行与畸形参数的处理结果 |
| 关联防御知识检索 | `kb_router` | 按 `SPF`、`DKIM`、`DMARC`、`email defense` 检索相关知识 |
| 读取技术细节 | `kb_read_file` | 对照攻击文档 [02-email-spoofing.md](02-email-spoofing.md) 核验全链绕过防护 |
| 知识目录定位 | `kb_catalog` | 查看 `19-dns-email` 板块全部加固与配置指南 |
