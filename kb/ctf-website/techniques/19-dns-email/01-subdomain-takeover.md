# 子域名接管深度

## 场景

目标组织使用了第三方云服务托管子域名，但该服务被停用或 DNS 记录未被清理。攻击者注册该服务上已释放的资源 (S3 bucket, CloudFront distribution, GitHub Pages 站点等)，从而完全控制该子域名。CTF 中通常表现为: 某个子域名指向已删除的云服务资源，攻击者注册该资源后能托管任意内容，进而窃取 cookie、绕过 CSP 同源检查或实施钓鱼。

## 输入信号

```
DNS CNAME 记录指向未知 / 不存在的云服务端点
HTTP 响应包含特定云服务的 404/403 错误页 (NoSuchBucket, BadRequest 等)
SSL/TLS 证书颁发失败 (指向已删除的 CloudFront)
子域名通过 dig/nslookup 返回 NXDOMAIN 但 CNAME 仍存在 (dangling CNAME)
网页引用子域名加载的资源 (script/img src) 返回特定云服务错误
子域名被第三方 CDN/WAF 代理但后端源站已不存在
```

## 1. Cloud Service Fingerprints

不同的云服务在被接管后有不同的指纹信号。快速识别服务类型是接管的关键。

```python
# takeover_fingerprints.py — 云服务指纹库
TAKEOVER_SIGNATURES = {
    # AWS S3
    'aws_s3': {
        'detect': [
            'NoSuchBucket',
            'The specified bucket does not exist',
            'The bucket you are attempting to access must be addressed',
            '404 Not Found (S3)',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.s3.amazonaws.com',
        'takeover': 'aws s3 mb s3://<bucket-name>',
    },
    # AWS CloudFront
    'aws_cloudfront': {
        'detect': [
            'BadRequest: The requested resource cannot be found',
            'CloudFront: The origin server did not find a current representation',
            'X-Amz-Cf-Error: OriginDnsError',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.cloudfront.net',
        'takeover': 'Create CloudFront distribution with custom origin',
    },
    # Azure
    'azure_cloudapp': {
        'detect': [
            'The resource you are looking for has been removed',
            'was not found (azurewebsites.net)',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.azurewebsites.net',
        'takeover': 'az webapp create --name <name>',
    },
    'azure_cdn': {
        'detect': [
            '404 - CDN endpoint not found',
            'The CDN endpoint was not found',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.azureedge.net',
        'takeover': 'Create Azure CDN endpoint with same name',
    },
    # GCP / Google Cloud
    'gcp_storage': {
        'detect': [
            'NoSuchBucket (storage.googleapis.com)',
            'The specified bucket does not exist (gs)',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.storage.googleapis.com',
        'takeover': 'gsutil mb gs://<bucket-name>',
    },
    'gcp_appengine': {
        'detect': [
            '404 Not Found (App Engine)',
            'This site is not available (Google App Engine)',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.appspot.com',
        'takeover': 'Deploy App Engine app with matching project ID',
    },
    # Heroku
    'heroku': {
        'detect': [
            'No such app (Heroku)',
            'There is no app configured at that hostname',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.herokudns.com',
        'takeover': 'heroku create --app <name> && heroku domains:add',
    },
    # GitHub Pages
    'github_pages': {
        'detect': [
            '404: Not Found (GitHub Pages)',
            'There is not a GitHub Pages site here',
        ],
        'dns_type': 'CNAME / A',
        'dns_pattern': '<user>.github.io',
        'takeover': 'Create GitHub Pages repo with CNAME file',
        'ip_addresses': ['185.199.108.153', '185.199.109.153', '185.199.110.153', '185.199.111.153'],
    },
    # Netlify
    'netlify': {
        'detect': [
            'Not Found - Netlify',
            'Page Not Found (Netlify)',
            'netlify.app',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.netlify.app',
        'takeover': 'Deploy Netlify site with same subdomain',
    },
    # Vercel
    'vercel': {
        'detect': [
            '404: Not Found (Vercel)',
            'The page could not be found (Vercel)',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.vercel.app',
        'takeover': 'vercel --prod with matching project name',
    },
    # Fastly
    'fastly': {
        'detect': [
            'Fastly error: unknown domain',
            'The Fastly service does not currently serve this domain',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.fastly.net',
        'takeover': 'Create Fastly service with matching domain',
    },
    # Shopify
    'shopify': {
        'detect': [
            'Sorry, this shop is currently unavailable (Shopify)',
            'Only one shop per subdomain is allowed',
            'No shop found for this domain',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.myshopify.com',
        'takeover': 'Create Shopify store with matching subdomain',
    },
    # Tumblr
    'tumblr': {
        'detect': [
            'There\'s nothing here (Tumblr)',
            'The page you requested cannot be found (Tumblr)',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.tumblr.com',
        'takeover': 'Create Tumblr blog with matching subdomain',
    },
    # Readme.io
    'readme': {
        'detect': [
            'Project doesnt exist... yet! (ReadMe)',
            '404 - This page doesnt exist (ReadMe)',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.readme.io',
        'takeover': 'Create ReadMe project with matching subdomain',
    },
    # Bitbucket
    'bitbucket': {
        'detect': [
            'The page you were looking for does not exist (Bitbucket)',
            'Repository not found (Bitbucket)',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.bitbucket.io',
        'takeover': 'Create Bitbucket Pages with CNAME',
    },
    # WordPress.com
    'wordpress': {
        'detect': [
            'Domain not found (WordPress.com)',
            'No site configured at this address',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.wordpress.com',
        'takeover': 'Create WordPress.com site',
    },
    # Pantheon
    'pantheon': {
        'detect': [
            'The site you are looking for could not be found (Pantheon)',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.pantheonsite.io',
        'takeover': 'Create Pantheon site with matching name',
    },
    # Aiven
    'aiven': {
        'detect': [
            'Not found (Aiven)',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.aivencloud.com',
        'takeover': 'Create Aiven service with matching subdomain',
    },
    # Zendesk
    'zendesk': {
        'detect': [
            'Help Center Closed (Zendesk)',
            'This help desk has been deactivated',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.zendesk.com',
        'takeover': 'Create Zendesk Help Center with matching subdomain',
    },
    # Intercom
    'intercom': {
        'detect': [
            'Intercom - Page not found',
            'This Intercom help desk has been deleted',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.custom.intercom.help',
        'takeover': 'Create Intercom help center',
    },
    # Freshdesk
    'freshdesk': {
        'detect': [
            'This Freshdesk domain is not available',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.freshdesk.com',
        'takeover': 'Create Freshdesk account',
    },
    # Simple Analytics
    'simple_analytics': {
        'detect': [
            'No site found (Simple Analytics)',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.simpleanalyticscdn.com',
        'takeover': 'Create Simple Analytics account',
    },
    # Teamwork
    'teamwork': {
        'detect': [
            'Oops - We didn\'t find your site (Teamwork)',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.teamwork.com',
        'takeover': 'Create Teamwork project',
    },
    # Campaign Monitor
    'campaign_monitor': {
        'detect': [
            'Trying to access your account? (Campaign Monitor)',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.createsend.com',
        'takeover': 'Create Campaign Monitor account',
    },
    # Statuspage (Atlassian)
    'statuspage': {
        'detect': [
            'No status page found (Statuspage)',
            'Status page does not exist (Atlassian Statuspage)',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.statuspage.io',
        'takeover': 'Create Statuspage with matching subdomain',
    },
    # Thinkific
    'thinkific': {
        'detect': [
            'The page you are looking for does not exist (Thinkific)',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.thinkific.com',
        'takeover': 'Create Thinkific site',
    },
    # Teachable
    'teachable': {
        'detect': [
            'This Teachable site does not exist',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.teachable.com',
        'takeover': 'Create Teachable site',
    },
    # Cargo
    'cargo': {
        'detect': [
            '404 Not Found (Cargo)',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.cargocollective.com',
        'takeover': 'Create Cargo site',
    },
    # KeyCDN
    'keycdn': {
        'detect': [
            'No such zone (KeyCDN)',
        ],
        'dns_type': 'CNAME',
        'dns_pattern': '*.kxcdn.com',
        'takeover': 'Create KeyCDN zone',
    },
}
```

## 2. Automated Discovery Pipeline

```python
# subdomain_takeover_discovery.py — 自动化发现与接管检查
import dns.resolver
import requests
import socket

class SubdomainTakeoverScanner:
    """子域名接管自动化扫描器"""
    
    def __init__(self, domain):
        self.domain = domain
        self.findings = []
    
    def enumerate_subdomains(self):
        """枚举子域名 (集成多种数据源)"""
        # 方法 1: 被动枚举 (证书透明度日志)
        # crt.sh 查询: https://crt.sh/?q=%25.target.com&output=json
        # 方法 2: DNS 字典爆破
        # 方法 3: 搜索引擎 dork: site:*.target.com
        # 方法 4: 第三方数据源: SecurityTrails, AlienVault OTX
        # 方法 5: Google Analytics / Tracking IDs 关联子域名
        pass
    
    def check_dangling_dns(self, subdomain):
        """检查 DNS 记录是否指向不存在的服务"""
        try:
            # 查询 CNAME 记录
            answers = dns.resolver.resolve(subdomain, 'CNAME')
            cname_target = str(answers[0].target).rstrip('.')
            
            # 查询 A 记录
            try:
                socket.gethostbyname(cname_target)
                return None  # 目标主机存在
            except socket.gaierror:
                # DNS 解析失败 → 可能是可接管的 CNAME
                return {
                    'subdomain': subdomain,
                    'type': 'CNAME',
                    'target': cname_target,
                    'vulnerable': True,
                }
                
        except dns.resolver.NoAnswer:
            # 无 CNAME 记录，尝试 A 记录
            try:
                answers = dns.resolver.resolve(subdomain, 'A')
                ips = [str(a) for a in answers]
                # 检查 IP 是否属于已知云服务
                return self.check_cloud_ip(subdomain, ips)
            except:
                return None
        except dns.resolver.NXDOMAIN:
            # 子域名不存在
            return None
    
    def check_cloud_ip(self, subdomain, ips):
        """检查 IP 是否属于云服务"""
        # GitHub Pages IP 范围
        github_pages_ips = [
            '185.199.108.153', '185.199.109.153',
            '185.199.110.153', '185.199.111.153'
        ]
        for ip in ips:
            if ip in github_pages_ips:
                # 访问 HTTP 检查是否是 GitHub Pages 404
                try:
                    r = requests.get(f'https://{subdomain}', timeout=5)
                    if 'There is not a GitHub Pages site here' in r.text:
                        return {
                            'subdomain': subdomain,
                            'type': 'A (GitHub Pages)',
                            'target': ip,
                            'vulnerable': True,
                        }
                except:
                    pass
        return None
    
    def verify_takeover(self, subdomain, service_type):
        """验证接管可行性: HTTP 响应指纹"""
        try:
            r = requests.get(f'https://{subdomain}', timeout=10, verify=False)
        except requests.exceptions.SSLError:
            r = requests.get(f'http://{subdomain}', timeout=10)
        except:
            return False
        
        for service, sig in TAKEOVER_SIGNATURES.items():
            for pattern in sig['detect']:
                if pattern.lower() in r.text.lower():
                    return True, service
        return False, None
    
    def generate_takeover_proof(self, subdomain, service):
        """生成接管 PoC (非破坏性)"""
        # PoC 文件内容: 仅包含无害的接管证明
        # 例如: 在注册的服务上创建 <h1>Subdomain Takeover PoC</h1>
        # 然后验证该内容出现在 subdomain 上
        
        poc_dns = f"""
DNS Takeover PoC for {subdomain}:
- DNS Type: CNAME
- Target: {service}
- Status: VULNERABLE — Register the above service with the same subdomain prefix
- Impact: Full control over {subdomain}, including SSL/TLS cert issuance, cookie theft, phishing
        """
        return poc_dns
```

### DNS Record Type Deep-Dive

```
# A 记录 (直接 IP)
最容易检测: DNS 指向某个 IP → HTTP 访问 → 观察响应
接管风险: IP 重新分配给其他用户 (AWS/Azure/GCP 弹性 IP)

# CNAME 记录 (别名)
最常见可接管类型: DNS 指向另一域名 → 该域名不再被服务提供商持有
关键是: CNAME 的 target 可被注册

# NS 记录 (权威域名服务器)
最危险类型: 子域名委托给外部 NS → 该 NS 被删除
攻击者注册该 NS → 完全控制子域名的所有 DNS 记录
Real CVE: NS 子域名接管可控制包括 _acme-challenge 在内的所有记录

# MX 记录 (邮件交换)
邮件服务器接管 → 拦截发送到该子域名的所有邮件
攻击者注册同名的 mailgun/sendgrid/mandrill 邮箱服务
→ 接收密码重置邮件、验证邮件

# ALIAS / ANAME 记录
类似 CNAME 但作用于根域: 根域不能有 CNAME, 但可以用 ALIAS
如果 ALIAS 指向不可用服务 → 根域可被接管

# TXT 记录 (文本)
TXT 记录中的 SPF/DKIM 可能引用外部服务
如果该服务被删除 → 邮件认证绕过 (详见 19-dns-email/02-email-spoofing.md)

# SRV 记录 (服务定位)
指向特定端口和优先级的目标主机
如果目标主机被释放 → 可接管该服务 (如 SIP、XMPP、LDAP)
```

## 3. DNS NS 子域名接管

```python
# ns_takeover.py — DNS NS 委派接管
# 场景: _domainkey.target.com NS 指向 ns1.victim-dns.com
# ns1.victim-dns.com 已过期 → 注册该域名 → 完全控制 _domainkey.target.com

def check_ns_takeover(subdomain):
    """检查 NS 记录是否可接管"""
    import dns.resolver
    import whois
    
    try:
        answers = dns.resolver.resolve(subdomain, 'NS')
        for ns_record in answers:
            ns_target = str(ns_record.target).rstrip('.')
            
            # 检查该域名是否可注册
            try:
                w = whois.whois(ns_target)
                if w.status is None:  # 域名未注册
                    return {
                        'subdomain': subdomain,
                        'ns_target': ns_target,
                        'vulnerable': True,
                        'impact': 'CRITICAL: Full DNS control over subdomain',
                    }
            except whois.parser.PywhoisError:
                # whois 数据库中没有记录 → 可能可注册
                return {
                    'subdomain': subdomain,
                    'ns_target': ns_target,
                    'vulnerable': True,
                }
    except:
        pass
    return None
```

## 4. CDN-Specific Takeover

### CloudFront Missing Origin

```python
# cloudfront_takeover.py — CloudFront 自定义域名接管
# 场景: 目标有 CNAME 指向 d123.cloudfront.net
# 但对应的 CloudFront Distribution 已被删除

import requests
import boto3

def check_cloudfront_takeover(cname_target):
    """确认 CloudFront 是否可接管"""
    # 步骤 1: 检查 DNS
    # CNAME: cdn.target.com → d123.cloudfront.net
    
    # 步骤 2: 访问 HTTPS
    try:
        r = requests.get('https://cdn.target.com', timeout=10)
    except requests.exceptions.SSLError:
        # SSL 证书错误 — CloudFront 已被删除但 SSL 未更新
        return True
    
    # 步骤 3: 确认 400 BadRequest
    if 'BadRequest' in r.text and 'CloudFront' in r.text:
        # 可接管!
        return True
    return False

def claim_cloudfront(subdomain):
    """接管 CloudFront (需要 AWS 账号)"""
    # 1. 创建 CloudFront distribution
    client = boto3.client('cloudfront')
    
    # 2. 设置 CNAMEs (Alternate Domain Names) = [subdomain]
    # 3. 设置 Origin = 任意存在的 S3 bucket
    # 4. 设置 ViewerCertificate 为默认 CloudFront 证书
    # 5. 等待 distribution 部署 (约 5-10 分钟)
    # 6. 访问 subdomain → 显示攻击者内容
    
    # 注意: ACM (AWS Certificate Manager) 无法为未拥有域名颁发证书
    # 但 CloudFront 默认证书 (*.cloudfront.net) 可用于自定义 CNAME
    pass
```

### Azure CDN / Verizon Edge

```python
# Azure CDN 接管: 当 Azure CDN endpoint 被删除后
# CNAME: cdn.target.com → target.azureedge.net
# 但 target.azureedge.net 已不存在
# 创建同名 Azure CDN endpoint → 获得控制权

# Fastly 接管: CNAME → global.prod.fastly.net
# Fastly service 被删除后 → "Fastly error: unknown domain"
# 创建同名 Fastly service → 接管
```

## 5. MX Record Takeover for Email Interception

```python
# mx_takeover.py — 邮件服务接管导致凭证窃取
# 场景: MX 记录指向已删除的 mailgun/sendgrid/sendmail 服务
# 攻击者注册该服务 → 接收所有发送到该域名的邮件

def claim_mx_service(domain, mx_target):
    """接管邮件服务"""
    # 1. 识别服务类型
    if 'mailgun.org' in mx_target:
        # Mailgun: 创建同名的 Mailgun domain
        pass
    elif 'sendgrid.net' in mx_target:
        # SendGrid: 创建同名的 SendGrid sender
        pass
    elif 'mandrill' in mx_target:
        # Mandrill (Mailchimp Transactional)
        pass
    elif 'sparkpostmail.com' in mx_target:
        # SparkPost
        pass
    
    # 2. 验证: 发送测试邮件到任意 @target.com 地址
    #    如果能收到 → 接管成功
```

## 6. Real CVEs and Bug Bounty Examples

```
# 经典案例分析:

CVE-2022-24706: Apache CouchDB subdomain takeover
→ CNAME 指向被删除的 cloudant.com 实例

Shopify — 多个子域名接管漏洞
→ myshopify.com 子域名指向用户创建的商店
→ 商店删除后未清理 DNS → 可注册

Uber — subdomain takeover via 3rd party DNS
→ 多个子域名 (如 developer.uber.com) 指向已删除的 Parse.com 服务
→ 奖励 $5,000+

GitHub — *.github.com 子域名接管
→ 用户修改 GitHub Pages 的 CNAME 但不清理 DNS
→ CNAME 指向 <user>.github.io → 该用户改名 → 接管

Tesla — DNS NS 委派接管
→ 子域名的 NS 记录指向已注册但未配置的 NS

Instagram (Facebook) — S3 bucket takeover
→ 静态资源域名指向已删除的 S3 bucket

NHS (UK National Health Service) — 多个子域名接管
→ 指向 Unbounce、Squarespace 等服务的 DNS 未同步

Microsoft — *.azureedge.net 接管
→ Azure CDN endpoint 删除后域名未释放

# 奖励金额参考:
# Critical: NS 接管 → $5,000-$15,000
# High: CNAME 接管 (含 cookie 窃取) → $2,000-$5,000
# Medium: CNAME 接管 (仅静态资源) → $500-$2,000
```

## 7. SSL/TLS Certificate Takeover

```python
# ssl_takeover.py — SSL 证书与子域名接管关联

def check_cert_takeover(subdomain):
    """检查 SSL 证书是否可被攻击者用于接管验证"""
    import ssl
    import socket
    
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=subdomain) as s:
            s.settimeout(5)
            s.connect((subdomain, 443))
            cert = s.getpeercert()
            # 如果证书有效 → 目标配置了证书 (可能已保护)
            # 如果证书无效 → DNS 已指向但 SSL 未配置
    except ssl.SSLCertVerificationError as e:
        # SSL 错误: 可能是 CloudFront 删除后证书不匹配
        return {'ssl_error': str(e), 'vulnerable': True}
    except socket.gaierror:
        # DNS 解析失败 → 无法连接
        return None
    except ConnectionRefusedError:
        # 端口关闭但 DNS 记录存在 → 可能是可接管
        return {'status': 'port_closed', 'vulnerable': True}
```

## 攻击链

```
CNAME 指向已删除 S3 bucket → 注册同名 bucket → 子域名完全接管 → 任意内容托管
NS 委派到过期域名 → 注册该域名 → 完全控制 DNS 记录 → SSL 证书 + 所有子域名
MX 指向已删除邮件服务 → 注册同名的 mailgun 域名 → 接收该域名所有邮件 → 密码重置链接窃取
CloudFront 自定义域名未清理 → 创建新 distribution 并设置 CNAME → SSL 证书 + 内容托管
GitHub Pages CNAME 残留 → 创建同名 GitHub Pages repo → 通过 CNAME 文件接管
Azure CDN endpoint 删除 → 创建同名 endpoint → 子域名内容控制
A 记录指向已释放 AWS/GCP 弹性 IP → 申请该 IP → 完全控制
dangling TXT 记录 (SPF/DKIM) → 接管引用的服务 → 伪造邮件来源
```

## 证据

记录: DNS 枚举结果 (所有子域名及对应服务类型)、HTTP 响应指纹、云服务 404 页截图、接管 PoC (只写入无害的接管证明文件，如 `<h1>Subdomain Takeover PoC - $(date)</h1>`)、DNS 传播确认。

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 子域名 HTTP 指纹探测 | `http_probe` | 对每个候选子域名发起 GET 探测响应 |
| 知识检索 | `kb_router` | 按云服务名搜索子域名接管相关技术 |
| 技术文件阅读 | `kb_read_file` | 读取具体接管案例的详细代码示例 |
| DNS 辅助工具 | `run_ctf_tool` | 使用 dirsearch/jwt_tool 辅助探测 |
