# Web CTF技术库

Web CTF / 授权网站安全技术库。按信号路由到可复现的最小探针、验证闭环和 MCP 工具。

## 完整目录（23 类 / 97 篇）

### 01-recon — 信息收集（5）

- [`01-recon/captcha-bypass.md`](01-recon/captcha-bypass.md) — 验证码绕过技术与自动化
- [`01-recon/cloudflare-bypass.md`](01-recon/cloudflare-bypass.md) — Cloudflare 绕过：寻找真实源服务器 IP
- [`01-recon/fofa-hunting.md`](01-recon/fofa-hunting.md) — FOFA 资产测绘与漏洞狩猎
- [`01-recon/recon-routing.md`](01-recon/recon-routing.md) — Recon & 路由绕过
- [`01-recon/version-fingerprinting.md`](01-recon/version-fingerprinting.md) — 版本指纹识别

### 02-auth — 认证与会话（14）

- [`02-auth/host-header.md`](02-auth/host-header.md) — Host Header 攻击
- [`02-auth/jwt/00-overview.md`](02-auth/jwt/00-overview.md) — JWT 攻击全景
- [`02-auth/jwt/01-alg-none.md`](02-auth/jwt/01-alg-none.md) — JWT `alg: none` 无签名绕过
- [`02-auth/jwt/02-algorithm-confusion.md`](02-auth/jwt/02-algorithm-confusion.md) — JWT 算法混淆 (Algorithm Confusion)
- [`02-auth/jwt/03-weak-key-bruteforce.md`](02-auth/jwt/03-weak-key-bruteforce.md) — JWT 弱 HMAC 密钥爆破
- [`02-auth/jwt/04-kid-injection.md`](02-auth/jwt/04-kid-injection.md) — JWT `kid` 参数注入
- [`02-auth/jwt/05-jku-x5u-abuse.md`](02-auth/jwt/05-jku-x5u-abuse.md) — JWT `jku` / `x5u` 密钥源劫持
- [`02-auth/jwt/06-claim-missing.md`](02-auth/jwt/06-claim-missing.md) — JWT Claim 验证缺失 & Token 混用
- [`02-auth/jwt/07-theft-replay.md`](02-auth/jwt/07-theft-replay.md) — JWT 窃取、重放与持久化
- [`02-auth/jwt/08-cve-library.md`](02-auth/jwt/08-cve-library.md) — JWT 依赖库漏洞 (CVE)
- [`02-auth/jwt/09-toolchain-defense.md`](02-auth/jwt/09-toolchain-defense.md) — JWT 工具链、攻击流程与防御矩阵
- [`02-auth/ldap-injection.md`](02-auth/ldap-injection.md) — LDAP Injection
- [`02-auth/oauth-sso.md`](02-auth/oauth-sso.md) — OAuth 2.0 / OIDC 攻击实战
- [`02-auth/saml-attacks.md`](02-auth/saml-attacks.md) — SAML 2.0 攻击

### 03-injection — 注入（7）

- [`03-injection/graphql.md`](03-injection/graphql.md) — GraphQL 攻击实战
- [`03-injection/grpc-protobuf.md`](03-injection/grpc-protobuf.md) — gRPC / Protobuf 攻击
- [`03-injection/hpp-crlf.md`](03-injection/hpp-crlf.md) — HPP / CRLF Injection / Header Injection
- [`03-injection/prototype-pollution.md`](03-injection/prototype-pollution.md) — Prototype Pollution (原型链污染)
- [`03-injection/redos-timing.md`](03-injection/redos-timing.md) — ReDoS & 时序攻击
- [`03-injection/sqli-nosqli.md`](03-injection/sqli-nosqli.md) — SQLi & NoSQLi (数据库注入高阶实战)
- [`03-injection/ssti.md`](03-injection/ssti.md) — SSTI (Server-Side Template Injection)

### 04-ssrf — SSRF 与跳转（2）

- [`04-ssrf/open-redirect.md`](04-ssrf/open-redirect.md) — Open Redirect & Redirect Chain Attacks
- [`04-ssrf/ssrf.md`](04-ssrf/ssrf.md) — SSRF (Server-Side Request Forgery)

### 05-deserialization — 反序列化（1）

- [`05-deserialization/deserialization.md`](05-deserialization/deserialization.md) — Deserialization Vulnerabilities

### 06-file-attacks — 文件攻击（1）

- [`06-file-attacks/file-upload-xxe-lfi.md`](06-file-attacks/file-upload-xxe-lfi.md) — File Upload / XXE / LFI / Path Traversal

### 07-client — 客户端安全（6）

- [`07-client/admin-bot-xss.md`](07-client/admin-bot-xss.md) — Admin Bot / XSS 实战
- [`07-client/cors-csrf.md`](07-client/cors-csrf.md) — CORS / CSRF 高级攻击
- [`07-client/js-runtime.md`](07-client/js-runtime.md) — JS Runtime / Browser Reversing
- [`07-client/postmessage.md`](07-client/postmessage.md) — PostMessage / 跨域通信攻击
- [`07-client/web-crypto-abuse.md`](07-client/web-crypto-abuse.md) — Web Crypto API 滥用
- [`07-client/websocket.md`](07-client/websocket.md) — WebSocket 攻击实战

### 08-infra — 基础设施（3）

- [`08-infra/http2-attacks.md`](08-infra/http2-attacks.md) — HTTP/2 攻击
- [`08-infra/race-cache-smuggling.md`](08-infra/race-cache-smuggling.md) — Race Condition / Cache Poisoning / Request Smuggling
- [`08-infra/web-cache-deception.md`](08-infra/web-cache-deception.md) — Web Cache Deception

### 09-cve — CVE 工作流（3）

- [`09-cve/cve-correlation-graph.md`](09-cve/cve-correlation-graph.md) — CVE Correlation Graph（CVE 关联网）
- [`09-cve/cve-workflow.md`](09-cve/cve-workflow.md) — CVE Workflow For World-Class Web CTF
- [`09-cve/multi-cve-chain-playbook.md`](09-cve/multi-cve-chain-playbook.md) — Multi-CVE Chain Playbook（多 CVE 组合联合利用）

### 10-cloud — 云原生（3）

- [`10-cloud/ci-cd-pipeline.md`](10-cloud/ci-cd-pipeline.md) — CI/CD Pipeline 攻击
- [`10-cloud/kubernetes-container.md`](10-cloud/kubernetes-container.md) — Kubernetes & 容器逃逸
- [`10-cloud/serverless-lambda.md`](10-cloud/serverless-lambda.md) — Serverless / Lambda 攻击

### 11-supply-chain — 供应链（1）

- [`11-supply-chain/dependency-confusion.md`](11-supply-chain/dependency-confusion.md) — Dependency Confusion & 供应链攻击

### 12-payment — 支付业务逻辑（10）

- [`12-payment/payment-bypass.md`](12-payment/payment-bypass.md) — Payment Bypass — 支付绕过深度技术手册
- [`12-payment/payment-callback-async.md`](12-payment/payment-callback-async.md) — Payment Callback & Async Attack — 支付回调与异步攻击深度手册
- [`12-payment/payment-digital-goods.md`](12-payment/payment-digital-goods.md) — Payment Digital Goods & IAP — 虚拟商品/内购攻击手册
- [`12-payment/payment-email-bounce-idor.md`](12-payment/payment-email-bounce-idor.md) — 退信滥用 + 订单号授权绕过窃取卡密
- [`12-payment/payment-logic.md`](12-payment/payment-logic.md) — Payment Logic Attacks — 支付类 Web CTF 技术手册
- [`12-payment/payment-php.md`](12-payment/payment-php.md) — PHP Payment Attacks — PHP 支付专项攻击手册
- [`12-payment/payment-race-lost-update.md`](12-payment/payment-race-lost-update.md) — Payment Race / Lost Update — 余额扣减丢失更新
- [`12-payment/payment-subscription.md`](12-payment/payment-subscription.md) — Payment Subscription — 订阅/定期付款攻击深度手册
- [`12-payment/platform-fingerprints.md`](12-payment/platform-fingerprints.md) — PHP 发卡/电商平台指纹库
- [`12-payment/ticket-rush-api-reversing.md`](12-payment/ticket-rush-api-reversing.md) — Ticket Rush API Reversing — 票务抢购状态机、Token 与风控参数

### 13-signature — 签名实现（7）

- [`13-signature/00-overview.md`](13-signature/00-overview.md) — Signature Forgery — 签名伪造与验证绕过全景手册
- [`13-signature/01-algorithm.md`](13-signature/01-algorithm.md) — Signature Algorithm Attacks — 签名算法降级/混淆/None 攻击深度手册
- [`13-signature/02-implementation.md`](13-signature/02-implementation.md) — Signature Implementation Bugs — 签名实现缺陷深度手册
- [`13-signature/03-key-attacks.md`](13-signature/03-key-attacks.md) — Key Attacks — 签名密钥攻击深度技术手册
- [`13-signature/04-canonicalization.md`](13-signature/04-canonicalization.md) — Canonicalization Attacks — 签名规范化绕过
- [`13-signature/05-length-extension.md`](13-signature/05-length-extension.md) — Hash Length Extension 攻击 — 深度技术手册
- [`13-signature/06-replay-nonce.md`](13-signature/06-replay-nonce.md) — Replay / Nonce / Timestamp — 重放攻击深度技术手册

### 14-idor — IDOR/越权（2）

- [`14-idor/01-idor-enumeration.md`](14-idor/01-idor-enumeration.md) — IDOR 深度枚举与利用 — 水平/垂直越权实战方法论
- [`14-idor/02-bac-business-logic.md`](14-idor/02-bac-business-logic.md) — 功能级访问控制缺失 (BAC) — 垂直越权与业务逻辑绕过

### 15-mass-assignment — 批量赋值（2）

- [`15-mass-assignment/01-mass-assignment.md`](15-mass-assignment/01-mass-assignment.md) — 批量赋值与属性注入深度利用手册
- [`15-mass-assignment/02-parameter-tampering.md`](15-mass-assignment/02-parameter-tampering.md) — 参数篡改全链 — 价格/数量/优惠券/竞态深度攻击

### 16-rate-limit — 速率限制（2）

- [`16-rate-limit/01-rate-limit-bypass.md`](16-rate-limit/01-rate-limit-bypass.md) — 速率限制绕过 — IP 轮换、Header 操纵与应用层绕过
- [`16-rate-limit/02-brute-force-tactics.md`](16-rate-limit/02-brute-force-tactics.md) — 高级暴力破解 — 凭证喷洒、MFA 疲劳、Hash 策略

### 17-api-attacks — API 攻击（2）

- [`17-api-attacks/01-api-discovery-leak.md`](17-api-attacks/01-api-discovery-leak.md) — API 发现与信息泄露 — Swagger、GraphQL、Source Map 与移动端提取
- [`17-api-attacks/02-api-key-leak.md`](17-api-attacks/02-api-key-leak.md) — API 密钥泄露与利用 — GitHub Dorking、客户端密钥链、云服务滥用

### 18-cors-csp-advanced — 浏览器隔离进阶（2）

- [`18-cors-csp-advanced/01-csp-bypass.md`](18-cors-csp-advanced/01-csp-bypass.md) — CSP 绕过全技术栈
- [`18-cors-csp-advanced/02-xs-leaks-browser-sidechannels.md`](18-cors-csp-advanced/02-xs-leaks-browser-sidechannels.md) — XS-Leaks 浏览器侧信道攻击

### 19-dns-email — DNS/邮件（2）

- [`19-dns-email/01-subdomain-takeover.md`](19-dns-email/01-subdomain-takeover.md) — 子域名接管深度
- [`19-dns-email/02-email-spoofing.md`](19-dns-email/02-email-spoofing.md) — 邮件伪造与 SPF / DKIM / DMARC

### 20-oauth-deep — OAuth 深入（2）

- [`20-oauth-deep/01-oauth-attack-chains.md`](20-oauth-deep/01-oauth-attack-chains.md) — OAuth 2.0 攻击全链
- [`20-oauth-deep/02-session-fixation-attacks.md`](20-oauth-deep/02-session-fixation-attacks.md) — Session 固定与 SSO 劫持

### 21-mobile-bridge — 移动 Web 桥接（2）

- [`21-mobile-bridge/01-webview-attacks.md`](21-mobile-bridge/01-webview-attacks.md) — WebView 攻击全技术
- [`21-mobile-bridge/02-cordova-reactnative.md`](21-mobile-bridge/02-cordova-reactnative.md) — 跨平台框架攻击面 — Cordova / React Native / Flutter / Electron

### 22-dos — DoS/DDoS（13）

- [`22-dos/01-application-layer-dos.md`](22-dos/01-application-layer-dos.md) — Application-Layer DoS
- [`22-dos/02-resource-exhaustion.md`](22-dos/02-resource-exhaustion.md) — Resource Exhaustion & Algorithm Complexity Attacks
- [`22-dos/03-amplification-drdos.md`](22-dos/03-amplification-drdos.md) — Amplification / DRDoS Attacks
- [`22-dos/04-redos.md`](22-dos/04-redos.md) — ReDoS — 正则表达式拒绝服务
- [`22-dos/05-http2-continuation.md`](22-dos/05-http2-continuation.md) — HTTP/2 CONTINUATION Flood & H2/H3 高级攻击
- [`22-dos/06-tcp-state-exhaustion.md`](22-dos/06-tcp-state-exhaustion.md) — TCP 协议栈状态耗尽
- [`22-dos/07-dns-dos.md`](22-dos/07-dns-dos.md) — DNS 拒绝服务攻击
- [`22-dos/08-tls-exhaustion.md`](22-dos/08-tls-exhaustion.md) — TLS/SSL 握手耗尽
- [`22-dos/09-cache-cdn-dos.md`](22-dos/09-cache-cdn-dos.md) — 缓存 / CDN 拒绝服务
- [`22-dos/10-api-abuse.md`](22-dos/10-api-abuse.md) — API 滥用拒绝服务
- [`22-dos/11-cloud-container-dos.md`](22-dos/11-cloud-container-dos.md) — 云原生 / 容器拒绝服务
- [`22-dos/12-ssrf-dos.md`](22-dos/12-ssrf-dos.md) — SSRF 驱动的拒绝服务
- [`22-dos/13-database-dos.md`](22-dos/13-database-dos.md) — 数据库层拒绝服务

### 23-paywall-bypass — Paywall 分析（5）

- [`23-paywall-bypass/01-paywall-detection-bypass.md`](23-paywall-bypass/01-paywall-detection-bypass.md) — Paywall 检测与绕过总览
- [`23-paywall-bypass/02-http-header-manipulation.md`](23-paywall-bypass/02-http-header-manipulation.md) — HTTP 请求头伪装
- [`23-paywall-bypass/03-network-rule-blocking.md`](23-paywall-bypass/03-network-rule-blocking.md) — Network 规则拦截 — 阻止 Paywall 脚本加载
- [`23-paywall-bypass/04-content-extraction.md`](23-paywall-bypass/04-content-extraction.md) — 内容提取 — JSON-LD / Next.js / archive.is
- [`23-paywall-bypass/05-dom-css-manipulation.md`](23-paywall-bypass/05-dom-css-manipulation.md) — DOM / CSS / Storage 操作

## 文档质量基线

每篇正文必须包含：H1 标题、可运行示例、工作流/攻击链、证据与验证闭环、MCP 工具映射，并且本地 Markdown 链接必须可解析。

```powershell
python scripts/misc/kb_doc_audit.py
```

## Web 攻击网与路由

- [攻击网](attack-network.md) — 多入口、多分叉到 Flag 的决策图。
- `kb-index.json` — `kb_router.py` 使用的信号映射。
- `python scripts/ctf-website/kb_router.py "<signal>"` — 按新信号检索。
