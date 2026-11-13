# Web CTF技术库

Web CTF / 网站攻防技术库。按信号路由到可复现的攻击路径、验证闭环和 MCP 工具。

## 完整目录（23 类 / 197 篇）

### 00-workflow — 工作流编排（1）

- [`00-workflow/24h-loop-orchestration.md`](../../../red/ctf-website/techniques/00-workflow/24h-loop-orchestration.md) — 24h Loop Orchestration

### 01-recon — 信息收集（10）

- [`01-recon/captcha-bypass-defense.md`](../../../blue/ctf-website/techniques/01-recon/captcha-bypass-defense.md) — 人机验证与 CAPTCHA 防绕过加固
- [`01-recon/captcha-bypass.md`](../../../red/ctf-website/techniques/01-recon/captcha-bypass.md) — 验证码绕过技术与自动化
- [`01-recon/cloudflare-bypass-defense.md`](../../../blue/ctf-website/techniques/01-recon/cloudflare-bypass-defense.md) — CDN / Cloudflare 源站隐藏与防直连加固
- [`01-recon/cloudflare-bypass.md`](../../../red/ctf-website/techniques/01-recon/cloudflare-bypass.md) — Cloudflare 绕过：寻找真实源服务器 IP
- [`01-recon/fofa-hunting-defense.md`](../../../blue/ctf-website/techniques/01-recon/fofa-hunting-defense.md) — 公网资产收敛与测绘暴露面防御
- [`01-recon/fofa-hunting.md`](../../../red/ctf-website/techniques/01-recon/fofa-hunting.md) — FOFA 资产测绘与漏洞狩猎
- [`01-recon/recon-routing-defense.md`](../../../blue/ctf-website/techniques/01-recon/recon-routing-defense.md) — 路由解析一致性与反向代理头信任加固
- [`01-recon/recon-routing.md`](../../../red/ctf-website/techniques/01-recon/recon-routing.md) — Recon & 路由绕过
- [`01-recon/version-fingerprinting-defense.md`](../../../blue/ctf-website/techniques/01-recon/version-fingerprinting-defense.md) — 技术栈指纹最小化与运行态错误收敛
- [`01-recon/version-fingerprinting.md`](../../../red/ctf-website/techniques/01-recon/version-fingerprinting.md) — 版本指纹识别

### 02-auth — 认证与会话（30）

- [`02-auth/host-header-defense.md`](../../../blue/ctf-website/techniques/02-auth/host-header-defense.md) — Host Header 注入与路由越权防御
- [`02-auth/host-header.md`](../../../red/ctf-website/techniques/02-auth/host-header.md) — Host Header 攻击
- [`02-auth/jwt/00-overview-defense.md`](../../../blue/ctf-website/techniques/02-auth/jwt/00-overview-defense.md) — JWT 安全架构与防御全景
- [`02-auth/jwt/00-overview.md`](../../../red/ctf-website/techniques/02-auth/jwt/00-overview.md) — JWT 攻击全景
- [`02-auth/jwt/01-alg-none-defense.md`](../../../blue/ctf-website/techniques/02-auth/jwt/01-alg-none-defense.md) — JWT alg:none 无签名绕过防御
- [`02-auth/jwt/01-alg-none.md`](../../../red/ctf-website/techniques/02-auth/jwt/01-alg-none.md) — JWT `alg: none` 无签名绕过
- [`02-auth/jwt/02-algorithm-confusion-defense.md`](../../../blue/ctf-website/techniques/02-auth/jwt/02-algorithm-confusion-defense.md) — JWT 非对称/对称算法混淆防御
- [`02-auth/jwt/02-algorithm-confusion.md`](../../../red/ctf-website/techniques/02-auth/jwt/02-algorithm-confusion.md) — JWT 算法混淆 (Algorithm Confusion)
- [`02-auth/jwt/03-weak-key-bruteforce-defense.md`](../../../blue/ctf-website/techniques/02-auth/jwt/03-weak-key-bruteforce-defense.md) — JWT HMAC 弱密钥与泄露防御
- [`02-auth/jwt/03-weak-key-bruteforce.md`](../../../red/ctf-website/techniques/02-auth/jwt/03-weak-key-bruteforce.md) — JWT 弱 HMAC 密钥爆破
- [`02-auth/jwt/04-kid-injection-defense.md`](../../../blue/ctf-website/techniques/02-auth/jwt/04-kid-injection-defense.md) — JWT kid 参数注入防御
- [`02-auth/jwt/04-kid-injection.md`](../../../red/ctf-website/techniques/02-auth/jwt/04-kid-injection.md) — JWT `kid` 参数注入
- [`02-auth/jwt/05-jku-x5u-abuse-defense.md`](../../../blue/ctf-website/techniques/02-auth/jwt/05-jku-x5u-abuse-defense.md) — JWT jku / x5u / x5c 密钥源劫持防御
- [`02-auth/jwt/05-jku-x5u-abuse.md`](../../../red/ctf-website/techniques/02-auth/jwt/05-jku-x5u-abuse.md) — JWT `jku` / `x5u` 密钥源劫持
- [`02-auth/jwt/06-claim-missing-defense.md`](../../../blue/ctf-website/techniques/02-auth/jwt/06-claim-missing-defense.md) — JWT Claim 校验与 Token 类型隔离防御
- [`02-auth/jwt/06-claim-missing.md`](../../../red/ctf-website/techniques/02-auth/jwt/06-claim-missing.md) — JWT Claim 验证缺失 & Token 混用
- [`02-auth/jwt/07-theft-replay-defense.md`](../../../blue/ctf-website/techniques/02-auth/jwt/07-theft-replay-defense.md) — JWT 凭证窃取、重放与持久化防御
- [`02-auth/jwt/07-theft-replay.md`](../../../red/ctf-website/techniques/02-auth/jwt/07-theft-replay.md) — JWT 窃取、重放与持久化
- [`02-auth/jwt/08-cve-library-defense.md`](../../../blue/ctf-website/techniques/02-auth/jwt/08-cve-library-defense.md) — JWT 依赖库 CVE 治理与安全调用防御
- [`02-auth/jwt/08-cve-library.md`](../../../red/ctf-website/techniques/02-auth/jwt/08-cve-library.md) — JWT 依赖库 CVE 与指纹路由
- [`02-auth/jwt/09-toolchain-operations-defense.md`](../../../blue/ctf-website/techniques/02-auth/jwt/09-toolchain-operations-defense.md) — JWT 防御验证流水线、CI 门禁与结果矩阵
- [`02-auth/jwt/09-toolchain-operations.md`](../../../red/ctf-website/techniques/02-auth/jwt/09-toolchain-operations.md) — JWT 工具链、操作流程与结果矩阵
- [`02-auth/ldap-injection-defense.md`](../../../blue/ctf-website/techniques/02-auth/ldap-injection-defense.md) — LDAP 过滤器注入与匿名绑定防御
- [`02-auth/ldap-injection.md`](../../../red/ctf-website/techniques/02-auth/ldap-injection.md) — LDAP Injection
- [`02-auth/oauth-sso-defense.md`](../../../blue/ctf-website/techniques/02-auth/oauth-sso-defense.md) — OAuth 2.0 / OIDC 单点登录安全防御
- [`02-auth/oauth-sso.md`](../../../red/ctf-website/techniques/02-auth/oauth-sso.md) — OAuth 2.0 / OIDC 攻击实战
- [`02-auth/saml-attacks-defense.md`](../../../blue/ctf-website/techniques/02-auth/saml-attacks-defense.md) — SAML 2.0 XML 签名包装与解析器差异防御
- [`02-auth/saml-attacks.md`](../../../red/ctf-website/techniques/02-auth/saml-attacks.md) — SAML 2.0 攻击
- [`02-auth/webauthn-passkey.md`](../../../red/ctf-website/techniques/02-auth/webauthn-passkey.md) — WebAuthn / Passkey 认证与凭据绑定分析
- [`02-auth/webauthn-passkey-defense.md`](../../../blue/ctf-website/techniques/02-auth/webauthn-passkey-defense.md) — WebAuthn 与 Passkey 防御：Ceremony 绑定、凭据归属与恢复流程

### 03-injection — 注入（12）

- [`03-injection/graphql-defense.md`](../../../blue/ctf-website/techniques/03-injection/graphql-defense.md) — GraphQL 防御与安全架构加固
- [`03-injection/graphql.md`](../../../red/ctf-website/techniques/03-injection/graphql.md) — GraphQL 攻击实战
- [`03-injection/hpp-crlf-defense.md`](../../../blue/ctf-website/techniques/03-injection/hpp-crlf-defense.md) — HPP 与 CRLF 响应头注入防御
- [`03-injection/hpp-crlf.md`](../../../red/ctf-website/techniques/03-injection/hpp-crlf.md) — HPP / CRLF Injection / Header Injection
- [`03-injection/prototype-pollution-defense.md`](../../../blue/ctf-website/techniques/03-injection/prototype-pollution-defense.md) — Prototype Pollution (原型链污染) 纵深防御
- [`03-injection/prototype-pollution.md`](../../../red/ctf-website/techniques/03-injection/prototype-pollution.md) — Prototype Pollution (原型链污染)
- [`03-injection/redos-timing-defense.md`](../../../blue/ctf-website/techniques/03-injection/redos-timing-defense.md) — ReDoS 正则回溯与时序侧信道防御
- [`03-injection/redos-timing.md`](../../../red/ctf-website/techniques/03-injection/redos-timing.md) — ReDoS & 时序攻击
- [`03-injection/sqli-nosqli-defense.md`](../../../blue/ctf-website/techniques/03-injection/sqli-nosqli-defense.md) — SQLi 与 NoSQLi 纵深防御及账本隔离
- [`03-injection/sqli-nosqli.md`](../../../red/ctf-website/techniques/03-injection/sqli-nosqli.md) — SQLi & NoSQLi (数据库注入高阶实战)
- [`03-injection/ssti-defense.md`](../../../blue/ctf-website/techniques/03-injection/ssti-defense.md) — SSTI (服务器端模板注入) 与多引擎沙盒加固
- [`03-injection/ssti.md`](../../../red/ctf-website/techniques/03-injection/ssti.md) — SSTI (Server-Side Template Injection)

### 04-ssrf — SSRF 与跳转（4）

- [`04-ssrf/open-redirect-defense.md`](../../../blue/ctf-website/techniques/04-ssrf/open-redirect-defense.md) — 开放重定向与 URL 解析差分防御
- [`04-ssrf/open-redirect.md`](../../../red/ctf-website/techniques/04-ssrf/open-redirect.md) — Open Redirect & Redirect Chain Attacks
- [`04-ssrf/ssrf-defense.md`](../../../blue/ctf-website/techniques/04-ssrf/ssrf-defense.md) — SSRF 纵深防御：协议封堵、DNS Pinning 与云元数据隔离
- [`04-ssrf/ssrf.md`](../../../red/ctf-website/techniques/04-ssrf/ssrf.md) — SSRF (Server-Side Request Forgery)

### 05-deserialization — 反序列化（2）

- [`05-deserialization/deserialization-defense.md`](../../../blue/ctf-website/techniques/05-deserialization/deserialization-defense.md) — 多语言反序列化安全防御与类型约束
- [`05-deserialization/deserialization.md`](../../../red/ctf-website/techniques/05-deserialization/deserialization.md) — Deserialization Vulnerabilities

### 06-file-attacks — 文件攻击（2）

- [`06-file-attacks/file-upload-xxe-lfi-defense.md`](../../../blue/ctf-website/techniques/06-file-attacks/file-upload-xxe-lfi-defense.md) — 文件上传隔离、XXE 禁用与路径穿越防御
- [`06-file-attacks/file-upload-xxe-lfi.md`](../../../red/ctf-website/techniques/06-file-attacks/file-upload-xxe-lfi.md) — File Upload / XXE / LFI / Path Traversal

### 07-client — 客户端安全（8）

- [`07-client/admin-bot-xss-defense.md`](../../../blue/ctf-website/techniques/07-client/admin-bot-xss-defense.md) — Admin Bot 与 XSS 跨站脚本纵深防御
- [`07-client/admin-bot-xss.md`](../../../red/ctf-website/techniques/07-client/admin-bot-xss.md) — Admin Bot / XSS 实战
- [`07-client/cors-csrf-defense.md`](../../../blue/ctf-website/techniques/07-client/cors-csrf-defense.md) — CORS 跨域策略与 CSRF 请求伪造防御
- [`07-client/cors-csrf.md`](../../../red/ctf-website/techniques/07-client/cors-csrf.md) — CORS / CSRF 高级攻击
- [`07-client/postmessage-defense.md`](../../../blue/ctf-website/techniques/07-client/postmessage-defense.md) — PostMessage 跨域消息通信纵深防御
- [`07-client/postmessage.md`](../../../red/ctf-website/techniques/07-client/postmessage.md) — PostMessage / 跨域通信攻击
- [`07-client/websocket-defense.md`](../../../blue/ctf-website/techniques/07-client/websocket-defense.md) — WebSocket / Socket.IO / MQTT 实时通道纵深防御
- [`07-client/websocket.md`](../../../red/ctf-website/techniques/07-client/websocket.md) — WebSocket 攻击实战

### 08-infra — 基础设施（6）

- [`08-infra/http2-attacks-defense.md`](../../../blue/ctf-website/techniques/08-infra/http2-attacks-defense.md) — HTTP/2 协议栈防御：HPACK 限额、CONTINUATION 封堵与 H2C 禁用
- [`08-infra/http2-attacks.md`](../../../red/ctf-website/techniques/08-infra/http2-attacks.md) — HTTP/2 攻击
- [`08-infra/race-cache-smuggling-defense.md`](../../../blue/ctf-website/techniques/08-infra/race-cache-smuggling-defense.md) — 并发竞态原子化、缓存键隔离与 HTTP 走私防御
- [`08-infra/race-cache-smuggling.md`](../../../red/ctf-website/techniques/08-infra/race-cache-smuggling.md) — Race Condition / Cache Poisoning / Request Smuggling
- [`08-infra/web-cache-deception-defense.md`](../../../blue/ctf-website/techniques/08-infra/web-cache-deception-defense.md) — Web Cache Deception 防御与 CDN/源站路径一致性加固
- [`08-infra/web-cache-deception.md`](../../../red/ctf-website/techniques/08-infra/web-cache-deception.md) — Web Cache Deception

### 09-cve — CVE 工作流与实战（15）

- [`09-cve/01-browser-sandbox-escape-defense.md`](../../../blue/ctf-website/techniques/09-cve/01-browser-sandbox-escape-defense.md) — Blink UAF 防御：CSSFontFeatureValuesMap 迭代器生命周期与浏览器沙箱加固（CVE-2026-2441）
- [`09-cve/01-browser-sandbox-escape.md`](../../../red/ctf-website/techniques/09-cve/01-browser-sandbox-escape.md) — Blink UAF：CSSFontFeatureValuesMap 迭代器悬空指针（CVE-2026-2441）
- [`09-cve/02-redis-zipmap-rce-defense.md`](../../../blue/ctf-website/techniques/09-cve/02-redis-zipmap-rce-defense.md) — Redis/Valkey RESTORE 防御：zipmap 规范编码校验与 ACL 隔离（CVE-2026-25243）
- [`09-cve/02-redis-zipmap-rce.md`](../../../red/ctf-website/techniques/09-cve/02-redis-zipmap-rce.md) — Redis/Valkey RESTORE：zipmap 长度前缀步长不一致（CVE-2026-25243）
- [`09-cve/03-cpanel-caldav-traversal-defense.md`](../../../blue/ctf-website/techniques/09-cve/03-cpanel-caldav-traversal-defense.md) — cPanel CalDAV 路径穿越与权限降级加固（CVE-2026-29205）
- [`09-cve/03-cpanel-caldav-traversal.md`](../../../red/ctf-website/techniques/09-cve/03-cpanel-caldav-traversal.md) — cPanel CalDAV 预认证路径穿越（CVE-2026-29205）
- [`09-cve/04-nezha-path-traversal-jwt-defense.md`](../../../blue/ctf-website/techniques/09-cve/04-nezha-path-traversal-jwt-defense.md) — Nezha Monitoring 防御：Go 路径段匹配加固与 JWT 密钥隔离（CVE-2026-53519）
- [`09-cve/04-nezha-path-traversal-jwt.md`](../../../red/ctf-website/techniques/09-cve/04-nezha-path-traversal-jwt.md) — Nezha Monitoring：路径遍历 + JWT 伪造管理员接管（CVE-2026-53519）
- [`09-cve/05-litellm-privesc-defense.md`](../../../blue/ctf-website/techniques/09-cve/05-litellm-privesc-defense.md) — LiteLLM 权限提升防御：RBAC 路由边界与 API Key 授权隔离（CVE-2026-47101）
- [`09-cve/05-litellm-privesc.md`](../../../red/ctf-website/techniques/09-cve/05-litellm-privesc.md) — LiteLLM：API Key 生成绕过角色限制 + 自提权（CVE-2026-47101）
- [`09-cve/06-nginx-rewrite-heapoverflow-defense.md`](../../../blue/ctf-website/techniques/09-cve/06-nginx-rewrite-heapoverflow-defense.md) — NGINX rewrite 模块堆溢出防御：版本升级、指令安全重构与运行缓解（CVE-2026-42945）
- [`09-cve/06-nginx-rewrite-heapoverflow.md`](../../../red/ctf-website/techniques/09-cve/06-nginx-rewrite-heapoverflow.md) — NGINX rewrite 模块：set 缓冲区长度错配堆溢出（CVE-2026-42945）
- [`09-cve/cve-correlation-graph.md`](09-cve/cve-correlation-graph.md) — CVE Correlation Graph（CVE 关联网）
- [`09-cve/cve-workflow.md`](09-cve/cve-workflow.md) — CVE Workflow For World-Class Web CTF
- [`09-cve/multi-cve-chain-playbook.md`](09-cve/multi-cve-chain-playbook.md) — Multi-CVE Chain Playbook（多 CVE 组合联合利用）

### 10-cloud — 云原生（18）

- [`10-cloud/aws-iam-privesc-defense.md`](../../../blue/ctf-website/techniques/10-cloud/aws-iam-privesc-defense.md) — AWS IAM 最小权限与提权路径防御
- [`10-cloud/aws-iam-privesc.md`](../../../red/ctf-website/techniques/10-cloud/aws-iam-privesc.md) — AWS IAM 权限枚举与提权路径
- [`10-cloud/ci-cd-pipeline-defense.md`](../../../blue/ctf-website/techniques/10-cloud/ci-cd-pipeline-defense.md) — CI/CD Pipeline 防御：上下文注入消除、Runner 隔离与供应链签名
- [`10-cloud/ci-cd-pipeline.md`](../../../red/ctf-website/techniques/10-cloud/ci-cd-pipeline.md) — CI/CD Pipeline 攻击
- [`10-cloud/container-runtime-escape-defense.md`](../../../blue/ctf-website/techniques/10-cloud/container-runtime-escape-defense.md) — 容器运行时逃逸防御：Docker Socket 隔离、Capabilities 收敛与 LSM 加固
- [`10-cloud/container-runtime-escape.md`](../../../red/ctf-website/techniques/10-cloud/container-runtime-escape.md) — 容器运行时逃逸打点
- [`10-cloud/github-actions-abuse-paths-defense.md`](../../../blue/ctf-website/techniques/10-cloud/github-actions-abuse-paths-defense.md) — GitHub Actions 滥用路径防御：Token 最小权限、触发器隔离与 Action 固定
- [`10-cloud/github-actions-abuse-paths.md`](../../../red/ctf-website/techniques/10-cloud/github-actions-abuse-paths.md) — GitHub Actions 滥用路径
- [`10-cloud/k8s-rbac-attack-paths-defense.md`](../../../blue/ctf-website/techniques/10-cloud/k8s-rbac-attack-paths-defense.md) — Kubernetes RBAC 最小权限防御与高危权限边阻断
- [`10-cloud/k8s-rbac-attack-paths.md`](../../../red/ctf-website/techniques/10-cloud/k8s-rbac-attack-paths.md) — Kubernetes RBAC 攻击路径
- [`10-cloud/kubernetes-container-defense.md`](../../../blue/ctf-website/techniques/10-cloud/kubernetes-container-defense.md) — Kubernetes 与容器逃逸纵深防御：Pod Security、控制面隔离与网络策略
- [`10-cloud/kubernetes-container.md`](../../../red/ctf-website/techniques/10-cloud/kubernetes-container.md) — Kubernetes & 容器逃逸
- [`10-cloud/serverless-lambda-defense.md`](../../../blue/ctf-website/techniques/10-cloud/serverless-lambda-defense.md) — Serverless / Lambda 防御：最小角色、事件源校验与执行隔离
- [`10-cloud/serverless-lambda.md`](../../../red/ctf-website/techniques/10-cloud/serverless-lambda.md) — Serverless / Lambda 攻击
- [`10-cloud/terraform-state-secrets-defense.md`](../../../blue/ctf-website/techniques/10-cloud/terraform-state-secrets-defense.md) — Terraform State 与 IaC 凭证防御：加密远端状态、零密钥输出与暴露阻断
- [`10-cloud/terraform-state-secrets.md`](../../../red/ctf-website/techniques/10-cloud/terraform-state-secrets.md) — Terraform State 与 IaC 凭证泄露
- [`10-cloud/presigned-object-storage.md`](../../../red/ctf-website/techniques/10-cloud/presigned-object-storage.md) — 对象存储预签名授权：签发、上传与消费链
- [`10-cloud/presigned-object-storage-defense.md`](../../../blue/ctf-website/techniques/10-cloud/presigned-object-storage-defense.md) — 对象存储预签名防御：签发授权、上传隔离与版本绑定

### 11-dos — 协议级 DoS（2）

- [`11-dos/01-valkey-resp-dos-defense.md`](../../../blue/ctf-website/techniques/11-dos/01-valkey-resp-dos-defense.md) — Valkey RESP 协议状态机 DoS 防御：版本升级、状态重置补丁与边界接入控制（CVE-2026-27623）
- [`11-dos/01-valkey-resp-dos.md`](../../../red/ctf-website/techniques/11-dos/01-valkey-resp-dos.md) — Valkey RESP 协议：预认证断言失败 DoS（CVE-2026-27623）

### 11-supply-chain — 供应链（4）

- [`11-supply-chain/dependency-confusion-defense.md`](../../../blue/ctf-website/techniques/11-supply-chain/dependency-confusion-defense.md) — Dependency Confusion 与供应链投毒防御：私有源隔离、锁文件校验与脚本禁用
- [`11-supply-chain/dependency-confusion.md`](../../../red/ctf-website/techniques/11-supply-chain/dependency-confusion.md) — Dependency Confusion & 供应链攻击
- [`11-supply-chain/artifact-provenance-verification.md`](../../../red/ctf-website/techniques/11-supply-chain/artifact-provenance-verification.md) — 构建产物来源验证：摘要、构建身份与消费绑定
- [`11-supply-chain/artifact-provenance-verification-defense.md`](../../../blue/ctf-website/techniques/11-supply-chain/artifact-provenance-verification-defense.md) — 构建制品来源防御：签名身份、Provenance 策略与消费绑定

### 12-payment — 支付业务逻辑（16）

- [`12-payment/payment-bypass-defense.md`](../../../blue/ctf-website/techniques/12-payment/payment-bypass-defense.md) — 支付绕过纵深防御 — 服务端权威计价、状态机与精度控制
- [`12-payment/payment-bypass.md`](../../../red/ctf-website/techniques/12-payment/payment-bypass.md) — Payment Bypass — 支付绕过深度技术手册
- [`12-payment/payment-callback-async-defense.md`](../../../blue/ctf-website/techniques/12-payment/payment-callback-async-defense.md) — 支付回调与异步链路防御 — 验签、幂等锁、Anti-SSRF 与事件因果保护
- [`12-payment/payment-callback-async.md`](../../../red/ctf-website/techniques/12-payment/payment-callback-async.md) — Payment Callback & Async Attack — 支付回调与异步攻击深度手册
- [`12-payment/payment-digital-goods-defense.md`](../../../blue/ctf-website/techniques/12-payment/payment-digital-goods-defense.md) — 虚拟商品与内购 (IAP) 防御 — 收据服务端直验、防重放与铸币防护
- [`12-payment/payment-digital-goods.md`](../../../red/ctf-website/techniques/12-payment/payment-digital-goods.md) — Payment Digital Goods & IAP — 虚拟商品/内购攻击手册
- [`12-payment/payment-email-bounce-idor-defense.md`](../../../blue/ctf-website/techniques/12-payment/payment-email-bounce-idor-defense.md) — 退信泄露与订单越权防御 — 最小化 NDR 回执与所有权强鉴权
- [`12-payment/payment-email-bounce-idor.md`](../../../red/ctf-website/techniques/12-payment/payment-email-bounce-idor.md) — 退信滥用 + 订单号授权绕过
- [`12-payment/payment-logic-defense.md`](../../../blue/ctf-website/techniques/12-payment/payment-logic-defense.md) — 支付业务逻辑纵深防御 — 多账本一致性、防注入与闭环校验
- [`12-payment/payment-logic.md`](../../../red/ctf-website/techniques/12-payment/payment-logic.md) — Payment Logic Attacks — 支付类 Web CTF 技术手册
- [`12-payment/payment-php-defense.md`](../../../blue/ctf-website/techniques/12-payment/payment-php-defense.md) — PHP 支付系统纵深防御 — 严格类型比较、反序列化禁用与 BCMath 计价
- [`12-payment/payment-php.md`](../../../red/ctf-website/techniques/12-payment/payment-php.md) — PHP Payment Attacks — PHP 支付专项攻击手册
- [`12-payment/payment-race-lost-update-defense.md`](../../../blue/ctf-website/techniques/12-payment/payment-race-lost-update-defense.md) — 余额扣减丢失更新 (Lost Update) 防御 — 条件原子更新、行锁与复式账本
- [`12-payment/payment-race-lost-update.md`](../../../red/ctf-website/techniques/12-payment/payment-race-lost-update.md) — Payment Race / Lost Update — 余额扣减丢失更新
- [`12-payment/payment-subscription-defense.md`](../../../blue/ctf-website/techniques/12-payment/payment-subscription-defense.md) — 订阅与周期计费防御 — 试用反滥用、Proration 校验与 Seat 强绑定
- [`12-payment/payment-subscription.md`](../../../red/ctf-website/techniques/12-payment/payment-subscription.md) — Payment Subscription — 订阅/定期付款攻击深度手册

### 14-idor — IDOR / 越权（4）

- [`14-idor/01-idor-enumeration-defense.md`](../../../blue/ctf-website/techniques/14-idor/01-idor-enumeration-defense.md) — IDOR 纵深防御 — 对象级授权 (BOLA)、多租户隔离与不可预测标识
- [`14-idor/01-idor-enumeration.md`](../../../red/ctf-website/techniques/14-idor/01-idor-enumeration.md) — IDOR 深度枚举与利用 — 水平/垂直越权实战方法论
- [`14-idor/02-bac-business-logic-defense.md`](../../../blue/ctf-website/techniques/14-idor/02-bac-business-logic-defense.md) — 功能级访问控制 (BAC) 防御 — 默认拒绝、防方法覆写与流程状态锁
- [`14-idor/02-bac-business-logic.md`](../../../red/ctf-website/techniques/14-idor/02-bac-business-logic.md) — 功能级访问控制缺失 (BAC) — 垂直越权与业务逻辑绕过

### 15-mass-assignment — 批量赋值（4）

- [`15-mass-assignment/01-mass-assignment-defense.md`](../../../blue/ctf-website/techniques/15-mass-assignment/01-mass-assignment-defense.md) — 批量赋值与属性注入防御 — DTO 白名单绑定、禁危险函数与 GraphQL 类型收敛
- [`15-mass-assignment/01-mass-assignment.md`](../../../red/ctf-website/techniques/15-mass-assignment/01-mass-assignment.md) — 批量赋值与属性注入深度利用手册
- [`15-mass-assignment/02-parameter-tampering-defense.md`](../../../blue/ctf-website/techniques/15-mass-assignment/02-parameter-tampering-defense.md) — 参数篡改与优惠券竞态防御 — 契约校验、不可变折扣账本与防 TOCTOU
- [`15-mass-assignment/02-parameter-tampering.md`](../../../red/ctf-website/techniques/15-mass-assignment/02-parameter-tampering.md) — 参数篡改全链 — 价格/数量/优惠券/竞态深度攻击

### 16-rate-limit — 速率限制（4）

- [`16-rate-limit/01-rate-limit-bypass-defense.md`](../../../blue/ctf-website/techniques/16-rate-limit/01-rate-limit-bypass-defense.md) — 速率限制绕过防御 — 可信代理链、规范化键、原子令牌桶与验证码强绑定
- [`16-rate-limit/01-rate-limit-bypass.md`](../../../red/ctf-website/techniques/16-rate-limit/01-rate-limit-bypass.md) — 速率限制绕过 — IP 轮换、Header 操纵与应用层绕过
- [`16-rate-limit/02-brute-force-tactics-defense.md`](../../../blue/ctf-website/techniques/16-rate-limit/02-brute-force-tactics-defense.md) — 高级暴力破解防御 — 反凭证喷洒、抗 MFA 疲劳、恒定时间认证与哈希加固
- [`16-rate-limit/02-brute-force-tactics.md`](../../../red/ctf-website/techniques/16-rate-limit/02-brute-force-tactics.md) — 高级暴力破解 — 凭证喷洒、MFA 疲劳、Hash 策略

### 17-api-attacks — API 攻击（4）

- [`17-api-attacks/01-api-discovery-leak-defense.md`](../../../blue/ctf-website/techniques/17-api-attacks/01-api-discovery-leak-defense.md) — API 发现与信息泄露防御 — 生产文档收敛、GraphQL 内省禁用、Source Map 隔离与版本治理
- [`17-api-attacks/01-api-discovery-leak.md`](../../../red/ctf-website/techniques/17-api-attacks/01-api-discovery-leak.md) — API 发现与信息泄露 — Swagger、GraphQL、Source Map 与移动端提取
- [`17-api-attacks/02-api-key-leak-defense.md`](../../../blue/ctf-website/techniques/17-api-attacks/02-api-key-leak-defense.md) — API 密钥泄露防御 — 前后端密钥隔离、最小权限作用域、CI 密钥门禁与云规则锁定
- [`17-api-attacks/02-api-key-leak.md`](../../../red/ctf-website/techniques/17-api-attacks/02-api-key-leak.md) — API 密钥泄露与利用 — GitHub Dorking、客户端密钥链、云服务滥用

### 18-cors-csp-advanced — 浏览器隔离进阶（4）

- [`18-cors-csp-advanced/01-csp-bypass-defense.md`](../../../blue/ctf-website/techniques/18-cors-csp-advanced/01-csp-bypass-defense.md) — CSP 绕过防御 — Strict-Dynamic、单次 Nonce、Trusted Types 与无脚本外带阻断
- [`18-cors-csp-advanced/01-csp-bypass.md`](../../../red/ctf-website/techniques/18-cors-csp-advanced/01-csp-bypass.md) — CSP 绕过全技术栈
- [`18-cors-csp-advanced/02-xs-leaks-browser-sidechannels-defense.md`](../../../blue/ctf-website/techniques/18-cors-csp-advanced/02-xs-leaks-browser-sidechannels-defense.md) — XS-Leaks 浏览器侧信道防御 — Fetch Metadata、CORP/COOP 跨源隔离与恒定响应防线
- [`18-cors-csp-advanced/02-xs-leaks-browser-sidechannels.md`](../../../red/ctf-website/techniques/18-cors-csp-advanced/02-xs-leaks-browser-sidechannels.md) — XS-Leaks 浏览器侧信道攻击

### 19-dns-email — DNS / 邮件（4）

- [`19-dns-email/01-subdomain-takeover-defense.md`](../../../blue/ctf-website/techniques/19-dns-email/01-subdomain-takeover-defense.md) — 子域名接管防御 — DNS 生命周期治理、悬空记录核销、托管域认领锁定与 CAA 收敛
- [`19-dns-email/01-subdomain-takeover.md`](../../../red/ctf-website/techniques/19-dns-email/01-subdomain-takeover.md) — 子域名接管深度
- [`19-dns-email/02-email-spoofing-defense.md`](../../../blue/ctf-website/techniques/19-dns-email/02-email-spoofing-defense.md) — 邮件伪造防御 — SPF/DKIM/DMARC 严格对齐、显示名同形字过滤与 SMTP/iCal 注入阻断
- [`19-dns-email/02-email-spoofing.md`](../../../red/ctf-website/techniques/19-dns-email/02-email-spoofing.md) — 邮件伪造与 SPF / DKIM / DMARC

### 20-oauth-deep — OAuth 深入（4）

- [`20-oauth-deep/01-oauth-attack-chains-defense.md`](../../../blue/ctf-website/techniques/20-oauth-deep/01-oauth-attack-chains-defense.md) — OAuth 2.0 攻击全链防御 — 强制 PKCE S256、精确 redirect_uri 匹配、State 绑定与授权码单次核销
- [`20-oauth-deep/01-oauth-attack-chains.md`](../../../red/ctf-website/techniques/20-oauth-deep/01-oauth-attack-chains.md) — OAuth 2.0 攻击全链
- [`20-oauth-deep/02-session-fixation-attacks-defense.md`](../../../blue/ctf-website/techniques/20-oauth-deep/02-session-fixation-attacks-defense.md) — Session 固定与 SSO 劫持防御 — 认证会话轮换、Cookie 主机锁定、JWT 吊销与命名空间隔离
- [`20-oauth-deep/02-session-fixation-attacks.md`](../../../red/ctf-website/techniques/20-oauth-deep/02-session-fixation-attacks.md) — Session 固定与 SSO 劫持

### 22-dos — DoS / DDoS（26）

- [`22-dos/01-application-layer-dos-defense.md`](../../../blue/ctf-website/techniques/22-dos/01-application-layer-dos-defense.md) — 应用层拒绝服务防御与协议弹性加固
- [`22-dos/01-application-layer-dos.md`](../../../red/ctf-website/techniques/22-dos/01-application-layer-dos.md) — Application-Layer DoS
- [`22-dos/02-resource-exhaustion-defense.md`](../../../blue/ctf-website/techniques/22-dos/02-resource-exhaustion-defense.md) — 资源耗尽与算法复杂度攻击防御
- [`22-dos/02-resource-exhaustion.md`](../../../red/ctf-website/techniques/22-dos/02-resource-exhaustion.md) — Resource Exhaustion & Algorithm Complexity Attacks
- [`22-dos/03-amplification-drdos-defense.md`](../../../blue/ctf-website/techniques/22-dos/03-amplification-drdos-defense.md) — UDP 反射与放大攻击（DRDoS）防御
- [`22-dos/03-amplification-drdos.md`](../../../red/ctf-website/techniques/22-dos/03-amplification-drdos.md) — Amplification / DRDoS Attacks
- [`22-dos/04-redos-defense.md`](../../../blue/ctf-website/techniques/22-dos/04-redos-defense.md) — ReDoS 正则表达式拒绝服务防御
- [`22-dos/04-redos.md`](../../../red/ctf-website/techniques/22-dos/04-redos.md) — ReDoS — 正则表达式拒绝服务
- [`22-dos/05-http2-continuation-defense.md`](../../../blue/ctf-website/techniques/22-dos/05-http2-continuation-defense.md) — HTTP/2 CONTINUATION Flood 与 H2/H3 协议弹性防御
- [`22-dos/05-http2-continuation.md`](../../../red/ctf-website/techniques/22-dos/05-http2-continuation.md) — HTTP/2 CONTINUATION Flood & H2/H3 高级攻击
- [`22-dos/06-tcp-state-exhaustion-defense.md`](../../../blue/ctf-website/techniques/22-dos/06-tcp-state-exhaustion-defense.md) — TCP 协议栈状态耗尽防御与内核调优
- [`22-dos/06-tcp-state-exhaustion.md`](../../../red/ctf-website/techniques/22-dos/06-tcp-state-exhaustion.md) — TCP 协议栈状态耗尽
- [`22-dos/07-dns-dos-defense.md`](../../../blue/ctf-website/techniques/22-dos/07-dns-dos-defense.md) — DNS 拒绝服务与缓存投毒防御
- [`22-dos/07-dns-dos.md`](../../../red/ctf-website/techniques/22-dos/07-dns-dos.md) — DNS 拒绝服务攻击
- [`22-dos/08-tls-exhaustion-defense.md`](../../../blue/ctf-website/techniques/22-dos/08-tls-exhaustion-defense.md) — TLS/SSL 握手耗尽防御与密码学优化
- [`22-dos/08-tls-exhaustion.md`](../../../red/ctf-website/techniques/22-dos/08-tls-exhaustion.md) — TLS/SSL 握手耗尽
- [`22-dos/09-cache-cdn-dos-defense.md`](../../../blue/ctf-website/techniques/22-dos/09-cache-cdn-dos-defense.md) — 缓存穿透、源站暴露与 CDN 拒绝服务防御
- [`22-dos/09-cache-cdn-dos.md`](../../../red/ctf-website/techniques/22-dos/09-cache-cdn-dos.md) — 缓存 / CDN 拒绝服务
- [`22-dos/10-api-abuse-defense.md`](../../../blue/ctf-website/techniques/22-dos/10-api-abuse-defense.md) — API 滥用拒绝服务防御与配额治理解析
- [`22-dos/10-api-abuse.md`](../../../red/ctf-website/techniques/22-dos/10-api-abuse.md) — API 滥用拒绝服务
- [`22-dos/11-cloud-container-dos-defense.md`](../../../blue/ctf-website/techniques/22-dos/11-cloud-container-dos-defense.md) — 云原生、Kubernetes 与 Serverless 拒绝服务防御
- [`22-dos/11-cloud-container-dos.md`](../../../red/ctf-website/techniques/22-dos/11-cloud-container-dos.md) — 云原生 / 容器拒绝服务
- [`22-dos/12-ssrf-dos-defense.md`](../../../blue/ctf-website/techniques/22-dos/12-ssrf-dos-defense.md) — SSRF 驱动的拒绝服务防御与出站隔离
- [`22-dos/12-ssrf-dos.md`](../../../red/ctf-website/techniques/22-dos/12-ssrf-dos.md) — SSRF 驱动的拒绝服务
- [`22-dos/13-database-dos-defense.md`](../../../blue/ctf-website/techniques/22-dos/13-database-dos-defense.md) — 数据库层拒绝服务防御与查询资源治理
- [`22-dos/13-database-dos.md`](../../../red/ctf-website/techniques/22-dos/13-database-dos.md) — 数据库层拒绝服务

### 24-database — 数据库安全（13）

- [`24-database/00-overview.md`](../../../red/ctf-website/techniques/24-database/00-overview.md) — Database Attack Surface — 数据库攻击全景与决策树
- [`24-database/01-sqli-fundamentals-defense.md`](../../../blue/ctf-website/techniques/24-database/01-sqli-fundamentals-defense.md) — SQL Injection Core Defense — SQL 注入基础防御与参数化体系
- [`24-database/01-sqli-fundamentals.md`](../../../red/ctf-website/techniques/24-database/01-sqli-fundamentals.md) — SQL Injection Core — SQL 注入基础与全类型覆盖
- [`24-database/02-sqli-advanced-defense.md`](../../../blue/ctf-website/techniques/24-database/02-sqli-advanced-defense.md) — Advanced SQLi & Second-Order Defense — 高级注入、二阶与 OOB 防御
- [`24-database/02-sqli-advanced.md`](../../../red/ctf-website/techniques/24-database/02-sqli-advanced.md) — Advanced SQLi & WAF Bypass — 高级注入与绕过技术
- [`24-database/03-nosql-injection-defense.md`](../../../blue/ctf-website/techniques/24-database/03-nosql-injection-defense.md) — NoSQL Injection Defense — MongoDB/Redis/ES/CouchDB/Memcached 全栈防御
- [`24-database/03-nosql-injection.md`](../../../red/ctf-website/techniques/24-database/03-nosql-injection.md) — NoSQL Injection — NoSQL 注入攻击
- [`24-database/04-config-exposure-defense.md`](../../../blue/ctf-website/techniques/24-database/04-config-exposure-defense.md) — Database Config Exposure Defense — 数据库配置与凭证防泄露
- [`24-database/04-config-exposure.md`](../../../red/ctf-website/techniques/24-database/04-config-exposure.md) — Database Config Exposure — 数据库配置泄露
- [`24-database/05-backup-log-leak-defense.md`](../../../blue/ctf-website/techniques/24-database/05-backup-log-leak-defense.md) — Database Backup & Log Leak Defense — 数据库备份、日志与运维残留防护
- [`24-database/05-backup-log-leak.md`](../../../red/ctf-website/techniques/24-database/05-backup-log-leak.md) — Database Backup & Log Leak — 数据库备份与日志泄露
- [`24-database/07-data-cleaning-defense.md`](../../../blue/ctf-website/techniques/24-database/07-data-cleaning-defense.md) — Leak Containment & Anti-Extraction Defense — 泄露遏制、凭证轮换与数据掩码体系
- [`24-database/07-data-cleaning.md`](../../../red/ctf-website/techniques/24-database/07-data-cleaning.md) — Database Dump Cleaning — 泄露数据清洗方法论

## 文档质量基线

每篇正文必须包含：H1 标题、可运行示例、工作流/攻击链、Evidence、MCP 工具映射，并且本地 Markdown 链接必须可解析。

## 实战写法

每篇文章按“入口信号 → 打点脚本 → 路径分叉 → 下一跳 → 成功标志 → Evidence → MCP 工具映射”组织。正文优先回答三个问题：从哪个请求/响应/源码信号进入、用什么脚本或工具把路径打通、成功后跳到哪条更高价值路径。

记录证据时写可复现字段：URL、method、关键 header、payload 变量、状态码、响应差异、时间窗口、listener 日志、flag/凭证/配置所在位置。不要把结尾写成泛泛的报告结论；如果需要表达服务端约束，也放在“路径是否还能成立”的技术语境里。

```powershell
python scripts/misc/kb_doc_audit.py
```

## Web 攻击网与路由

- [攻击网](../../../red/ctf-website/techniques/attack-network.md) — 多入口、多分叉到 Flag 的决策图。
- [防御网](../../../blue/ctf-website/techniques/defense-network.md)
- `kb-index.json` — `kb_router.py` 使用的信号映射。
- `python scripts/ctf-website/kb_router.py "<signal>"` — 按新信号检索。
