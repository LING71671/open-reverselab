# Web CTF 技术库

AI 实战 Lab。每个文件 = 可复制运行的攻击代码。每个文件有攻击链。

## 目录 (48 files, ~9500 lines)

```
01-recon/           (2)   recon-routing + version-fingerprinting
02-auth/            (15)  jwt×11 + oauth-sso + host-header + saml + ldap
03-injection/       (7)   sqli + ssti + prototype-pollution + graphql + hpp-crlf + redos-timing + grpc-protobuf
04-ssrf/            (2)   ssrf + open-redirect
05-deserialization/ (1)   deserialization (6 languages, Jackson/Hessian/JSON.Net)
06-file-attacks/    (1)   upload + xxe + lfi + pdf-rce
07-client/          (6)   xss + js-runtime + websocket + cors-csrf + postmessage + web-crypto
08-infra/           (3)   race-cache-smuggling + http2-attacks + web-cache-deception
09-cve/             (3)   cve-workflow + cve-correlation-graph + multi-cve-chain
10-cloud/           (3)   serverless + kubernetes + ci-cd
11-supply-chain/    (1)   dependency-confusion
12-payment/        (1)   payment-logic
```

## 分类索引

### 01-recon — 信息收集
- `recon-routing.md`: Header fuzzing, 路径绕过, HTTP method矩阵, 代理差异, 参数发现, API schema
- `version-fingerprinting.md`: 多源指纹, lockfile, Wappalyzer, Swagger, CVE联动

### 02-auth — 认证 & 会话
- `jwt/` (11): alg:none, 算法混淆, 弱密钥, kid注入, jku/x5u, Claim, 窃取, CVE
- `oauth-sso.md`: redirect_uri, state CSRF, code复用, PKCE, Implicit Flow, Client Secret, Device Code
- `host-header.md`: 密码重置劫持, Host→SSRF, Vhost绕过
- `saml-attacks.md`: XSW, Void Canonicalization, Round-Trip, Golden SAML
- `ldap-injection.md`: 过滤器注入, 盲注, JNDI反序列化, OpenLDAP匿名查询

### 03-injection — 注入攻击
- `sqli-nosqli.md`: WAF/Cloudflare/AWS Bypass, OOB, Second-Order, Stacked, PG/Oracle/SQLite, NoSQL全集, WAFFLED Content-Type Smuggling, Polyglot Payloads
- `ssti.md`: 9引擎, 10种Jinja2绕过, OOB
- `prototype-pollution.md`: 8 sinks, QS PP, Constructor.prototype, React RSC RCE, Class Pollution
- `graphql.md`: Introspection, Batch/Alias, Subscription, Persisted Query
- `hpp-crlf.md`: HPP WAF绕过, Response Splitting, Email注入
- `redos-timing.md`: Catastrophic Backtracking, Auth Bypass race, WAF evasion, 时序逐字节恢复token
- `grpc-protobuf.md`: Protobuf field injection, blind enum, gRPC-Web payload manipulation

### 04-ssrf — SSRF
- `ssrf.md`: Gopher打7种服务, Cloud Metadata全厂商, DNS Rebinding, IMDSv2 bypass, IPv6嵌入, 0.0.0.0绕过, CRLF splitting, 17种协议
- `open-redirect.md`: redirect参数字典, OAuth redirect劫持, filter绕过, redirect→XSS/SSRF

### 05-deserialization — 反序列化
- `deserialization.md`: PHP/Python/Node.js/Java/.NET/Ruby 6语言, ysoserial, Jackson polymorphic, Hessian Dubbo, JSON.Net, JDK 17/21 gadgets

### 06-file-attacks — 文件攻击
- `file-upload-xxe-lfi.md`: 扩展名fuzz, Zip Slip, XXE 6种+OOB, PHP Wrapper 12种, LFI字典+Session竞态, RFI, wkhtmltopdf/puppeteer PDF RCE

### 07-client — 客户端
- `admin-bot-xss.md`: 6种外带, CSP绕过, DOM Clobbering, Sanitizer绕过, Browser Parser Differentials, ISO-2022-JP
- `js-runtime.md`: fetch/XHR/WebCrypto/CryptoJS Hook, Proxy全对象, WASM逆向, AST去混淆
- `websocket.md`: 消息重放, CSWSH, Socket.IO, MQTT
- `cors-csrf.md`: CORS 4级利用, CSRF 8种绕过, SameSite Lax, JSON CSRF
- `postmessage.md`: Null origin bypass, event.source hijacking, OAuth token窃取, Structured Clone利用
- `web-crypto-abuse.md`: Math.random() Z3破解, RSA因子分解, extractable:false绕过, ECB降级

### 08-infra — 基础设施
- `race-cache-smuggling.md`: Turbo Intruder, 10种竞态, CL.TE/TE.CL/TE.TE/H2.CL smuggling
- `http2-attacks.md`: HPACK bomb, CONTINUATION flood, H2C upgrade smuggling, Stream multiplexing
- `web-cache-deception.md`: 静态扩展欺骗, delimiter绕过, 路径穿越, Stored XSS via CDN

### 09-cve — CVE工作流
- `cve-workflow.md`: NVD/EPSS/KEV, 指纹→CVE, PoC适配
- `cve-correlation-graph.md`: 9种关系类型, 聚类策略
- `multi-cve-chain-playbook.md`: 8种Primitive, 5种链式组合

### 10-cloud — 云原生
- `serverless-lambda.md`: Lambda Runtime API, IAM提取, Event Injection, 冷启动竞态
- `kubernetes-container.md`: SA token, RBAC→privileged pod, runc CVE-2024-21626, kubelet, etcd
- `ci-cd-pipeline.md`: Jenkins Groovy RCE, GitHub Actions注入, GitLab CI YAML, Self-hosted runner

### 11-supply-chain — 供应链
- `dependency-confusion.md`: 内部包枚举, npm投毒, manifest/tarball不一致, Typosquatting, PyPI攻击

### 12-payment — 支付业务逻辑
- `payment-logic.md`: 商品/订单/金额/回调/签名/幂等/订单IDOR/优惠余额/退款权益错配攻击矩阵

## 工具映射

```
scripts/ctf-website/cve_lookup.py          → CVE查询
scripts/ctf-website/cve_graph.py           → CVE关系图
scripts/ctf-website/cve_chain_planner.py   → 攻击链策划
scripts/ctf-website/fingerprint_cve_pipeline.py → 指纹→CVE管道
scripts/ctf-website/http_probe.py          → HTTP探测
scripts/ctf-website/install_missing_tools.ps1 → 第三方工具安装
scripts/misc/test_crlf.py                  → CRLF探测
scripts/misc/test_api_csrf*.py             → CSRF探测
scripts/misc/test_smuggling.py             → Smuggling探测
scripts/misc/test_sqli_time.py             → SQLi时间盲注
scripts/misc/test_email_*.py               → Email攻击
```

## 攻击链总览

```
Recon → Fingerprint → CVE → Primitive → Chain → Flag

每个文件末尾都有 ## 攻击链 章节，覆盖 200+ 条完整攻击链路。
```

## 使用原则

1. Recon→指纹落稳再选攻击面
2. 伪代码复制→改参数→跑
3. 一次一个变量
4. 30 min 无果换面
5. 证据全程落盘 cases/<case>/

