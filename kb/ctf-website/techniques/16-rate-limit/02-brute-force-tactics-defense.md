---
id: "ctf-website/16-rate-limit/02-brute-force-tactics-defense"
title: "高级暴力破解防御 — 反凭证喷洒、抗 MFA 疲劳、恒定时间认证与哈希加固"
title_en: "Advanced Brute Force Defense — Anti-Spraying, Phishing-Resistant MFA, Constant-Time Auth & Hash Hardening"
summary: >
  针对凭证喷洒（1 密码 × N 用户）、MFA 推送疲劳（Push Bombing）、时间侧信道用户名枚举、凭证复用（Credential Stuffing）
  以及 Windows/AD 哈希攻击链（Pass-the-Hash/Kerberoasting/AS-REP Roasting/NTLM Relay），给出基于速度异常检测、
  Number Matching / FIDO2 MFA、恒定时间哑校验与域身份加固的防御体系及可运行验证代码。
summary_en: >
  Comprehensive blue-team defense against credential spraying, MFA push bombing, timing-based username enumeration,
  credential stuffing, and Windows/AD hash attack chains (PtH, Kerberoasting, AS-REP Roasting, NTLM Relay). Covers
  distinct-user spray detection, number-matching/FIDO2 MFA, constant-time dummy hashing, and AD hardening with runnable checks.
board: "ctf-website"
category: "16-rate-limit"
signals: ["credential spraying", "MFA fatigue", "timing side channel", "credential stuffing", "Argon2id", "FIDO2", "Kerberoasting defense"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "kb_catalog"]
keywords: ["反凭证喷洒", "MFA疲劳防御", "Number Matching", "恒定时间认证", "用户枚举防御", "凭证复用检查", "Argon2id", "Kerberoasting防御"]
difficulty: "advanced"
tags: ["defense", "blue-team", "hardening", "authentication", "mfa", "anti-spraying", "active-directory"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/16-rate-limit/02-brute-force-tactics", "ctf-website/16-rate-limit/01-rate-limit-bypass-defense"]
track: "blue"
defends: "ctf-website/16-rate-limit/02-brute-force-tactics"
---

# 高级暴力破解防御 — 反凭证喷洒、抗 MFA 疲劳、恒定时间认证与哈希加固

## 威胁模型与防御目标

现代口令攻击不再依赖单账号高频猜解，而是围绕“低频绕过锁定”与“非口令因子薄弱点”展开。对照 [02-brute-force-tactics.md](02-brute-force-tactics.md)，蓝队需同时覆盖在线认证链路与离线哈希/域认证面：

| 攻击向量 | 绕过传统限流的机制 | 蓝队加固控制 |
|---|---|---|
| 凭证喷洒（1 密码 × N 用户） | 单账号失败次数不超锁定阈值，逃避账号锁定 | 按 `(IP/ASN, 滑动窗口)` 统计**不同用户名数量**与错误率，触发跨账号协同封禁 |
| MFA 疲劳（Push Bombing） | 连续发送单键批准推送诱使用户误点 | 切换至 FIDO2/WebAuthn 或强制 Number Matching；配置 MFA 推送速率上限与连拒自动冻结 |
| MFA 旁路（`skip_mfa` / 恢复码 / 旧协议） | 内部接口未校验 MFA 会话状态，或保留 IMAP/POP3 基础认证 | 会话状态机强校验 `mfa_verified=True`；恢复码高熵单次消费；全面关闭非 MFA 遗留协议 |
| 时间侧信道用户名枚举 | 无效用户名提前返回，有效用户名执行慢哈希导致 50ms+ 耗时差 | 对不存在用户执行等价耗时的哑密码哈希校验（Dummy Verify），统一错误文案与状态码 |
| 凭证复用（Credential Stuffing） | 直接重用外部泄露库的真实 `(email, password)` 对 | 注册/改密拦截已泄露密码（HIBP k-anonymity 前缀校验）；异常设备/地理风险登录强校验 MFA |
| Windows/AD 哈希攻击链（PtH/Relay/Kerberoasting/DCSync） | NTLM 可中继、RC4 服务票据可离线爆破、无预认证与过宽复制权限 | 启用 SMB 签名与 EPA 阻断 NTLM 中继；服务账号用 gMSA + AES256；开启 Kerberos 预认证；高权限入 Protected Users；限制复制 ACL |

## 核心防御实现

### 1. 恒定时间认证 + 跨账号凭证喷洒检测 + 抗疲劳 MFA

以下 Python 实现展示可直接集成至认证服务的三大核心防线：
1. **反凭证喷洒检测器**：独立统计同一来源 IP/子网在时间窗口内尝试过的**去重用户名数**与失败率；即使每个账号仅尝试 1 次密码，跨账号宽度超过阈值即锁定来源并告警。
2. **恒定时间口令校验**：无论用户是否存在，均执行完全相同的 `PBKDF2-HMAC-SHA256`（生产推荐 `Argon2id`）工作量，再用 `hmac.compare_digest` 对比结果，消除时间侧信道。
3. **Number Matching + 抗疲劳 MFA 状态机**：生成 2 位数字匹配码绑定到本次登录会话，禁止无条件 `approve`，并在连续拒绝或高频触发时自动冻结账号待审核。

```python
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field


# 预计算哑盐与哑摘要，供不存在的用户在恒定时间路径中复用
DUMMY_SALT = b"constant-time-dummy-salt-v1"
DUMMY_HASH = hashlib.pbkdf2_hmac("sha256", b"dummy-reference-password", DUMMY_SALT, 120_000)


def verify_password_constant_time(
    password: str,
    stored_salt: bytes | None,
    stored_hash: bytes | None,
) -> bool:
    """对存在与不存在的用户执行等价计算开销，消除时间侧信道枚举。"""
    salt = stored_salt if stored_salt is not None else DUMMY_SALT
    target = stored_hash if stored_hash is not None else DUMMY_HASH
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    matched = hmac.compare_digest(candidate, target)
    return matched and (stored_salt is not None) and (stored_hash is not None)


@dataclass
class SprayDetector:
    """按来源 IP/前缀统计去重账号广度，拦截 1 密码 x N 用户凭证喷洒。"""

    distinct_user_threshold: int = 8
    window_seconds: float = 300.0
    _ip_users: dict[str, dict[str, float]] = field(default_factory=dict)

    def record_attempt(self, source_ip: str, username: str, now: float | None = None) -> bool:
        ts = now if now is not None else time.monotonic()
        cutoff = ts - self.window_seconds
        seen = {u: t for u, t in self._ip_users.get(source_ip, {}).items() if t > cutoff}
        seen[username.casefold()] = ts
        self._ip_users[source_ip] = seen
        return len(seen) <= self.distinct_user_threshold


@dataclass
class AntiFatigueMFAService:
    """支持 Number Matching 与连续推送冻结的 MFA 控制器。"""

    max_pushes_per_window: int = 3
    window_seconds: float = 300.0
    _challenges: dict[str, tuple[str, str, float]] = field(default_factory=dict)
    _push_history: dict[str, list[float]] = field(default_factory=dict)
    _frozen_users: set[str] = field(default_factory=set)

    def start_challenge(self, username: str, now: float | None = None) -> tuple[str, str]:
        user_key = username.casefold()
        if user_key in self._frozen_users:
            raise PermissionError("account mfa frozen due to push bombing")

        ts = now if now is not None else time.monotonic()
        cutoff = ts - self.window_seconds
        history = [t for t in self._push_history.get(user_key, []) if t > cutoff]
        if len(history) >= self.max_pushes_per_window:
            self._frozen_users.add(user_key)
            raise PermissionError("mfa push rate exceeded; account frozen")

        history.append(ts)
        self._push_history[user_key] = history

        challenge_id = secrets.token_urlsafe(18)
        number_code = f"{secrets.randbelow(90) + 10}"  # 10..99 两位匹配码
        self._challenges[challenge_id] = (user_key, number_code, ts + 90.0)
        return challenge_id, number_code

    def approve_challenge(self, challenge_id: str, user_entered_number: str, now: float | None = None) -> bool:
        ts = now if now is not None else time.monotonic()
        record = self._challenges.pop(challenge_id, None)
        if not record:
            return False
        user_key, expected_number, expires_at = record
        if user_key in self._frozen_users or ts > expires_at:
            return False
        return secrets.compare_digest(expected_number, user_entered_number.strip())
```

### 2. 已泄露密码拦截与高强度恢复码策略

- **k-Anonymity 泄露口令拦截**：仅计算口令 SHA-1 前 5 位 hex 查询泄露索引接口，本地比对剩余 35 位后缀，命中则拒绝用于注册或改密，同时在已持有泄露凭据登录时强制触发 MFA 挑战。
- **高熵恢复码**：废弃 4-8 位纯数字备用码；生成至少 10 组随机 64 位熵（如 `secrets.token_hex(8)`）单次消费恢复码，数据库只存储其 SHA-256 摘要，并受与登录同等级的失败次数锁定约束。

### 3. Windows / Active Directory 哈希防御基线

针对离线破解与域内横向移动链路，部署以下域控制器与主机配置基线：

```powershell
# Active Directory 哈希与中继加固基线示例（域控管理环境）
# 1. 开启 Kerberos 预认证（阻止 AS-REP Roasting），确保所有账号未勾选 DontRequirePreauth
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Set-ADAccountControl -DoesNotRequirePreAuth $false

# 2. 启用服务账号 AES-256 加密并迁移至 gMSA（消除弱口令 Kerberoasting）
Set-ADUser -Identity "svc_app" -KerberosEncryptionType AES256

# 3. 高权限管理员加入 Protected Users 组（禁用 NTLM、限制委派与内存明文缓存）
Add-ADGroupMember -Identity "Protected Users" -Members "tier0_admin"

# 4. 强制 SMB 签名与 LDAP/HTTP EPA 阻断 NTLM 中继（GPO 等效策略）
Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
```

- **Credential Guard 与 LSASS 保护**：开启 `RunAsPPL` 与基于虚拟化的安全（VBS Credential Guard），防止非授权进程转储 LSASS 中的 NTLM/Kerberos 凭据。
- **DCSync 权限收敛**：仅允许域控制器计算机账号拥有 `DS-Replication-Get-Changes` 与 `DS-Replication-Get-Changes-All` 权限。

## 防御工作流

1. **枚举与侧信道消除**：核查登录、找回密码、注册三个入口的响应文案、HTTP 状态码与耗时分布；对未命中用户的路径补齐等价哑哈希计算，统一返回模糊提示。
2. **喷洒与撞库防护上线**：在认证网关部署去重用户名宽度窗口统计与泄露口令库拦截，并强制全站禁用非 MFA 的 IMAP/POP3/SMTP/Legacy API 登录通道。
3. **MFA 升级为抗疲劳模式**：停用一键确认型 Push，升级为 FIDO2/WebAuthn 或含地理/IP 上下文的 Number Matching，并配置连续推送超限自动冻结与 SOC 告警。
4. **认证状态机闭环**：确保所有受保护接口只信任服务端会话中的 `auth_level == "mfa_verified"` 标记，彻底移除调试开关与无校验恢复码接口。
5. **域身份与哈希面收敛**：禁用弱加密套件（RC4/DES）与 NTLMv1，强制 SMB 签名与 EPA，高权限账号迁入 `Protected Users`，并定期校验 DCSync ACL。

## 验证与判定标准

执行下方回归自检脚本，确认时间恒定性、跨账号喷洒拦截与抗疲劳 MFA 控制有效：

```python
import hashlib
import statistics
import time


def run_self_checks() -> None:
    # 1. 恒定时间密码校验：有效用户（错密）与无效用户耗时差应保持在极低抖动范围内
    real_salt = b"user-specific-salt-001"
    real_hash = hashlib.pbkdf2_hmac("sha256", b"CorrectHorseBatteryStaple!", real_salt, 120_000)

    assert verify_password_constant_time("CorrectHorseBatteryStaple!", real_salt, real_hash) is True
    assert verify_password_constant_time("WrongPassword", real_salt, real_hash) is False
    assert verify_password_constant_time("WrongPassword", None, None) is False

    valid_user_times, invalid_user_times = [], []
    for _ in range(7):
        t0 = time.perf_counter()
        verify_password_constant_time("WrongPassword", real_salt, real_hash)
        valid_user_times.append((time.perf_counter() - t0) * 1000)

        t1 = time.perf_counter()
        verify_password_constant_time("WrongPassword", None, None)
        invalid_user_times.append((time.perf_counter() - t1) * 1000)

    diff_ms = abs(statistics.median(valid_user_times) - statistics.median(invalid_user_times))
    assert diff_ms < 25.0, f"Timing delta too large: {diff_ms:.2f}ms"

    # 2. 凭证喷洒拦截：同一 IP 对 8 个不同用户各试 1 次放行，第 9 个用户被判定为喷洒
    detector = SprayDetector(distinct_user_threshold=8, window_seconds=300.0)
    for i in range(8):
        assert detector.record_attempt("203.0.113.50", f"user{i}@example.com", now=100.0 + i) is True
    assert detector.record_attempt("203.0.113.50", "user8@example.com", now=110.0) is False

    # 3. 抗疲劳 MFA：必须匹配数字码，错误数字核销失败，高频触发自动冻结
    mfa = AntiFatigueMFAService(max_pushes_per_window=2, window_seconds=300.0)
    cid1, code1 = mfa.start_challenge("alice", now=10.0)
    assert mfa.approve_challenge(cid1, "00", now=15.0) is False       # 错误匹配码拒绝并作废
    assert mfa.approve_challenge(cid1, code1, now=16.0) is False    # 重放同一 challenge 拒绝

    cid2, code2 = mfa.start_challenge("alice", now=20.0)
    assert mfa.approve_challenge(cid2, code2, now=25.0) is True     # 正确匹配码通过

    # 第 3 次超出窗口内推送阈值 -> 账号 MFA 冻结
    try:
        mfa.start_challenge("alice", now=30.0)
        raise AssertionError("Expected PermissionError when push limit exceeded")
    except PermissionError:
        pass

    print(f"[PASS] All brute-force defense checks passed (timing delta={diff_ms:.2f}ms).")


if __name__ == "__main__":
    run_self_checks()
```

判定通过标准：
- 有效用户与不存在用户的认证中位数耗时差低于 `25ms`（不再出现 `50ms+` 的明暗分支差异），且错误响应体与 HTTP 状态码完全一致；
- 同一源 IP 在滑动窗口内触达第 9 个不同账号时立即被 `SprayDetector` 阻断；
- 错误的 Number Matching 响应会立即作废当前 MFA 挑战并禁止重放，连续高频触发推送时账号自动进入冻结状态；
- 域内所有用户均开启 Kerberos 预认证，高权限账号位于 `Protected Users` 且服务端强制 SMB/LDAP 签名。

## MCP 工具映射

| 防御阶段 | MCP 工具 | 用途说明 |
|---|---|---|
| 认证端点一致性探测 | `http_probe` | 测量登录/找回密码对存在与不存在账号的响应体与时间分布是否一致 |
| 关联防御知识检索 | `kb_router` | 按 `credential spraying`、`MFA fatigue`、`timing` 检索防御指引 |
| 读取技术细节 | `kb_read_file` | 对照攻击面文档 [02-brute-force-tactics.md](02-brute-force-tactics.md) 核查遗留口令风险 |
| 知识目录定位 | `kb_catalog` | 浏览 `16-rate-limit` 与身份认证防御相关条目 |
