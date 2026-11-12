---
id: "ctf-website/17-api-attacks/02-api-key-leak-defense"
title: "API 密钥泄露防御 — 前后端密钥隔离、最小权限作用域、CI 密钥门禁与云规则锁定"
title_en: "API Key Leakage Defense — Client-Server Key Separation, Least-Privilege Scopes, CI Secret Gates & Cloud Rule Lockdown"
summary: >
  针对 GitHub 代码泄露、Source Map/APK 硬编码密钥、Firebase 公开配置滥用、Stripe/AWS/GitHub/Slack 秘密密钥失窃
  以及错误响应和日志明文回显问题，建立“前端零秘密密钥 + 运行时密钥托管 + OIDC 短效联邦凭证 + CI 提交门禁 + 安全规则强约束”的完整防线，并附可运行自检代码。
summary_en: >
  Defense against GitHub secret leaks, hardcoded credentials in Source Maps and APKs, Firebase misconfiguration abuse,
  Stripe/AWS/GitHub/Slack secret compromise, and error-log secret exposure. Covers strict client-server key separation,
  OIDC short-lived federation, CI secret scanning gates, and Firebase/cloud access hardening with runnable checks.
board: "ctf-website"
category: "17-api-attacks"
signals: ["API key leak", "secret scanning", "OIDC federation", "Firebase security rules", "restricted key", "log redaction", "key rotation"]
mcp_tools: ["http_probe", "kb_router", "kb_read_file", "kb_catalog"]
keywords: ["API密钥防御", "密钥隔离", "Firebase安全规则", "CI密钥门禁", "OIDC无密钥认证", "日志掩码", "Stripe受限密钥", "密钥轮换"]
difficulty: "advanced"
tags: ["defense", "blue-team", "hardening", "api-keys", "secrets", "cloud", "firebase"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/17-api-attacks/02-api-key-leak", "ctf-website/17-api-attacks/01-api-discovery-leak-defense"]
track: "blue"
defends: "ctf-website/17-api-attacks/02-api-key-leak"
---

# API 密钥泄露防御 — 前后端密钥隔离、最小权限作用域、CI 密钥门禁与云规则锁定

## 威胁模型与防御目标

API 密钥泄露的破坏力取决于**泄露位置是否越过信任边界**以及**密钥本身具备的作用域与生命周期**。对照 [02-api-key-leak.md](02-api-key-leak.md)，蓝队需从以下五个维度收口：

| 风险场景 | 攻击影响 | 防御控制 |
|---|---|---|
| 客户端代码/APK/Source Map 含服务端秘密密钥 | 直接调用 Stripe 退款/转账、AWS IAM API、GitHub 仓库写权限或 Slack 读消息 | 严格区分 Publishable 与 Secret 凭证；客户端只留公开初始化标识，特权调用全部经后端代理 |
| Firebase Web 配置公开 + 规则宽松 | 利用公开 `apiKey` + `projectId` 匿名登录或直接读写 Firestore / Realtime DB / Storage | 强制 Firestore/RTDB/Storage 认证与资源归属规则；对 Google API Key 绑定来源域名/包名与 API 白名单 |
| GitHub / Postman / `.env` 静态长效密钥泄露 | 自动化 Dorking 秒级收割长期有效凭据 | Pre-commit + CI 阻断；用 GitHub Actions OIDC 换取 AWS/GCP 短效 STS Token 取代静态 IAM Key |
| 密钥权限过度宽泛（Wildcard Scope） | 一处微服务凭据泄露即波及全账户资金与全仓库资产 | Stripe 使用受限密钥（`rk_live_`）精确授权；GitHub 使用 Fine-grained PAT 并设短 TTL；AWS 遵循最小权限 IAM Policy |
| HTTP 错误栈/日志回显与 Webhook 无签名校验 | 报错体泄露请求头凭据，或任意伪造支付回调 | 异常处理器与结构化日志统一执行正则掩码；Webhook 强制验证原始请求体 HMAC + 时间戳防重放 |

## 架构加固方案

### 1. 前后端密钥边界与最小权限矩阵

| 凭据类别 | 是否允许下发客户端 | 强制加固策略 |
|---|---|---|
| 支付秘密密钥（`sk_live_*` / `rk_live_*` / PayPal Secret） | **禁止** | 仅存后端 Secret Manager；非全功能服务改用最小权限受限密钥（仅允许 `payment_intents:write` 等） |
| 支付可公开密钥（`pk_live_*`） | 允许 | 仅用于前端令牌化组件，金额/折扣/发货判定完全由服务端完成 |
| Webhook 签名密钥（`whsec_*`） | **禁止** | 服务端基于原始 Body 校验签名与时间戳漂移（`<= 300s`） |
| 云静态访问密钥（IAM Access Key） | **禁止** | 废弃静态用户 Key，全面改用实例角色（IMDSv2）或 CI/CD OIDC 联合身份颁发 15-60 分钟 STS 临时凭据 |
| Firebase `apiKey`（`AIza...`） | 仅配合强规则允许 | 限制 HTTP Referer / Android 包名+签名指纹，仅勾选 IdentityToolkit 等必要 API，并锁定数据库规则 |
| 代码托管 / 协同 Token（GitHub / Slack） | **禁止** | 启用 Fine-grained Token、最短到期时间与只读最小 Scope；禁用 PR Artifact 导出环境变量 |

### 2. Firebase 安全规则锁定模板

即使前端携带了公开的 Firebase `apiKey` 与 `projectId`，只要服务端安全规则收敛，攻击者也无法读写非授权数据：

```javascript
// firestore.rules — 默认拒绝并强制按登录用户 UID 隔离读写
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId}/{document=**} {
      allow read, write: if request.auth != null
                         && request.auth.uid == userId
                         && request.auth.token.firebase.sign_in_provider != 'anonymous';
    }
    match /{document=**} {
      allow read, write: if false;
    }
  }
}
```

同时在 Firebase Authentication 控制台关闭未使用的**匿名登录（Anonymous Sign-in）**与无验证自助注册，避免攻击者仅凭公开 `apiKey` 调用 `accounts:signUp` 获取有效 `idToken`。

### 3. CI 密钥门禁、边界分级分类与运行时日志掩码（Python）

以下脚本可同时作为 **CI 提交前拦截器** 与 **应用错误/日志出口过滤器**，识别敏感前缀（使用正则结构定义，不硬编码真实示例凭据），并在输出前完成哈希指纹化与字符掩码：

```python
import hashlib
import re
from dataclasses import dataclass


SECRET_RULES: tuple[tuple[str, str, re.Pattern[str], bool], ...] = (
    ("stripe_secret", "critical", re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b"), True),
    ("stripe_restricted", "high", re.compile(r"\brk_(?:live|test)_[0-9A-Za-z]{16,}\b"), True),
    ("stripe_webhook", "high", re.compile(r"\bwhsec_[0-9A-Za-z]{16,}\b"), True),
    ("stripe_publishable", "info", re.compile(r"\bpk_(?:live|test)_[0-9A-Za-z]{16,}\b"), False),
    ("aws_access_key_id", "critical", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), True),
    ("github_token", "critical", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{40,})\b"), True),
    ("slack_token", "high", re.compile(r"\bxox[bp]-[0-9A-Za-z-]{16,}\b"), True),
    ("google_api_key", "medium", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), False),
    ("pem_private_key", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), True),
)


@dataclass(frozen=True)
class SecretFinding:
    rule: str
    severity: str
    is_server_secret: bool
    fingerprint: str


def scan_artifact_text(content: str, is_client_bundle: bool = False) -> list[SecretFinding]:
    """扫描代码、Source Map 或构建产物中的潜在密钥；客户端产物对公开 Key 仅作提示，对秘密密钥阻断。"""
    findings: list[SecretFinding] = []
    for name, severity, pattern, is_secret in SECRET_RULES:
        for match in pattern.finditer(content):
            token = match.group(0)
            # 跳过明显占位符（如 EXAMPLE / placeholder）
            if "EXAMPLE" in token or "PLACEHOLDER" in token.upper():
                continue
            if is_client_bundle and not is_secret:
                # 公开前端 Key（如 pk_live_ / AIza）仍需记录以便确认 Referer 与规则限制
                eff_severity = "low"
            else:
                eff_severity = severity
            digest = hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
            findings.append(SecretFinding(name, eff_severity, is_secret, f"sha256:{digest}"))
    return findings


def redact_sensitive_text(log_line: str) -> str:
    """在错误响应与结构化日志输出前自动遮蔽任何密钥与 Authorization Bearer 凭据。"""
    redacted = log_line
    for _, _, pattern, _ in SECRET_RULES:
        redacted = pattern.sub(lambda m: f"{m.group(0)[:6]}***REDACTED***", redacted)
    redacted = re.sub(
        r"(?i)(authorization\s*[:=]\s*(?:bearer|basic|token)\s+)[^\s\"']+",
        r"\1***REDACTED***",
        redacted,
    )
    return redacted
```

### 4. GitHub Actions OIDC 无静态密钥部署示例

以 OIDC 联合认证替代在仓库 Secrets 中长期存放 `AKIA...` 静态访问密钥：

```yaml
# .github/workflows/deploy.yml (关键权限片段)
permissions:
  id-token: write
  contents: read
# 使用 aws-actions/configure-aws-credentials 通过 role-to-assume 获取 15 分钟临时凭据
```

## 防御工作流

1. **秘密边界盘点**：将所有第三方凭据按 `publishable` 与 `secret` 分类；凡落入前端 JS、`.js.map`、APK 或公开 Postman 集合的秘密密钥一律视为已泄露。
2. **立即吊销与轮换**：按“先吊销旧密钥并签发最小权限新密钥 -> 核查对应云厂商审计日志（CloudTrail / Stripe Events / GitHub Security Log）-> 清理仓库历史提交”顺序处置。
3. **无密钥联邦替换**：将 CI/CD 与云原生工作负载中的静态 IAM Key 替换为 OIDC/STS 或工作负载身份联合，配置短期到期告警。
4. **Firebase 与云端策略收敛**：锁定 Firestore/RTDB/Storage 规则为认证用户自有数据读写，关闭多余匿名登录，为浏览器端 `AIza...` 密钥设置来源域名与 API 白名单。
5. **CI 门禁与出口过滤**：启用 GitHub Push Protection、Pre-commit 密钥扫描及应用层统一 `redact_sensitive_text` 出口过滤，杜绝异常栈或错误响应回显密钥。

## 验证与判定标准

执行下方自检代码，使用**动态拼接的合成样本**（避免静态文件触发密钥检测模式）验证扫描阻断与日志遮蔽逻辑：

```python
def run_self_checks() -> None:
    # 动态构造合成测试串，验证检测器与遮蔽器精度
    syn_stripe_sec = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    syn_stripe_pub = "pk_live_" + "z9y8x7w6v5u4t3s2r1q0p9o8"
    syn_gh = "ghp_" + "A1B2C3D4E5F6G7H8I9J0K1L2M3"
    syn_pem = "-----BEGIN " + "PRIVATE KEY-----"

    # 1. 客户端构建中出现秘密密钥必须标记为 is_server_secret=True 并阻断发布
    client_js = f'const stripeKey = "{syn_stripe_pub}"; const adminLeak = "{syn_stripe_sec}";'
    findings = scan_artifact_text(client_js, is_client_bundle=True)
    server_leaks = [f for f in findings if f.is_server_secret]
    pub_notices = [f for f in findings if not f.is_server_secret]
    assert len(server_leaks) == 1 and server_leaks[0].rule == "stripe_secret"
    assert len(pub_notices) == 1 and pub_notices[0].severity == "low"

    # 2. 服务端源码/配置中出现 GitHub Token 与 PEM 私钥必须被阻断
    repo_text = f"TOKEN={syn_gh}\nKEY={syn_pem}\n"
    repo_findings = scan_artifact_text(repo_text, is_client_bundle=False)
    rules_hit = {f.rule for f in repo_findings}
    assert {"github_token", "pem_private_key"}.issubset(rules_hit)

    # 3. 错误响应与日志出口必须完全遮蔽密钥明文与 Bearer Token
    raw_err = f"Upstream error: Authorization: Bearer {syn_gh} failed with {syn_stripe_sec}"
    safe_err = redact_sensitive_text(raw_err)
    assert syn_gh not in safe_err
    assert syn_stripe_sec not in safe_err
    assert "***REDACTED***" in safe_err

    print("[PASS] All API key leakage defense checks passed.")


if __name__ == "__main__":
    run_self_checks()
```

判定通过标准：
- 客户端构建门禁可准确区分公开初始化键与秘密密钥，命中秘密密钥时阻断构建/合并，且仅记录指纹而非原文；
- 错误响应与日志出口经 `redact_sensitive_text` 处理后不包含任何密钥原文或 `Authorization` 凭据；
- Firebase 存储与数据库规则在未认证或跨用户访问时一律返回 `PERMISSION_DENIED`；
- CI/CD 流水线不再配置静态云厂商长期 `AccessKey`，全部通过短期 STS/OIDC 签发。

## MCP 工具映射

| 防御阶段 | MCP 工具 | 用途说明 |
|---|---|---|
| 客户端暴露面核查 | `http_probe` | 检查 `/__/firebase/init.json`、公开静态 JS 与错误接口是否返回敏感配置 |
| 关联防御知识检索 | `kb_router` | 按 `API key defense`、`Firebase rules`、`secret management` 检索指南 |
| 读取技术细节 | `kb_read_file` | 对照攻击文档 [02-api-key-leak.md](02-api-key-leak.md) 核验各类 Provider 滥用边界 |
| 知识目录定位 | `kb_catalog` | 查看 `17-api-attacks` 与云安全加固目录 |
