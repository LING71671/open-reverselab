---
id: "ctf-website/01-recon/captcha-bypass-defense"
title: "人机验证与 CAPTCHA 防绕过加固"
title_en: "CAPTCHA & Anti-Automation Defense Hardening"
summary: >
  针对 OCR 识别、打码平台代打、Token 跨请求复用、前端校验绕过与短信验证码爆破等人机验证绕过手法，提供服务端原子一次性消费、Token 上下文强绑定（action/session/IP/phone）、测试密钥封堵与风险分层限流架构。
summary_en: >
  Defense-in-depth hardening against CAPTCHA bypass vectors including OCR, solving farms, token replay, client-only checks, and SMS OTP brute-force. Covers atomic single-use token consumption, strict action/session/phone binding, test-key blocking, and layered rate limiting.
board: "ctf-website"
category: "01-recon"
signals: ["CAPTCHA", "验证码", "reCAPTCHA", "Turnstile", "短信验证码", "Token 重放", "人机验证加固", "anti-bot"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["CAPTCHA防御", "防重放", "一次性Token", "验证码绑定", "reCAPTCHA服务端校验", "Turnstile加固", "短信防爆破", "blue-team"]
difficulty: "intermediate"
tags: ["defense", "blue-team", "captcha", "anti-automation", "rate-limit", "web-security"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/01-recon/captcha-bypass", "ctf-website/01-recon/recon-routing-defense"]
track: "blue"
defends: "ctf-website/01-recon/captcha-bypass"
---
# 人机验证与 CAPTCHA 防绕过加固

## 防御目标与威胁面

人机验证失效的根因通常不在前端挑战难度本身，而在**服务端校验链缺失或状态机未原子化**。常见失陷点包括：

1. **缺失服务端强制校验**：仅依赖前端 JS 或 `localStorage`/Cookie 标志位放行，业务接口未验证凭证。
2. **Token 跨请求重放与多账号共用**：未将 `captcha_id`、reCAPTCHA/Turnstile Token 与具体 `session_id`、`action`、客户端指纹或目标手机号绑定，或验证后未原子删除（TOCTOU 并发窗口）。
3. **测试密钥与调试开关遗留**：生产环境仍允许 Google reCAPTCHA 测试 `sitekey`（`6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI`）或固定万能验证码通过。
4. **短信/图形验证码熵值与频控不足**：4~6 位纯数字无尝试次数上限，或生成图像干扰不足被通用 OCR 毫秒级识别。

## 核心防御架构

| 攻击向量 | 根治控制措施 | 关键实现约束 |
|---|---|---|
| 前端状态伪造 / 删参绕过 | 服务端中间件强制 Fail-Closed | 缺失字段、空字符串、数组类型均直接返回 `400/403` |
| Token 重放 / 并发消费 | Redis `GETDEL` 或 Lua 原子脚本一次性核销 | TTL 控制在 60~120 秒，核销后立即作废 |
| 跨接口 / 跨账号借用 | 签发与核验绑定 `(action, session_id, target_identity)` | Turnstile/reCAPTCHA v3 必须校对响应 `action` 与 `hostname` |
| 短信码爆破与串号 | `phone + scene + code` 三元组哈希校验 + 失败计数锁定 | 单手机号 5 分钟内错误 ≥ 5 次即作废当前验证码 |
| 测试密钥上线风险 | 启动自检拦截已知测试 Key | 禁止已知测试 `sitekey`/`secret` 进入生产配置 |
| 自动化/打码平台代打 | 行为指纹 + 分层限流 + 敏感操作二次挑战 | 异常 IP/ASN/TLS 指纹触发步进验证或滑动窗口封禁 |

## 加固代码与离线核查示例

以下 Python 参考实现演示**原子一次性核销、上下文绑定校验及测试密钥拦截**的防护逻辑与自检用例：

```python
import hmac
import hashlib
import time
from typing import Dict, Optional, Tuple

KNOWN_TEST_KEYS = {
    "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI",  # reCAPTCHA v2 test sitekey
    "1x00000000000000000000AA",                   # Turnstile always-pass sitekey
    "1x0000000000000000000000000000000AA",        # Turnstile always-pass secret
}


class AtomicCaptchaStore:
    """模拟 Redis GETDEL 原子核销与失败计数锁定。"""

    def __init__(self, ttl_sec: int = 120, max_attempts: int = 5):
        self.ttl_sec = ttl_sec
        self.max_attempts = max_attempts
        self._records: Dict[str, dict] = {}
        self._used_external_tokens: Dict[str, float] = {}

    def issue(self, challenge_id: str, expected_code: str, action: str, identity: str, now: Optional[float] = None) -> None:
        ts = now if now is not None else time.time()
        digest = hmac.new(b"server-ephemeral-pepper", expected_code.encode(), hashlib.sha256).hexdigest()
        self._records[challenge_id] = {
            "digest": digest,
            "action": action,
            "identity": identity,
            "expires_at": ts + self.ttl_sec,
            "attempts": 0,
        }

    def verify_and_consume(
        self, challenge_id: object, code: object, action: str, identity: str, now: Optional[float] = None
    ) -> Tuple[bool, str]:
        # 1. Fail-closed 严格类型检查，防御数组/空值/删参绕过
        if not isinstance(challenge_id, str) or not isinstance(code, str) or not challenge_id or not code:
            return False, "invalid_input_type"

        rec = self._records.get(challenge_id)
        if not rec:
            return False, "missing_or_consumed"

        ts = now if now is not None else time.time()
        if ts > rec["expires_at"]:
            self._records.pop(challenge_id, None)
            return False, "expired"

        # 2. 强上下文绑定（防跨接口、跨账号/手机号串用）
        if rec["action"] != action or rec["identity"] != identity:
            return False, "context_mismatch"

        expected = rec["digest"]
        actual = hmac.new(b"server-ephemeral-pepper", code.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, actual):
            rec["attempts"] += 1
            if rec["attempts"] >= self.max_attempts:
                self._records.pop(challenge_id, None)
                return False, "locked_and_revoked"
            return False, "wrong_code"

        # 3. 核验成功立即原子移除，杜绝重放
        self._records.pop(challenge_id, None)
        return True, "ok"

    def verify_external_token(
        self, sitekey: str, token: object, resp_payload: dict, expected_host: str, expected_action: str, now: Optional[float] = None
    ) -> Tuple[bool, str]:
        if sitekey in KNOWN_TEST_KEYS:
            return False, "forbidden_test_key"
        if not isinstance(token, str) or len(token) < 16:
            return False, "invalid_token"
        ts = now if now is not None else time.time()
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        if token_hash in self._used_external_tokens and self._used_external_tokens[token_hash] > ts:
            return False, "replayed_token"
        if not resp_payload.get("success"):
            return False, "provider_rejected"
        if resp_payload.get("hostname") != expected_host or resp_payload.get("action") != expected_action:
            return False, "claim_mismatch"
        self._used_external_tokens[token_hash] = ts + 300
        return True, "ok"


if __name__ == "__main__":
    store = AtomicCaptchaStore(ttl_sec=120, max_attempts=3)
    store.issue("cid-1", "839201", action="login", identity="13800001111", now=1000.0)
    assert store.verify_and_consume(["cid-1"], "839201", "login", "13800001111", now=1005.0) == (False, "invalid_input_type")
    assert store.verify_and_consume("cid-1", "839201", "register", "13800001111", now=1005.0) == (False, "context_mismatch")
    assert store.verify_and_consume("cid-1", "839201", "login", "13800002222", now=1005.0) == (False, "context_mismatch")
    assert store.verify_and_consume("cid-1", "839201", "login", "13800001111", now=1010.0) == (True, "ok")
    assert store.verify_and_consume("cid-1", "839201", "login", "13800001111", now=1011.0) == (False, "missing_or_consumed")
    assert store.verify_external_token("6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI", "x" * 20, {"success": True}, "app.example", "login")[0] is False
    print("CAPTCHA defense self-check passed.")
```

## 防御工作流

```text
1. 入口清点：列出所有触发登录、注册、短信下发、支付与表单提交的 API 路由
2. 配置核查：确认生产环境变量与前端模板未残留 reCAPTCHA/Turnstile 测试密钥
3. 中间件加固：在网关或路由守卫统一强制类型检查与 Fail-Closed 校验，拒绝空值与数组参数
4. 原子与绑定改造：将挑战记录改为 Redis GETDEL 原子核销，并强制校验 action/hostname/identity
5. 纵深限流：按 IP、设备指纹、账号与手机号四维叠加令牌桶限流与异常评分降级策略
```

## 验证与判定标准

- **删除参数与异常类型测试**：向目标接口发送无 `captcha` 字段、空字符串及 JSON 数组时，必须稳定返回 `400` 或 `403`，不得进入业务逻辑。
- **重放与并发核销**：同一合法 `captcha_id` 或 Turnstile/reCAPTCHA Token 并发重放 20 次，至多允许 1 次返回业务成功，其余 19 次全部返回拒绝。
- **跨场景/跨账号隔离**：在 `/register` 或手机号 A 申请的凭证提交至 `/login` 或手机号 B 时，服务端必须因上下文不匹配而拒绝。
- **测试密钥零残留**：CI/CD 配置检查确认生产配置不包含公开测试 `sitekey`/`secret`。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索对应攻击手法与加固方案 | `kb_router` | 以 `CAPTCHA`、`reCAPTCHA`、`Turnstile` 检索红蓝成对文档 |
| 读取关联文档细节 | `kb_read_file` | 读取 [captcha-bypass.md](captcha-bypass.md) 对照所有绕过路径 |
| 浏览防御目录 | `kb_catalog` | 查看 `ctf-website/01-recon` 下全部蓝队条目 |
