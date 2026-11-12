---
id: "general/signature/06-replay-nonce-defense"
title: "重放攻击与 Nonce/Timestamp 绕过防御（原子去重 / 严格时间窗 / 上下文绑定）"
title_en: "Defense Against Replay Attacks and Nonce/Timestamp Bypass"
summary: >
  防御纯重放、跨用户/跨接口重放、弱随机 Nonce 预测、Nonce 缺失/数组绕过、时间戳操纵及并发竞态重放：实施 128-bit CSPRNG 一次性 Nonce、Redis 原子 SET NX EX 去重、严格双向时间偏斜窗口、上下文绑定签名与数据库幂等行锁。
summary_en: >
  Defense against plain replay, cross-user/context replay, weak nonce prediction, missing/array nonce bypass, timestamp manipulation, and concurrent race replay: 128-bit CSPRNG single-use nonces, atomic Redis SET NX EX deduplication, strict timestamp skew window, context binding, and DB idempotency locks.
board: "general"
category: "signature"
signals:
  - "atomic SET NX EX"
  - "CSPRNG nonce"
  - "timestamp skew window"
  - "context binding"
  - "idempotency lock"
  - "anti-replay"
mcp_tools:
  - "kb_router"
  - "workspace_write_text"
  - "make_sigma_stub"
keywords:
  - "replay defense"
  - "nonce deduplication"
  - "timestamp validation"
  - "idempotency"
  - "race condition defense"
difficulty: "advanced"
tags:
  - "signature-defense"
  - "anti-replay"
  - "nonce"
  - "idempotency"
  - "concurrency"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "general/signature/06-replay-nonce"
  - "general/signature/00-overview-defense"
track: "blue"
defends: "general/signature/06-replay-nonce"
---
# 重放攻击与 Nonce/Timestamp 绕过防御（原子去重 / 严格时间窗 / 上下文绑定）

## 防御目标

彻底堵死签名请求被原样重放、跨用户/跨路径重用、通过 `nonce` 缺失/数组/空值绕过、利用负/超大 `timestamp` 失效窗口以及高并发竞态窗口重复触发发货或扣款等持久化副作用的风险。

## 重放攻击向量与防御矩阵

| 攻击向量 | 常见漏洞实现 | 强制防御策略 |
|---|---|---|
| 纯重放 / Nonce 复用 | 仅验签未存储已使用 `nonce`，或先 `GET` 后 `SET` 非原子导致并发竞态 | 使用 **Redis `SET key 1 NX EX ttl`** 或数据库 `UNIQUE(scope, nonce)` **原子插槽**，先占锁成功再执行业务 |
| 弱随机 / 可预测 Nonce | 使用自增整数、`time()` 或 `Math.random()` 生成 `nonce` | 客户端/签发方强制使用 >= 128-bit CSPRNG（如 UUIDv4 / `secrets.token_hex(16)`） |
| Nonce 缺失 / `null` / 数组绕过 | `if nonce: check(nonce)` 导致不传或传 `nonce[]=x` 绕过校验 | 强制 `nonce` 为必填字符串且正则匹配（如 `^[0-9a-fA-F-]{16,64}$`），缺失或类型不符直接拒绝 |
| 时间戳窗口操纵 | 允许未来时间戳、`ts=0`、负数或非整数，或窗口 TTL 大于 Nonce 缓存时长 | 强制 `abs(server_now - ts) <= MAX_SKEW`（推荐 60~300 秒），且 **Nonce 缓存 TTL >= `2 * MAX_SKEW`** 消除过期空窗 |
| 跨用户 / 跨接口重放 | 签名未覆盖 HTTP Method、Path、Host、Tenant/User ID | 将 `(method, path, user_id, key_id, ts, nonce)` 全部纳入待签原文，消除跨上下文复用 |
| 支付回调并发与幂等绕过 | 同一订单并发两次回调均穿过初始状态检查 | 业务层配合数据库 `UPDATE orders SET status='paid' WHERE id=? AND status='pending'` 原子状态机与唯一事务流水号 |

## 防御实现与校验示例

### 1. 原子 Nonce 去重 + 严格时间窗 + 上下文绑定验证器（Python）

演示单原子 `try_acquire_nonce`、双向时间窗校验、上下文全绑定以及与订单幂等锁联动的标准防御模式：

```python
import hashlib
import hmac
import re
import threading
import time

NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")

class AtomicReplayProtector:
    def __init__(self, max_skew_sec: int = 120):
        self.max_skew_sec = max_skew_sec
        self.nonce_ttl_sec = max_skew_sec * 2 + 30  # 严格大于双向时间窗
        self._lock = threading.Lock()
        self._store: dict[str, int] = {}

    def try_acquire(self, scope: str, nonce: str, now: int) -> bool:
        # 模拟 Redis SET <key> 1 NX EX <ttl> 的原子语义
        key = f"{scope}:{nonce}"
        with self._lock:
            expired = [k for k, exp in self._store.items() if exp <= now]
            for k in expired:
                del self._store[k]
            if key in self._store:
                return False
            self._store[key] = now + self.nonce_ttl_sec
            return True

def verify_bound_request(
    secret: bytes,
    protector: AtomicReplayProtector,
    method: str,
    path: str,
    user_id: str,
    ts: object,
    nonce: object,
    body: bytes,
    sig_hex: object,
    server_now: int | None = None,
) -> tuple[bool, str]:
    if not isinstance(ts, int) or isinstance(ts, bool) or ts <= 0:
        return False, "invalid_timestamp"
    if not isinstance(nonce, str) or not NONCE_RE.fullmatch(nonce):
        return False, "invalid_nonce"
    if not isinstance(sig_hex, str) or len(sig_hex) != 64:
        return False, "invalid_signature"

    now = int(time.time()) if server_now is None else server_now
    if abs(now - ts) > protector.max_skew_sec:
        return False, "timestamp_outside_window"

    # 上下文全绑定待签串：方法、路径、用户、时间戳、Nonce 与 Body 摘要
    body_hash = hashlib.sha256(body).hexdigest()
    signing_input = f"{method.upper()}\n{path}\n{user_id}\n{ts}\n{nonce}\n{body_hash}".encode("utf-8")
    expected = hmac.new(secret, signing_input, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig_hex.lower(), expected):
        return False, "signature_mismatch"

    scope = f"{method.upper()}:{path}:{user_id}"
    if not protector.try_acquire(scope, nonce, now):
        return False, "replay_detected"
    return True, "ok"

if __name__ == "__main__":
    sec = b"K" * 32
    prot = AtomicReplayProtector(max_skew_sec=120)
    now = 1700000500
    nonce = "a1b2c3d4e5f60718293a4b5c"
    body = b'{"order_id":"ORD9","amount":500}'
    bh = hashlib.sha256(body).hexdigest()
    msg = f"POST\n/api/pay/callback\nuser_42\n{now}\n{nonce}\n{bh}".encode()
    sig = hmac.new(sec, msg, hashlib.sha256).hexdigest()

    assert verify_bound_request(sec, prot, "POST", "/api/pay/callback", "user_42", now, nonce, body, sig, now)[0] is True
    # 原样重放 -> 拦截
    assert verify_bound_request(sec, prot, "POST", "/api/pay/callback", "user_42", now, nonce, body, sig, now) == (False, "replay_detected")
    # 跨用户重放 -> 签名不匹配拦截
    assert verify_bound_request(sec, prot, "POST", "/api/pay/callback", "user_99", now, nonce, body, sig, now) == (False, "signature_mismatch")
    # 负数/未来时间戳 -> 拦截
    assert verify_bound_request(sec, prot, "POST", "/api/pay/callback", "user_42", -1, nonce, body, sig, now) == (False, "invalid_timestamp")
    print("replay_nonce_defense_check: PASS")
```

## 防御工作流

```text
1. 签名字段完整性：强制待签原文绑定 HTTP Method、Path、用户/商户 ID、Timestamp 与 Nonce
2. 时间窗与类型校验：校验 ts 为正整数且处于 [now - skew, now + skew] 区间，拒绝缺失/数组/畸形 nonce
3. 原子防重放存储：使用 Redis SET NX EX 或 DB 唯一索引原子写入 nonce，TTL 必须覆盖整个时间窗口
4. 先验签后占锁：先校验 HMAC/非对称签名合法，再写入 Nonce 缓存，避免恶意伪造请求打满 Nonce 内存（DoS）
5. 业务幂等兜底：支付、积分与权益变更必须叠加数据库事务行锁与条件更新（WHERE status = 'pending'）
```

## 验证与判定标准

- **并发重放零通过**：对同一合法签名请求发起 50 并发线程重放，仅 1 个请求成功，其余 49 个全部返回 `replay_detected`
- **边界时间窗**：`ts=0`、`ts=-1`、`ts=now+3600` 及 `ts=now-3600` 均返回 `invalid_timestamp` 或 `timestamp_outside_window`
- **跨上下文阻断**：将 `user_42` 的合法签名请求发往 `user_99` 或不同 API 路径时 100% 返回 `signature_mismatch`

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 关联重放与规范化检索 | `kb_router` | 检索统一验签管线与 HPP 防护方案 |
| 原子重放测试脚本生成 | `workspace_write_text` | 将并发重放与边界时间戳测试脚本写入工作区 |
| 重放高频攻击告警 | `make_sigma_stub` | 生成针对同一 Nonce 短时高频重放（`replay_detected`）的告警规则 |
