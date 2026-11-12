---
id: "ctf-website/07-client/websocket-defense"
title: "WebSocket / Socket.IO / MQTT 实时通道纵深防御"
title_en: "WebSocket, Socket.IO, and MQTT Security Hardening"
summary: >
  针对 WebSocket、Socket.IO 与 MQTT over WebSocket 的全链路防御指南。覆盖握手阶段 Origin 精确白名单与一次性短期票据防 CSWSH、连接后逐消息权限与对象归属重验、防重放单调序列号与分布式幂等并发锁、消息 Schema 防注入（SQLi/NoSQLi/PP/SSTI）以及 Socket.IO Namespace/Room 与 MQTT Topic ACL 加固。
summary_en: >
  Full-lifecycle defense guide for WebSocket, Socket.IO, and MQTT over WebSocket. Covers strict handshake Origin allowlisting and short-lived tickets against CSWSH, per-message authorization and object-ownership re-verification, monotonic sequence numbers and idempotency locks against race conditions, schema validation against injection, and Socket.IO/MQTT ACL hardening.
board: "ctf-website"
category: "07-client"
signals: ["WebSocket防御", "CSWSH防护", "逐事件鉴权", "Socket.IO ACL", "MQTT主题ACL", "并发幂等锁", "seq防重放"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog", "http_probe"]
keywords: ["WebSocket防御", "CSWSH防御", "Socket.IO鉴权", "MQTT ACL", "消息重放防护", "WebSocket竞态防御", "Origin白名单", "实时消息注入防护"]
difficulty: "advanced"
tags: ["defense", "blue-team", "websocket", "cswsh", "realtime", "client-side"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/07-client/websocket", "ctf-website/07-client/cors-csrf-defense", "ctf-website/03-injection/sqli-nosqli-defense", "ctf-website/12-payment/payment-race-lost-update"]
track: "blue"
defends: "ctf-website/07-client/websocket"
---

# WebSocket / Socket.IO / MQTT 实时通道纵深防御

WebSocket 的常见隐患是“只防握手不防帧”：攻击者要么利用 Cookie 自动携带发起 CSWSH 跨站劫持，要么在 `connection_init` 通过后篡改 `role`、`userId`、`roomId`、`orderId`、`amount`、`seq` 越权订阅或并发竞态刷单，甚至通过 `filter` 字段绕开 REST 中间件直接触达数据库与模板引擎。防御必须覆盖**握手鉴权、逐帧授权、原子并发控制、Schema 隔离**四个阶段。

## 防御工作流

```text
HTTP 101 握手强制精确 Origin 白名单 + 一次性短期 WS Ticket（禁 URL 长期 Token）
  → 连接上下文绑定服务端不可变身份（忽略消息内 role/userId/isAdmin）
  → 每一条 join/subscribe/action 消息重验对象归属与实时会话吊销状态
  → 对状态变更消息强制单调 seq/idempotency_key + 数据库事务锁（校验先于落库）
  → 消息体经强 Schema 校验与参数化入库，Socket.IO/MQTT 按 Namespace/Room/Topic 落 ACL
```

## 1. 握手阶段抗 CSWSH 加固

1. **精确 `Origin` 白名单**：WebSocket 协议不遵循同源策略且浏览器自动携带 Cookie。升级握手处理函数必须检查 `Origin` 头精确匹配静态白名单集合（拒绝缺失 `Origin`、`null`、`target.com.evil.com` 与 `http://` 降级），不匹配时直接拒绝升级返回 `403`。
2. **Cookie 属性 + 短期一次性票据**：会谈 Cookie 设 `SameSite=Lax`（或 `Strict`）+ `Secure` + `HttpOnly`。对于跨子域或原生混合端场景，先通过已保护的 HTTPS `POST /api/ws-ticket`（带 CSRF 校验）换取绑定 `user_id + client_ip`、TTL `<= 30s` 且单次消费即作废的随机 `ticket`，禁止把长期 JWT 明文放入 `wss://.../ws?token=...` 防止代理/访问日志泄露。

## 2. 逐事件鉴权与业务状态原子性

| 风险位置 | 典型利用方式 | 强制加固要求 |
|---|---|---|
| 身份/权限字段 | 客户端上送 `{"role":"admin","userId":1}` | 服务端一律忽略客户端传来的身份字段，全部从服务端连接会话 `conn.user_id`、`conn.role` 取值 |
| `join` / `subscribe` | 订阅 `roomId: "admin"`、`orderId: 9001` 或通配 `*` | 每次订阅必须查询数据库确认 `user_id` 对该房间/订单/租户具备访问权限 |
| 并发竞态 (`race_ws`) | 单连接并发发送 50 条兑换/转账消息 | 每连接/每用户使用异步互斥锁或数据库行级锁（`SELECT ... FOR UPDATE`）配合唯一 `idempotency_key` 串行化状态变更 |
| 校验与落库倒置 | 回执 `ack=false` 但钱包/订单已先改写 | 严禁“先异步投递副作用再回包校验”，所有金额/权限检查必须在同一数据库事务提交前完成 |
| 时序重放 (`seq`/`nonce`) | 重放旧 `seq` 或乱序/负值时间字段 | 维护连接级严格单调递增序号 `seq > conn.last_seq` 与时间窗校验，超窗或重复直接丢弃 |

## 3. 消息注入防护（SQLi / NoSQLi / PP / SSTI）

WebSocket 事件处理器常直接拼装数据库或状态对象，必须与 REST API 执行同等级防线：
- **Schema 强约束**：所有 JSON 帧经过 Pydantic/Zod 校验，拒绝非法类型（防止 `{"id": {"$gt": ""}}` NoSQL 注入）与 `__proto__` / `constructor` / `prototype` 键。
- **参数化查询与白名单路由**：`filter`、`sort`、`orderBy` 等参数走枚举白名单与 SQL 预编译绑定，禁用自由表达式或字符串拼模板。
- **限帧与背压**：限制单帧最大字节（如 `<= 64 KB`）与每秒消息速率（令牌桶），防止大帧或高频泛洪拖垮事件循环。

## 4. Socket.IO 与 MQTT over WebSocket 专项 ACL

- **Socket.IO**：禁止仅在根命名空间 `/` 做一次握手鉴权。必须对 `/admin`、`/internal` 等每个 Namespace 注册独立的 `io.of(ns).use(authMiddleware)` 认证中间件；客户端调用 `socket.on("join", ...)` 时强制执行房间归属鉴权与事件白名单映射，禁止暴露未授权的调试事件名。
- **MQTT over WebSocket**：Broker 禁用匿名登录（`allow_anonymous false`），强制启用账号认证与细粒度 Topic ACL：禁止普通客户端订阅 `#`、`+/+/#` 或 `$SYS/#` 系统主题，禁止非管理身份向 `admin/+/cmd` 等控制主题发布消息。

## 5. 可运行 WebSocket 帧策略与并发防重放校验器

以下 Python 代码展示服务端 WebSocket 升级 `Origin` 校验、连接上下文隔离、单调 `seq` 防重放、字段白名单与异步并发幂等控制逻辑，并附带完整断言测试：

```python
#!/usr/bin/env python3
"""WebSocket 握手 Origin/Ticket 校验、逐帧鉴权与并发幂等控制器。"""
import asyncio
from dataclasses import dataclass, field

ALLOWED_WS_ORIGINS = frozenset({"https://target.example", "https://app.target.example"})
FORBIDDEN_KEYS = frozenset({"__proto__", "constructor", "prototype"})


class WsSecurityError(PermissionError):
    pass


def verify_ws_handshake(origin: str | None, ticket_store: set[str], ticket: str | None) -> None:
    """升级阶段防 CSWSH：严格 Origin 白名单 + 一次性票据消费。"""
    if not origin or origin == "null" or origin not in ALLOWED_WS_ORIGINS:
        raise WsSecurityError(f"rejected origin: {origin!r}")
    if not ticket or ticket not in ticket_store:
        raise WsSecurityError("invalid or replayed ws ticket")
    ticket_store.remove(ticket)  # 单次有效


@dataclass
class WsSessionContext:
    user_id: int
    role: str
    allowed_rooms: set[str]
    last_seq: int = 0
    processed_nonces: set[str] = field(default_factory=set)
    balance: int = 100
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)


async def handle_ws_frame(ctx: WsSessionContext, frame: dict) -> dict:
    """逐帧执行 Schema 防注入、单调 seq 防重放、房间 ACL 与并发原子锁。"""
    if not isinstance(frame, dict):
        raise WsSecurityError("frame must be JSON object")
    if any(k in FORBIDDEN_KEYS for k in frame.keys()):
        raise WsSecurityError("prototype pollution key blocked")

    # 1. 严格忽略客户端携带的 role / userId / isAdmin 欺骗字段
    action = frame.get("type")
    seq = frame.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq <= ctx.last_seq:
        raise WsSecurityError(f"replay or out-of-order seq: {seq}")

    async with ctx._lock:
        # 双重检查避免并发协程越过同一 seq
        if seq <= ctx.last_seq:
            raise WsSecurityError(f"concurrent duplicate seq blocked: {seq}")

        if action == "subscribe":
            room = frame.get("roomId")
            if not isinstance(room, str) or room not in ctx.allowed_rooms:
                raise WsSecurityError(f"unauthorized room subscription: {room!r}")
            ctx.last_seq = seq
            return {"ack": True, "subscribed": room, "as_user": ctx.user_id}

        if action == "redeem":
            amount = frame.get("amount")
            nonce = frame.get("nonce")
            if not isinstance(amount, int) or amount <= 0 or amount > ctx.balance:
                raise WsSecurityError("invalid redeem amount")
            if not isinstance(nonce, str) or nonce in ctx.processed_nonces:
                raise WsSecurityError("duplicate or missing idempotency nonce")
            # 所有校验全部通过后再推进余额与序号
            ctx.balance -= amount
            ctx.processed_nonces.add(nonce)
            ctx.last_seq = seq
            return {"ack": True, "balance": ctx.balance}

        raise WsSecurityError(f"unsupported action: {action!r}")


async def run_self_checks() -> None:
    tickets = {"tk_one_time_123"}
    # 1. CSWSH Origin 校验
    for bad_orig in (None, "null", "https://evil.example", "https://target.example.evil.com"):
        try:
            verify_ws_handshake(bad_orig, tickets, "tk_one_time_123")
            raise AssertionError(f"expected handshake reject for {bad_orig}")
        except WsSecurityError:
            pass
    verify_ws_handshake("https://target.example", tickets, "tk_one_time_123")
    assert "tk_one_time_123" not in tickets

    # 2. 逐帧越权、PP 与防重放测试
    ctx = WsSessionContext(user_id=1001, role="user", allowed_rooms={"general", "user_1001"}, balance=50)
    for bad_frame in (
        {"type": "subscribe", "roomId": "admin", "role": "admin", "seq": 1},
        {"type": "subscribe", "roomId": "*", "seq": 1},
        {"type": "subscribe", "roomId": "general", "__proto__": {"isAdmin": True}, "seq": 1},
        {"type": "redeem", "amount": -10, "nonce": "n1", "seq": 1},
    ):
        try:
            await handle_ws_frame(ctx, bad_frame)
            raise AssertionError(f"expected frame reject for {bad_frame}")
        except WsSecurityError:
            pass

    # 3. 并发竞态测试：10 个并发同 nonce/同 seq 请求仅成功 1 次
    res = await asyncio.gather(
        *[handle_ws_frame(ctx, {"type": "redeem", "amount": 50, "nonce": "race_n1", "seq": 1}) for _ in range(10)],
        return_exceptions=True,
    )
    ok_count = sum(1 for r in res if isinstance(r, dict) and r.get("ack"))
    assert ok_count == 1 and ctx.balance == 0
    print(f"[PASS WS] handshake, per-frame ACL, PP block, and race lock passed (ok={ok_count}, balance={ctx.balance})")


if __name__ == "__main__":
    asyncio.run(run_self_checks())
```

## 验证与判定标准

| 验证项 | 预期加固表现 | 阻断失败标志 |
|---|---|---|
| CSWSH 握手与 Origin | 非白名单/`null`/前缀后缀变形 Origin 握手直接返回 `403`；ticket 单次失效 | 跨站页面携带 Cookie 建立 `101` 连接并收发消息 |
| 逐消息越权与伪造 | 篡改 `role`/`userId`/`roomId` 返回权限错误；Socket.IO `/admin` 及 MQTT `$SYS/#` 拒绝 | 收到跨账号广播或 `admin_room` 消息 |
| 并发竞态与重放 | 50 并发同消息仅首次生效，旧 `seq` 丢弃，失败时不提前修改数据库状态 | `ack=false` 但余额/订单已扣减，或并发兑现超额 |
| 消息帧注入防护 | SQLi/NoSQLi 对象、`__proto__`、`{{7*7}}` 在 Schema 校验层拒绝或参数化处理 | 触发 SQL 报错、原型修改或异常崩溃 |

## MCP 工具映射

| 防御环节 | MCP 工具 | 说明 |
|---|---|---|
| 防御知识路由 | `kb_router` | 按 `websocket`、`cswsh`、`socketio`、`mqtt`、`race` 检索配对文档 |
| 读取攻击矩阵 | `kb_read_file` | 对照 `ctf-website/07-client/websocket` 核验握手与帧级别加固覆盖 |
| 浏览目录索引 | `kb_catalog` | 查看 `07-client` 与 `12-payment`、`03-injection` 联动防御文档 |
| 握手与响应核验 | `http_probe` | 切换到 `red` 或 `both` 轨道后测试 WebSocket 握手端点的 Origin 拒绝响应 |
