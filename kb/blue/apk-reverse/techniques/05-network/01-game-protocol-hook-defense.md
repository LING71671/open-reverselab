---
id: "apk-reverse/05-network/01-game-protocol-hook-defense"
title: "游戏协议防 Hook、抗重放与端到端加固"
title_en: "Game Protocol Anti-Hook, Anti-Replay, and End-to-End Hardening"
summary: >
  针对 OkHttp/Retrofit Java 层 Hook、Native sendto/recvfrom 抓包、Protobuf 结构逆向以及延迟重放绕过（4.9 秒缓存复用），提供服务端权威校验、每包单调 seq+nonce、AEAD+HMAC 会话密钥绑定及协议字段剥离方案。
summary_en: >
  Defense-in-depth against OkHttp/Retrofit Java hooks, native sendto/recvfrom hooking, Protobuf reverse engineering, and delayed packet replay. Covers server-authoritative state validation, per-packet monotonic seq and nonce, AEAD+HMAC session binding, and Protobuf reflection stripping.
board: "apk-reverse"
category: "05-network"
signals:
  - "OkHttp Hook 防护"
  - "sendto/recvfrom 抗抓包"
  - "延迟发包防重放"
  - "Protobuf 去反射"
  - "HMAC seq nonce"
  - "服务端权威校验"
mcp_tools:
  - "android_http_observation_recipe"
  - "android_crypto_unpack_recipe"
  - "ghidra_headless_analyze"
  - "kb_router"
keywords:
  - "游戏协议防御"
  - "防重放"
  - "seq nonce"
  - "Protobuf加固"
  - "OkHttp防Hook"
  - "AEAD"
  - "blue-team"
difficulty: "intermediate"
tags:
  - "defense"
  - "blue-team"
  - "network"
  - "anti-replay"
  - "protobuf"
  - "game-security"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "apk-reverse/05-network/01-game-protocol-hook"
  - "apk-reverse/05-network/03-tls-pinning-unpinning-defense"
  - "apk-reverse/05-network/02-license-verification-bypass-defense"
track: "blue"
defends: "apk-reverse/05-network/01-game-protocol-hook"
---
# 游戏协议防 Hook、抗重放与端到端加固

## 防御目标与威胁面

在游戏与实时业务中，攻击者无需破解传输层 TLS 即可通过 Frida Hook Java 层 `OkHttp`/`Retrofit` 或 Native 层 `libc.so` 的 `sendto`/`recvfrom` 获取序列化明文，进而利用 `protoc --decode_raw` 或 `protobuf-inspector` 推断协议结构，甚至通过缓存合法签名封包并在有效时间窗内延迟重放（例如利用 5 秒窗口在 4.9 秒重发）完成刷奖或状态伪造。

单纯加密载荷或依赖固定时间窗无法阻断 Hook 与延迟重放，必须同时落实**服务端权威状态机**、**严格单调序列号与一次性 Nonce**、**应用层 AEAD 会话加密**以及**传输层 Pinning**。

## 核心防御矩阵

| 攻击向量 | 根治控制措施 | 关键实现约束 |
|---|---|---|
| 延迟发包 / 时间窗口内重放 | 服务端强制单调递增 `seq` + 服务端签发 `challenge/nonce` | 同一连接或会话内 `seq <= last_seq` 立即丢弃并断开；关键动作使用单次挑战 |
| Hook `OkHttp` / `sendto` 获取明文 | 协议体在 Native 层经 ECDH 协商的会话密钥做 AES-GCM/ChaCha20-Poly1305 加密 | AAD 绑定 `(session_id, msg_type, seq, ts)`，篡改包头即认证失败 |
| `protoc --decode_raw` 推断结构 | 发布包启用 Protobuf Lite 并剥离 `.proto` 描述符与枚举名 | 避免在字段传输明文敏感状态值，关键数值由服务端独立计算 |
| 代理重定向（`redsocks`/`iptables`） | TLS 双向认证或 Native SPKI Pinning + 非标准二进制帧校验 | 即使流量被转发至代理也无法完成握手或伪造有效帧 |
| 客户端直接上行作弊数值 | 服务端权威校验（只接收输入意图，不信任客户端结果） | 校验冷却时间、移动速度上限、资源余额与状态迁移合法性 |

## 加固代码与协议校验示例

以下 Python 参考实现演示**单调序列号滑动防重放、时间窗校验与 HMAC-SHA256 包完整性验证**：

```python
import hashlib
import hmac
import struct
import time
from typing import Dict, Tuple


class SessionPacketGuard:
    """服务端游戏协议抗重放与完整性校验器。"""

    def __init__(self, session_key: bytes, max_skew_sec: float = 3.0) -> None:
        self.session_key = session_key
        self.max_skew_sec = max_skew_sec
        self.last_seq: Dict[int, int] = {}

    def build_packet(self, session_id: int, seq: int, msg_type: int, payload: bytes, ts: int) -> bytes:
        header = struct.pack(">QIHI", session_id, seq, msg_type, ts)
        mac = hmac.new(self.session_key, header + payload, hashlib.sha256).digest()[:16]
        return header + payload + mac

    def verify_packet(self, raw: bytes, now: float | None = None) -> Tuple[bool, str, bytes]:
        if len(raw) < 18 + 16:
            return False, "packet_too_short", b""

        header = raw[:18]
        payload = raw[18:-16]
        tag = raw[-16:]
        session_id, seq, _msg_type, ts = struct.unpack(">QIHI", header)

        expected_tag = hmac.new(self.session_key, header + payload, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, expected_tag):
            return False, "invalid_mac", b""

        cur_ts = now if now is not None else time.time()
        if abs(cur_ts - ts) > self.max_skew_sec:
            return False, "timestamp_expired", b""

        prev = self.last_seq.get(session_id, 0)
        if seq <= prev:
            return False, "replay_or_out_of_order", b""

        self.last_seq[session_id] = seq
        return True, "ok", payload


if __name__ == "__main__":
    guard = SessionPacketGuard(session_key=b"ephemeral-ecdh-session-key-32b!!", max_skew_sec=3.0)
    pkt1 = guard.build_packet(session_id=1001, seq=1, msg_type=0x10, payload=b"\x08\x01", ts=1700000000)
    pkt2 = guard.build_packet(session_id=1001, seq=2, msg_type=0x10, payload=b"\x08\x02", ts=1700000001)

    assert guard.verify_packet(pkt1, now=1700000000.5)[0] is True
    # 即使仍在 3 秒时间窗内，重放同一 seq=1 封包也会被立即拒绝
    assert guard.verify_packet(pkt1, now=1700000001.0)[:2] == (False, "replay_or_out_of_order")
    # 篡改载荷无法通过 HMAC 校验
    tampered = pkt2[:-17] + b"\xff" + pkt2[-16:]
    assert guard.verify_packet(tampered, now=1700000001.2)[:2] == (False, "invalid_mac")
    assert guard.verify_packet(pkt2, now=1700000001.5)[:2] == (True, "ok")
    print("Game protocol anti-replay self-check passed.")
```

### Android 端 Protobuf Lite 与混淆配置

```text
# build.gradle.kts — 禁止在 Release 包携带 full protobuf 反射描述符
protobuf {
    protoc { artifact = "com.google.protobuf:protoc:3.25.3" }
    generateProtoTasks {
        all().forEach { task ->
            task.builtins {
                create("java") { option("lite") }
            }
        }
    }
}
```

## 防御工作流

```text
1. 协议盘点：识别全部走 OkHttp/Retrofit 与 Native Socket 的高价值接口与二进制消息号
2. 会话密钥升级：在 TLS 握手外叠加 ECDH 临时会话密钥与 AEAD/HMAC，确保 sendto 捕获到的仅为密文帧
3. 单调防重放改造：服务端为每个会话维护严格递增 seq 与单次业务 nonce，淘汰纯时间戳窗口校验
4. 序列化瘦身：客户端切换 Protobuf Lite 并开启 R8 混淆字段名，C++ 侧剥离反射表与符号
5. 状态机权威校验：服务端对客户端上报动作实施速率、状态前提与数值边界核验
```

## 验证与判定标准

- **重放攻击阻断**：在 `max_skew_sec` 窗口内（如 1 秒后）原样重放已成功处理的请求封包，服务端必须返回 `replay_or_out_of_order` 并拒绝二次记账。
- **抓包明文不可见**：使用 `android_http_observation_recipe` 或挂载 `sendto`/`recvfrom` 观察正常业务流时，关键业务字段不得以未加密 JSON 或带字段名的可读字符串出现。
- **篡改拒收**：修改加密帧或包头 `seq`/`msg_type` 任意 1 字节，服务端认证标签校验必须在反序列化前拦截。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 验证 HTTP 层密文与头信息 | `android_http_observation_recipe` | 检查是否仍有明文业务请求或遗漏的调试端点 |
| 核对客户端加密路径 | `android_crypto_unpack_recipe` | 确认密钥派生与加解密调用不暴露硬编码常量密钥 |
| 静态检查 Native 发包函数 | `ghidra_headless_analyze` | 核查 Release SO 是否已剥离 `.proto` 描述符与调试符号 |
| 检索对应红蓝文档 | `kb_router` | 对照 [01-game-protocol-hook.md](../../../../red/apk-reverse/techniques/05-network/01-game-protocol-hook.md) 覆盖全部 Hook 路径 |
