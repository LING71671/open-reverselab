---
id: "general/cheating/02-packet-interception-defense"
title: "封包拦截与重放防御（TLS Pinning / 协议双向校验 / 序列号抗重放）"
title_en: "Defense Against Packet Interception and Replay"
summary: >
  防御 Winsock/LD_PRELOAD/NFQUEUE/MITM 封包劫持与重放攻击：采用双向证书绑定与自定义通道加密、基于 AEAD 的逐包序列号与抗重放滑动窗口、指令完整性校验以及服务端业务状态机裁决。
summary_en: >
  Defense against Winsock/LD_PRELOAD/NFQUEUE/MITM packet hijacking and replay: mutual TLS pinning, AEAD per-packet sequence counters with anti-replay sliding windows, command integrity MACs, and server-authoritative state validation.
board: "general"
category: "cheating"
signals:
  - "AEAD packet framing"
  - "anti-replay window"
  - "TLS pinning"
  - "IAT integrity"
  - "LD_PRELOAD detection"
  - "server authoritative"
mcp_tools:
  - "rizin_imports"
  - "ghidra_headless_analyze"
  - "search_pattern"
  - "make_sigma_stub"
  - "kb_router"
keywords:
  - "packet integrity"
  - "anti-replay"
  - "AEAD"
  - "TLS pinning"
  - "protocol defense"
  - "hook detection"
difficulty: "intermediate"
tags:
  - "anti-cheat"
  - "network-defense"
  - "AEAD"
  - "anti-replay"
  - "TLS-pinning"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "general/cheating/02-packet-interception"
  - "general/signature/06-replay-nonce-defense"
track: "blue"
defends: "general/cheating/02-packet-interception"
---
# 封包拦截与重放防御（TLS Pinning / 协议双向校验 / 序列号抗重放）

## 防御目标

阻断攻击者通过 IAT/VMT Hook（`send`/`recv`）、`LD_PRELOAD`、Linux `NFQUEUE`、SOCKS5 代理或 TLS Unpinning 截取明文协议、修改载荷字段以及重放历史封包，确保网络消息的机密性、完整性、顺序性与服务端不可伪造性。

## 分层防御矩阵

| 攻击向量 | 威胁表现 | 防御策略 | 落地控制 |
|---|---|---|---|
| Winsock / Socket API Hook | 劫持 `send`/`recv`/`WSASend` 读取明文并篡改 | IAT/Inline 完整性校验 + 上行前完成加密 | 封包加密在业务层完成后再调用 Socket API，并校验 `ws2_32.dll` 导出函数头字节 |
| `LD_PRELOAD` / 动态库劫持 | Linux 下替换 `send`/`SSL_write` | 静态链接加密库 + `/proc/self/maps` 与环境变量核查 | 启动时检查 `LD_PRELOAD` 与异常映射 `.so`，关键传输走静态编译的 BoringSSL/mbedTLS |
| TLS MITM 与 Unpinning | 代理伪造证书或 Hook 证书回调 | 多层 SPKI Pinning + 会话密钥派生绑定 | 同时在 TLS 握手校验公钥指纹，并在应用层用 ECDH 协商二级会话密钥（AEAD） |
| 校验和逆向与篡改 | 还原 CRC32/异或校验后构造伪造包 | 用标准 AEAD（AES-GCM / ChaCha20-Poly1305）替代弱校验 | 禁止使用可逆异或或裸 CRC 作为完整性校验，所有包头纳入 AAD |
| Scapy / 协议重放 | 原样重放历史封包触发重复动作 | 单调递增 `seq` + 服务端滑动窗口位图 | 拒绝重复或过旧序列号，强绑定会话 ID 与请求方向位 |

## 防御实现与校验示例

### 1. 基于单调序列号与滑动窗口的抗重放校验器（Python）

对每个会话维护严格递增的接收高水位与 64 位滑动窗口，同时校验 AEAD（此处演示 HMAC-SHA256 帧结构校验逻辑）避免篡改与重放：

```python
import hmac
import hashlib
import struct

class AntiReplaySession:
    def __init__(self, session_key: bytes, window_size: int = 64):
        self.key = session_key
        self.window_size = window_size
        self.max_seq = 0
        self.bitmap = 0

    def sign_packet(self, seq: int, direction: int, payload: bytes) -> bytes:
        header = struct.pack(">QB", seq, direction)
        tag = hmac.new(self.key, header + payload, hashlib.sha256).digest()[:16]
        return header + tag + payload

    def verify_packet(self, packet: bytes, expected_dir: int) -> tuple[bool, str, bytes]:
        if len(packet) < 25:
            return False, "truncated_packet", b""
        header = packet[:9]
        tag = packet[9:25]
        payload = packet[25:]
        seq, direction = struct.unpack(">QB", header)
        if direction != expected_dir or seq == 0:
            return False, "invalid_header", b""

        expected_tag = hmac.new(self.key, header + payload, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, expected_tag):
            return False, "mac_mismatch", b""

        if seq > self.max_seq:
            shift = seq - self.max_seq
            self.bitmap = ((self.bitmap << shift) | 1) & ((1 << self.window_size) - 1) if shift < self.window_size else 1
            self.max_seq = seq
            return True, "ok", payload

        diff = self.max_seq - seq
        if diff >= self.window_size:
            return False, "stale_seq", b""
        if (self.bitmap >> diff) & 1:
            return False, "replay_detected", b""
        self.bitmap |= (1 << diff)
        return True, "ok", payload

if __name__ == "__main__":
    sess = AntiReplaySession(b"session-key-material-32bytes!!")
    p1 = sess.sign_packet(1, 0, b'{"action":"move","dx":1}')
    assert sess.verify_packet(p1, 0)[0] is True
    assert sess.verify_packet(p1, 0) == (False, "replay_detected", b"")
    tampered = p1[:-1] + b"9"
    assert sess.verify_packet(tampered, 0)[1] == "mac_mismatch"
    print("packet_defense_check: PASS")
```

### 2. IAT/导出表 Hook 静态入口完整性校验逻辑

客户端在关键网络发包前，可核对 `send`/`WSASend` 前 16 字节是否被写入 `E9`(JMP) / `FF 25` / `48 B8 ... FF E0` 跳板指令，发现异常即上报告警并阻断会话。

## 防御工作流

```text
1. 传输加密升级：用标准 TLS 1.3 + SPKI Pinning 并在应用层叠加 ECDH 协商的 AEAD 会话密钥
2. 帧格式加固：强制包头携带 session_id、direction 与 64-bit 单调 seq，并将包头纳入 AAD 认证
3. 抗重放部署：服务端网关对每条连接启用 64-bit 滑动窗口位图与幂等事务锁
4. 本地防劫持：客户端静态链接加密库，巡检 ws2_32/libc 关键函数 prologue 与 LD_PRELOAD 环境变量
5. 语义合法性校验：服务端对位移速率、技能 CD、交易余额做物理与状态机上限校验，不信任客户端直传结果
```

## 验证与判定标准

- **重放阻断**：同一合法密文帧重放第二次时，网关 100% 返回 `replay_detected` 并断开或限流连接
- **篡改拦截**：修改封包任意 1 比特（含序列号或载荷）均触发 `mac_mismatch` 且状态不发生变更
- **Unpinning 抗性**：在启用系统代理证书且屏蔽 Java/上层 Pinning 的条件下，客户端应用层会话密钥或内置静态 TLS 校验仍拒绝 MITM 握手

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 导入表与网络库检查 | `rizin_imports` | 核对二进制是否误用明文 Socket 或动态暴露弱校验函数 |
| 协议加解密逻辑定位 | `ghidra_headless_analyze` | 排查客户端是否残留硬编码密钥或弱 CRC 校验 |
| Hook 跳板特征搜索 | `search_pattern` | 在内存转储或 DLL 镜像中搜索常见跳转桩字节模式 |
| 异常网络行为检测规则 | `make_sigma_stub` | 为异常代理/重放流量模式生成日志检测规则 |
