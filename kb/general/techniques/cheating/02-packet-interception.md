# 封包拦截与修改

## 场景

游戏使用客户端-服务器模型进行状态同步，修改/拦截/伪造网络包可以获得不公平优势。现代反作弊在传输层叠加了 TLS 加密、自定义协议混淆、packet sequencing 完整性校验和服务器端一致性校验。

## 输入信号

- 游戏使用 TCP/UDP 与服务器通信，Wireshark 可见未加密数据或已加密数据
- 服务器端反作弊通过校验包序列和时间戳检测异常
- 游戏使用了证书固定（cert pinning）或内嵌 CA 证书
- 使用 SSL/TLS 加密但需要中间人解密

## Winsock Hook

### IAT Hook send/recv

```cpp
#include <Windows.h>
#include <MinHook.h>
#include <cstdio>

// 原始函数指针
int (WINAPI* Original_send)(SOCKET s, const char* buf, int len, int flags);
int (WINAPI* Original_recv)(SOCKET s, char* buf, int len, int flags);
int (WINAPI* Original_WSASend)(SOCKET s, LPWSABUF buffers, DWORD count,
    LPDWORD bytes, DWORD flags, LPWSAOVERLAPPED overlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE routine);
int (WINAPI* Original_WSARecv)(SOCKET s, LPWSABUF buffers, DWORD count,
    LPDWORD bytes, DWORD flags, LPWSAOVERLAPPED overlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE routine);

// Hook send: 记录并可选修改
int WINAPI Hooked_send(SOCKET s, const char* buf, int len, int flags) {
    // 协议头识别 (常见游戏协议魔数)
    if (len >= 4) {
        uint32_t magic = *(uint32_t*)buf;
        
        // 仅记录非心跳包 (心跳通常小于 32 字节)
        if (len > 32) {
            LogPacket("[SEND] sock=%d len=%d magic=0x%08X", s, len, magic);
            DumpHex(buf, min(len, 128));
        }
        
        // 可选修改: 修改 buf 内容然后重新计算 checksum
        // char* modified = ModifyPacket(buf, len);
        // return Original_send(s, modified, len, flags);
    }
    return Original_send(s, buf, len, flags);
}

int WINAPI Hooked_recv(SOCKET s, char* buf, int len, int flags) {
    int ret = Original_recv(s, buf, len, flags);
    if (ret > 0 && ret < 4096) {
        LogPacket("[RECV] sock=%d len=%d", s, ret);
        
        // 可选: 解密或数据包可视化
        // DecryptAndDisplay(buf, ret);
        
        // 可选: 丢弃特定包 (如封号指令)
        // if (IsBanPacket(buf, ret)) {
        //     memset(buf, 0, ret);
        //     return 0;  // 假装没收到
        // }
    }
    return ret;
}

// MinHook 安装
void InstallHooks() {
    MH_Initialize();
    
    // IAT Hook (ws2_32.dll)
    MH_CreateHookApi(L"ws2_32.dll", "send", Hooked_send,
        (void**)&Original_send);
    MH_CreateHookApi(L"ws2_32.dll", "recv", Hooked_recv,
        (void**)&Original_recv);
    MH_CreateHookApi(L"ws2_32.dll", "WSASend", Hooked_WSASend,
        (void**)&Original_WSASend);
    MH_CreateHookApi(L"ws2_32.dll", "WSARecv", Hooked_WSARecv,
        (void**)&Original_WSARecv);
    
    MH_EnableHook(MH_ALL_HOOKS);
}
```

### VMT Hook (C++ 虚函数表劫持)

某些游戏使用 C++ socket wrapper 类，不直接调用 Winsock API，而是调用类的虚函数。这时需要 VMT hook：

```cpp
class SocketWrapper {
public:
    virtual int Send(const char* data, int len) = 0;
    virtual int Recv(char* buffer, int size) = 0;
    virtual int Close() = 0;
};

// VMT Hook: 替换虚函数表中的函数指针
void HookSocketVMT(SocketWrapper* instance) {
    void** vtable = *(void***)instance;
    void** new_vtable = (void**)VirtualAlloc(NULL, 3 * sizeof(void*),
        MEM_COMMIT, PAGE_READWRITE);
    
    // 复制原始 vtable
    memcpy(new_vtable, vtable, 3 * sizeof(void*));
    
    // 替换前两个函数
    original_vtable_[0] = new_vtable[0];
    new_vtable[0] = &Hooked_Send;
    new_vtable[1] = &Hooked_Recv;
    
    // 替换实例的 vtable 指针
    DWORD old;
    VirtualProtect(instance, sizeof(void*), PAGE_READWRITE, &old);
    *(void**)instance = new_vtable;
    VirtualProtect(instance, sizeof(void*), old, &old);
    
    // EAC/BE 检测 VMT hook:
    // - 扫描虚函数表指针是否指向可写页面
    // - 验证 vtable 函数指针是否在原始模块范围内
    // 绕过: 直接在原始 vtable 页面写 (VirtualProtect → RWX)
}
```

## Linux 封包劫持

### LD_PRELOAD 劫持

```c
// preload_socket.c — 编译为 .so, LD_PRELOAD 注入
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/socket.h>
#include <stdio.h>

typedef ssize_t (*orig_send_t)(int, const void*, size_t, int);
typedef ssize_t (*orig_recv_t)(int, void*, size_t, int);

ssize_t send(int sockfd, const void* buf, size_t len, int flags) {
    static orig_send_t orig_send = NULL;
    if (!orig_send)
        orig_send = (orig_send_t)dlsym(RTLD_NEXT, "send");
    
    fprintf(stderr, "[PRELOAD SEND] sock=%d len=%zu\n", sockfd, len);
    hexdump(stderr, buf, len > 64 ? 64 : len);
    
    // 可选修改
    // void* modified = malloc(len);
    // memcpy(modified, buf, len);
    // PatchPacket(modified, len);
    // ssize_t ret = orig_send(sockfd, modified, len, flags);
    // free(modified);
    // return ret;
    
    return orig_send(sockfd, buf, len, flags);
}

ssize_t recv(int sockfd, void* buf, size_t len, int flags) {
    static orig_recv_t orig_recv = NULL;
    if (!orig_recv)
        orig_recv = (orig_recv_t)dlsym(RTLD_NEXT, "recv");
    
    ssize_t ret = orig_recv(sockfd, buf, len, flags);
    if (ret > 0) {
        fprintf(stderr, "[PRELOAD RECV] sock=%d len=%zd\n", sockfd, ret);
    }
    return ret;
}
```

### iptables NFQUEUE 中间人

```bash
# 将所有出站流量重定向到用户态处理
iptables -t mangle -A OUTPUT -p tcp --dport 27015 -j NFQUEUE --queue-num 1
iptables -t mangle -A INPUT -p tcp --sport 27015 -j NFQUEUE --queue-num 1

# NFQUEUE 用户态处理器 (C/libnetfilter_queue)
```

## SSL/TLS 拦截

### 证书固定绕过 — Frida

```javascript
// Frida SSL Unpinning (Android/iOS)
function bypassSSLUnpinning() {
    // Android: TrustManager 固定绕过
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    
    TrustManagerImpl.verifyChain.implementation = function(untrusted, trustAnchor, 
        chain, authType, host, clientAuth) {
        // 直接返回信任链，跳过证书校验
        return untrusted;
    };
    
    // Android Network Security Config bypass (Nougat+)
    var NetworkSecurityConfig = Java.use('android.security.net.config.NetworkSecurityConfig');
    NetworkSecurityConfig.isCleartextTrafficPermitted.implementation = function() {
        return true;
    };
    
    // iOS: NSURLSession SSL bypass
    var SessionDelegate = ObjC.classes.NSURLSession;
    // ...
}

// Windows: SChannel cert verification bypass
// Hook CertVerifyCertificateChainPolicy → 返回 TRUE
```

### Frida Windows SChannel Hook

```javascript
// Windows SChannel cert verification
var CertVerifyCertificateChainPolicy = Module.findExportByName(
    "Crypt32.dll", "CertVerifyCertificateChainPolicy"
);

Interceptor.attach(CertVerifyCertificateChainPolicy, {
    onEnter: function(args) {
        // CERT_CHAIN_POLICY_SSL = 4
        if (args[0].toInt32() === 4) {
            this.skip = true;
        }
    },
    onLeave: function(ret) {
        if (this.skip) {
            ret.replace(1);  // TRUE — 允许所有证书
        }
    }
});

// Hook WinHttpSetOption → 跳过 SSL 错误
var WinHttpSetOption = Module.findExportByName(
    "winhttp.dll", "WinHttpSetOption"
);
Interceptor.attach(WinHttpSetOption, {
    onEnter: function(args) {
        // WINHTTP_OPTION_SECURITY_FLAGS = 31
        if (args[1].toInt32() === 31) {
            // 跳过所有安全校验
            args[3].writeInt32(0);
        }
    }
});
```

## 协议逆向与解码

### 识别加密与明文区域

```cpp
// 常见游戏协议结构:
// [magic:4] [opcode:2] [seq:4] [crc:2] [payload...]
// 加密的 payload 特征: 高熵值, 无法解释为任何已知编码

// 熵值检测函数:
double CalculateEntropy(const uint8_t* data, size_t len) {
    std::array<double, 256> freq = {0};
    for (size_t i = 0; i < len; ++i) freq[data[i]]++;
    
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            double p = freq[i] / len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

// 典型熵值:
// 明文: 4.0-5.5
// 压缩数据: 7.0-8.0
// 加密数据: 7.5-8.0 (接近完全随机)
// XOR 单字节: 4.0-5.5 (如 key 为单字节)
```

### 协议结构推断

```python
import struct
from collections import Counter

def analyze_packet(packet: bytes):
    """已知结构推断"""
    if len(packet) < 4:
        return
    
    magic = struct.unpack_from('<I', packet, 0)[0]
    print(f"Magic: 0x{magic:08X}")
    
    # 魔数常见值:
    # 0xDEADC0DE — 自定义魔数
    # 0x01010101 — 简单协议 (字节对齐)
    # 游戏特有: Ghost Recon → 0x47524547 ("GREP")
    # Fortnite → 0xDEADBEEF 或 0xF00DC0DE
    
    # 尝试猜测 opcode 位置 (通常在魔数后 2-4 字节)
    # 如果不同包在固定位置呈现规律性变化 → opcode
    
    # 长度字段识别:
    # 包长度字段通常在 ±4 字节内
    possible_len_fields = []
    for offset in range(4, 12):
        if offset + 2 <= len(packet):
            possible_len = struct.unpack_from('<H', packet, offset)[0]
            if possible_len == len(packet):
                print(f"Length field at offset {offset}: {possible_len}")
                possible_len_fields.append(offset)
    
    # 序列号识别: 连续抓包观察递增字段
    # 如果特定偏移在连续包中 +1/+N → sequence number
```

### 重放攻击

```python
# Packet Replay Tool (Python + scapy)
from scapy.all import *
import json

class PacketReplayer:
    def __init__(self, config_file):
        with open(config_file) as f:
            self.config = json.load(f)
        
        # 从 WireShark pcap 或 raw capture 加载
        self.captured_packets = []
    
    def load_pcap(self, pcap_path):
        self.captured_packets = rdpcap(pcap_path)
        print(f"Loaded {len(self.captured_packets)} packets")
    
    def replay_packet(self, pkt_num, modify=None):
        """重放指定编号的包，可选参数修改"""
        pkt = self.captured_packets[pkt_num]
        
        if modify:
            raw = bytes(pkt[Raw])
            # 修改指定位置 (例如: 把子弹数改成 999)
            modified = bytearray(raw)
            for offset, value in modify.items():
                modified[offset] = value & 0xFF
                modified[offset+1] = (value >> 8) & 0xFF
            pkt[Raw] = bytes(modified)
        
        # 发送 (可能需要调整 seq/checksum)
        sendp(pkt, iface=self.config['interface'], verbose=False)
    
    def continuous_modify(self, pkt_num, interval_ms=50):
        """连续发送修改后的包 (如连发宏)"""
        from time import sleep
        while True:
            self.replay_packet(pkt_num, self.config['modifications'])
            sleep(interval_ms / 1000.0)
    
    def packet_timing_manipulation(self, delay_ms=0, drop_rate=0.0):
        """延迟/随机丢弃出站包，用于:
        - 延迟射击报告 → 制造更大 hitbox 窗口
        - 丢弃移动包 → 制造回溯 (rubber banding 攻击)
        - 选择性丢包 → 只丢伤害包
        """
        import random
        def packet_filter(pkt):
            if random.random() < drop_rate:
                print(f"[DROP] dropped packet: {pkt.summary()}")
                return False  # 丢弃
            if delay_ms > 0:
                from time import sleep
                sleep(delay_ms / 1000.0)
            return True
        return packet_filter
```

### Checksum 绕过

```cpp
// 游戏常用简单 XOR checksum:
// packet[len-2] = XOR all bytes except checksum
// 
// 修改包内容后需要重新计算:
uint16_t RecalculateChecksum(const uint8_t* data, size_t len, int offset) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; ++i) {
        if (i == offset || i == offset + 1) continue;  // 跳过 checksum 字段
        crc ^= data[i];
        for (int j = 0; j < 8; ++j) {
            if (crc & 1) crc = (crc >> 1) ^ 0xA001;
            else crc >>= 1;
        }
    }
    return crc;
}

// 更复杂: 加密游戏 (如 Apex Legend/EAC) 使用 AES-GCM
// 需要逆向出 key 才能重放
// 方法: Frida hook 加密库 (OpenSSL/Botan/mbedTLS)
```

## SOCKS5 代理中间人

```cpp
// 将游戏流量重定向到可控 SOCKS5 代理
// 代理可以记录、修改、重放所有流量

// 使用 WinDivert (Windows) / NFQueue (Linux) 重定向:
// divert TCP traffic → SOCKS5 proxy → game server

// WinDivert 规则示例:
// divert.exe divert --rules "outbound and tcp.DstPort == 27015" --proxy localhost:1080

// SOCKS5 代理中的 intercept 逻辑:
void HandleGamePacket(const uint8_t* data, size_t len) {
    PacketAnalyzer analyzer;
    
    // 1. 识别操作码
    uint16_t opcode = analyzer.GetOpcode(data);
    
    // 2. 特定操作码的修改
    switch (opcode) {
    case 0x0101: // 射击包
        printf("Shot packet\n");
        // 可以: 延迟发送 (制造困难射击窗口)
        // 可以: 修改命中判定
        break;
    case 0x0202: // 位置更新
        // 可以: 修改坐标
        break;
    case 0x0303: // 交互请求
        // 可以: 放大交互范围
        break;
    }
}
```

## 反检测与注意事项

```
反作弊检测封包修改的手段:
1. 服务器端一致性校验: 客户端操作与服务器物理引擎结果对比
   → 绕过: 只修改客户端表现不发送到服务器
2. 时间戳验证: 包到达间隔异常 → 加速/减速检测
   → 绕过: 保持正常发包间隔
3. 序列号连续性: 插入/丢弃包导致序列号跳跃
   → 绕过: 捕获并维护序列号自增
4. 操作码频率统计: 异常操作频率模式
   → 绕过: 模拟人类操作间隔
5. 完整性校验 (HMAC/Signature)
   → 需要在 HMAC key 或签名函数处设断点
6. Beacon/ping 检测: 服务端下发必须回复的随机校验包
   → 绕过: 转发原包回复
```

## 攻击链

```
Wireshark 抓包 → 识别协议结构 (magic/opcode/length/checksum)
→ 判断是否加密 → 如加密: Hook 加密库/SSL unpin → 解密
→ 分析操作码与数据字段含义 → 设计修改策略
→ 实现 Hook (IAT/VMT/LD_PRELOAD/SOCKS5)
→ 实现修改/重放逻辑 → 绕过完整性校验
→ 验证: 服务器接受修改后的包
```

## MCP 工具映射

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 基础知识查找 | `kb_router` | 搜索网络协议逆向相关知识点 |
| 特征码定位网络函数 | `search_pattern` | 在样本中定位 send/recv 调用 |
| 导入表扫描网络 API | `rizin_imports` | 过滤 ws2_32/winhttp/openssl 相关导入 |
| Hook 汇编生成 | `rizin_assemble_bytes` | 验证跳转指令的正确性 |
| 字节 Patch 绕过校验 | `patch_bytes` | 修改网络验证逻辑 |
| PE 偏移计算 | `pe_address_to_offset` | 定位 IAT 表地址写 hook |
| 工具链状态 | `python_re_tool_install` | 安装 scapy/cryptography 等包 |

## 证据与验证闭环

- 固定输入样本、SHA256、工具版本和全部参数，先保存未处理 baseline。
- 每个假设至少绑定一个可观察量：已知明密文对、协议字段、状态转移、时间分布、偏移或重放输出。
- 用独立脚本重放核心变换，并以断言、输出哈希或逐字段 diff 验证，不以“看起来合理”作为结论。
- 原始抓包/样本进入 `exports/general/`，派生文件与原件分离并记录转换链。
