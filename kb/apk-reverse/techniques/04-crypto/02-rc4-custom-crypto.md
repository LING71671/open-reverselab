# 自定义对称加密：RC4 与组合模式

## 场景

游戏/应用使用自定义对称加密保护网络通信和本地数据。不像 AES 有标准库调用可 Hook，自定义实现需要从算法层面识别和逆推。

## 输入信号

- 数据呈现随机字节但长度与明文一致（排除块加密）
- 代码中有 256 字节的 S-Box 初始化循环
- 字符串中出现 "rc4"、"ksa"、"prga" 注释
- 加密函数接收 key + data，无 IV 参数

## RC4 手工实现识别

```c
// 特征1: KSA (Key Scheduling Algorithm)
// 256 字节 S 盒 + key 循环 XOR swap
void rc4_ksa(const char *key, int key_len, unsigned char *S) {
    for (int i = 0; i < 256; i++) S[i] = i;     // S 盒初始 0..255
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) % 256; // key 参与 j 计算
        swap(S[i], S[j]);                         // 交换 S[i] ↔ S[j]
    }
}

// 特征2: PRGA (Pseudo-Random Generation Algorithm)
// 逐字节 XOR, S 盒动态变化
void rc4_crypt(unsigned char *S, const char *in, int len, char *out) {
    int i = 0, j = 0;
    for (int n = 0; n < len; n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        swap(S[i], S[j]);
        out[n] = in[n] ^ S[(S[i] + S[j]) % 256];  // XOR with keystream
    }
}
```

## Ghidra 中识别 RC4

```
# 静态特征搜索:
1. 函数中有 256 次循环的 memset(S, 0..255)
2. 循环中反复 swap 两个 S[?] 元素
3. 最后是 XOR 操作 on data bytes
4. 常数 256 出现在边界检查中

# Ghidra Python 脚本扫描:
fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    if func.getBody().getNumAddresses() > 20:
        # 搜索立即数 256 (0x100)
```

## Python 复现

```python
def rc4_crypt(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    # KSA
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    # PRGA
    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)

# 验证: rc4 加解密完全对称
cipher = rc4_crypt(b"hello world", b"secret")
plain  = rc4_crypt(cipher, b"secret")  # == b"hello world"
```

## 实战: Frida Hook 自定义加密

```javascript
// 目标: 定位 RC4 调用点并 dump key + data
// 方法: Hook 函数入口 → dump 参数 → Hook 出口 → dump 结果

// 如果函数名未知, 用地址 Hook
var rc4_addr = Module.findBaseAddress("libgame.so").add(0x12345)
Interceptor.attach(rc4_addr, {
    onEnter: function(args) {
        // args[0] = data ptr, args[1] = key ptr, args[2] = len
        this.data = args[0]
        this.key = args[1]
        this.len = args[2].toInt32()
        console.log("[RC4] key:", hexdump(this.key, {length: 16}))
        console.log("[RC4] data len:", this.len)
    },
    onLeave: function(ret) {
        console.log("[RC4] encrypted:", hexdump(this.data, {length: Math.min(this.len, 64)}))
    }
})
```

## 常见自定义加密组合

| 模式 | 特征 | 密钥来源 |
|------|------|---------|
| RC4(key) | 单层流加密 | 硬编码 / 服务器下发 |
| RC4(md5(response)) | 动态密钥 | 上次请求的 md5 |
| RC4(key1) + Base64 | 加密后编码 | 硬编码 |
| XOR(const) + RC4(key) | 两层加密 | 硬编码固定 key |
| AES-CBC(data, key) + RC4(data, key2) | 混合加密 | 双密钥 |

## API 签名模式提取

```python
# 常见的请求签名: md5(param1=val1&param2=val2&...&timestamp=xxx&secret=yyy)
import hashlib
def forge_sign(params: dict, secret: str) -> str:
    ordered = sorted(params.items())
    raw = "&".join(f"{k}={v}" for k, v in ordered)
    raw += f"&secret={secret}"  # 或追加 appkey
    return hashlib.md5(raw.encode()).hexdigest()

# RC4 加密请求参数
def encrypt_params(params: dict, key: bytes) -> str:
    raw = json.dumps(params)
    encrypted = rc4_crypt(raw.encode(), key)
    return base64.b64encode(encrypted).decode()
```

## 攻击链

```
抓包获取密文 → Ghidra 搜索 256 循环 + XOR swap 模式 → 确认是 RC4
→ Frida Hook 加密函数入口 dump key → Python 离线复现验证
→ 确定密钥来源 (硬编码/服务器下发/md5派生) → 写出完整加解密流程
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| Frida 抓加密函数入口 dump key/input/output | `android_crypto_unpack_recipe` | Frida 抓加密函数入口 dump key/input/output |
| 分析 native 加密函数 | `ghidra_headless_analyze` | 分析 native 加密函数 |
| 自动验证 RC4/Custom 解密 | `solve_crypto_from_evidence` | 自动验证 RC4/Custom 解密 |

## 证据与验证闭环

- 记录 APK/SO 的 SHA256、包名、版本、ABI、设备/Android/Frida 版本及原始样本路径。
- 静态结论必须绑定类名、方法签名、RVA/文件偏移、字符串或 Xref；动态结论绑定 hook 点、参数、返回值和时间戳。
- 在未修改样本与实验副本上分别复现，保存 Frida 日志、dump 哈希和重放脚本到 `exports/android/`。
- Patch/重打包必须记录原始字节、修改字节、签名方式和安装启动结果，不能以“构建成功”代替行为验证。
