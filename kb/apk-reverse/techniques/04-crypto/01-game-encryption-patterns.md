# 游戏数据加解密识别与绕过

## 场景

游戏对通信数据、内存关键值、存档文件进行了加密保护。需要识别加密算法、定位 Key/IV、写出解密脚本。

## 输入信号

- 抓包数据全是乱码，无明显 JSON/Protobuf 结构
- 内存中关键数值（血量/金币）在 CheatEngine 中搜不到直接值
- SharedPreferences 中存的是 Base64+乱码
- native 层有大量 `javax.crypto.Cipher` 调用

## 加密层次识别

### 层次 1: 网络层 TLS/SSL Pinning

```bash
# 检测: 抓包失败、Burp 看不到请求
# Frida 一键绕过 (通用):
frida -U -f com.target.app -l ssl_pinning_bypass.js
```

```javascript
// SSL Pinning bypass 通用模板
Java.perform(function() {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager')
    // Hook checkServerTrusted 返回 void (信任所有证书)
    var SSLContext = Java.use('javax.net.ssl.SSLContext')
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
        .implementation = function(km, tm, sr) {
            // 注入自定义 TrustManager
        }
})
```

### 层次 2: 应用层加密 (AES/DES/RSA)

```java
// 目标代码模式
SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
byte[] encrypted = cipher.doFinal(plaintext);
```

### 层次 3: 内存层 XOR/混淆

```c
// native 层直接操作 int/float
int realGold = storedGold ^ 0xDEADBEEF;  // 简单 XOR
float realX = storedX * magicMultiplier;  // 乘性混淆
```

## Frida 抓加密参数模板

```javascript
// Hook Java Cipher
Java.perform(function() {
    var Cipher = Java.use("javax.crypto.Cipher")
    var orig_init = Cipher.init.overload(
        'int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec')

    orig_init.implementation = function(opmode, key, params) {
        console.log("[Cipher.init] mode:", opmode,
            "algo:", this.getAlgorithm())
        if (key) {
            var keyBytes = key.getEncoded()
            console.log("[KEY]", bytesToHex(keyBytes))
        }
        if (params) {
            var IvSpec = Java.use("javax.crypto.spec.IvParameterSpec")
            if (params.$className === 'javax.crypto.spec.IvParameterSpec') {
                console.log("[IV]", bytesToHex(params.getIV()))
            }
        }
        return orig_init.call(this, opmode, key, params)
    }
})

function bytesToHex(bytes) {
    return Array.from(bytes, b => ('0'+b.toString(16)).slice(-2)).join('')
}
```

```javascript
// Hook native 加密 (libcrypto/libssl)
var AES_set_encrypt_key = Module.findExportByName("libcrypto.so", "AES_set_encrypt_key")
Interceptor.attach(AES_set_encrypt_key, {
    onEnter: function(args) {
        console.log("[AES key]", hexdump(args[0], {length: args[1].toInt32()}))
    }
})
```

## 常见算法特征速查

| 算法 | 特征 | Key 长度 | IV 长度 |
|------|------|---------|--------|
| AES-128-CBC | SecretKeySpec + IvParameterSpec | 16 bytes | 16 bytes |
| AES-256-GCM | GCMParameterSpec | 32 bytes | 12 bytes |
| DES | DESKeySpec / "DES" | 8 bytes | 8 bytes |
| RSA/ECB | Cipher.getInstance("RSA") | 128-512 bytes | 无 |
| HMAC-SHA256 | Mac.getInstance("HmacSHA256") | 任意 | 无 |
| 自定义 XOR | 内存中反复 xor 常量 | 1-4 bytes | 无 |

## 实战: 从内存 dump 到解密验证

```python
# 拿到 key/iv/ciphertext 后的离线验证
from Crypto.Cipher import AES

key = bytes.fromhex("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
iv = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
ciphertext = bytes.fromhex("...")

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)
# 验证: 看解密结果是否是合法的 JSON/Protobuf/文本
```

## 攻击链

```
抓包乱码 → 确认非标准协议 → jadx 搜索 Cipher/encrypt/SecretKey →
Frida hook Cipher.init → 提取 key/iv/算法 → Python 离线解密验证
→ 内存中也异或: Frida hook XOR 点 → 确定 XOR key → 解密内存字段
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| Frida 抓 Cipher.init → key/iv/算法 → logcat 汇总 | `android_crypto_unpack_recipe` | 一键：Frida 抓 Cipher.init → key/iv/算法 → logcat 汇总 |
| 从 key/IV/input/output 自动解密验证 | `solve_crypto_from_evidence` | 从 key/IV/input/output 自动解密验证 |
| 生成可运行的 Python 解密复现脚本 | `make_crypto_replay_scaffold` | 生成可运行的 Python 解密复现脚本 |
| 一键 parse → solve → replay scaffold → buffer carve | `postprocess_frida_crypto_result` | 一键 parse → solve → replay scaffold → buffer carve |
