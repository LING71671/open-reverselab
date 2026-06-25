# 伪随机数生成器(PRNG)破解 — 从输出恢复内部状态与种子

> PRNG 不安全是 CTF、游戏外挂和密码学的经典主题。一旦攻击者获得了几个连续的输出，很多 PRNG 可以完全恢复内部状态，从而预测所有过去和未来的输出。本文覆盖 LCG、MT19937、XorShift、V8 Math.random()、PHP mt_rand()、Java Random 以及 ECDSA nonce 重用导致的私钥泄露。

## 1. LCG (线性同余生成器) 完全破解

### 1.1 数学原理

LCG 递推式：`S_{n+1} = (a * S_n + c) mod m`

三个参数的恢复方法：
- **给定连续输出** → 解线性同余方程组（模 m）
- **m 未知** → 从输出差值求 GCD
- **所有参数未知** → 截获 4-6 个连续输出即可

### 1.2 参数恢复 (已知 m，未知 a, c)

```python
# lcg_crack.py — LCG 参数恢复与预测
import math
from typing import Tuple, Optional


def crack_known_m(states: list, m: int) -> Tuple[int, int]:
    """
    已知模数 m，从连续状态恢复 a 和 c
    
    S1 = (a * S0 + c) mod m
    S2 = (a * S1 + c) mod m
    
    → S1 - S2 = a * (S0 - S1) mod m
    → a = (S1 - S2) * (S0 - S1)^{-1} mod m
    → c = (S1 - a * S0) mod m
    """
    assert len(states) >= 3, "Need at least 3 states"
    
    # 取最前面 3 个
    s0, s1, s2 = states[0], states[1], states[2]
    
    # a = (s1 - s2) * modinv(s0 - s1, m) % m
    a = ((s1 - s2) * pow(s0 - s1, -1, m)) % m
    
    # c = (s1 - a * s0) % m
    c = (s1 - a * s0) % m
    
    # 验证
    for i in range(3, len(states)):
        expected = (a * states[i-1] + c) % m
        if expected != states[i]:
            raise ValueError(f"LCG参数错误: 位置{i}期望{expected}得到{states[i]}")
    
    return a, c


def crack_unknown_m(states: list) -> Tuple[int, int, int]:
    """
    完全未知参数：从连续输出恢复 m, a, c
    
    原理：S_{n+1} - S_n = a * (S_n - S_{n-1}) mod m
    定义 T_n = S_{n+1} - S_n
    则 T_{n+1} = a * T_n mod m
    也就是 T_{n+2} * T_n - T_{n+1}^2 = 0 mod m
    因此 m | gcd(T_{n+2}*T_n - T_{n+1}^2) 对所有 n
    
    需要至少 6 个连续状态
    """
    assert len(states) >= 6, "Need at least 6 states"
    
    # 计算差值 T_n
    diffs = [states[i+1] - states[i] for i in range(len(states) - 1)]
    
    # 计算一些 m 的倍数
    multiples = []
    for i in range(len(diffs) - 2):
        t0, t1, t2 = diffs[i], diffs[i+1], diffs[i+2]
        multiples.append(t2 * t0 - t1 * t1)
    
    # m 是这些值的 GCD
    m = abs(multiples[0])
    for val in multiples[1:]:
        m = math.gcd(m, abs(val))
    
    # 通常 m 是合数中的大质因子
    # 常见 m 值: 2^31-1, 2^32, 2^48, 2^64
    known_primes = [2**31 - 1, 2**32, 2**48, 2**64]
    for prime in known_primes:
        if prime % m == 0:
            m = prime
            break
    
    # 现在恢复 a 和 c
    a, c = crack_known_m(states, m)
    
    return m, a, c


def predict_lcg(m: int, a: int, c: int, current_state: int, n: int = 10) -> list:
    """预测未来 n 个 LCG 输出"""
    preds = []
    state = current_state
    for _ in range(n):
        state = (a * state + c) % m
        preds.append(state)
    return preds


def recover_lcg_seed(outputs: list, m: int, a: int, c: int) -> int:
    """
    从第一个输出向左回退恢复初始种子
    
    S_{n-1} = (S_n - c) * a^{-1} mod m
    """
    a_inv = pow(a, -1, m)
    state = outputs[0]
    while True:
        prev = (state - c) * a_inv % m
        if (a * prev + c) % m == state:
            state = prev
        else:
            # 已经回退到初始种子（不能再退了就是）
            return prev
```

### 1.3 标准库 LCG 参数速查

```python
# lcg_constants.py — 已知 LCG 参数
LCG_PARAMETERS = {
    "glibc":        {"m": 2**31,           "a": 1103515245,     "c": 12345},
    "java_util_Random": {"m": 2**48,       "a": 25214903917,    "c": 11},
    "ANSI_C":        {"m": 2**31,          "a": 1103515245,     "c": 12345},
    "BSD":           {"m": 2**31,          "a": 1103515245,     "c": 12345},
    "C++11_minstd":  {"m": 2**31 - 1,      "a": 48271,          "c": 0},
    "C++11_minstd0": {"m": 2**31 - 1,      "a": 16807,          "c": 0},
    "borland_c":     {"m": 2**32,          "a": 22695477,       "c": 1},
    "MUSL":          {"m": 2**64,          "a": 6364136223846793005, "c": 1442695040888963407},
    "VisualBasic":   {"m": 2**24,          "a": 1140671485,     "c": 12820163},
}

# Java Random 特别注意：
# java.util.Random 的 LCG 输出是取最高的 32 bits（而不是直接值）
# state 是 48-bit，但 nextInt() 返回 state >> 16
def crack_java_random(values: list) -> int:
    """
    从 Java Random.nextInt() 输出恢复 48-bit 种子
    
    每个输出是 state >> 16，因此丢失了低 16 位。
    需要 2 个连续输出，但需要对低 16 位进行爆破
    
    Java Random:
    seed = (old_seed * 0x5DEECE66DL + 0xBL) & ((1L << 48) - 1)
    return (int)(seed >>> 16)
    """
    m = 2**48
    a = 25214903917
    c = 11
    
    # 对每个可能的低 16 位进行搜索
    for low16 in range(2**16):
        candidate_seed = (values[0] << 16) | low16
        next_seed = (a * candidate_seed + c) % m
        if (next_seed >> 16) == values[1]:
            return candidate_seed
    
    return None
```

## 2. Mersenne Twister (MT19937) 状态恢复

### 2.1 核心原理

MT19937 的内部状态是 624 个 32-bit 整数。给定 624 个连续 32-bit 输出后，可以完全恢复内部状态并预测过去/未来的所有输出。

```python
# mt19937_crack.py — Mersenne Twister 完全状态恢复

def untemper(y: int) -> int:
    """
    逆向 MT19937 的 tempering 变换
    
    MT 在输出前对内部状态做变换：
    y = y ^ (y >> u)
    y = y ^ ((y << s) & b)
    y = y ^ ((y << t) & c)
    y = y ^ (y >> l)
    
    这个函数恢复变换前的内部状态
    """
    u, d = 11, 0xFFFFFFFF
    s, b = 7,  0x9D2C5680
    t, c = 15, 0xEFC60000
    l    = 18
    
    # 逆向最后一步: y = y ^ (y >> l)
    # l=18, 高 18 位不变
    y = y ^ (y >> l)
    
    # 逆向: y = y ^ ((y << t) & c)
    # t=15, c=0xEFC60000
    y = y ^ ((y << t) & c)
    
    # 逆向: y = y ^ ((y << s) & b)
    # s=7, 分步逆向
    def undo_left_shift_xor_and(y: int, shift: int, mask: int) -> int:
        result = y
        for i in range(shift, 32, shift):
            result = y ^ ((result << shift) & mask)
        return result
    
    y = undo_left_shift_xor_and(y, s, b)
    
    # 逆向: y = y ^ (y >> u)
    # u=11, 分步逆向
    def undo_right_shift_xor(y: int, shift: int) -> int:
        result = y
        for i in range(shift, 32, shift):
            result ^= (result >> shift)
        return result
    
    y = undo_right_shift_xor(y, u)
    
    return y & 0xFFFFFFFF


def recover_mt19937_state(outputs: list) -> list:
    """
    从 624 个连续 32-bit 输出恢复 MT19937 内部状态
    
    Returns: 624 个内部状态值（可以克隆任意 MT 实例）
    """
    assert len(outputs) >= 624, f"Need 624 outputs, got {len(outputs)}"
    
    internal_state = []
    for i in range(624):
        internal_state.append(untemper(outputs[i] & 0xFFFFFFFF))
    
    return internal_state


class MT19937Clone:
    """
    MT19937 克隆：给定 624 个输出后，完全复制生成器
    
    可用于预测后续输出（和回推上前输出）
    """
    
    def __init__(self, outputs: list):
        self.mt = recover_mt19937_state(outputs[:624])
        self.index = 624
    
    def twist(self):
        """执行一次 twist（生成下一轮 624 个状态）"""
        lower_mask = (1 << 31) - 1
        upper_mask = 1 << 31
        
        for i in range(624):
            x = (self.mt[i] & upper_mask) | (self.mt[(i + 1) % 624] & lower_mask)
            xA = x >> 1
            if x & 1:
                xA ^= 0x9908B0DF
            self.mt[i] = self.mt[(i + 397) % 624] ^ xA
        
        self.index = 0
    
    def get_random_number(self) -> int:
        """获取下一个 32-bit 随机数"""
        if self.index >= 624:
            self.twist()
        
        y = self.mt[self.index]
        self.index += 1
        
        # Tempering
        y ^= (y >> 11)
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= (y >> 18)
        
        return y & 0xFFFFFFFF
```

### 2.2 不完整输出场景

现实场景中不一定能拿到 624 个完整连续输出：

```python
def mt_crack_with_limited_output(outputs: list, known_positions: list) -> dict:
    """
    只有部分位置的部分输出时，用 Z3 约束求解
    
    outputs: [(position, value), ...]  
    known_positions: 已知的输出位置（0-index）
    """
    from z3 import BitVec, Solver, sat
    
    solver = Solver()
    
    # 创建 624 个符号状态变量
    mt = [BitVec(f"mt_{i}", 32) for i in range(624)]
    
    # 添加 MT twist 约束
    lower_mask = 0x7FFFFFFF
    upper_mask = 0x80000000
    
    for pos, value in outputs:
        i = len(mt) - 624 + pos  # 对应 twist 后的哪个位置
        if i < 0:
            continue
        
        # Tempering 约束
        y = mt[i]
        y = y ^ LShR(y, 11)
        y = y ^ ((y << 7) & 0x9D2C5680)
        y = y ^ ((y << 15) & 0xEFC60000)
        y = y ^ LShR(y, 18)
        
        solver.add(y == value)
    
    if solver.check() == sat:
        model = solver.model()
        state = [model.eval(mt[i]).as_long() for i in range(624)]
        return {"success": True, "state": state}
    
    return {"success": False}
```

### 2.3 PHP mt_rand() 种子恢复

PHP 的 `mt_rand()` 使用 MT19937，但种子空间只有 32-bit：

```python
# php_mt_seed_crack.py
def crack_php_mt_seed(first_output: int) -> int:
    """
    PHP mt_rand() 种子恢复
    
    PHP 的 mt_srand(seed) 种子只有 32-bit
    可以用已知的第一个输出暴力破解种子
    """
    import mt19937ar  # PHP 的 MT 实现
    
    for seed in range(2**32):
        mt19937ar.srand(seed)
        if mt19937ar.rand() == first_output:
            return seed
    
    return None


# 更实际的用法：利用 php_mt_seed 工具
def php_mt_seed_tool(outputs: list) -> int:
    """
    推荐使用专门工具 php_mt_seed (https://github.com/openwall/php_mt_seed)
    它利用 PHP MT 实现的特殊性，速度远快于纯 Python 爆破
    
    Usage: ./php_mt_seed VALUE0 VALUE1 ...
    可以同时匹配多个输出来精确定位种子
    """
    output_str = " ".join(str(v) for v in outputs[:4])
    return f"Use: ./php_mt_seed {output_str}"
```

## 3. V8 Math.random() 破解 (XorShift128+)

### 3.1 XorShift128+ 状态恢复

V8 (Chrome/Node.js) 使用 XorShift128+ 实现 Math.random()。状态是两个 64-bit 整数，可以从 5-8 个连续 double 输出恢复。

```python
# v8_xorshift128plus_crack.py — V8 Math.random() 破解

import struct
from typing import Tuple, Optional


def double_to_uint64(d: float) -> int:
    """
    Math.random() 返回 [0, 1) 的 double
    
    内部：mantissa 的 52 bits 来自 XorShift128+ 输出的高 52 bits
    然后 * (1.0 / 2^52)
    """
    packed = struct.pack('d', d)
    return struct.unpack('<Q', packed)[0]


def v8_double_to_state_value(d: float) -> int:
    """
    从 Math.random() 输出恢复 XorShift128+ 输出的高 52 bits
    
    double 的 IEEE 754:
    - sign (1) 固定 0
    - exponent (11) 固定 0x3FF (表示 [1, 2) 范围)
    - mantissa/fraction (52) — XorShift128+ 输出的高 52 bits
    
    所以：output = 0x3FF + state_value / 2^52
    """
    u64 = double_to_uint64(d)
    # 去掉 exponent 和 sign，只剩 mantissa
    mantissa = u64 & ((1 << 52) - 1)
    return mantissa


def crack_v8_math_random(outputs: list) -> Tuple[int, int]:
    """
    从 5-8 个 Math.random() 输出恢复 XorShift128+ 状态
    
    XorShift128+ 状态 (s0, s1):
        s1_new = s0
        s0_new = s0 ^ (s0 << 23)
        s1_new = s0 ^ s1 ^ (s0_new >> 17) ^ (s1 >> 26)
        
    Returns: (state0, state1)
    """
    from z3 import BitVec, Solver, sat, LShR
    
    # 从 double 恢复部分状态 bits
    parts = [v8_double_to_state_value(d) for d in outputs]
    
    solver = Solver()
    s0 = BitVec("s0", 64)
    s1 = BitVec("s1", 64)
    
    for i, mantissa in enumerate(parts):
        if i == 0:
            # 第一个输出 = s0 + s1 的高 52 bits
            result = s0 + s1
        else:
            # 更新状态
            new_s1 = s0
            t = s0 ^ (s0 << 23)
            new_s0 = s0 ^ s1 ^ LShR(t, 17) ^ LShR(s1, 26)
            s0, s1 = new_s0, new_s1
            result = s1 + s0
        
        # 只约束高 52 bits（低 12 bits 未知）
        solver.add(LShR(result, 12) == mantissa)
    
    if solver.check() == sat:
        model = solver.model()
        real_s0 = model.eval(s0).as_long()
        real_s1 = model.eval(s1).as_long()
        return real_s0, real_s1
    
    return None, None


class V8RandomClone:
    """克隆 V8 Math.random() 生成器"""
    
    def __init__(self, state0: int, state1: int):
        self.s0 = state0 & 0xFFFFFFFFFFFFFFFF
        self.s1 = state1 & 0xFFFFFFFFFFFFFFFF
    
    def random(self) -> float:
        """返回 [0, 1) 的 double，与 V8 Math.random() 完全一致"""
        s1 = self.s0
        s0 = self.s1
        self.s0 = s0
        s1 ^= (s1 << 23)
        self.s1 = s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26)
        
        # 转换为 [0, 1) double
        result = (self.s1 + s0) & 0xFFFFFFFFFFFFFFFF
        
        # IEEE 754 编码
        # double 的 52 bits mantissa = 高 52 bits of result
        mantissa = result >> 12
        # 0x3FF 是 [1,2) 的 exponent
        bits = (0x3FF << 52) | mantissa
        packed = struct.pack('<Q', bits)
        return struct.unpack('<d', packed)[0] - 1.0
```

### 3.2 Node.js 实际案例

```python
# node_random_crack.py — Node.js 的 Math.random() 完整攻击
def attack_node_math_random(samples: int = 8) -> dict:
    """
    攻击 Node.js 中的 Math.random()
    
    通过观察连续输出恢复 XorShift128+ 状态
    
    Step-by-step:
    1. 从 Node.js 进程或 web page 收集 8 个 Math.random() 值
    2. 调用 crack_v8_math_random() 恢复 (s0, s1)
    3. 用 V8RandomClone 预测后续值
    """
    return {
        "required_samples": 8,
        "known_threat": "CVE-2021-21225",
        "mitigation": "Use crypto.getRandomValues() instead",
    }
```

## 4. ECDSA Nonce 重用 → 私钥恢复

### 4.1 数学原理

如果两个 ECDSA 签名使用了同一个 nonce k，则私钥直接暴露：

```
给定两个签名 (r, s1), (r, s2) 对不同的消息 m1, m2：
k = (z1 - z2) * (s1 - s2)^{-1} mod n
d = (s1 * k - z1) * r^{-1} mod n

其中 z = hash(m) 截断到 n 的比特长度
```

```python
# ecdsa_nonce_reuse.py — ECDSA nonce 重用攻击
from hashlib import sha256
from typing import Tuple


def recover_ecdsa_private_key_from_nonce_reuse(
    r: int,
    s1: int, z1: int,  # 签名 1 的 s 和消息 hash z
    s2: int, z2: int,  # 签名 2 的 s 和消息 hash z
    n: int,            # 曲线阶
) -> int:
    """
    从 two ECDSA 签名共用 nonce k 恢复私钥
    """
    # k = (z1 - z2) * (s1 - s2)^{-1} mod n
    k = ((z1 - z2) * pow(s1 - s2, -1, n)) % n
    
    # d = (s1 * k - z1) * r^{-1} mod n
    d = ((s1 * k - z1) * pow(r, -1, n)) % n
    
    # 验证
    if (s2 * k - z2) * pow(r, -1, n) % n != d:
        raise ValueError("Signature mismatch: not same nonce?")
    
    return d


def ecdsa_broadcast_attack(signatures: list, n: int, curve_name: str = "secp256k1") -> int:
    """
    广播攻击：当同一私钥的多个签名中，至少两个用了相同 nonce
    
    signatures: [(r, s, z), ...]
    n: 曲线阶
    """
    for i in range(len(signatures)):
        for j in range(i + 1, len(signatures)):
            r_i, s_i, z_i = signatures[i]
            r_j, s_j, z_j = signatures[j]
            
            if r_i == r_j:  # 相同 nonce → 相同 r
                try:
                    d = recover_ecdsa_private_key_from_nonce_reuse(
                        r_i, s_i, z_i, s_j, z_j, n
                    )
                    return d
                except ValueError:
                    continue
    
    return None


# secp256k1 (Bitcoin/ETH) 曲线参数
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# P-256 (NIST) 曲线参数
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def ecdsa_biased_nonce_attack(signatures: list, n: int, bias_bits: int = 8) -> int:
    """
    Biased nonce 攻击（如 CVE-2023-44487 / CVE-2022-21449）
    
    当 nonce 的高 bit 固定或 low bit 偏置时，
    可以用 lattice attack (Howgrave-Graham, Boneh-Venkatesan)
    
    需要约 sqrt(n / 2^{bias_bits}) 个签名样本
    """
    # 实现见 Howgrave-Graham & Smart 1999, LLL lattice reduction
    # 此处提供概念框架
    return 0  # placeholder
```

### 4.2 实际案例：Android PRNG 缺陷

```python
# android_ecdsa_rng_bug.py
"""
CVE-2013-7372: Android 4.4 之前的 PRNG 缺陷
Java's SecureRandom 在 Android 4.3 和更早版本中可能返回相同序列

影响：所有在 Android < 4.4 上生成的 ECDSA 密钥

检测方法：
1. 从同一设备获取两个 ECDSA 签名
2. 比较 r 值 → 如果 r 相同，则 nonce 重用
3. 通过 nonce 重用攻击恢复私钥
"""
```

## 5. PRNG 检测与指纹识别

```python
# prng_fingerprint.py — PRNG 类型自动识别

def fingerint_prng(outputs: list) -> str:
    """
    给定连续输出，自动识别 PRNG 类型
    """
    n = len(outputs)
    
    # 1. 检查 LCG
    for name, params in LCG_PARAMETERS.items():
        m, a, c = params["m"], params["a"], params["c"]
        valid = True
        for i in range(1, min(n, 5)):
            expected = (a * outputs[i-1] + c) % m
            if expected != outputs[i]:
                valid = False
                break
        if valid:
            return f"LCG ({name})"
    
    # 2. 检查 MT19937 (需要 624 个输出)
    if n >= 624:
        try:
            state = recover_mt19937_state(outputs[:624])
            clone = MT19937Clone(outputs[:624])
            if all(clone.get_random_number() == o for o in outputs[624:628]):
                return "MT19937"
        except:
            pass
    
    # 3. IC 分析判断质量
    from collections import Counter
    bit_counts = Counter()
    for val in outputs[:100]:
        for i in range(32):
            if val & (1 << i):
                bit_counts[i] += 1
    
    bias = max(abs(c / 100 - 0.5) for c in bit_counts.values())
    
    if bias > 0.15:
        return f"Weak PRNG (bit bias={bias:.3f})"
    
    return "Unknown (possibly cryptographically secure)"
```

## 6. 标准库 PRNG 速查

```python
LIBRARY_PRNG_REFERENCE = {
    "CPP11_mt19937": {
        "algorithm": "Mersenne Twister MT19937",
        "params": {"state_size": 624, "word_size": 32},
        "crack": "State recovery from 624 consecutive outputs",
    },
    "CPP11_minstd_rand": {
        "algorithm": "LCG",
        "params": {"m": 2**31-1, "a": 48271, "c": 0},
        "crack": "Direct LCG crack from 3 outputs",
    },
    "Java_util_Random": {
        "algorithm": "LCG with 48-bit state",
        "params": {"m": 2**48, "a": 25214903917, "c": 11},
        "crack": "48-bit state from 2 nextInt() outputs (2^16 brute-force)",
    },
    "Net_Random": {
        "algorithm": "Unknown (implementation-specific)",
        "note": "System.Random in .NET uses a modified Knuth subtractive generator",
    },
    "PHP_mt_rand": {
        "algorithm": "MT19937 with 32-bit seed",
        "params": {"seed_bits": 32},
        "crack": "Seed brute-forceable from single output (2^32)",
    },
    "Python_random": {
        "algorithm": "MT19937",
        "params": {"state_size": 624},
        "crack": "Standard MT19937: 624 outputs to full state recovery",
    },
    "V8_Math_random": {
        "algorithm": "XorShift128+",
        "params": {"state": "two 64-bit integers"},
        "crack": "5-8 outputs via Z3 constraint solving",
    },
    "SecureRandom": {
        "algorithm": "OS entropy (cryptographically secure)",
        "note": "Not crackable by state observation",
    },
}
```

## 7. CVE 参考

- **CVE-2021-21225**: V8 Math.random() 预测导致 Chrome 沙箱逃逸
- **CVE-2013-7372**: Android PRNG 缺陷导致 ECDSA 密钥泄露
- **CVE-2022-21449**: Java ECDSA 签名验证绕过（"Psychic Signature"）
- **CVE-2023-44487**: HTTP/2 Rapid Reset 中 nonce 随机性不足
- **CVE-2024-3094**: XZ Utils 供应链攻击（后门植入和随机性分析）
- **CVE-2008-0166**: Debian OpenSSL PRNG 漏洞（仅 32768 个可能的密钥）

## 8. 工具与参考

- [php_mt_seed](https://github.com/openwall/php_mt_seed) — PHP mt_rand 种子爆破
- [z3](https://github.com/Z3Prover/z3) — 约束求解器
- RNG-Detective — PRNG 自动分类工具
- Howgrave-Graham & Smart, "Lattice Attacks on DSA" (1999)
- The Mersenne Twister: Matsumoto & Nishimura (1998)

## MCP 工具映射

| 分析步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| PRNG 模式知识检索 | `kb_router` | 按 PRNG 输出特征搜索知识库 |
| 知识库文件阅读 | `kb_read_file` | 阅读特定 PRNG 破解方法 |
| 样本哈希 | `hash_file` | 确认分析样本的唯一性 |
| 分析工具安装 | `python_re_tool_install` | 安装 z3-solver、Crypto 等依赖 |
| PE 初筛 | `triage_pe` | PE 文件中 PRNG 实现的初步识别 |

## 工作流

收集输入输出对 → 常量/结构/熵识别 → 建立变换假设 → Python 复现 → 断言比对 → 批量解码与产物哈希。


## 证据与验证闭环

- 固定输入样本、SHA256、工具版本和全部参数，先保存未处理 baseline。
- 每个假设至少绑定一个可观察量：已知明密文对、协议字段、状态转移、时间分布、偏移或重放输出。
- 用独立脚本重放核心变换，并以断言、输出哈希或逐字段 diff 验证，不以“看起来合理”作为结论。
- 原始抓包/样本进入 `exports/general/`，派生文件与原件分离并记录转换链。
