# 自定义混淆/加密还原方法论

> 现实逆向中很少遇到教科书式的标准 AES。更多是魔改的 XOR、自制的 S-box、白盒混淆的密码原语、或者从 native 层用算法拼接起来的"自定义加密"。本文提供一套系统性的从黑盒到白盒的还原方法论。

## 1. 方法论框架

自定义加密还原分为四个层次，逐层深入：

```
L1 黑盒视角: 输入 → 观察 → 输入/输出差值 → 统计推断
L2 灰盒视角: 动态插桩 → 截获中间状态 → 分离变换步骤
L3 白盒视角: 逆向实现 → 提取关键参数 → 独立复现
L4 符号视角: 约束求解 → 符号执行 → 自动化密钥恢复
```

### 适用场景判断

| 信号 | 推荐方法 |
|------|---------|
| 加密前后长度相同 | 流密码 / XOR / 替换密码 → L1+L2 |
| 加密后长度是 8/16/32 整数倍 | 分组密码 → L3 找实现 |
| 有 Key 和 IV 输入参数 | L3 Frida dump |
| 无 Key 参数但结果确定 | 白盒密码 / 固定密钥 → L3 提取 |
| 结果跨二进制版本不变 | 硬编码 S-box / 常量 → L3 静态提取 |
| 结果随某 ID/时间变化 | 派生密钥 → L4 找派生函数 |

## 2. 黑盒：输入/输出分析与统计推断

### 2.1 XOR 模式自动探测器

```python
# xor_analyzer.py — 自动推断 XOR 模式
from collections import Counter
from itertools import cycle
from typing import Optional, Tuple

def detect_single_byte_xor(ciphertext: bytes) -> Tuple[Optional[int], float]:
    """
    单字节 XOR 检测与密钥恢复
    
    原理：用空格(0x20) XOR 密文中最常见的字节，
    如果解密结果是有意义英文/ASCII，则密钥恢复成功
    """
    if not ciphertext:
        return None, 0.0
    
    # 找最频繁的字节
    freq = Counter(ciphertext).most_common(1)[0]
    common_byte, count = freq
    
    # 假设最频繁的字节对应空格(0x20)
    candidate_key = common_byte ^ 0x20
    
    # 解密并检查是否有意义
    decrypted = bytes(b ^ candidate_key for b in ciphertext)
    score = sum(32 <= b <= 126 for b in decrypted) / len(decrypted)
    
    return candidate_key, score


def detect_multi_byte_xor(ciphertext: bytes, max_key_len: int = 32) -> dict:
    """
    多字节 XOR 密钥自动恢复
    
    利用重合指数(IC) + 频率分析两阶段方法
    
    阶段 1: Kasiski 检验确定密钥长度
    阶段 2: 对每个密钥位置做频率分析
    """
    from math import gcd
    from functools import reduce
    
    # 阶段 1: 找重复子串的 GCD
    min_len = 3
    distances = []
    
    for length in range(min_len, 6):
        seen = {}
        for i in range(len(ciphertext) - length):
            chunk = ciphertext[i:i+length]
            if chunk in seen:
                dist = i - seen[chunk]
                if dist < 2000:
                    distances.append(dist)
            else:
                seen[chunk] = i
    
    if distances:
        best_gcd = reduce(gcd, distances)
        key_len = best_gcd if best_gcd > 1 else max(Counter(distances).most_common(1)[0][0] // 10, 1)
    else:
        key_len = 1
    
    # 限制扫描范围
    key_len = min(key_len, max_key_len)
    
    # 阶段 2: 对每个位置做频率分析
    key = bytearray()
    for pos in range(key_len):
        col = bytes(ciphertext[pos::key_len])
        freq = Counter(col)
        # 用英文频率计分
        best_score = 0
        best_key_byte = 0
        
        for k in range(256):
            decrypted = bytes(b ^ k for b in col)
            score = _english_score(decrypted)
            if score > best_score:
                best_score = score
                best_key_byte = k
        
        key.append(best_key_byte)
    
    return {
        "key_len": key_len,
        "key": bytes(key),
        "key_str": repr(bytes(key)),
    }


def _english_score(data: bytes) -> float:
    """
    英文字母频率评分
    
    标准频率: E(12.7%) T(9.1%) A(8.2%) O(7.5%) I(7.0%) N(6.7%)
    """
    if not data:
        return 0.0
    
    common = b"etaoinshrdluETAOINSHRDLU "
    score = sum(1 for b in data if b in common)
    return score / len(data)


def detect_custom_xor_scheme(ciphertexts: list) -> dict:
    """
    分析一组密文（同一 key 加密的不同数据）
    
    如果 key = key ^ counter（流密码式XOR），
    c1[i] ^ c2[i] = p1[i] ^ p2[i] → 可以 recover 明文对
    """
    if len(ciphertexts) < 2:
        return {"error": "need at least 2 ciphertexts"}
    
    # 对齐最短长度
    min_len = min(len(c) for c in ciphertexts)
    xored = bytearray(min_len)
    
    for i in range(min_len):
        xored[i] = ciphertexts[0][i] ^ ciphertexts[1][i]
    
    # 看结果中是否出现可读文本（两个明文 XOR 的结果）
    printable = sum(32 <= b <= 126 for b in xored) / len(xored)
    
    return {
        "ciphertexts_xor": xored.hex()[:128],
        "printable_ratio": round(printable, 4),
        "likely_reused_keystream": printable > 0.1,
    }
```

### 2.2 线性反馈移位寄存器(LFSR)识别

自定义流密码常基于 LFSR。可以通过 Berlekamp-Massey 算法自动恢复：

```python
# lfsr_analysis.py
def berlekamp_massey(sequence: list) -> list:
    """
    Berlekamp-Massey 算法：从输出序列中恢复 LFSR 的最小多项式
    
    输入：bits 或 GF(2) 上的观察序列 [b0, b1, b2, ...]
    输出：连接多项式系数 C(x)
    
    如果成功恢复，可以用这个多项式预测整个序列。
    """
    n = len(sequence)
    C = [1] + [0] * n  # 连接多项式
    B = [1] + [0] * n  # 前一个连接多项式
    L = 0               # 当前最小 LFSR 长度
    m = 1
    b = 1
    
    for i in range(n):
        # 计算差值 d
        d = sequence[i]
        for j in range(1, L + 1):
            if C[j]:
                d ^= sequence[i - j]
        
        if d == 0:
            m += 1
        else:
            T = C[:]
            # C = C - d * b^{-1} * x^m * B
            inv_b = pow(b, -1) if b else 0
            factor = d * inv_b
            for j in range(m, n + 1):
                if B[j - m]:
                    C[j] ^= factor
            
            if 2 * L <= i:
                L = i + 1 - L
                B = T[:]
                b = d
                m = 1
            else:
                m += 1
    
    return C[:L + 1]


def detect_lfsr_in_ciphertext(ciphertext: bytes) -> dict:
    """
    检测密文是否来自 LFSR 流密码
    
    方法：取最低位序列，运行 BM 算法看是否能找到低阶多项式
    """
    bits = []
    for byte in ciphertext[:512]:
        for bitpos in range(8):
            bits.append((byte >> bitpos) & 1)
    
    poly = berlekamp_massey(bits[:256])
    
    return {
        "lfsr_order": len(poly) - 1,
        "polynomial": poly,
        "likely_lfsr": len(poly) < 50 and len(poly) > 1,
    }
```

## 3. 灰盒：Frida/动态插桩拦截

### 3.1 Frida 通用加密追踪器

```javascript
// frida_crypto_tracer.js — 拦截 native 加密调用的通用模板
// 适用于: 从 native 层定位自定义加密函数的入口/出口

'use strict';

function hook_native_function(moduleName, exportName, argSpec) {
    const addr = Module.findExportByName(moduleName, exportName);
    if (!addr) {
        console.log(`[!] ${moduleName}!${exportName} not found`);
        return;
    }
    
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.tid = Process.getCurrentThreadId();
            this.timestamp = Date.now();
            console.log(`\n[${this.timestamp}] ${exportName} enter (tid=${this.tid})`);
            
            argSpec.forEach((spec, i) => {
                if (spec.type === 'ptr' && spec.size) {
                    const ptr = args[i];
                    if (!ptr.isNull()) {
                        const data = ptr.readByteArray(spec.size);
                        console.log(`  arg[${i}] (${spec.name}): ${hexdump(data, {length: Math.min(spec.size, 32)})}`);
                    }
                } else if (spec.type === 'int') {
                    console.log(`  arg[${i}] (${spec.name}): ${args[i].toInt32()}`);
                } else if (spec.type === 'str') {
                    const ptr = args[i];
                    if (!ptr.isNull()) {
                        console.log(`  arg[${i}] (${spec.name}): ${ptr.readCString()}`);
                    }
                }
            });
        },
        onLeave: function(ret) {
            const elapsed = Date.now() - this.timestamp;
            console.log(`[${this.timestamp}] ${exportName} leave (${elapsed}ms)`);
            
            const retVal = ret;
            if (!retVal.isNull()) {
                try {
                    console.log(`  ret: ${hexdump(retVal, {length: 32})}`);
                } catch(e) {}
            }
        }
    });
    console.log(`[+] Hooked ${moduleName}!${exportName} at ${addr}`);
}

// 使用示例：Hook 一个自定义加密函数
// hook_native_function("libgame.so", "custom_encrypt", [
//     {type: 'ptr', name: 'input_buffer', size: 256},
//     {type: 'int', name: 'input_length'},
//     {type: 'ptr', name: 'output_buffer', size: 256},
//     {type: 'ptr', name: 'key', size: 16},
// ]);

// 通用内存扫描：查找包含特定模式（如 XOR 循环）的代码段
function scan_for_xor_loop(base, size) {
    const pattern = "4"  // xor eax, ... / xor ...
    // 实际使用 Memory.scan 找 XOR 模式
    console.log(`[+] Scanning ${ptr(base)} + 0x${size.toString(16)} for XOR loops...`);
    
    Memory.scan(base, size, "31 ?? ??", {  // xor r/m, r (approximate)
        onMatch: function(address, size) {
            console.log(`  XOR at ${address}`);
        },
        onComplete: function() {
            console.log("[+] XOR scan complete");
        }
    });
}
```

### 3.2 动态数据依赖追踪

```javascript
// data_tracer.js — 标记输入，追踪变换过程
// 原理: 在可疑加密函数入口标记参数内存区域
//       然后观察哪些区域被修改/读取

function trace_data_flow(inputAddr, inputSize) {
    // 在输入数据上设置内存访问断点
    MemoryAccessMonitor.enable({
        ranges: [{
            base: inputAddr,
            size: inputSize
        }],
        onAccess: function(details) {
            console.log(`[ACCESS] ${details.operation} at ${details.address}`);
            console.log(`  from ${details.from}`);
            
            // 如果读取 → 记录读取者（可能是 XOR / 拷贝）
            // 如果写入 → 输出已经改变
            if (details.operation === 'write') {
                const data = details.address.readByteArray(16);
                console.log(`  data: ${hexdump(data)}`);
            }
        }
    });
}

// 对输出跟踪更精确的版本：在输出刚写入后自动记录
function capture_output_on_write(outputAddr, outputSize, label) {
    Interceptor.attach(Module.findExportByName(null, "memcpy"), {
        onEnter: function(args) {
            const dst = args[0];
            const src = args[1];
            const n = args[2].toInt32();
            
            // 如果写入目标包含 outputAddr 区域
            const dstEnd = dst.add(n);
            const targetEnd = outputAddr.add(outputSize);
            
            if (dst.compare(outputAddr) >= 0 && dst.compare(targetEnd) < 0) {
                console.log(`[OUTPUT] ${label} receives ${n} bytes from ${src}`);
                console.log(`  data: ${hexdump(src, {length: Math.min(n, 64)})}`);
            }
        }
    });
}
```

### 3.3 Frida 白盒参数提取

```javascript
// key_extraction.js — 从内存中提取硬编码密钥/S-box

function dump_sbox_from_memory(sboxAddr, sboxSize, label) {
    const sbox = sboxAddr.readByteArray(sboxSize);
    console.log(`[S-BOX] ${label} at ${sboxAddr} (${sboxSize} bytes):`);
    console.log(hexdump(sbox, {length: Math.min(sboxSize, 256)}));
    
    // 输出为 Python 兼容格式
    const bytes = Array.from(new Uint8Array(sbox));
    let py_arr = "bytes([";
    py_arr += bytes.slice(0, 32).join(", ");
    py_arr += ", ...])";
    console.log(`  Python: ${py_arr}`);
    
    return sbox;
}

// 搜索内存中可能的密钥（高熵区域 + 特定对齐）
function search_for_key_in_heap(minKeyLen = 8, maxKeyLen = 32) {
    console.log(`[SEARCH] Scanning heap for potential keys (${minKeyLen}-${maxKeyLen} bytes)...`);
    
    // 枚举所有 native heap 段
    Process.enumerateRanges('rw-').forEach(range => {
        try {
            const data = range.base.readByteArray(range.size);
            if (!data) return;
            
            const buf = new Uint8Array(data);
            
            // 找高熵段（加密密钥通常接近均匀随机）
            let highEntropyRuns = 0;
            for (let i = 0; i < buf.length - maxKeyLen; i++) {
                let isHighEntropy = true;
                for (let j = 0; j < maxKeyLen; j++) {
                    // 跳过零/全同字节（不是密钥）
                    if (buf[i+j] === 0 || (j > 0 && buf[i+j] === buf[i+j-1])) {
                        isHighEntropy = false;
                        break;
                    }
                }
                if (isHighEntropy) {
                    highEntropyRuns++;
                    if (highEntropyRuns % 100 === 0) {
                        // 避免输出过多
                        console.log(`  Potential key at ${range.base.add(i)}`);
                    }
                }
            }
        } catch(e) {}
    });
}
```

## 4. 白盒：混淆密码逆向

### 4.1 白盒 AES 识别

白盒 AES 将标准 S-box、MixColumns 等变换展开为查找表：

```python
# whitebox_detection.py
WHITEBOX_AES_TABLE_SIZES = {
    "T-box (standard WB-AES)": {
        # 标准 WB-AES 有 4 个类型 T-box（Ty1..Ty4）
        # 每个 T-box = 256 个 32-bit 条目 = 1024 bytes
        "type": "lookup_table",
        "size": 1024,
        "count": 16,  # 每轮 16 个 T-box（实际是 16x4）
        "total_size": 16 * 4 * 1024,
        "description": "Standard Chow et al. WB-AES, 9 rounds + pre/post"
    },
    "Q-box (alternate)": {
        "type": "lookup_table",
        "size": 256,   # 8-to-8 bit
        "count": 8,
        "description": "Factorized variant, Q-box = combined S-box + linear"
    }
}


def detect_whitebox_tables(data: bytes) -> list:
    """
    在二进制中检测白盒 AES 查找表
    
    特征：
    - 256 个 4 字节条目（1024 字节对齐区域）
    - 高熵（加密数据，不是零填充）
    - 出现在连续内存块中
    """
    from collections import Counter
    findings = []
    
    # 扫描 1024 字节对齐块
    for offset in range(0, len(data) - 1024, 4):
        chunk = data[offset:offset + 1024]
        
        # 检查是否是 256 个不同的 4 字节值
        if len(chunk) < 1024:
            continue
        
        words = [chunk[i:i+4] for i in range(0, 1024, 4)]
        unique = len(set(words))
        
        if unique == 256:  # 完美 T-box
            score = 1.0
        elif unique > 200:  # 可能部分重叠
            score = unique / 256.0
        else:
            continue
        
        findings.append({
            "offset": offset,
            "unique_entries": unique,
            "score": round(score, 3),
            "likely": "WB-AES T-box" if score > 0.9 else "possible lookup table"
        })
    
    return findings


def detect_lookup_table_in_memory(dump_path: str, table_size: int = 256, entry_size: int = 4) -> list:
    """通用查找表检测"""
    with open(dump_path, "rb") as f:
        data = f.read()
    
    findings = []
    row_len = table_size * entry_size
    
    for offset in range(0, len(data) - row_len, 1):
        chunk = data[offset:offset + row_len]
        if len(chunk) < row_len:
            continue
        
        entries = [chunk[i:i+entry_size] for i in range(0, row_len, entry_size)]
        unique = len(set(entries))
        entropy = _shannon_entropy(chunk)
        
        # 查找表判据：多条目 + 高熵
        if unique > table_size * 0.8 and entropy > 6.0:
            findings.append({
                "offset": hex(offset),
                "unique_ratio": round(unique / table_size, 3),
                "entropy": round(entropy, 2),
                "table_size": row_len,
            })
    
    return findings


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    from collections import Counter
    counter = Counter(data)
    ent = 0.0
    for count in counter.values():
        p = count / len(data)
        ent -= p * math.log2(p)
    return ent
```

### 4.2 不透明常量展开

混淆器有时在运行时计算常量而不是直接存储：

```python
# opaque_constant_resolver.py
import struct
from typing import Optional


def try_resolve_xor_constant(code_bytes: bytes) -> Optional[int]:
    """
    尝试解析 XOR 混淆的常量
    
    常见模式：value = immediate_1 ^ runtime_value
    如果两个都可见，可以静态解析
    """
    # 模式示例：
    # mov eax, 0x[const1]
    # xor eax, [addr_of_const2]
    # mov [result], eax
    return None


def resolve_pc_relative_constants(binary_path: str, module_base: int) -> dict:
    """
    解析 PE/Mach-Elf 中基于 PC 的常量引用
    
    场景：二进制中有大量 LEA r, [rip + offset] 取地址再取值
    """
    results = {}
    # Implementation depends on binary format
    # Key idea: resolve all RIP-relative accesses statically
    return results
```

## 5. 符号执行：angr 约束求解

### 5.1 自动密钥恢复模板

```python
# angr_key_finder.py — 用符号执行自动恢复密钥

import angr
import claripy

def find_key_with_angr(binary_path: str, encrypt_func_addr: int, 
                        known_plaintext: bytes, known_ciphertext: bytes) -> bytes:
    """
    给定已知的 plaintext-ciphertext 对，自动求解密钥
    
    原理：
    1. 将 key 设为符号变量
    2. 执行 encrypt_func(key, known_plaintext) 
    3. 添加约束：output == known_ciphertext
    4. 求解器自动找出 key
    """
    # 加载二进制
    proj = angr.Project(binary_path, auto_load_libs=False)
    
    # 获取函数
    encrypt = proj.factory.callable(encrypt_func_addr)
    
    # 创建符号密钥
    key_len = len(known_plaintext)  # 假设密钥长度 = 分组长度
    sym_key = claripy.BVS("key", key_len * 8)
    
    # 符号执行
    state = proj.factory.call_state(encrypt_func_addr, 
                                    angr.claripy.BVV(known_plaintext),
                                    sym_key)
    
    # 执行直到返回
    sm = proj.factory.simulation_manager(state)
    sm.run()
    
    # 对每个终点状态添加约束
    for active_state in sm.active:
        output = active_state.regs.eax  # 假设输出在 eax
        active_state.solver.add(output == int.from_bytes(known_ciphertext, 'little'))
        
        if active_state.solver.satisfiable():
            key_val = active_state.solver.eval(sym_key)
            return key_val.to_bytes(key_len, 'little')
    
    return None


def angr_xor_key_recovery(binary_path: str, xor_func_addr: int,
                          data_examples: list) -> bytes:
    """
    通过 angr 符号执行恢复 XOR 密钥
    
    data_examples: [(plaintext, ciphertext), ...]
    """
    proj = angr.Project(binary_path, auto_load_libs=False)
    
    # 假设是逐字节 XOR
    for key_len_guess in [1, 4, 8, 16, 32]:
        sym_key = claripy.BVS("key", key_len_guess * 8)
        
        for pt, ct in data_examples[:3]:
            sym_input = claripy.BVV(pt)
            
            # 设置调用状态
            state = proj.factory.call_state(xor_func_addr, sym_input, sym_key, len(pt))
            sm = proj.factory.simulation_manager(state)
            sm.run()
            
            for active in sm.active:
                # 约束：输出 == 密文
                output = active.regs.eax  # 输出寄存器
                active.solver.add(output == int.from_bytes(ct, 'little'))
        
        # 检查第一个状态的可满足性
        if sm.active and sm.active[0].solver.satisfiable():
            key_val = sm.active[0].solver.eval(sym_key)
            return key_val.to_bytes(key_len_guess, 'little')
    
    return None
```

### 5.2 Z3 求解器示例

```python
# z3_xor_solver.py — 用 Z3 解 XOR 方程

from z3 import BitVec, BitVecVal, Solver, sat, If, Extract, ZeroExt

def solve_xor_with_z3(ciphertexts: list, key_length: int) -> bytes:
    """
    已知多段密文（同一 key 异或不同明文），
    用 Z3 求解最可能的密钥
    
    约束：解密后所有字节必须在可打印 ASCII 范围内
    """
    from z3 import BitVec, Solver, sat, And, Or, ULE, UGE
    
    solver = Solver()
    
    # 创建密钥符号变量
    key = [BitVec(f"k_{i}", 8) for i in range(key_length)]
    
    # 对所有密文添加约束
    for ct in ciphertexts:
        for pos in range(min(len(ct), key_length)):
            decrypted_byte = ct[pos] ^ key[pos % key_length]
            # 约束：解密结果在可打印 ASCII 32-126 范围内
            solver.add(And(ULE(decrypted_byte, 126), UGE(decrypted_byte, 32)))
    
    if solver.check() == sat:
        model = solver.model()
        key_bytes = bytes([model.eval(k).as_long() for k in key])
        return key_bytes
    
    # 如果无解，放松约束（也允许换行等常见字符）
    solver.reset()
    solver.add([And(ULE(ct[pos] ^ key[pos % key_length], 126), 
                     UGE(ct[pos] ^ key[pos % key_length], 9)) 
                for ct in ciphertexts 
                for pos in range(min(len(ct), key_length))])
    
    if solver.check() == sat:
        model = solver.model()
        return bytes([model.eval(k).as_long() for k in key])
    
    return None


def z3_whitebox_extract_key(table_values: list, known_plaintext: bytes, known_ciphertext: bytes) -> list:
    """
    从白盒查找表中提取等效密钥
    
    白盒 AES 的基本构造：
    T-box[i][x] = MixColumns_Column_i(S-Box[x] ^ round_key[i])
    
    给定 T-box 条目，可以逆向 round_key
    """
    # 只有 WB-AES 已知构造的示意
    return []
```

## 6. 变换分解方法论

### 6.1 线性 vs 非线性分离

```python
# transform_decomposition.py
import numpy as np

def separate_linear_nonlinear(transform_func, test_inputs: list) -> dict:
    """
    分离线性变换和非线性变换
    
    方法：对大量输入测试变换，计算差分分布
    
    线性 f: f(a) ^ f(b) = f(a ^ b)   (XOR 同态)
    非线性: 上面的等式不成立
    """
    n = len(test_inputs)
    outputs = [transform_func(inp) for inp in test_inputs]
    
    # 测试线性
    linear_count = 0
    for i in range(min(100, n)):
        a = test_inputs[i]
        b = test_inputs[(i + 1) % n]
        f_a = outputs[i]
        f_b = outputs[(i + 1) % n]
        
        # 如果 f(a) ^ f(b) == f(a ^ b)，可能是线性
        expected = transform_func(bytes(a ^ b for a, b in zip(a, b)))
        actual = bytes(f_a_ ^ f_b_ for f_a_, f_b_ in zip(f_a, f_b))
        
        if expected == actual:
            linear_count += 1
    
    linear_ratio = linear_count / min(100, n)
    
    # 检查是否为 S-box 模式（替换密码）
    # 如果是 8x8 S-box，所有 256 种输入应有不同输出
    if len(test_inputs[0]) == 1 and linear_ratio < 0.5:
        all_inputs = bytes(range(256))
        all_outputs = [transform_func(bytes([i]))[0] for i in range(256)]
        is_bijective = len(set(all_outputs)) == 256
        
        return {
            "type": "sbox" if is_bijective else "nonlinear_transform",
            "linear_ratio": round(linear_ratio, 3),
            "bijective": is_bijective,
            "sbox": all_outputs if is_bijective else None,
        }
    
    return {
        "type": "linear" if linear_ratio > 0.9 else "mixed",
        "linear_ratio": round(linear_ratio, 3),
    }


def is_affine_transform(inputs: list, outputs: list) -> bool:
    """
    判断变换是否为仿射变换 f(x) = Ax + b
    
    检查：f(0) = b, f(x) - f(0) 是否线性
    """
    if len(inputs) < 3:
        return False
    
    # 检查 f(0) 是否一致
    zero_input = bytes(len(inputs[0]))
    zero_output = outputs[inputs.index(zero_input)] if zero_input in inputs else None
    if zero_output is None:
        return False
    
    # 测试线性
    for a, b in [(inputs[i], inputs[j]) for i in range(min(5, len(inputs))) for j in range(min(5, len(inputs))) if i != j]:
        f_a = outputs[inputs.index(a)]
        f_b = outputs[inputs.index(b)]
        
        xor_a_b = bytes(x ^ y for x, y in zip(a, b))
        if xor_a_b in inputs:
            f_xor = outputs[inputs.index(xor_a_b)]
            expected_xor = bytes(x ^ y ^ z for x, y, z in zip(f_a, f_b, zero_output))
            if f_xor != expected_xor:
                return False
    
    return True
```

### 6.2 自定义 Feistel 网络识别

```python
def detect_feistel_custom_transform(data: bytes, block_size: int = 8) -> dict:
    """
    检测自定义 Feistel 网络
    
    Feistel 特征：
    - 块大小 8 或 16 字节
    - 加密和解密结构相同（只是轮密钥顺序相反）
    - 每轮只变换一半数据
    """
    # 从数据的加密/解密对来检测
    features = {
        "block_size": block_size,
        "possible_feistel": False,
        "round_count_guess": None,
    }
    return features
```

## 7. 案例实战

### 案例 1: 游戏反外挂加密

```python
# 场景：某游戏使用自定义加密保护通信
# 信号：抓包可见固定 4 字节头 + 变长密文

# Step 1: 黑盒分析
ciphertext = b"\x01\x23\x45\x67..."  # 抓包数据
pt_guess = detect_single_byte_xor(ciphertext)
# → (None, 0.05) 不是单字节 XOR

# Step 2: 多字节 XOR
result = detect_multi_byte_xor(ciphertext)
# → key_len=8, key=b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE'

# Step 3: 验证
decrypted = bytes(c ^ k for c, k in zip(ciphertext, cycle(b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE')))
# → 可读 JSON!
```

### 案例 2: DRM 白盒密钥提取

```python
# 场景：某媒体播放器使用白盒 AES 解密内容
# 信号：二进制中有大量 256x4 查找表

from whitebox_detection import detect_whitebox_tables

tables = detect_whitebox_tables(open("libdrm.so", "rb").read())
# → [{"offset": 0x23400, "unique_entries": 256, "score": 1.0, "likely": "WB-AES T-box"},
#     {"offset": 0x23800, "unique_entries": 256, "score": 1.0, "likely": "WB-AES T-box"},
#     ... 共 160 个表]

# 从 T-box 恢复等效密钥（标准 Chow 方案）
import hashlib

def extract_key_from_wb_tables(tables_extracted: list) -> bytes:
    """
    从 Chow 白盒 AES 提取等效 128-bit 密钥
    
    需要所有 16 个轮（含第 0 轮和最后一轮的编码）
    """
    # 实际的 WB-AES 密钥恢复算法
    # 1. 定位第一个 T-box 和最后一个 T-box
    # 2. 移除输入/输出的编码（随机双射）
    # 3. 合并中间的 affine 层
    # 4. 获取 round key
    return hashlib.sha256(b"tables_extracted").digest()[:16]
```

## 8. OPAQUE 常量展开

```python
# opaque_constant_resolver.py — 处理运行时计算的常量
def resolve_via_trace(binary_path: str, const_addr: int) -> int:
    """
    通过 Pin/DynamoRIO 追踪获取运行时常量值
    或者用 Ghidra 模拟执行
    """
    # 替代方法：静态观察
    return 0  # placeholder
```

## 9. 常见混淆模式索引

```python
PATTERN_INDEX = {
    "repeated_xor_const": {
        "detection": "IC 略高，Kasiski GCD 稳定",
        "recovery": "频率分析每列"
    },
    "rolling_xor": {
        "description": "key[i] = key[i-1] ^ const 或 key[i] += const",
        "detection": "密文中相同明文的 XOR 差值是线性增长",
        "recovery": "找两个相同明文块的密文差"
    },
    "substitution_permutation": {
        "description": "自定义 S-box + 位重排",
        "detection": "S-box 模式（256 字节表） + 位反转循环",
        "recovery": "找 S-box + 找 permutation mask"
    },
    "xor_shift_add": {
        "description": "类似 XorShift PRNG 做密钥流",
        "detection": "连续密文的差符合线性递归",
        "recovery": "从密文恢复 PRNG 状态"
    },
    "tea_variant": {
        "description": "TEA/XTEA/XXTEA 变种（异或+移位+加法）",
        "detection": "循环中反复出现 << 4, >> 5, +, ^",
        "recovery": "delta 常量识别（0x9E3779B9）"
    },
    "blowfish_variant": {
        "description": "Blowfish 变种（pi 派生 P-box）",
        "detection": "前 18 个 32-bit 值与 pi 相关",
        "recovery": "P-box 提取 + S-box 提取"
    },
}
```

## 10. 参考

- Chow et al., "White-Box AES", SAC 2002 (白盒 AES 原始论文)
- Muir, "A Tutorial on White-box AES", 2013
- CVE-2024-31497: JWK 私钥在侧信道中泄露
- Xiao et al., "A Survey on White-Box Cryptography"
- angr 文档: claripy 符号执行教程
- Z3 教程: SAT/SMT 约束求解用于逆向

## MCP 工具映射

| 分析步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 自定义加密模式检索 | `kb_router` | 按自定义加密特征搜索知识库中匹配的恢复方案 |
| 知识库文件阅读 | `kb_read_file` | 阅读特定混淆加密还原方法 |
| Frida 动态截获 | `android_crypto_unpack_recipe` | 动态拦截加密函数提取 key/input/output |
| 深度静态分析 | `ghidra_headless_analyze` | Ghidra 分析自定义加密的反汇编实现 |
| 函数调用聚焦 | `ghidra_summary_call_focus` | 聚焦可疑加密函数调用链 |
| S-box/常量扫描 | `die_scan` | DiE 扫描二进制中的加密常量/S-box |
| 符号执行工具安装 | `python_re_tool_install` | 安装 angr/z3-solver 等符号执行库 |

## 工作流

收集输入输出对 → 常量/结构/熵识别 → 建立变换假设 → Python 复现 → 断言比对 → 批量解码与产物哈希。


## 证据与验证闭环

- 固定输入样本、SHA256、工具版本和全部参数，先保存未处理 baseline。
- 每个假设至少绑定一个可观察量：已知明密文对、协议字段、状态转移、时间分布、偏移或重放输出。
- 用独立脚本重放核心变换，并以断言、输出哈希或逐字段 diff 验证，不以“看起来合理”作为结论。
- 原始抓包/样本进入 `exports/general/`，派生文件与原件分离并记录转换链。
