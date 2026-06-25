# 算法盲识别：从字节特征反推加密/哈希/压缩算法

> 面对一段未知的二进制 blob，如何在不运行代码的情况下确定它使用了什么加密/哈希/压缩算法？本文给出系统性的特征工程方法论，覆盖 S-box 指纹、魔数识别、熵分析、块检测和操作模式诊断。

## 1. 方法论层次

算法盲识别按侵入性递增分为四个层次：

| 层次 | 方法 | 需要 | 适用场景 |
|------|------|------|----------|
| L1 静态特征 | S-box 匹配、魔数匹配 | 纯二进制 | 标准算法（AES/SHA/zlib） |
| L2 统计特征 | 熵/卡方/游程检验 | 纯二进制 | 区分加密 vs 压缩 vs 编码 |
| L3 结构特征 | 块边界检测、ECB 模式 | 多段数据 | 确定分组密码模式 |
| L4 操作特征 | XOR 频率/Kasiski 分析 | 多段数据 | 流密码/自定义 XOR |

## 2. S-box 指纹数据库与模糊匹配

### 2.1 标准 S-box 特征向量

```python
# sbox_fingerprints.py — 密码学 S-box 指纹数据库
import struct
from typing import Dict, List, Tuple, Optional

# 关键 S-box 特征：取前 32 字节的差值分布（差分均匀度近似）
SBOX_FINGERPRINTS: Dict[str, dict] = {
    "AES_Rijndael": {
        # AES 的 Rijndael S-box 是有限域 GF(2^8) 下 x->x^{-1} + 仿射变换
        # 前 16 字节: 0x63 0x7c 0x77 0x7b 0xf2 0x6b 0x6f 0xc5
        #              0x30 0x01 0x67 0x2b 0xfe 0xd7 0xab 0x76
        "prefix": bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"),
        "size": 256,
        "type": "substitution",
        "properties": "bijective, non-linear GF(2^8), max diff 4/256"
    },
    "DES_S1": {
        # DES S-box 1 是 6->4 bit 压缩代替
        # DES S1 前 16 字节: 0x0e 0x04 0x0d 0x01 0x02 0x0f 0x0b 0x08
        #                     0x03 0x0a 0x06 0x0c 0x05 0x09 0x00 0x07
        "prefix": bytes.fromhex("0e040d01020f0b08030a060c05090007"),
        "size": 64,  # 每盒 4x16
        "type": "compression",
        "properties": "6-to-4 bit, non-linear, Feistel"
    },
    "DES_S2": {
        "prefix": bytes.fromhex("0f0301000a060c0b05090307080f02040e"),
        "size": 64,
        "type": "compression",
        "properties": "DES S-box 2"
    },
    "SM4_Sbox": {
        # SM4（中国商密）S-box
        # 前 16 字节: 0xd6 0x90 0xe9 0xfe 0xcc 0xe1 0x3d 0xb7
        #              0x16 0xb6 0x14 0xc2 0x28 0xfb 0x2c 0x05
        "prefix": bytes.fromhex("d690e9feece13db716b614c228fb2c05"),
        "size": 256,
        "type": "substitution",
        "properties": "Chinese national standard, GF(2^8) affine"
    },
    "Blowfish_P": {
        # Blowfish 的 P-array（前 18 个 32-bit 字）
        # 来自 pi 的小数部分
        "prefix": bytes.fromhex("243f6a8885a308d313198a2e03707344a4093822299f31d0"),
        "size": 18 * 4,
        "type": "key_schedule",
        "properties": "pi fraction digits, Feistel"
    },
    "ChaCha20_constants": {
        # "expand 32-byte k" 的十六进制 — ChaCha20 的常量
        "prefix": b"expand 32-byte k",
        "size": 16,
        "type": "constant",
        "properties": "ChaCha20 initial state constant"
    },
    "Serpent_S0": {
        # Serpent 的 S-box 0
        "prefix": bytes.fromhex("031f0e05370a09180f0708101f1d0e0a"),
        "size": 16,
        "type": "substitution",
        "properties": "4-to-4 bit, bitsliced"
    },
    "Keccak_theta": {
        # Keccak-f 轮常量（SHA-3 用）
        # RC[0..11]: 前 12 个 64-bit 轮常数
        "prefix": bytes.fromhex("0000000000000001000080820000008a80008000800080800000008b0000008b"),
        "size": 24 * 8,
        "type": "round_constant",
        "properties": "SHA-3 sponge"
    },
}


def fuzzy_sbox_match(data: bytes, threshold: float = 0.6) -> List[Tuple[str, float]]:
    """
    模糊匹配 S-box/常量指纹
    
    使用滑动窗口余弦相似度。对于 DES 等小 S-box 用精确匹配更可靠。
    """
    results = []
    for name, fp in SBOX_FINGERPRINTS.items():
        prefix = fp["prefix"]
        if len(data) < len(prefix):
            continue
        
        # 滑动窗口匹配（应对偏移对齐问题）
        best_score = 0.0
        for offset in range(min(16, len(data) - len(prefix) + 1)):
            window = data[offset:offset + len(prefix)]
            matches = sum(1 for a, b in zip(window, prefix) if a == b)
            score = matches / len(prefix)
            best_score = max(best_score, score)
        
        if best_score >= threshold:
            results.append((name, best_score))
    
    return sorted(results, key=lambda x: -x[1])


def search_sbox_in_memory(dump_path: str) -> Dict[str, List[int]]:
    """
    从内存 dump 中搜索所有已知 S-box 的出现位置
    用于识别 native 层使用了哪种算法
    """
    with open(dump_path, "rb") as f:
        data = f.read()
    
    found: Dict[str, List[int]] = {}
    for name, fp in SBOX_FINGERPRINTS.items():
        prefix = fp["prefix"]
        pos = 0
        offsets = []
        while True:
            pos = data.find(prefix, pos)
            if pos == -1:
                break
            offsets.append(pos)
            pos += 1
        if offsets:
            found[name] = offsets
    
    return found
```

### 2.2 AES 特有指纹

AES S-box 有高度规律的结构，可以在二进制中即使部分匹配也识别：

```python
def verify_aes_sbox(sbox: bytes) -> bool:
    """
    验证 256 字节是否是合法的 AES Rijndael S-box
    
    数学性质：
    1. 双射（一一映射）
    2. 对任意非零输入 x，S(x) = A * (x^{-1}) + b（GF(2^8) 仿射）
    3. 最大差分均匀度 = 4/256
    4. 非线性度 = 112
    """
    if len(sbox) != 256:
        return False
    
    # 性质 1: 双射检查
    if len(set(sbox)) != 256:
        return False
    
    # 性质 3: 差分均匀度检查（快速近似）
    # 对每个 Δx != 0，检查 output 对数量
    max_diff = 0
    for dx in range(1, 256):
        counts = {}
        for x in range(256):
            y1 = sbox[x]
            y2 = sbox[x ^ dx]
            dy = y1 ^ y2
            counts[dy] = counts.get(dy, 0) + 1
        max_diff = max(max_diff, max(counts.values()))
    
    return max_diff <= 4  # AES 最大差分均匀度是 4
```

## 3. 哈希常量识别

### 3.1 初始向量 (IV/H0) 数据库

Merkle-Damgard 和海绵结构的哈希函数使用特定初始状态：

```python
# hash_constants.py
HASH_IV_DB = {
    "MD5": {
        # MD5 的 4 个 32-bit 初始向量（little-endian 存储时）
        # 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
        "iv_le": bytes.fromhex("0123456789abcdeffedcba9876543210"),
        "iv_be": bytes.fromhex("67452301efcdab8998badcfe10325476"),
        "digest_size": 16,
        "block_size": 64,
    },
    "SHA1": {
        # SHA1 的 5 个 32-bit
        # 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
        "iv_be": bytes.fromhex("67452301efcdab8998badcfe10325476c3d2e1f0"),
        "block_size": 64,
    },
    "SHA256": {
        # SHA256 前 8 个质数平方根的小数部分的前 32-bit
        # 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
        # 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        "iv_be": bytes.fromhex("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19"),
        "block_size": 64,
    },
    "SHA512": {
        # SHA512 的 8 个 64-bit
        "iv_be": bytes.fromhex(
            "6a09e667f3bcc908bb67ae8584caa73b"
            "3c6ef372fe94f82ba54ff53a5f1d36f1"
            "510e527fade682d19b05688c2b3e6c1f"
            "1f83d9abfb41bd6b5be0cd19137e2179"
        ),
        "block_size": 128,
    },
    "SHA3_256": {
        # Keccak-f[1600] 初始状态全 0，但 sponge 的容量不同
        # 这里无法简单用固定向量检测
        "note": "Keccak-f initial state is all zeros; detection via round constants instead",
        "block_size": 136,
    },
    "BLAKE2b": {
        # BLAKE2b 的 IV 是 SHA-512 IV 的 XOR 修改
        # 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, ...
        "iv_be": bytes.fromhex(
            "6a09e667f3bcc908bb67ae8584caa73b"
            "3c6ef372fe94f82ba54ff53a5f1d36f1"
            "510e527fade682d19b05688c2b3e6c1f"
            "1f83d9abfb41bd6b5be0cd19137e2179"
        ),
        "block_size": 128,
    },
}
```

### 3.2 轮常量识别

哈希算法的压缩函数中使用的轮常量也是高区分度特征：

```python
ROUND_CONSTANTS = {
    "SHA256_K": {
        # SHA256 的 64 个轮常量（前 8 个）
        # 质数立方根的小数部分的前 32-bit
        "prefix": bytes.fromhex(
            "428a2f9871374491b5c0fbcfe9b5dba5"
            "3956c25b59f111f1923f82a4ab1c5ed5"
        ),
        "count": 64,
    },
    "SHA512_K": {
        # SHA512 的 80 个轮常量（前 4 个 64-bit）
        "prefix": bytes.fromhex(
            "428a2f98d728ae227137449123ef65cd"
            "b5c0fbcfec4d3b2fe9b5dba58189dbbc"
        ),
        "count": 80,
    },
    "SHA1_K": {
        # SHA1 的 4 个轮常量
        # 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6
        "prefix": bytes.fromhex("5a8279996ed9eba18f1bbcdcca62c1d6"),
        "count": 4,
    },
    "MD5_T": {
        # MD5 的 64 个 T 常量（前 8 个 sin 函数生成）
        "prefix": bytes.fromhex(
            "d76aa478e8c7b756242070dbc1bdceee"
            "f57c0faf4787c62aa8304613fd469501"
        ),
        "count": 64,
    },
}
```

```python
def detect_hash_via_constants(dump: bytes) -> List[str]:
    """
    扫描内存/二进制 dump，匹配哈希常量的出现
    
    用于当逆向师看到一段模糊的反汇编，想快速确认是什么算法
    """
    candidates = []
    
    # 检查 IV
    for name, iv_info in HASH_IV_DB.items():
        if "iv_be" in iv_info:
            if iv_info["iv_be"] in dump:
                candidates.append(f"{name}(IV-BE)")
        if "iv_le" in iv_info:
            if iv_info["iv_le"] in dump:
                candidates.append(f"{name}(IV-LE)")
    
    # 检查轮常量
    for name, rc_info in ROUND_CONSTANTS.items():
        if rc_info["prefix"] in dump:
            candidates.append(f"{name}(round_constants)")
    
    return candidates
```

## 4. 魔数与容器格式识别

### 4.1 压缩/归档格式魔数

```python
# magic_signatures.py
COMPRESSION_MAGIC = {
    "zlib": {
        # 0x78 0x01 (no compression), 0x78 0x9C (default), 0x78 0xDA (best)
        "magic": bytes.fromhex("789c"),
        "alternatives": [bytes.fromhex("7801"), bytes.fromhex("78da")],
        "note": "DEFLATE with zlib wrapper, CM=8 (deflate), CINFO=7(32k window)"
    },
    "gzip": {
        # RFC 1952: 0x1F 0x8B 0x08
        "magic": bytes.fromhex("1f8b08"),
        "note": "GZIP file format, deflate compression"
    },
    "bzip2": {
        # 0x425A68 ('BZh')
        "magic": b"BZh",
        "note": "BZIP2 block header"
    },
    "lz4": {
        # LZ4 frame magic: 0x04224D18 (LE)
        "magic": bytes.fromhex("04224d18"),
        "note": "LZ4 frame format"
    },
    "lzma": {
        # LZMA / XZ: 0xFD 0x37 0x7A 0x58 0x5A 0x00
        "magic": bytes.fromhex("fd377a585a00"),
        "note": "XZ/LZMA2 stream"
    },
}

COMPRESSION_HEURISTIC = {
    "deflate_raw": {
        # 未包装的 Deflate 流很难识别，但有以下特征：
        # - 前 3 bits 表示最后一块 (1) 和压缩类型 (10=动态 Huffman)
        # - 0x00 0x00 0xFF 0xFF 结尾？
        "pattern": "no fixed magic; use entropy + inflation test",
    }
}
```

### 4.2 PKCS 填充检测

分组密码的填充模式提供了算法线索：

```python
def detect_pkcs_padding(data: bytes) -> Optional[int]:
    """
    检测 PKCS7/PKCS5 填充，返回块大小
    
    PKCS7 填充特征：最后 N 字节的值全部为 N
    - 如果最后 1 字节 = 0x01 → 可能填充 1 字节（也可能是巧合）
    - 如果最后 2 字节 = 0x02 0x02 → 可能填充 2 字节
    - 最后必须满足所有填充字节相等
    
    干扰：明文最后恰好有重复字节
    解决方案：检查解密后 padding 的有效性
    """
    if len(data) < 2:
        return None
    
    last_byte = data[-1]
    if last_byte < 1 or last_byte > 32:  # 填充值只能 1..32 (256位)
        return None
    
    pad_len = last_byte
    if pad_len > len(data):
        return None
    
    padding = data[-pad_len:]
    if all(b == pad_len for b in padding):
        return pad_len
    
    return None


def detect_block_size(data: bytes) -> Optional[int]:
    """
    猜测分组密码的块大小
    
    如果同一 key/IV 加密了多段数据，同一块的密文等长重复
    """
    n = len(data)
    candidates = []
    
    for block_size in [8, 16, 32]:  # DES, AES, Twofish/Serpent
        if n % block_size == 0:
            # 检查块内字节分布是否均匀
            blocks = [data[i:i+block_size] for i in range(0, n, block_size)]
            unique_blocks = len(set(blocks))
            # 对自然图像/文本，全不同是加密的良好指示
            if unique_blocks == len(blocks):
                candidates.append((block_size, "all_unique"))
            elif unique_blocks < len(blocks) * 0.7:
                # 有重复块 → 可能是 ECB 模式或重复数据
                candidates.append((block_size, f"repeated_{unique_blocks}/{len(blocks)}"))
    
    return candidates[0][0] if candidates else None
```

### 4.3 流密码 vs 分组密码判决

```python
def stream_vs_block_cipher(data: bytes, sample_count: int = 5) -> str:
    """
    区分流密码和分组密码
    
    流密码：密文长度 = 明文长度，没有填充对齐
    分组密码：密文长度是块大小的整数倍（有填充）
    
    注意：CFB/OFB/CTR 模式虽然底层是分组密码，但产生流密码特性
    """
    n = len(data)
    
    # 检查是否对齐 8 或 16
    is_block_aligned = (n % 8 == 0) or (n % 16 == 0)
    
    # 统计最后字节的分布（PKCS7 特征）
    if n >= 32:
        last_byte = data[-1]
        # 如果最后 16 或 32 字节中所有值相同 → 可能 PKCS
        trailing_bytes = data[-16:]
        if len(set(trailing_bytes)) == 1:
            return "block_cipher (likely PKCS padding)"
        
        matches_pkcs = all(b == last_byte for b in data[-last_byte:]) if last_byte <= 16 else False
        if matches_pkcs and is_block_aligned:
            return f"block_cipher (PKCS{last_byte})"
    
    if is_block_aligned:
        return "likely block_cipher (aligned)"
    
    return "likely stream_cipher"
```

## 5. 熵分析与可视化

### 5.1 滑动窗口熵

```python
# entropy_analyzer.py
import math
from collections import Counter
from typing import List, Tuple


def shannon_entropy(data: bytes) -> float:
    """计算字节序列的香农熵"""
    if not data:
        return 0.0
    counter = Counter(data)
    entropy = 0.0
    for count in counter.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy


def sliding_window_entropy(data: bytes, window: int = 256, step: int = 64) -> List[Tuple[int, float]]:
    """
    滑动窗口熵分析
    
    用途：
    - 加密/压缩数据：熵 ~7.0-8.0 (接近均匀分布)
    - 明文文本：熵 ~3.5-5.0
    - 零填充区域：熵 ~0.0
    - 结构头：熵 ~2.0-4.0
    """
    result = []
    for offset in range(0, len(data), step):
        chunk = data[offset:offset + window]
        if len(chunk) < 4:
            break
        ent = shannon_entropy(chunk)
        result.append((offset, ent))
    return result


def classify_region(entropy: float) -> str:
    """根据熵值分类区域类型"""
    if entropy < 1.0:
        return "ZERO/LOW (padding, zeros)"
    elif entropy < 3.0:
        return "STRUCTURED (headers, metadata)"
    elif entropy < 5.5:
        return "TEXT (plaintext, strings)"
    elif entropy < 7.0:
        return "SEMI-RANDOM (compressed, mixed)"
    else:
        return "HIGH-ENTROPY (encrypted, packed)"


def ascii_entropy_bar(entropy: float, width: int = 48) -> str:
    """返回 ASCII 熵条，用于终端可视化"""
    bar_len = int(entropy / 8.0 * width)
    bar = "#" * bar_len + "." * (width - bar_len)
    label = classify_region(entropy)
    return f"[{bar}] {entropy:.2f}  {label}"


def print_entropy_profile(data: bytes, window: int = 256, step: int = 64):
    """打印完整的熵轮廓"""
    print(f"Data size: {len(data)} bytes, window={window}, step={step}\n")
    profile = sliding_window_entropy(data, window, step)
    
    # 全局熵
    global_entropy = shannon_entropy(data)
    print(f"Global entropy: {global_entropy:.4f}")
    print(ascii_entropy_bar(global_entropy))
    print()
    
    # 逐段
    for offset, ent in profile:
        pct = (offset / len(data)) * 100
        label = classify_region(ent)
        bar_len = int(ent / 8.0 * 20)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        print(f"  0x{offset:08x} ({pct:5.1f}%) |{bar}| {ent:.2f}  {label}")
    
    print()
    
    # 高熵区域标记
    high_entropy = [(o, e) for o, e in profile if e > 7.0]
    if high_entropy:
        print(f"[!] High-entropy regions ({len(high_entropy)} windows): possible encryption/compression")
    
    # 低熵区域标记
    low_entropy = [(o, e) for o, e in profile if e < 2.0]
    if low_entropy:
        print(f"[!] Low-entropy regions ({len(low_entropy)} windows): possible padding/headers")
```

### 5.2 熵热力图 JSON 输出

```python
def entropy_heatmap_json(data: bytes, window: int = 128) -> dict:
    """
    生成结构化的熵热力图，兼容 binwalk --entropy 格式
    
    JSON 输出可以被 MCP 工具消费
    """
    profile = sliding_window_entropy(data, window, window)
    return {
        "global_entropy": shannon_entropy(data),
        "data_size": len(data),
        "window_size": window,
        "profile": [
            {"offset": offset, "entropy": round(ent, 4)}
            for offset, ent in profile
        ],
        "classification": classify_region(shannon_entropy(data)),
    }
```

## 6. 操作模式检测

### 6.1 ECB 模式检测

ECB 模式的最大弱点：相同的明文块产生相同的密文块。

```python
def detect_ecb_mode(data: bytes, block_size: int = 16) -> Tuple[bool, int, float]:
    """
    ECB 模式检测
    
    原理：将数据分块，计算唯一块数。如果唯一块数 << 总块数，强烈提示 ECB。
    
    阈值：对于随机明文，重复块概率接近 0
          对于真实数据（图像、结构化文本），重复块 > 5% 即提示 ECB
    
    Returns: (is_ecb, block_size, repetition_ratio)
    """
    blocks = [data[i:i+block_size] for i in range(0, len(data) - len(data) % block_size, block_size)]
    if not blocks:
        return False, block_size, 0.0
    
    unique = len(set(blocks))
    total = len(blocks)
    ratio = (total - unique) / total
    
    # ECB 判据：重复块比例 > 1%（对随机明文不可能）
    is_ecb = ratio > 0.01 and total >= 4
    
    return is_ecb, block_size, ratio


def ecb_byte_plot(data: bytes, block_size: int = 16) -> str:
    """
    生成 ASCII ECB 检测图
    
    每行表示一个块，显示第一个字节值，相邻相同块标记
    """
    blocks = [data[i:i+block_size] for i in range(0, len(data) - len(data) % block_size, block_size)]
    seen = {}
    lines = []
    
    for idx, block in enumerate(blocks):
        marker = " " if block not in seen else "R"  # R = repeated
        seen.setdefault(block, []).append(idx)
        first_byte = block[0] if block else 0
        lines.append(f"{idx:4d} [{marker}] 0x{first_byte:02x}  {block[:8].hex()}")
    
    # 重复块统计
    repeat_groups = {k: v for k, v in seen.items() if len(v) > 1}
    
    result = "\n".join(lines[:100])  # 只显示前 100 块
    if repeat_groups:
        result += f"\n\n[!] ECB 模式检测: {len(repeat_groups)} 组块重复出现"
        for blk, positions in list(repeat_groups.items())[:5]:
            result += f"\n    块 {blk[:8].hex()}... 出现在位置: {positions}"
    
    return result
```

### 6.2 CBC 模式 vs CTR 模式

```python
def distinguish_cbc_ctr(data1: bytes, data2: bytes) -> str:
    """
    区分 CBC 和 CTR 模式
    
    已知：同一 key 加密的两个不同密文
    
    CBC: c_i = E_k(p_i ^ c_{i-1}) → 块间有依赖
    CTR: c_i = E_k(nonce || counter) ^ p_i → 每个块独立
    
    攻击：翻转 data1 的某一位 → CBC 会使对应块完全混乱
          CTR 只影响对应位
    """
    # 检测方法：修改 first ciphertext 然后看 second 的解密
    # 此处给出逻辑判断
    return """
    CBC 特征：
    - 块间依赖：翻转 c_i 的任意位，p_{i+1} 对应位同样翻转（解密特性）
    - 错误传播：一个块损坏影响两个块
    
    CTR 特征：
    - 每个块独立加密，无依赖
    - 任意位翻转只影响对应位
    - 密文长度 = 明文长度（无填充）
    
    实验方法：
    1. 翻转第一个密文块的第 0 字节的 bit 0
    2. 观察解密后第二个块的对应变化
    3. 如果第二个块完全混乱 → CBC
    4. 如果只变了第 0 字节 → CTR
    """
```

### 6.3 Kasiski 检验与重合指数

```python
def kasiski_examination(data: bytes, min_len: int = 3) -> dict:
    """
    Kasiski 检验：寻找重复子串之间的距离
    
    用于维吉尼亚密码/多字节 XOR 密钥长度的确定
    """
    from collections import defaultdict
    
    distances = defaultdict(list)
    
    # 扫描所有长度 >= min_len 的重复子串
    for length in range(min_len, min(min_len + 4, len(data) // 4)):
        seen = {}
        for i in range(len(data) - length):
            chunk = data[i:i+length]
            if chunk in seen:
                dist = i - seen[chunk]
                # 跳跃太大可能是巧合
                if dist < 5000:
                    distances[length].append(dist)
            else:
                seen[chunk] = i
    
    # GCD 分析：密钥长度通常是间隔的 GCD
    from math import gcd
    from functools import reduce
    
    key_len_candidates = {}
    for length, dists in distances.items():
        if len(dists) >= 2:
            g = reduce(gcd, dists)
            if g > 1:
                key_len_candidates[length] = {
                    "gcd": g,
                    "samples": len(dists),
                    "distances": dists[:10],
                }
    
    return key_len_candidates


def index_of_coincidence(data: bytes) -> float:
    """
    重合指数 (Index of Coincidence)
    
    IC = sum(n_i * (n_i - 1)) / (N * (N - 1))
    
    英文文本 IC ≈ 0.065
    随机字节 IC ≈ 0.0039 (1/256)
    维吉尼亚加密 IC ≈ 0.0039-0.045（取决于密钥长度）
    """
    if len(data) < 2:
        return 0.0
    
    counter = Counter(data)
    n = len(data)
    ic = sum(count * (count - 1) for count in counter.values()) / (n * (n - 1))
    
    return ic


def guess_xor_key_multi_byte(data: bytes, max_key_len: int = 32) -> dict:
    """
    多字节 XOR 密钥恢复
    
    步骤：
    1. 用 Kasiski 猜测密钥长度
    2. 对每个密钥字节位置做频率分析
    3. 输出最可能的 key
    """
    ic_by_len = {}
    
    for key_len in range(1, max_key_len + 1):
        # 将数据分组为 key_len 列
        ics = []
        for col in range(key_len):
            col_data = bytes(data[col::key_len])
            if len(col_data) >= 2:
                ics.append(index_of_coincidence(col_data))
        
        if ics:
            avg_ic = sum(ics) / len(ics)
            ic_by_len[key_len] = avg_ic
    
    # IC 接近英文文本的 key_len 是候选
    candidates = sorted(
        [(k, v) for k, v in ic_by_len.items() if v > 0.04],
        key=lambda x: -x[1]
    )
    
    return {"ic_by_len": ic_by_len, "candidates": candidates}
```

## 7. 工具链

### 7.1 命令行使用

```bash
# 组合分析
python algorithm_identifier.py dump.bin

# binwalk 熵图
binwalk --entropy dump.bin

# DiE 扫描
diec dump.bin

# 自己的工具链
python -c "
from entropy_analyzer import print_entropy_profile
data = open('dump.bin', 'rb').read()
print_entropy_profile(data)
"
```

### 7.2 完整分析管线

```python
#!/usr/bin/env python3
# algorithm_identifier.py — 完整算法识别管线

import sys


def full_analysis(data: bytes) -> dict:
    """运行全套算法识别管线，返回结构化报告"""
    report = {
        "basic_stats": {
            "size": len(data),
            "entropy": round(shannon_entropy(data), 4),
        },
        "encryption_detection": {},
        "compression_magic": [],
        "sbox_matches": [],
        "hash_constant_matches": [],
        "ecb_detection": {},
        "ic_analysis": {},
    }
    
    # 1. 熵分类
    ent = shannon_entropy(data)
    report["basic_stats"]["classification"] = classify_region(ent)
    
    # 2. 流/分组判断
    report["encryption_detection"]["stream_vs_block"] = stream_vs_block_cipher(data)
    
    # 3. 魔数匹配
    for name, info in COMPRESSION_MAGIC.items():
        if data[:len(info["magic"])] == info["magic"]:
            report["compression_magic"].append(name)
        else:
            for alt in info.get("alternatives", []):
                if data[:len(alt)] == alt:
                    report["compression_magic"].append(f"{name}(alt)")
                    break
    
    # 4. S-box 匹配
    sbox_matches = fuzzy_sbox_match(data)
    report["sbox_matches"] = [{"name": n, "score": round(s, 3)} for n, s in sbox_matches]
    
    # 5. 哈希常量匹配
    report["hash_constant_matches"] = detect_hash_via_constants(data)
    
    # 6. ECB 检测
    is_ecb, bs, ratio = detect_ecb_mode(data)
    report["ecb_detection"] = {
        "is_ecb": is_ecb,
        "block_size": bs,
        "repetition_ratio": round(ratio, 4),
    }
    
    # 7. 填充检测
    pad_len = detect_pkcs_padding(data)
    if pad_len:
        report["encryption_detection"]["pkcs_padding"] = pad_len
    
    # 8. Kasiski/IC
    ic_data = {}
    for kl in [1, 2, 4, 8, 16, 32]:
        if len(data) > kl * 4:
            cols = [bytes(data[c::kl]) for c in range(kl)]
            ics = [index_of_coincidence(c) for c in cols if len(c) > 1]
            if ics:
                ic_data[kl] = round(sum(ics) / len(ics), 4)
    report["ic_analysis"] = ic_data
    
    return report


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python algorithm_identifier.py <binary_file>")
        sys.exit(1)
    
    with open(sys.argv[1], "rb") as f:
        data = f.read()
    
    import json
    report = full_analysis(data)
    print(json.dumps(report, indent=2))
```

## 8. 实战案例

### 案例 1: 识别未知 blob

```python
# 假设从游戏 APK 的 assets 目录取出 data.bin
data = open("data.bin", "rb").read()

# 熵检查
ent = shannon_entropy(data)  # → 7.98 (接近 8.0，强力提示加密或压缩)

# 魔数检查
if data[:2] == b'\x78\x9c':
    import zlib
    plain = zlib.decompress(data)
    # 解压后是 JSON

# S-box 检查
matches = fuzzy_sbox_match(data)
# → [("AES_Rijndael", 0.875)]  # 部分匹配到 AES S-box

# ECB 检查
is_ecb, bs, ratio = detect_ecb_mode(data)
# → (True, 16, 0.23)  # 23% 的块重复，肯定 ECB
```

### 案例 2: 识别内存 dump 中的算法

```python
# 从 Frida dump 出的 lib 段搜索
from sbox_fingerprints import search_sbox_in_memory
import json

found = search_sbox_in_memory("libtarget.so.dump")
print(json.dumps(found, indent=2))
# {
#   "AES_Rijndael": [0x34500, 0x34890],  # 两个位置有 AES S-box
#   "SHA256_K": [0x35000],                # SHA256 轮常量
# }
# → 目标使用了 AES + SHA256
```

### 案例 3: 自定义 XOR 变种

```python
data = open("unknown_encrypted.bin", "rb").read()

ic = index_of_coincidence(data)
# IC ≈ 0.045 → 略高于随机，提示可能有短密钥 XOR

kasiski = kasiski_examination(data, min_len=4)
# → {3: {"gcd": 5, ...}}  # 建议密钥长度 = 5

# 按密钥长度 5 做频率分析
for pos in range(5):
    col = bytes(data[pos::5])
    # 英文频率分析找最可能的 XOR key byte
    freq = Counter(col).most_common(1)[0]
    key_byte = freq[0] ^ 0x20  # 假设空格是最常见字符
    print(f"key[{pos}] = 0x{key_byte:02x}")
```

## 9. 参考

- FIPS 197 (AES S-box 规范)
- FIPS 180-4 (SHA-1, SHA-256, SHA-512 初始值)
- FIPS 202 (SHA-3 Keccak)
- RFC 1950 (zlib), RFC 1951 (Deflate), RFC 1952 (gzip)
- NIST SP 800-38A (分组密码模式 ECB/CBC/CFB/OFB/CTR)
- CVE-2023-5363: OpenSSL ECB 误用漏洞
- CVE-2013-0169: CBC padding oracle

## MCP 工具映射

| 分析步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 算法盲识别查询 | `kb_router` | 按熵值/S-box 特征搜索知识库中匹配的算法条目 |
| 知识库文件阅读 | `kb_read_file` | 阅读匹配到的具体算法技术文件 |
| 二进制文件熵扫描 | `die_scan` | DiE 扫描识别编译器/packer/熵特征 |
| PE 文件初筛 | `triage_pe` | PE 文件的完整初筛（含熵分析） |
| 深度静态分析 | `ghidra_headless_analyze` | Ghidra 深度分析反汇编中调用的加密函数 |
| 工具安装 | `python_re_tool_install` | 安装 ent、binwalk 等分析工具 |

## 证据与验证闭环

- 固定输入样本、SHA256、工具版本和全部参数，先保存未处理 baseline。
- 每个假设至少绑定一个可观察量：已知明密文对、协议字段、状态转移、时间分布、偏移或重放输出。
- 用独立脚本重放核心变换，并以断言、输出哈希或逐字段 diff 验证，不以“看起来合理”作为结论。
- 原始抓包/样本进入 `exports/general/`，派生文件与原件分离并记录转换链。
