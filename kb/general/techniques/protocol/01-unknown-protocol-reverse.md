# 未知协议逆向方法论

> 面对一个没有文档的自定义 TCP/UDP/串行协议，如何从零开始解构其格式、字段、状态机和校验和？本文提供系统性的方法论，覆盖熵分析定界、CRC 逆向工程、字段依赖映射、状态机推断和差分分析。

## 1. 协议逆向四阶段

```
Phase 1 — 定界: 从原始字节流中划出独立消息的边界
Phase 2 — 字段解析: 确定类型/长度/值/校验字段
Phase 3 — 语义推断: 建立字段间的依赖关系和取值空间
Phase 4 — 状态机: 从请求-回复序列推断交互协议状态
```

## 2. Phase 1: 从字节流中切分消息

### 2.1 熵定界法

消息边界处的熵会突然下降（固定 magic/长度字段包含低熵信息）：

```python
# protocol_slicer.py — 基于熵的消息定界
import math
from collections import Counter
from typing import List, Tuple


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    ent = 0.0
    for count in counter.values():
        p = count / len(data)
        ent -= p * math.log2(p)
    return ent


def find_message_boundaries(stream: bytes, window: int = 4) -> List[int]:
    """
    通过局部熵检测找消息边界
    
    原理：消息之间的 magic/长度字段熵较低，
    消息正文（加密/压缩）熵较高。
    熵的突变点 = 边界候选
    """
    boundaries = [0]
    
    for i in range(window, len(stream) - window, 1):
        left = stream[i - window:i]
        right = stream[i:i + window]
        
        left_ent = shannon_entropy(left)
        right_ent = shannon_entropy(right)
        
        # 熵差值 > 阈值 → 边界
        if abs(right_ent - left_ent) > 2.0:
            boundaries.append(i)
    
    boundaries.append(len(stream))
    return boundaries


def detect_magic_prefix(stream: bytes, min_len: int = 2, min_occ: int = 3) -> List[Tuple[bytes, List[int]]]:
    """
    检测重复出现的前缀（magic bytes）
    
    如果协议有固定 magic 头（如 0xAA 0xBB 开头的包），
    这些位置就是已知的消息边界
    """
    from collections import defaultdict
    
    prefix_positions = defaultdict(list)
    
    for i in range(len(stream) - min_len):
        prefix = stream[i:i + min_len]
        prefix_positions[prefix].append(i)
    
    # 过滤：出现 >= min_occ 次且间隔有规律
    result = []
    for prefix, positions in prefix_positions.items():
        if len(positions) >= min_occ:
            # 间隔分析：如果间隔的方差较小→更可能是真正的包边界
            gaps = [positions[j+1] - positions[j] for j in range(len(positions) - 1)]
            if gaps:
                avg_gap = sum(gaps) / len(gaps)
                variance = sum((g - avg_gap) ** 2 for g in gaps) / len(gaps)
                result.append((prefix, positions, avg_gap, variance))
    
    # 按出现次数降序
    result.sort(key=lambda x: -len(x[1]))
    return [(p, pos) for p, pos, _, _ in result[:20]]


def scan_message_by_timing(tcp_stream: list) -> List[int]:
    """
    基于时间间隔分割消息
    
    从 pcap 的时间戳分析：如果两个包的时间差 > typical_inter_packet_gap * 5，
    可能是两个独立消息（而不是同一个消息的分片）
    
    tcp_stream: [(timestamp, data), ...]
    """
    if len(tcp_stream) < 2:
        return []
    
    boundaries = [0]
    gaps = []
    
    for i in range(1, len(tcp_stream)):
        gap = tcp_stream[i][0] - tcp_stream[i-1][0]
        gaps.append(gap)
    
    if not gaps:
        return []
    
    avg_gap = sum(gaps) / len(gaps)
    threshold = avg_gap * 5
    
    for i in range(1, len(tcp_stream)):
        gap = tcp_stream[i][0] - tcp_stream[i-1][0]
        if gap > threshold:
            boundaries.append(i)
    
    return boundaries
```

### 2.2 长度定界与可变长度字段

```python
def detect_length_field(messages: List[bytes], candidate_positions: List[int]) -> dict:
    """
    检测消息头中的长度字段
    
    方法：对一个候选位置，读取其值，检查是否等于消息剩余长度。
    """
    if len(messages) < 2:
        return {"error": "Need >= 2 messages"}
    
    results = {}
    min_len = min(len(m) for m in messages)
    
    for size in [1, 2, 4]:  # 尝试不同长度编码
        for offset in candidate_positions:
            if offset + size > min_len:
                continue
            
            matches = 0
            for msg in messages:
                if size == 1:
                    declared_len = msg[offset]
                elif size == 2:
                    # 尝试 big-endian 和 little-endian
                    declared_len_be = int.from_bytes(msg[offset:offset+2], 'big')
                    declared_len_le = int.from_bytes(msg[offset:offset+2], 'little')
                elif size == 4:
                    declared_len_be = int.from_bytes(msg[offset:offset+4], 'big')
                    declared_len_le = int.from_bytes(msg[offset:offset+4], 'little')
                
                if size == 1:
                    if declared_len == len(msg) - offset - size:
                        matches += 1
                else:
                    if declared_len_be == len(msg) - offset - size:
                        matches += 1
                    if declared_len_le == len(msg) - offset - size:
                        matches += 1
            
            if matches >= len(messages) * 0.8:
                results[(offset, size)] = matches
    
    return results


def detect_message_type_field(messages: List[bytes], offset: int, size: int) -> dict:
    """
    检测消息类型/命令字段
    
    如果多个消息在相同偏移有不同值（且值类别有限），
    很可能是 type/cmd/opcode 字段
    """
    types_seen = set()
    for msg in messages:
        if offset + size <= len(msg):
            val = int.from_bytes(msg[offset:offset+size], 'big')
            types_seen.add(val)
    
    return {
        "offset": offset,
        "size": size,
        "distinct_values": len(types_seen),
        "values": sorted(types_seen)[:20],
        "likely_type_field": len(types_seen) < len(messages) * 0.5 and len(types_seen) >= 2,
    }
```

## 3. Phase 2: 字段类型推断

### 3.1 固定 vs 变长字段的熵区分

```python
# field_classifier.py — 字段类型自动分类
from collections import Counter


def classify_field(data_snapshots: List[bytes], offset: int, size: int) -> str:
    """
    根据一批消息样本中同一字段的统计特征推断其类型
    """
    values = []
    for snap in data_snapshots:
        if offset + size <= len(snap):
            values.append(int.from_bytes(snap[offset:offset+size], 'big'))
    
    if not values:
        return "unknown"
    
    unique = len(set(values))
    value_range = max(values) - min(values) if values else 0
    entropy_per_byte = size * 8 if len(values) > 1 else 0
    
    # 类型判据表
    if unique == 1:
        return "constant/padding"
    
    if size == 1 and unique < 20:
        return "type/flag (1 byte, few values)"
    
    if size in (1, 2) and value_range < 100:
        return "small_counter/id"
    
    if size == 4 and any(v > 1000000 for v in values):
        # 大值→可能是 timestamp (Unix 时间戳)
        return "timestamp/sequence"
    
    # 检查整数组是否是等差数列 → 序列号
    if len(values) >= 3:
        diffs = [values[i+1] - values[i] for i in range(len(values) - 1)]
        if len(set(diffs)) <= 2 and diffs[0] > 0 and diffs[0] < 100:
            return "sequence_number"
    
    # 检查是否是 2 的幂 → 可能是 flag bitmask
    if all(v > 0 and (v & (v - 1)) == 0 for v in values[:10]):
        return "bitmask/flag"
    
    return f"data ({unique} unique, range {value_range})"


def field_entropy_profile(data_snapshots: List[bytes], field_size: int = 1) -> dict:
    """
    对整个消息做逐字节熵分析，生成字段类型地图
    
    返回：每个 offset 的熵值和一个推断的类型标签
    """
    max_len = max(len(s) for s in data_snapshots)
    profile = {}
    
    for offset in range(0, max_len - field_size + 1):
        bytes_at_offset = []
        for snap in data_snapshots:
            if offset + field_size <= len(snap):
                bytes_at_offset.append(snap[offset:offset + field_size])
        
        if not bytes_at_offset:
            continue
        
        unique = len(set(bytes_at_offset))
        entropy = math.log2(unique + 1) if unique > 1 else 0.0
        
        if offset + field_size > max_len - 4:
            # 可能校验和字段（最后几个字节）
            label = "checksum/signature" if entropy > 3.0 else "padding"
        elif entropy < 0.5:
            label = "constant/magic"
        elif entropy < 2.0:
            label = "type/len (low var)"
        elif entropy < 4.0:
            label = "field medium var"
        else:
            label = "payload/random"
        
        profile[offset] = {
            "entropy": round(entropy, 3),
            "unique_values": unique,
            "label": label,
        }
    
    return profile


def print_field_profile(profile: dict, max_offset: int):
    """ASCII 字段地图打印"""
    for offset in range(max_offset):
        if offset in profile:
            info = profile[offset]
            bar_len = int(info["entropy"] / 5 * 20)
            bar = "#" * bar_len + "." * (20 - bar_len)
            print(f"  [{offset:3d}] |{bar}| e={info['entropy']:.2f} {info['unique_values']:3d}  {info['label']}")
        else:
            print(f"  [{offset:3d}] |{'?'*20}|")
```

### 3.2 校验和/CRC 逆向

```python
# crc_reverse.py — 校验和算法逆向

def crc_differential_analysis(messages: List[bytes], checksum_pos: int) -> dict:
    """
    CRC 差分分析核心方法
    
    原理：如果修改一个 payload 字节，checksum 的变化是有规律的。
    通过分析变化模式，可以推断 CRC 多项式和初始值（CRC RevEng 工具的核心）
    
    步骤：
    1. 取一个消息做模板
    2. 逐字节修改 payload 中的一位
    3. 观察 checksum 的变化
    """
    results = {}
    
    if len(messages) < 2:
        return {"error": "Need >= 2 messages for differential analysis"}
    
    # 取两个只有 1 字节不同的消息
    base = messages[0]
    for other in messages[1:]:
        # 找不同的位置
        diff_positions = []
        for i in range(min(len(base), len(other))):
            if base[i] != other[i]:
                diff_positions.append(i)
        
        if len(diff_positions) == 1:
            pos = diff_positions[0]
            delta_payload = base[pos] ^ other[pos]
            delta_checksum = base[checksum_pos] ^ other[checksum_pos] if checksum_pos < len(base) else 0
            
            results[pos] = {
                "payload_delta": delta_payload,
                "checksum_delta": delta_checksum,
            }
    
    return results


def try_crc_reversing(checksum_bytes: bytes, data: bytes, crc_width: int = 16) -> dict:
    """
    尝试使用 CRC RevEng 自动逆向 CRC 参数
    
    对于 8/16/32-bit CRC，可以尝试所有常见多项式和初始值组合
    """
    # CRC 参数范围:
    #   width: 8, 16, 32
    #   poly: 0x1021 (CCITT), 0x8005, 0x04C11DB7 (CRC32), etc
    #   init: 0x0000, 0xFFFF, 0xFFFFFFFF
    #   refin: True/False (input reflection)
    #   refout: True/False (output reflection)
    #   xorout: 0x0000, 0xFFFF, etc
    
    crc_candidates = []
    crc_parameters = [
        {"width": 16, "poly": 0x1021, "init": 0xFFFF, "refin": False, "refout": False, "xorout": 0x0000, "name": "CRC-16/CCITT-FALSE"},
        {"width": 16, "poly": 0x8005, "init": 0x0000, "refin": True,  "refout": True,  "xorout": 0x0000, "name": "CRC-16/IBM"},
        {"width": 16, "poly": 0x1021, "init": 0xFFFF, "refin": True,  "refout": True,  "xorout": 0x0000, "name": "CRC-16/XMODEM"},
        {"width": 32, "poly": 0x04C11DB7, "init": 0xFFFFFFFF, "refin": True,  "refout": True,  "xorout": 0xFFFFFFFF, "name": "CRC-32"},
        {"width": 32, "poly": 0x1EDC6F41, "init": 0xFFFFFFFF, "refin": True,  "refout": True,  "xorout": 0xFFFFFFFF, "name": "CRC-32C (Castagnoli)"},
        {"width": 8,  "poly": 0x07, "init": 0x00, "refin": False, "refout": False, "xorout": 0x00, "name": "CRC-8"},
        {"width": 8,  "poly": 0x9B, "init": 0xFF, "refin": False, "refout": False, "xorout": 0x00, "name": "CRC-8/DVB-S2"},
    ]
    
    for params in crc_parameters:
        computed = crc_compute(data, params)
        if computed == int.from_bytes(checksum_bytes, 'big'):
            crc_candidates.append(params)
    
    return {"candidates": crc_candidates}


def crc_compute(data: bytes, params: dict) -> int:
    """
    通用 CRC 计算（使用位运算）
    """
    width = params["width"]
    poly = params["poly"]
    init = params["init"]
    refin = params["refin"]
    refout = params["refout"]
    xorout = params["xorout"]
    
    crc = init
    for byte in data:
        if refin:
            byte = reflect_byte(byte)
        crc ^= byte << (width - 8)
        for _ in range(8):
            if crc & (1 << (width - 1)):
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= (1 << width) - 1
    
    if refout:
        crc = reflect_bits(crc, width)
    crc ^= xorout
    
    return crc & ((1 << width) - 1)


def reflect_byte(b: int) -> int:
    """字节位反射"""
    result = 0
    for i in range(8):
        result |= ((b >> i) & 1) << (7 - i)
    return result


def reflect_bits(val: int, width: int) -> int:
    result = 0
    for i in range(width):
        result |= ((val >> i) & 1) << (width - 1 - i)
    return result


def brute_force_crc_algorithm(data_with_checksum: bytes, data_len: int, checksum_len: int) -> dict:
    """
    暴力搜索所有可能的 CRC 参数
    
    对较短的 checksum (1-2 字节)，可以用已知的数据-校验和对直接暴力
    """
    import struct
    
    data = data_with_checksum[:data_len]
    actual_crc = data_with_checksum[data_len:data_len + checksum_len]
    
    # 常用 CRC-16 poly
    poly_16_list = [0x1021, 0x8005, 0x1021, 0x0589, 0x3D65, 0xA001, 0x8BB7]
    init_list = [0x0000, 0xFFFF, 0x1D0F, 0x037E]
    
    for poly in poly_16_list:
        for init in init_list:
            for refin in [False, True]:
                for refout in [False, True]:
                    for xorout in [0x0000, 0xFFFF]:
                        params = {
                            "width": checksum_len * 8,
                            "poly": poly,
                            "init": init,
                            "refin": refin,
                            "refout": refout,
                            "xorout": xorout,
                        }
                        computed = crc_compute(data, params)
                        cmp_bytes = computed.to_bytes(checksum_len, 'big')
                        if cmp_bytes == actual_crc:
                            return params
    
    return {"error": "No standard CRC params matched"}
```

### 3.3 自定义校验和检测

```python
def detect_checksum_type(messages: List[bytes], checksum_pos: int, checksum_size: int) -> str:
    """
    区分不同类型的校验和
    
    特征:
    - XOR: 所有消息校验和 = 数据的 XOR → 简单的异或校验
    - SUM: 校验和 = 数据字节和 mod 256 → 累加和
    - CRC: 校验和看起来随机，但差分有规律
    - Adler: 类似 zlib 的 A + B*65536 模式
    - MD5/SHA: 16/20 字节，高熵，长
    """
    if checksum_size >= 16:
        return "hash (MD5/SHA)"
    
    # 对 XOR 校验
    xor_match = 0
    sum_match = 0
    crc_match = 0
    
    for msg in messages[:50]:
        if checksum_pos + checksum_size > len(msg):
            continue
        
        crc_val = int.from_bytes(msg[checksum_pos:checksum_pos + checksum_size], 'big')
        data = msg[:checksum_pos] + msg[checksum_pos + checksum_size:]
        
        # XOR 校验
        xor_sum = 0
        for b in data:
            xor_sum ^= b
        if checksum_size == 1:
            xor_sum &= 0xFF
        elif checksum_size == 2:
            xor_sum &= 0xFFFF
        if xor_sum == crc_val:
            xor_match += 1
        
        # 加法校验
        add_sum = sum(data)
        if checksum_size == 1:
            add_sum &= 0xFF
        elif checksum_size == 2:
            add_sum &= 0xFFFF
        if add_sum == crc_val:
            sum_match += 1
    
    total = len(messages)
    if xor_match / total > 0.9:
        return "XOR checksum"
    if sum_match / total > 0.9:
        return "ADDITIVE checksum"
    if max(xor_match, sum_match) / total < 0.2:
        return "CRC or unknown (looks random)"
    
    return "unknown"
```

## 4. Phase 3: 语义依赖映射

```python
# field_dependency.py — 字段依赖关系推断

def map_field_dependencies(message_pairs: List[Tuple[bytes, bytes]]) -> dict:
    """
    建立请求-回复对的字段依赖映射
    
    方法：
    1. 找到每个请求字段对应的回复字段
    2. 检查字段间是否有恒等、偏移、哈希等关系
    """
    dependencies = {}
    
    for req, resp in message_pairs[:100]:
        # 检查请求中的长度字段是否对应回复中的数据量
        pass
    
    return dependencies


def detect_id_echo(pairs: List[Tuple[bytes, bytes]]) -> List[Tuple[int, int]]:
    """
    检测请求中的 ID/序列号是否在回复中原样返回
    
    这是最常见的协议模式：req 放一个 seq_id，resp 原样带回
    """
    echoes = []
    for req_offset in range(0, min(len(p) for p in [pr[0] for pr in pairs[:10]])):
        for resp_offset in range(0, min(len(p) for p in [pr[1] for pr in pairs[:10]])):
            match_count = 0
            for req, resp in pairs:
                if req[req_offset:req_offset+4] == resp[resp_offset:resp_offset+4]:
                    match_count += 1
            
            if match_count >= len(pairs) * 0.8:
                echoes.append((req_offset, resp_offset))
    
    return echoes
```

## 5. Phase 4: 状态机推断

```python
# state_machine.py — 协议状态机推断

def infer_sequence_numbers(messages: List[bytes], offset: int, size: int) -> List[int]:
    """
    提取可能的序列号
    
    序列号在正常交互中应单调递增（可能回绕）
    """
    seqs = []
    for msg in messages:
        if offset + size <= len(msg):
            seq = int.from_bytes(msg[offset:offset+size], 'big')
            seqs.append(seq)
    return seqs


def infer_state_machine(conversation: List[Tuple[str, bytes]]) -> dict:
    """
    从对话历史推断状态机
    
    conversation: [("C->S", data), ("S->C", data), ...]
    
    方法：
    1. 提取每个消息的 type/cmd 字段
    2. 分析哪些 cmd 可以跟随哪些 cmd
    3. 构建状态转换图
    """
    transitions = {}
    states_seen = set()
    
    for i in range(len(conversation) - 1):
        current_type = _extract_type(conversation[i][1])
        next_type = _extract_type(conversation[i + 1][1])
        
        if current_type not in transitions:
            transitions[current_type] = {}
        if next_type not in transitions[current_type]:
            transitions[current_type][next_type] = 0
        transitions[current_type][next_type] += 1
        
        states_seen.add(current_type)
        states_seen.add(next_type)
    
    return {
        "states": sorted(states_seen),
        "transitions": transitions,
        "graphviz": _to_graphviz(transitions),
    }


def _extract_type(msg: bytes, type_offset: int = 0, type_size: int = 1) -> int:
    """提取类型字段（假设第一个字节是 type）"""
    if len(msg) >= type_offset + type_size:
        return int.from_bytes(msg[type_offset:type_offset + type_size], 'big')
    return -1


def _to_graphviz(transitions: dict) -> str:
    """生成 Graphviz DOT 格式状态图"""
    lines = ["digraph ProtocolSM {"]
    for src, targets in transitions.items():
        for dst, count in targets.items():
            lines.append(f'  "{src}" -> "{dst}" [label="{count}"];')
    lines.append("}")
    return "\n".join(lines)
```

## 6. 差分分析工具

```python
# differential_analysis.py — 修改一个字段观察响应变化

def make_single_field_mutation(msg: bytes, offset: int, size: int, delta: int = 1) -> bytes:
    """生成单个字段变异的消息"""
    mut = bytearray(msg)
    old = int.from_bytes(msg[offset:offset+size], 'big')
    new = (old + delta) & ((1 << (size * 8)) - 1)
    mut[offset:offset+size] = new.to_bytes(size, 'big')
    return bytes(mut)


def diff_response_pair(original_response: bytes, mutated_response: bytes) -> List[dict]:
    """
    比较两个响应，找出差异

    用于确定哪个字段'触发'了响应的变化
    """
    diffs = []
    min_len = min(len(original_response), len(mutated_response))
    
    for i in range(min_len):
        if original_response[i] != mutated_response[i]:
            diffs.append({
                "offset": i,
                "original": original_response[i],
                "mutated": mutated_response[i],
                "delta": mutated_response[i] - original_response[i],
            })
    
    return diffs
```

## 7. 协议模糊测试

```python
# protocol_fuzzer.py — 针对未知协议的结构感知模糊测试

def structural_fuzzer(base_msg: bytes, field_map: dict) -> List[bytes]:
    """
    基于半已知结构的协议模糊测试
    
    field_map: {"length": (pos, size), "type": (pos, size), ...}
    """
    mutations = []
    
    # 1. 类型字段遍历
    if "type" in field_map:
        pos, size = field_map["type"]
        for type_val in range(1, 256):
            mut = bytearray(base_msg)
            mut[pos:pos+size] = type_val.to_bytes(size, 'big')
            mutations.append(bytes(mut))
    
    # 2. 长度字段变形
    if "length" in field_map:
        pos, size = field_map["length"]
        for len_mod in [-1, 0, 1, 255, 65535]:
            mut = bytearray(base_msg)
            current_len = int.from_bytes(mut[pos:pos+size], 'big')
            new_len = max(0, current_len + len_mod)
            mut[pos:pos+size] = new_len.to_bytes(size, 'big')
            mutations.append(bytes(mut))
    
    # 3. 随机变异 payload
    import random
    for _ in range(20):
        mut = bytearray(base_msg)
        payload_start = max(field_map.get(k)[0] + field_map.get(k)[1] for k in ["type", "length"] if k in field_map)
        if payload_start < len(mut):
            pos = random.randint(payload_start, len(mut) - 1)
            mut[pos] = random.randint(0, 255)
        mutations.append(bytes(mut))
    
    return mutations
```

## 8. 整合分析管线

```python
#!/usr/bin/env python3
# protocol_analyzer.py — 完整协议分析管线
import json


def analyze_protocol(pcap_file: str) -> dict:
    """
    一键分析未知协议
    
    从 pcap 导入 → 定界 → 字段分析 → 校验和 → 状态机
    """
    report = {
        "file": pcap_file,
        "message_boundaries": [],
        "field_profile": {},
        "checksum_type": None,
        "state_machine": None,
    }
    
    # Step 1: 加载流量（需要 scapy）
    # from scapy.all import rdpcap
    # packets = rdpcap(pcap_file)
    # tcp_stream = extract_tcp_stream(packets)
    
    # Step 2: 消息边界
    # boundaries = find_message_boundaries(tcp_stream)
    # magic = detect_magic_prefix(tcp_stream)
    
    # Step 3: 字段分析
    # messages = [tcp_stream[b:boundaries[i+1]] ...]
    # field_types = field_entropy_profile(messages)
    # checksum = detect_checksum_type(messages, -2, 2)
    
    # Step 4: 状态机
    # sm = infer_state_machine(conversation)
    
    return report


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python protocol_analyzer.py <pcap_file>")
        sys.exit(1)
    
    report = analyze_protocol(sys.argv[1])
    print(json.dumps(report, indent=2))
```

## 9. 工具链推荐

```bash
# CRC RevEng — 自动逆向 CRC 参数
# https://github.com/abbrev/reveng
reveng -m <data_hex> <crc_hex>

# Wireshark 自定义协议解析器（Lua 插件编写指南）
# 查看: https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html

# Scapy 自定义协议层
# from scapy.packet import Packet, bind_layers
# from scapy.fields import ...

# binwalk + entropy 分析
binwalk --entropy unknown.bin

# 010 Editor + 自定义模板编写
```

## 10. 案例实战

### 案例 1: IoT 设备协议

```
场景：某智能灯使用 UDP 自定义协议
抓包看到：AA BB CC DD ... 开头，变化很小

分析：
1. Magic: AA BB → 固定前缀
2. CC → 命令类型 (01=开关, 02=亮度, 03=颜色)
3. DD → 序列号（每次 +1）
4. 最后 2 字节 → XOR 校验
```

### 案例 2: 游戏协议差分

```python
"""
场景：某 MMO 游戏使用自定义 TCP 协议
分析途径：
1. 熵分析显示消息头 12 字节低熵，之后高熵（加密）
2. 前 2 字节: 长度字段（大端，14-289）
3. 字节 2-3: 指令码（已知 0x01=移动, 0x02=聊天, 0x03=攻击）
4. 字节 4-7: 用户 ID（5-6 字节在 2 个消息中相同→会话标识）
5. 最后 2 字节: CRC-16/CCITT 校验
"""
```

## 11. 参考

- Protocol Informatics Project (PI) — 协议逆向工程综述
- Comparetti et al., "Prospex: Specification Inference for Malicious Protocol Implementations" (CCS 2008)
- Cui et al., "RolePlayer: Automatically Replaying Malicious Network Attacks" (USENIX Security 2006)
- CRC RevEng: https://reveng.sourceforge.io/
- Scapy 文档: https://scapy.readthedocs.io/
- Wireshark Lua 脚本示例: https://wiki.wireshark.org/Lua/
- CVE-2019-9504: Bluetooth ZeroMQ 协议分析漏洞

## MCP 工具映射

| 分析步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 协议逆向知识检索 | `kb_router` | 按协议特征（魔数、熵值）搜索知识库 |
| 知识库文件阅读 | `kb_read_file` | 阅读匹配的协议分析方案 |
| PCAP 中 PE 分析 | `triage_pe` | 分析 PCAP 中提取的 PE 样本（如果协议传输了恶意软件） |
| DiE 扫描 | `die_scan` | 扫描提取的二进制段识别算法/类型 |
| Ghidra 深度分析 | `ghidra_headless_analyze` | 分析实现该协议的二进制文件 |
| Ghidra 函数聚焦 | `ghidra_summary_call_focus` | 聚焦协议处理相关函数 |
| 分析工具安装 | `python_re_tool_install` | 安装 scapy、crcmod 等协议分析库 |

## 证据与验证闭环

- 固定输入样本、SHA256、工具版本和全部参数，先保存未处理 baseline。
- 每个假设至少绑定一个可观察量：已知明密文对、协议字段、状态转移、时间分布、偏移或重放输出。
- 用独立脚本重放核心变换，并以断言、输出哈希或逐字段 diff 验证，不以“看起来合理”作为结论。
- 原始抓包/样本进入 `exports/general/`，派生文件与原件分离并记录转换链。
