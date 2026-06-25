# Protobuf / FlatBuffers 无 Schema 逆向

> 面对一段未知的 Protobuf 或 FlatBuffers 数据且无法获取 `.proto` 或 `.fbs` 文件时，如何从原始字节解码、推断字段类型和结构层次？本文提供从原始字节到完整 schema 推断的完整方法论。

## 1. Protobuf 二进制格式基础

### 1.1 Wire Types

Protobuf 的每个字段由一个 `(field_number, wire_type, payload)` 三元组编码：

| Wire Type | ID | 编码方式 | 典型类型 |
|-----------|----|---------|---------|
| Varint | 0 | 变长整数 (LEB128) | int32, int64, uint32, bool, enum, sint32 |
| Fixed64 | 1 | 8 字节固定长度 (小端) | fixed64, sfixed64, double |
| Length-delimited | 2 | varint 长度 + 数据 | string, bytes, embedded message, packed repeated |
| Fixed32 | 5 | 4 字节固定长度 (小端) | fixed32, sfixed32, float |

Wire type 3 (Start group) 和 4 (End group) 已弃用。

### 1.2 关键编码规则

```
字段头 = (field_number << 3) | wire_type
       ^^^^^^^^^^^^^^   ^^^^^^^^
       高位 = 字段序号    低 3 位 = wire type
```

Varint 编码 (LEB128)：每个字节的高位表示是否继续，低 7 位是数据。

```python
# protobuf_wire_decoder.py — 原始 Protobuf 解码器（无需 .proto）
from typing import List, Tuple, Any


def _decode_varint(data: bytes, offset: int) -> Tuple[int, int]:
    """
    解码 Protobuf varint
    
    返回: (值, 消耗的字节数)
    """
    value = 0
    shift = 0
    i = offset
    while i < len(data):
        byte = data[i]
        value |= (byte & 0x7F) << shift
        shift += 7
        i += 1
        if not (byte & 0x80):
            break
    return value, i - offset


def _decode_signed_varint(value: int) -> int:
    """
    Protobuf 的 sint32/sint64 使用 ZigZag 编码
    
    ZigZag: n -> (n << 1) ^ (n >> 31)  [32-bit]
            0 -> 0, -1 -> 1, 1 -> 2, -2 -> 3, ...
    """
    return (value >> 1) ^ -(value & 1)


def decode_protobuf_field(data: bytes, offset: int) -> dict:
    """
    解码单个 Protobuf 字段
    
    Returns: 字段信息或 None（如果偏移无效）
    """
    if offset >= len(data):
        return None
    
    # 读取字段头
    header, consumed = _decode_varint(data, offset)
    offset += consumed
    
    field_number = header >> 3
    wire_type = header & 0x7
    
    result = {
        "field_number": field_number,
        "wire_type": wire_type,
        "start_offset": offset - consumed,
    }
    
    if wire_type == 0:  # Varint
        value, consumed = _decode_varint(data, offset)
        result["type"] = "varint"
        result["value"] = value
        result["value_hex"] = hex(value)
        result["signed"] = _decode_signed_varint(value)
        result["size"] = consumed + (offset - result["start_offset"])
        
    elif wire_type == 1:  # Fixed64
        if offset + 8 <= len(data):
            val = int.from_bytes(data[offset:offset+8], 'little')
            import struct
            result["type"] = "fixed64"
            result["value"] = val
            result["value_hex"] = f"0x{val:016x}"
            result["as_double"] = struct.unpack('<d', data[offset:offset+8])[0]
            result["size"] = 8 + (offset - result["start_offset"])
        else:
            result["type"] = "fixed64_truncated"
            result["size"] = len(data) - result["start_offset"]
            
    elif wire_type == 2:  # Length-delimited
        length, consumed = _decode_varint(data, offset)
        offset += consumed
        if offset + length <= len(data):
            payload = data[offset:offset+length]
            result["type"] = "length_delimited"
            result["length"] = length
            result["payload"] = payload
            
            # 尝试解码 payload 中的文本
            try:
                result["as_string"] = payload.decode('utf-8')
            except:
                pass
            
            # 尝试子消息解码
            try:
                sub_fields = decode_protobuf_message(payload)
                if sub_fields:
                    result["sub_fields"] = sub_fields
            except:
                pass
            
            result["size"] = length + consumed + (offset - result["start_offset"])
        else:
            result["type"] = "length_truncated"
            result["size"] = len(data) - result["start_offset"]
            
    elif wire_type == 5:  # Fixed32
        if offset + 4 <= len(data):
            val = int.from_bytes(data[offset:offset+4], 'little')
            import struct
            result["type"] = "fixed32"
            result["value"] = val
            result["value_hex"] = f"0x{val:08x}"
            result["as_float"] = struct.unpack('<f', data[offset:offset+4])[0]
            result["size"] = 4 + (offset - result["start_offset"])
        else:
            result["type"] = "fixed32_truncated"
            result["size"] = len(data) - result["start_offset"]
    
    return result


def decode_protobuf_message(data: bytes, max_fields: int = 128) -> List[dict]:
    """
    解码完整的 Protobuf 消息（递归）
    
    返回字段列表，包含嵌入的子消息
    """
    fields = []
    offset = 0
    field_count = 0
    
    while offset < len(data) and field_count < max_fields:
        field = decode_protobuf_field(data, offset)
        if field is None:
            break
        fields.append(field)
        offset += field["size"]
        field_count += 1
        
        # 防无限循环
        if field["size"] == 0:
            break
    
    return fields
```

## 2. 无 Schema 解码实战

### 2.1 从原始字节解码

```python
# protobuf_no_schema.py — 无 schema 解码器

def analyze_protobuf_blob(data: bytes) -> dict:
    """
    完全无 schema 的 Protobuf 分析
    
    输出：
    - 字段列表（类型推断）
    - 结构层次（嵌入消息）
    - 枚举候选
    - repeated 字段检测
    """
    fields = decode_protobuf_message(data)
    
    # 统计字段出现频次
    field_counts = {}
    for f in fields:
        fn = f["field_number"]
        field_counts[fn] = field_counts.get(fn, 0) + 1
    
    # repeated 字段检测：同一 field_number 出现多次
    repeated_fields = [fn for fn, count in field_counts.items() if count > 1]
    
    return {
        "total_fields": len(fields),
        "field_numbers_used": sorted(field_counts.keys()),
        "repeated_fields": repeated_fields,
        "fields": fields,
    }


def protobuf_field_type_table() -> str:
    """
    从解码结果生成 field -> type 对照表
    类似 .proto 文件的骨架
    """
    return """
    // 推断得到的 .proto 骨架（基于实际解码）
    message DecodedMessage {
        // field 1: varint (values: [1, 2, 3]) -> enum?
        // field 2: length_delimited (string: "hello") -> string
        // field 3: fixed32 (float: 3.14) -> float
        // field 4: length_delimited (sub_message with 3 fields) -> embedded message
        // field 2 appears 5 times -> repeated string
    }
    """
```

### 2.2 深度类型推断

```python
# field_type_classifier.py — Protobuf 字段类型自动分类

def classify_varint_field(values: List[int]) -> str:
    """
    从 varint 字段的取值分布推断具体类型
    """
    if not values:
        return "unknown"
    
    min_v, max_v = min(values), max(values)
    
    # bool 检测：全部是 0 或 1
    if all(v in (0, 1) for v in values):
        return "bool"
    
    # enum 检测：少量离散值
    unique = len(set(values))
    if unique <= 15 and max_v < 256:
        return f"enum (values={sorted(set(values))})"
    
    # 检查是否是 ZigZag 编码（负数值）
    zigzag = all(v >= 0 for v in values)
    zigzag_decoded = [_decode_signed_varint(v) for v in values]
    has_negative = any(v < 0 for v in zigzag_decoded)
    
    if has_negative and zigzag:
        return "sint32"
    
    # 数字范围猜测
    if max_v < 256:
        return "uint32 (small range)"
    elif max_v < 65536:
        return "uint32"
    elif max_v > 2**31:
        return "int64/uint64"
    else:
        return "int32/uint32"


def classify_fixed32_field(values: List[int]) -> str:
    """
    判断 fixed32 字段是 float 还是 int
    """
    import struct
    
    # 尝试解释为 float
    float_like = []
    for v in values[:20]:
        f = struct.unpack('<f', struct.pack('<I', v & 0xFFFFFFFF))[0]
        # 合理的 float 范围
        if 0.0 <= abs(f) < 1e20 and not (f != f):  # not NaN
            float_like.append(True)
        else:
            float_like.append(False)
    
    if sum(float_like) >= len(float_like) * 0.8:
        return "float"
    
    return "fixed32 (int)"


def classify_fixed64_field(values: List[int]) -> str:
    """
    判断 fixed64 字段是 double 还是 int
    """
    import struct
    
    double_like = []
    for v in values[:20]:
        d = struct.unpack('<d', struct.pack('<Q', v))[0]
        if 0.0 <= abs(d) < 1e300 and not (d != d):
            double_like.append(True)
        else:
            double_like.append(False)
    
    if sum(double_like) >= len(double_like) * 0.8:
        return "double"
    
    # 检查是否是 Unix 时间戳
    if 1000000000 < min(values) < 2000000000:
        return "fixed64 (timestamp)"
    
    if any(v >> 32 == 0 for v in values[:10]):
        return "fixed64 (upper 32 zero, likely int)"
    
    return "sfixed64"


def classify_length_field(payloads: List[bytes]) -> str:
    """
    从 length-delimited 字段的 payload 推断类型
    """
    if not payloads:
        return "unknown"
    
    # 尝试 UTF-8 解码
    string_scores = []
    for p in payloads[:20]:
        try:
            p.decode('utf-8')
            string_scores.append(True)
        except:
            string_scores.append(False)
    
    if sum(string_scores) >= len(string_scores) * 0.8:
        # 进一步：是正常文本还是 base64?
        import base64
        b64_scores = []
        for p in payloads[:20]:
            try:
                base64.b64decode(p)
                b64_scores.append(True)
            except:
                b64_scores.append(False)
        
        if sum(b64_scores) >= len(b64_scores) * 0.8:
            return "bytes (base64 encoded)"
        return "string"
    
    # 尝试解码为子消息
    sub_field_counts = []
    for p in payloads[:10]:
        try:
            fields = decode_protobuf_message(p)
            sub_field_counts.append(len(fields))
        except:
            sub_field_counts.append(0)
    
    if max(sub_field_counts) >= 2:
        avg_sub = sum(sub_field_counts) / len(sub_field_counts)
        return f"embedded_message (avg {avg_sub:.0f} sub-fields)"
    
    # 固定长度 -> bytes
    return "bytes"
```

### 2.3 Protobuf 消息可视化

```python
def print_protobuf_tree(fields: List[dict], indent: int = 0) -> str:
    """
    以树状结构打印 Protobuf 消息
    """
    prefix = "  " * indent
    lines = []
    
    for f in fields:
        fn = f["field_number"]
        wt = f["wire_type"]
        
        if f["type"] == "varint":
            type_hint = classify_varint_field([f["value"]])
            lines.append(f"{prefix}field {fn} [varint]: {f['value']}  ({type_hint})")
            
        elif f["type"] == "fixed64":
            type_hint = classify_fixed64_field([f["value"]])
            if "as_double" in f:
                lines.append(f"{prefix}field {fn} [fixed64]: {f['as_double']}  ({type_hint})")
            else:
                lines.append(f"{prefix}field {fn} [fixed64]: 0x{f['value']:016x}  ({type_hint})")
                
        elif f["type"] == "fixed32":
            type_hint = classify_fixed32_field([f["value"]])
            if "as_float" in f:
                lines.append(f"{prefix}field {fn} [fixed32]: {f['as_float']}  ({type_hint})")
            else:
                lines.append(f"{prefix}field {fn} [fixed32]: {f['value']}  ({type_hint})")
                
        elif f["type"] == "length_delimited":
            payload = f.get("payload", b"")
            if "as_string" in f:
                lines.append(f"{prefix}field {fn} [string]: \"{f['as_string']}\"")
            elif "sub_fields" in f:
                lines.append(f"{prefix}field {fn} [message]:")
                lines.append(print_protobuf_tree(f["sub_fields"], indent + 2))
            else:
                lines.append(f"{prefix}field {fn} [bytes]: {payload[:32].hex()}...")
    
    return "\n".join(lines)


def generate_proto_skeleton(fields: List[dict]) -> str:
    """
    从解码结果生成 .proto 文件骨架
    """
    type_map = {
        "varint": "int32",
        "fixed64": "fixed64",
        "fixed32": "fixed32",
        "length_delimited_string": "string",
        "length_delimited_message": "SomeMessage",
        "length_delimited_bytes": "bytes",
    }
    
    lines = ['syntax = "proto3";', '', 'message DecodedMessage {']
    duplicates = {}
    
    for f in fields:
        fn = f["field_number"]
        duplicates[fn] = duplicates.get(fn, 0) + 1
        is_repeated = duplicates[fn] > 1
        
        if f["type"] == "varint":
            pb_type = "int32"
        elif f["type"] == "fixed64":
            pb_type = "fixed64"
        elif f["type"] == "fixed32":
            pb_type = "fixed32"
        elif f["type"] == "length_delimited":
            if "as_string" in f:
                pb_type = "string"
            elif "sub_fields" in f:
                pb_type = "EmbeddedMessage"
            else:
                pb_type = "bytes"
        
        label = "repeated " if is_repeated else ""
        lines.append(f"  {label}{pb_type} field_{fn} = {fn};")
    
    lines.append('}')
    return "\n".join(lines)
```

## 3. 工具链使用

### 3.1 protobuf-inspector

```bash
# 安装
pip install protobuf-inspector

# 使用
protobuf_inspector < raw_pb_data.bin
# 自动分析字段编号、类型、值

# 配合 pcap:
tshark -r capture.pcap -Y "http" -T fields -e http.file_data | \
  while read line; do echo "$line" | base64 -d | protobuf_inspector; done
```

### 3.2 protoscope

```bash
# 安装: Go 语言
go install github.com/protocolbuffers/protoscope/cmd/protoscope@latest

# 使用: 精准显示每个 wire byte
protoscope file.pb
# 输出:
# 1: VARINT 42
# 2: LENDEL "hello world"
# 3: 1: VARINT 100
#    2: LENDEL "nested"

# 高级用法：带偏移显示
protoscope -annotate file.pb
```

### 3.3 blackboxprotobuf

```python
# blackboxprotobuf — 自动 schema 推断与修改
import blackboxprotobuf

# 自动推断 schema
with open("message.bin", "rb") as f:
    data = f.read()

# 解码（自动推断类型）
deserialized, typedef = blackboxprotobuf.protobuf_to_json(data)

# typedef 包含了推断的 schema
print(typedef)
# {'1': {'type': 'int', 'name': ''}, '2': {'type': 'str', 'name': ''}}

# 修改字段值
deserialized['1'] = 9999
deserialized['3'] = "injected"

# 重新编码
new_data = blackboxprotobuf.protobuf_from_json(deserialized, typedef)

# 输出 schema 用于后续修改
print(blackboxprotobuf.generate_schema(typedef))
```

### 3.4 自定义解码器集成

```python
#!/usr/bin/env python3
# protobuf_decoder_cli.py — 命令行解码器

import sys
import json


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python protobuf_decoder_cli.py <binary_file>")
        print("  python protobuf_decoder_cli.py -s <binary_file>  # show skeleton")
        print("  python protobuf_decoder_cli.py -j <binary_file>  # JSON output")
        sys.exit(1)
    
    with open(sys.argv[-1], "rb") as f:
        data = f.read()
    
    fields = decode_protobuf_message(data)
    
    if "-s" in sys.argv:
        print(generate_proto_skeleton(fields))
    elif "-j" in sys.argv:
        print(json.dumps([f for f in fields if "payload" not in f or isinstance(f.get("payload"), str)], indent=2))
    else:
        print(print_protobuf_tree(fields))


if __name__ == "__main__":
    main()
```

## 4. FlatBuffers 逆向

### 4.1 FlatBuffers 结构总览

FlatBuffers 没有运行时解包开销，序列化后直接是内存对齐的结构体：

```
一个 FlatBuffers 二进制由以下组成：
  ┌─────────────┐
  │ UOffsetT     │ ← 指向根 table 的偏移（从文件尾开始）
  │ ...          │
  │ vtable(s)    │ ← 虚表：描述哪些字段存在、偏移
  │ table data   │ ← 实际字段值
  │ uoffset 数组 │ ← 字符串偏移表
  │ 字符串数据    │
  └─────────────┘
```

```python
# flatbuffers_reverse.py — FlatBuffers 无 schema 逆向

import struct
from typing import List, Tuple, Optional


UOFFSET_SIZE = 4  # FlatBuffers 默认 4 字节偏移


def read_flatbuffers_root(data: bytes) -> dict:
    """
    从 FlatBuffers 二进制中提取根 table
    
    结构：
    - 最后 4 字节: 根 table 的偏移（相对于末尾）
    - 根 table 结构: {vtable_offset (2), padding (2), field_data...}
    - vtable: {table_size (2), vtable_size (2), field_offsets...}
    """
    if len(data) < 4:
        return {"error": "too small"}
    
    # 读取根偏移量
    root_offset = struct.unpack_from('<I', data, len(data) - 4)[0]
    root_abs = len(data) - 4 - root_offset
    
    if root_abs < 0 or root_abs >= len(data):
        return {"error": "invalid root offset"}
    
    # 读取 table header
    # 前 2 字节: vtable 的相对偏移（负值，相对于 table 起始）
    vtable_rel = struct.unpack_from('<h', data, root_abs)[0]
    vtable_abs = root_abs - vtable_rel  # vtable 在 table 之前
    
    if vtable_abs < 0 or vtable_abs >= len(data):
        return {"error": "invalid vtable offset"}
    
    # 读取 vtable
    table_size = struct.unpack_from('<H', data, vtable_abs)[0]
    vtable_size = struct.unpack_from('<H', data, vtable_abs + 2)[0]
    
    # vtable_size >= 4 (至少 table_size + vtable_size)
    if vtable_size < 4 or vtable_size > 256:
        return {"error": "invalid vtable size"}
    
    if table_size > 4096:
        return {"error": f"table too large: {table_size}"}
    
    # 解析每个字段
    fields = {}
    vtable_entries = (vtable_size - 4) // 2
    
    for i in range(vtable_entries):
        field_offset_raw = struct.unpack_from('<H', data, vtable_abs + 4 + i * 2)[0]
        field_num = i  # FlatBuffers 字段编号从 0 开始（实际 schema 从 1 开始？看实现）
        
        if field_offset_raw == 0:
            # 字段不存在
            continue
        
        field_abs = root_abs + field_offset_raw
        if field_abs >= len(data):
            continue
        
        # 类型判断需要查看后续字节
        # FlatBuffers 不存储类型 → 需要从使用模式推断
        fields[field_num] = {
            "vtable_offset": field_offset_raw,
            "absolute_offset": field_abs,
            "possible_types": ["byte", "bool", "enum", "offset"],
        }
    
    return {
        "root_offset": root_offset,
        "root_abs": root_abs,
        "table_size": table_size,
        "vtable_size": vtable_size,
        "field_count": len(fields),
        "fields": fields,
    }


def find_all_vtables(data: bytes) -> List[dict]:
    """
    扫描 FlatBuffers 中的所有 vtable
    
    方法：vtable 通常在 table 之前、结构体之后。
    由于 vtable 以 table_size + vtable_size 开头，
    且这两个值通常在 256 以内，可以作为初筛。
    """
    vtables = []
    
    for i in range(0, len(data) - 4, 2):  # vtable 至少 4 字节
        table_size = struct.unpack_from('<H', data, i)[0]
        vtable_size = struct.unpack_from('<H', data, i + 2)[0]
        
        # 合理性检查
        if table_size < 4 or table_size > 4096:
            continue
        if vtable_size < 4 or vtable_size > 256:
            continue
        if vtable_size > table_size:
            continue
        if (vtable_size - 4) % 2 != 0:  # 偶数个字段偏移
            continue
        
        # 检查字段偏移是否都指向合理范围
        valid = True
        for j in range(4, vtable_size, 2):
            field_off = struct.unpack_from('<H', data, i + j)[0]
            if field_off > table_size:
                valid = False
                break
        
        if valid:
            vtables.append({
                "offset": i,
                "table_size": table_size,
                "vtable_size": vtable_size,
                "fields": (vtable_size - 4) // 2,
            })
    
    return vtables


def analyze_flatbuffer_offsets(data: bytes) -> dict:
    """
    分析 FlatBuffers 中的偏移表
    
    FlatBuffers 用 UOffsetT (4 bytes) 表示偏移，
    偏移从当前字段位置向后（正向偏移）。
    字符串/向量通过偏移引用。
    """
    offsets_found = []
    
    for i in range(0, len(data) - 4, 4):
        potential_offset = struct.unpack_from('<I', data, i)[0]
        
        # 偏移应该在合理范围内
        if 4 <= potential_offset < len(data) * 2:
            target = i + potential_offset
            if 0 <= target < len(data):
                offsets_found.append({
                    "source": i,
                    "offset": potential_offset,
                    "target": target,
                })
    
    return {
        "total_offsets": len(offsets_found),
        "offsets": offsets_found[:100],
    }
```

### 4.2 FlatBuffers schema 推断

```python
def infer_flatbuffers_schema(sample_messages: List[bytes]) -> dict:
    """
    从多个 FlatBuffers 消息样本推断 schema 结构
    
    方法：
    1. 对每个样本读根 table
    2. 对比不同样本中相同 field_number 的数据类型
    3. 推断类型（byte/float/string/vector/sub-table）
    """
    schemas = {}
    
    for msg_idx, msg in enumerate(sample_messages):
        root = read_flatbuffers_root(msg)
        if "fields" not in root:
            continue
        
        for field_num, field_info in root["fields"].items():
            if field_num not in schemas:
                schemas[field_num] = {"types_seen": set(), "values": []}
            
            abs_off = field_info["absolute_offset"]
            if abs_off + 4 <= len(msg):
                # 读取字节模式
                val = struct.unpack_from('<I', msg, abs_off)[0]
                schemas[field_num]["values"].append(val)
    
    # 类型推断
    for fn, info in schemas.items():
        vals = info["values"]
        if not vals:
            continue
        
        # 检查是否是标量类型
        if len(set(vals)) <= 2 and all(v in (0, 1) for v in vals):
            info["inferred_type"] = "bool"
        elif all(isinstance(v, (int, float)) and 0 <= v < 256 for v in vals):
            info["inferred_type"] = "byte/ubyte"
        elif all(v > 0 and v < len(sample_messages[0]) for v in vals[:10]):
            info["inferred_type"] = "uoffset (reference)"
        else:
            info["inferred_type"] = "int/float (check byte pattern)"
    
    return schemas


def flatbuffers_to_fbs_skeleton(sample: bytes) -> str:
    """
    从样本生成 .fbs 骨架
    """
    root = read_flatbuffers_root(sample)
    
    lines = ['// Generated FlatBuffers schema (inferred)', 'table RootTable {']
    
    if "fields" in root:
        for field_num, info in root["fields"].items():
            lines.append(f'  field_{field_num}: int;  // offset={info["vtable_offset"]}')
    
    lines.append('}')
    lines.append(f'root_type RootTable;')
    
    return "\n".join(lines)
```

## 5. gRPC 无 proto 服务发现

### 5.1 gRPC 反射 API

gRPC 本身有反射 API（如果服务端开启了）：

```bash
# grpcurl — gRPC 命令行工具
# 列出所有服务
grpcurl -plaintext localhost:50051 list

# 列出服务的所有方法
grpcurl -plaintext localhost:50051 list my.package.MyService

# 获取方法请求/响应的 proto 描述
grpcurl -plaintext localhost:50051 describe my.package.MyService.MyMethod

# 直接调用
grpcurl -plaintext -d '{"id": 123}' localhost:50051 my.package.MyService.GetUser

# 无 proto 文件调用（使用反射）
grpcurl -plaintext -protoset-out service.protoset localhost:50051 describe
```

### 5.2 无反射时的暴力方法

```python
# grpc_bruteforce.py — 无 proto 时推断 gRPC 服务

import struct


def parse_grpc_http2_frame(data: bytes) -> dict:
    """
    解析 gRPC 的 HTTP/2 Data frame
    
    gRPC 数据负载格式：
      [compression_flag (1)] [message_length (4)] [message (Protobuf)]
    """
    if len(data) < 5:
        return {"error": "too short for gRPC frame header"}
    
    flag = data[0]
    msg_len = struct.unpack_from('>I', data, 1)[0]  # big-endian!
    
    if flag != 0:
        compression = "gzip" if flag == 1 else f"unknown({flag})"
    else:
        compression = "none"
    
    msg_start = 5
    if msg_start + msg_len > len(data):
        return {"error": "truncated message"}
    
    protobuf_data = data[msg_start:msg_start + msg_len]
    fields = decode_protobuf_message(protobuf_data)
    
    return {
        "compression": compression,
        "message_length": msg_len,
        "protobuf_fields": fields,
        "text": print_protobuf_tree(fields),
    }


def enumerate_grpc_methods_by_pattern(pcaps: List[bytes]) -> set:
    """
    从 gRPC 流量中提取可能的 service/method 路径
    
    gRPC 路径在 HTTP/2 :path header 中：
    /package.ServiceName/MethodName
    """
    import re
    methods = set()
    
    for pcap_data in pcaps:
        # 从 HTTP/2 HEADERS 帧中寻找路径
        found = re.findall(rb'/([A-Za-z0-9_.]+/[A-Za-z0-9_]+)', pcap_data)
        for f in found:
            methods.add(f.decode())
    
    return methods
```

### 5.3 gRPC 请求重放

```python
# grpc_replay.py — gRPC 请求重放与修改

def grpc_replay_with_modifications(base_request: bytes, modifications: dict) -> bytes:
    """
    对 gRPC 请求做字段修改后重放
    
    modifications: {field_number: new_value}
    """
    # 1. 解码请求
    fields = decode_protobuf_message(base_request)
    
    # 2. 修改字段
    modified = list(fields)
    for i, f in enumerate(modified):
        if f["field_number"] in modifications:
            if f["type"] == "varint":
                modified[i] = f  # 实际需要重新编码
    
    # 3. 重新编码（需要完整的 protobuf 序列化器）
    return b""


class GrpcMethodExplorer:
    """gRPC 方法自动探索"""
    
    def __init__(self, target: str):
        self.target = target
        self.discovered_methods = {}
    
    def discover(self):
        """尝试通过反射发现方法"""
        import subprocess
        result = subprocess.run(
            ["grpcurl", "-plaintext", self.target, "list"],
            capture_output=True, text=True, timeout=10
        )
        services = result.stdout.strip().split("\n")
        
        for svc in services:
            svc = svc.strip()
            if not svc:
                continue
            methods_result = subprocess.run(
                ["grpcurl", "-plaintext", self.target, "list", svc],
                capture_output=True, text=True, timeout=10
            )
            methods = methods_result.stdout.strip().split("\n")
            self.discovered_methods[svc] = [m.strip() for m in methods if m.strip()]
        
        return self.discovered_methods
```

## 6. 类型推断汇总表

```python
# 从 Protobuf 字节推断类型的完整决策树

TYPE_INFERENCE_TREE = """
原始字节
├── Wire Type 0 (Varint)
│   ├── 值在 {0, 1} → bool
│   ├── 小集合 (< 16) → enum
│   ├── 值很大 (> 2^32) → int64/uint64
│   ├── ZigZag 解码后有负值 → sint32/sint64
│   └── 其他 → int32/uint32
│
├── Wire Type 1 (Fixed64)
│   ├── 浮点模式 → double
│   ├── 1e9 - 2e9 → Unix 时间戳 (int64)
│   └── 其他 → fixed64/sfixed64
│
├── Wire Type 2 (Length-delimited)
│   ├── UTF-8 可解码 → string
│   ├── 子字段解码成功 → embedded message
│   ├── Base64 可解码 → bytes (encoded)
│   ├── 长度固定 (4/8/16) → 可能是 packed repeated
│   └── 其他 → bytes
│
└── Wire Type 5 (Fixed32)
    ├── 浮点模式 → float
    └── 其他 → fixed32/sfixed32
"""
```

## 7. 案例实战

### 案例 1: 移动端 API 协议还原

```python
"""
场景：某 App 使用 Protobuf 但未提供 .proto 文件
抓取到一个请求：

    08 96 01 12 06 48656C6C6F 1A 03 74657374

解码步骤：
1.  08 = 0000 1000 → field=1, wire=0 (varint)
    96 01 = 150 → field 1 = 150
2.  12 = 0001 0010 → field=2, wire=2 (length-delimited)
    06 = 6 → 6 字节
    48656C6C6F = "Hello"
3.  1A = 0001 1010 → field=3, wire=2 (length-delimited)
    03 = 3 → 3 字节
    74657374 = "test"

推断 schema:
    message Request {
        int32 user_id = 1;     // 150
        string greeting = 2;   // "Hello"
        string suffix = 3;     // "test"
    }
"""
```

### 案例 2: FlatBuffers 游戏协议

```
场景：某手游使用 FlatBuffers 作为协议格式

FlatBuffers 字节（十六进制）:
0C 00 00 00  // 根偏移量：从末尾往前 12 字节
08 00  // vtable 中的 table 大小
0C 00  // vtable 大小 = 12 字节（4+4 个字段偏移）
08 00  // field 0 的偏移 = 8
00 00  // field 1 的偏移 = 0 (不存在)
01 00 00 00  // field 0 的值 (int) = 1
48656C6C6F 00  // 字符串 "Hello\0"

推断：
- 根 table 有 2 个字段（field 0, 1）
- field 1 不存在（偏移 = 0）
- field 0 是 int (值 = 1)
- 之后有字符串 "Hello"
```

## 8. 参考

- Protobuf 编码规范: https://protobuf.dev/programming-guides/encoding/
- FlatBuffers 二进制格式: https://flatbuffers.dev/flatbuffers_internals.html
- gRPC 反射: https://grpc.io/docs/guides/reflection/
- protobuf-inspector: https://pypi.org/project/protobuf-inspector/
- blackboxprotobuf: https://pypi.org/project/blackboxprotobuf/
- protoscope: https://github.com/protocolbuffers/protoscope
- grpcurl: https://github.com/fullstorydev/grpcurl

## MCP 工具映射

| 分析步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| Protobuf 无 schema 解码检索 | `kb_router` | 按 protobuf/FlatBuffers 特征搜索知识库 |
| 知识库文件阅读 | `kb_read_file` | 阅读匹配的 protobuf/flatbuffers 还原方案 |
| PCAP/样本初筛 | `triage_pe` | 分析实现协议处理的 PE 样本 |
| 协议实现深度分析 | `ghidra_headless_analyze` | Ghidra 分析 protobuf 序列化/反序列化代码 |
| Ghidra 函数聚焦 | `ghidra_summary_call_focus` | 聚焦序列化相关函数调用链 |
| 分析工具安装 | `python_re_tool_install` | 安装 protobuf-inspector、blackboxprotobuf 等 |

## 工作流

抓取多组会话 → 划分帧边界 → 推断字段与状态机 → 主动单字段变异 → 重放验证 → 生成解析器/协议说明。


## 证据与验证闭环

- 固定输入样本、SHA256、工具版本和全部参数，先保存未处理 baseline。
- 每个假设至少绑定一个可观察量：已知明密文对、协议字段、状态转移、时间分布、偏移或重放输出。
- 用独立脚本重放核心变换，并以断言、输出哈希或逐字段 diff 验证，不以“看起来合理”作为结论。
- 原始抓包/样本进入 `exports/general/`，派生文件与原件分离并记录转换链。
