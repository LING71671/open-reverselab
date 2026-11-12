---
id: "pe-reverse/03-static-analysis/06-electron-asar-reverse"
title: "Electron 应用 asar 静态还原与混淆破解"
title_en: "Electron App asar Static Reverse & Deobfuscation"
summary: >
  针对打包后的 Electron 桌面应用：asar Pickle 头的手写解析偏移坑、零解包按需读文件、javascript-obfuscator 字符串数组模式（含双层别名链）的 vm+Babel 通用还原流程、Electron fuse wire 的变体 sentinel 定位与逐位读取、六类包体积归因方法。
summary_en: >
  Reverse packed Electron desktop apps: asar Pickle header pitfalls and offset-correct parsing, on-demand single-file extraction without full unpack, a vm+Babel pipeline to defeat javascript-obfuscator string-array mode (incl. two-hop alias chains), locating variant Electron fuse-wire sentinels and decoding per-fuse bits, and a six-bucket size attribution method.
board: "pe-reverse"
category: "03-static-analysis"
signals:
  - "electron"
  - "app.asar"
  - "asar header"
  - "javascript-obfuscator"
  - "_0x"
  - "string array"
  - "fuse wire"
  - "contextBridge"
  - "ipcMain"
  - "electron 逆向"
  - "asar 解包"
  - "去混淆"
mcp_tools:
  - triage_pe
  - sample_full_workup
keywords:
  - "electron"
  - "asar"
  - "deobfuscation"
  - "javascript-obfuscator"
  - "vm eval"
  - "babel ast"
  - "fuse wire"
  - "ipc channels"
  - "contextBridge"
  - "size attribution"
difficulty: "intermediate"
tags:
  - "electron"
  - "asar"
  - "deobfuscation"
  - "static-analysis"
language: "zh-CN"
last_updated: "2026-08-31"
related_articles: []
---
# Electron 应用 asar 静态还原与混淆破解

## 场景

目标是 Electron 打包的桌面应用（如 `<App>.exe` + `resources/app.asar`）：
需要回答"程序怎么跑、有哪些接口、包为什么这么大"，且不能修改安装目录。

## 输入信号

- 安装目录根有大量 Chromium DLL（`d3dcompiler_47.dll`/`vk_swiftshader.dll`/
  `icudtl.dat`/`LICENSES.chromium.html`）→ Electron/CEF 系
- `resources/app.asar`（可能带 `app.asar.unpacked/`）
- exe 的 VS_VERSIONINFO CompanyName 保留 `GitHub, Inc.` 且
  `SquirrelAwareVersion=1` → electron-builder/Squirrel 打包
- JS 内全是 `_0x` 前缀 + `while(!![])` + `parseInt` 混合表达式
  → javascript-obfuscator 字符串数组模式

## asar 磁盘格式与解析坑

```python
# 正确偏移（electron/asar disk.ts 的 Pickle 编码）:
#   [0:4)   uint32 = 4            # 第一个 pickle 的 payload 大小
#   [4:8)   uint32 header_size    # header pickle 总长（含自身 4B 头）
#   [8:12)  uint32                # header pickle payload 大小
#   [12:16) uint32 json_len       # writeString 的字符串长度
#   [16:16+json_len) header JSON
#   files 数据起点 = 8 + header_size
# 坑: 直接从 [12:16) 读 json_len 当起始，会把 'json_len' 字段当 JSON 解析，
# UnicodeDecodeError 'invalid continuation byte' 就是踩到这里。
import json, struct
def read_header(f):
    f.seek(0)
    f.read(4)                                   # 恒为 4
    header_size = struct.unpack("<I", f.read(4))[0]
    payload_size = struct.unpack("<I", f.read(4))[0]
    json_len = struct.unpack("<I", f.read(4))[0]
    header = json.loads(f.read(json_len))       # 从 16 开始
    return header, 8 + header_size
# 每个文件节点: {"size":int, "offset":"字符串", "unpacked":bool?, "integrity":{...}}
# 读文件: data = f.seek(8 + header_size + int(node["offset"]))
#         f.read(node["size"])   # offset 是字符串，必须 int()
# unpacked=True 的文件在 <asar>.unpacked/<path>
```

零解包按需读文件比整体解包快得多（大体积 asar 只需 seek+read）。
体积归因时只需遍历 header JSON，不用读文件内容。

## javascript-obfuscator 字符串数组还原（vm 求值 + AST 替换）

```javascript
// 通用还原流程（Node + @babel/*）：
// 1) 识别三件套: 数组函数 / 轮转 IIFE(while(!![]) + push(shift())) /
//    解码函数(x = x - 0xNN 模式，1~2 参数，内含 base64+URI 或 RC4)
// 2) 按【数组函数 → 轮转 IIFE → 解码函数】顺序拼入 vm 沙箱执行；
//    漏掉轮转 IIFE 会得到错位垃圾串（症状: 解码出乱序随机串）
// 3) 别名链必须传递解析：混淆器会生成
//    const _0xa = _0x491b; const _0x4169d7 = _0x3ef739(=_0xa);
//    也常写进 var 声明链 _0x1b15b0 = _0x3b32, _0x4595b0 = _0x3ef739, ...
//    解析: /(_0x[0-9a-f]+)\s*=\s*(_0x[0-9a-f]+)\s*[;,]/g 循环 until decoder
// 4) 用正则枚举全部 decoder 调用点（alias(arg1[,arg2])）逐个在 vm 求值，
//    生成 {alias|arg1|arg2: string} 表
// 5) babel traverse 把 CallExpression 替换为 t.stringLiteral(table[key])
// 6) 兜底: 数组函数体可能 >5KB，长度阈值勿写死 3000
const vm = require("vm"), parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;
const generate = require("@babel/generator").default;
const t = require("@babel/types");
// 按上述 5 步即可独立组装为通用去混淆脚本
```

验证标准：替换后 grep 明文特征（`ipcMain`、`https://`、UI 字符串）；
原始未混淆的小文件不命中三件套属于正常情况。

## Electron IPC / 接口面静态盘点

```python
# 通道名常是运行时拼接，必须同时扫两种形态:
#   1) 明文: invoke("agent:start") / replaceHandler(ipcMain, "agent:stop")
#   2) 拼接: channelPrefix + ":start"（IPC_CONCAT: (\w+)\s*\+\s*['"]:([\w-]+)）
#   preload 的 contextBridge.exposeInMainWorld("electronAPI", {...}) 是全清单来源
# HTTP 面: 抓 https?:// 与 '/api/...' '/v1/...' 字面量；对 127.0.0.1 监听
# 端口可直接 urllib GET 探测（/health 常无鉴权，/api/* 会 401 证实鉴权存在）
```

## Electron fuse wire（含变体 sentinel）

```python
# 标准 sentinel: dL7pKGdnNz796PbbjQWNKmHXBZzsu2qj
# 变体示例:     dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX   ← 尾部会随版本变
# 因此定位时用部分前缀 dL7pKGdnNz79 find，再验证后续结构。
# wire 格式: sentinel(32B) + version(1B) + count(1B) + count 个 ASCII '0'/'1'
# （老版本是每 fuse 1 字节 0/1/2，两种都要兼容）
# bit 顺序: run_as_node, cookie_encryption, node_options, cliInspectArg,
#   cliInspectBrkArg, embedded_asar_integrity_validation, only_load_app_from_asar,
#   load_browser_process_specific_runtime, grant_file_protocol_extra_privileges
# embedded_asar_integrity_validation=0 → 替换 asar 不会被启动拒绝
```

## 包体积六类归因

```
chromium_runtime(exe+dll+pak+icu) / locales / embedded_runtimes(应用自带
node/git/python) / 自研子进程二进制 / asar_bundle(main+npm+字体+map) / misc
→ asar 内再按 npm 包、扩展名聚合（.map 常占 30-50%，字体重复打包常见）
→ 给"可裁剪项"时逐项列字节与依据（如 .map、大型媒体库、重复字体等）
```

## 动态交叉（只读优先）

- 进程树+命令行（Get-CimInstance）即可确认 spawn 参数与静态启动构造一致
- Get-NetTCPConnection 确认本地监听与主↔子进程连接
- userData 的 SQLite（better-sqlite3 写的 `config(key,value)` 表）可
  `sqlite3 "file:...?mode=ro"` 只读打开，输出字段名+长度（不输出 token 明文）
- 需要安装根证书/重启应用的抓包（mitmproxy/CDP）放最后，先问用户

## 验证与判定标准

- asar 解析: 提取 `package.json` 后 `json.loads` 成功且 `main` 字段与
  解包目录一致；`files_start + offset` 读出的字节与 `asar extract-file`
  官方工具（如有 node 环境可交叉）一致。
- 去混淆: 替换计数 >0 且产物 grep 得到明文 API/IPC 通道；摘要或校验类
  函数能还原出完整调用语义即判成功。
- fuse: sentinel 定位偏移 + version/count 位串长度自洽（例如
  version=1 count=9）。
- 体积归因: 六类之和 == `Get-ChildItem -Recurse` 总字节（误差 0）。
- 动态交叉: 子进程命令行与静态构造参数字面一致；监听端口与静态默认端口一致。

## 攻击链

```
DiE/版本资源识别 Electron → asar header 正确偏移解析 → 零解包读
package.json/env-constants → 去混淆（数组+轮转+decoder+别名链）→
main.js 启动链/preload contextBridge → IPC 全通道 CSV → HTTP API 面
→ fuse wire 逐位读 → 体积六类归因 → 进程树/端口/userData 只读动态交叉
→（可选）本机端口 GET 探测 → 报告
```

## MCP 工具映射

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| PE 初筛（节表/导入/版本） | `triage_pe` | 结构化初筛产物 |
| 全流程编排 | `sample_full_workup` | 初筛→静态→动态自动化 |
| asar 内文件提取 | 无（按上文 `read_header` 编写单文件提取脚本） | 零解包按需读取 |
| fuse 读取 | 无（按上文 sentinel 前缀扫描） | 逐位解析 fuse 状态 |
