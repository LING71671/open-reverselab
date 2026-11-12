---
id: "general/01-kernel/02-slab-cross-cache-defense"
title: "Slab 跨缓存释放防御（禁用非特权 BPF / SLUB 加固 / KFENCE 策略）"
title_en: "Defense Against Slab Cross-Cache Free and KFENCE Exploitation"
summary: >
  针对 CVE-2026-31429（KFENCE 精确大小打破 skb_kfree_head 启发式路由）的纵深防御：通过 kernel.unprivileged_bpf_disabled=1 阻断 BPF_PROG_TEST_RUN 触发入口，开启 KSPP SLUB 硬化选项（CONFIG_RANDOM_KMALLOC_CACHES / init_on_free），并校验内核修复提交 0f42e3f4fe2a。
summary_en: >
  Defense against CVE-2026-31429 (KFENCE exact size breaking skb_kfree_head heuristic): block BPF_PROG_TEST_RUN via kernel.unprivileged_bpf_disabled=1, enable KSPP SLUB hardening (CONFIG_RANDOM_KMALLOC_CACHES, init_on_free), and verify patch commit 0f42e3f4fe2a.
board: "general"
category: "01-kernel"
signals:
  - "unprivileged_bpf_disabled"
  - "SLUB hardening"
  - "init_on_free"
  - "CONFIG_RANDOM_KMALLOC_CACHES"
  - "KFENCE"
  - "CVE-2026-31429"
mcp_tools:
  - "kb_router"
  - "workspace_write_text"
  - "make_sigma_stub"
keywords:
  - "slab defense"
  - "SLUB hardening"
  - "unprivileged BPF"
  - "KSPP"
  - "cross-cache defense"
  - "KFENCE"
difficulty: "advanced"
tags:
  - "kernel-defense"
  - "slab"
  - "SLUB"
  - "BPF-hardening"
  - "KSPP"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "general/01-kernel/02-slab-cross-cache"
  - "general/01-kernel/05-pintheft-io-uring-page-cache-defense"
track: "blue"
defends: "general/01-kernel/02-slab-cross-cache"
---
# Slab 跨缓存释放防御（禁用非特权 BPF / SLUB 加固 / KFENCE 策略）

## 防御目标

阻断非特权进程利用 `BPF_PROG_TEST_RUN` 触发 `skb_kfree_head` 在 `CONFIG_KFENCE=y` 下的跨缓存释放（CVE-2026-31429），并通过 SLUB 分配器加固（随机化 kmalloc 缓存、释放清零、freelist 随机化与硬化）提高跨缓存堆利用门槛。

## 分层防御矩阵

| 防御控制面 | 配置参数 / 修复项 | 防护作用 | 优先级 |
|---|---|---|---|
| 阻断非特权 BPF 入口 | `sysctl -w kernel.unprivileged_bpf_disabled=1`（或 `2`） | 禁止非 `CAP_BPF`/`CAP_SYS_ADMIN` 进程调用 `bpf()` 与 `BPF_PROG_TEST_RUN` | P0（立即可用缓解） |
| 内核根因修复 | 合入上游 `0f42e3f4fe2a`（`skb_kfree_head` 统一走 `kfree()`） | 消除 `kfence_ksize()` 返回精确大小 704 字节引发的误判分支 | P0（根本解决） |
| SLUB 随机化与硬化 | `CONFIG_RANDOM_KMALLOC_CACHES=y`、`CONFIG_SLAB_FREELIST_RANDOM=y`、`CONFIG_SLAB_FREELIST_HARDENED=y` | 隔离不同调用点分配的 `kmalloc` 对象，破坏确定性跨缓存重占与指针伪造 | P1（KSPP 基线） |
| 释放内存清零 | `init_on_alloc=1` / `init_on_free=1`（启动参数或 `CONFIG_INIT_ON_FREE_DEFAULT_ON=y`） | 清除残留数据并加速暴露 UAF / 跨缓存破坏 | P1（KSPP 基线） |
| 编译时边界强化 | `CONFIG_HARDENED_USERCOPY=y`、`CONFIG_FORTIFY_SOURCE=y` | 限制跨 Slab 对象的拷贝越界 | P2 |

## 防御实现与校验示例

### 1. sysctl 与内核 KSPP 基线配置文件

```ini
# /etc/sysctl.d/99-slab-bpf-hardening.conf
kernel.unprivileged_bpf_disabled = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
```

### 2. 内核版本、sysctl 与 KSPP SLUB 配置核验脚本（Python）

```python
import re

MIN_FIXED_KERNELS = {
    (6, 6): (6, 6, 136),
    (6, 12): (6, 12, 82),
    (6, 18): (6, 18, 23),
    (6, 19): (6, 19, 13),
}

def is_kernel_patched_cve_2026_31429(version_str: str) -> bool:
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", version_str.strip())
    if not m:
        return False
    ver = tuple(int(x) for x in m.groups())
    major_minor = (ver[0], ver[1])
    if major_minor in MIN_FIXED_KERNELS:
        return ver >= MIN_FIXED_KERNELS[major_minor]
    return ver < (6, 3, 0) or ver >= (7, 0, 0)

def check_kspp_slab_config(kconfig: dict[str, str], sysctl_vals: dict[str, str]) -> dict:
    issues = []
    if sysctl_vals.get("kernel.unprivileged_bpf_disabled") not in {"1", "2"}:
        issues.append("unprivileged_bpf_not_disabled")
    for opt in ("CONFIG_SLAB_FREELIST_RANDOM", "CONFIG_SLAB_FREELIST_HARDENED", "CONFIG_INIT_ON_FREE_DEFAULT_ON"):
        if kconfig.get(opt) != "y":
            issues.append(f"missing:{opt}")
    return {"compliant": len(issues) == 0, "issues": issues}

if __name__ == "__main__":
    assert is_kernel_patched_cve_2026_31429("6.6.135") is False
    assert is_kernel_patched_cve_2026_31429("6.6.136") is True
    assert is_kernel_patched_cve_2026_31429("6.12.82") is True
    res = check_kspp_slab_config(
        {"CONFIG_SLAB_FREELIST_RANDOM": "y", "CONFIG_SLAB_FREELIST_HARDENED": "y", "CONFIG_INIT_ON_FREE_DEFAULT_ON": "y"},
        {"kernel.unprivileged_bpf_disabled": "1"},
    )
    assert res["compliant"] is True
    print("slab_defense_check: PASS")
```

## 防御工作流

```text
1. 立即缓解：在生产环境配置 kernel.unprivileged_bpf_disabled=1 并执行 sysctl --system 生效
2. 版本排查：核对集群 uname -r 是否处于 6.3~7.0-rc7 受影响区间（未合入 0f42e3f4fe2a）
3. 内核升级：升级至对应 LTS 修复版本（>= 6.6.136 / 6.12.82 / 6.18.23 / 6.19.13）
4. KSPP 基线对齐：检查 /boot/config-$(uname -r) 中的 SLUB 随机化、init_on_free 与 KFENCE 配置
5. 日志告警：监控 dmesg 中 warn_free_bad_obj 与 SLUB corruption 异常事件
```

## 验证与判定标准

- **BPF 入口阻断**：`cat /proc/sys/kernel/unprivileged_bpf_disabled` 输出为 `1` 或 `2`，普通用户在容器或主机内调用 `bpf(BPF_PROG_TEST_RUN, ...)` 返回 `EPERM`
- **内核修复确认**：`is_kernel_patched_cve_2026_31429` 返回 `True`，且压测 SKB 分配释放循环无 `warn_free_bad_obj` 输出
- **KSPP 核验通过**：`check_kspp_slab_config()` 返回 `compliant == True`

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 内核加固知识路由 | `kb_router` | 检索关联 SLUB/BPF/KSPP 防御指南 |
| 配置与基线生成 | `workspace_write_text` | 生成 sysctl 与内核编译配置检查产物 |
| 内核异常告警规则 | `make_sigma_stub` | 生成针对 `warn_free_bad_obj` 及异常 `bpf` 系统调用的检测规则 |
