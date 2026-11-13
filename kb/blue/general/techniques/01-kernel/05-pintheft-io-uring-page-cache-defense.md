---
id: "general/01-kernel/05-pintheft-io-uring-page-cache-defense"
title: "PinTheft（RDS zcopy + io_uring 页缓存污染 LPE）防御"
title_en: "Defense Against PinTheft RDS Zerocopy and io_uring Page-Cache Poisoning"
summary: >
  防御 QVD-2026-27616（RDS zerocopy 错误路径多释放叠加 io_uring dangling struct page* 窃取 FOLL_PIN 引用并覆写 SUID 页缓存）：全局禁用非特权 io_uring（kernel.io_uring_disabled=2）、黑名单禁用 rds/rds_tcp 模块、容器 Seccomp 拦截 io_uring 与 AF_RDS，并强化内核补丁与只读根分区保护。
summary_en: >
  Defense against QVD-2026-27616 (RDS zerocopy double-free + io_uring dangling struct page* FOLL_PIN theft): disable io_uring via kernel.io_uring_disabled=2, blacklist rds/rds_tcp modules, block io_uring/AF_RDS via seccomp, and deploy kernel patches with read-only rootfs protection.
board: "general"
category: "01-kernel"
signals:
  - "io_uring_disabled"
  - "rds blacklist"
  - "FOLL_PIN hardening"
  - "seccomp io_uring"
  - "QVD-2026-27616"
  - "dm-verity"
mcp_tools:
  - "kb_router"
  - "workspace_write_text"
  - "make_sigma_stub"
keywords:
  - "PinTheft defense"
  - "io_uring hardening"
  - "RDS disable"
  - "FOLL_PIN"
  - "page cache protection"
difficulty: "advanced"
tags:
  - "kernel-defense"
  - "io_uring"
  - "RDS"
  - "page-cache"
  - "seccomp"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "general/01-kernel/05-pintheft-io-uring-page-cache"
  - "general/01-kernel/01-page-cache-write-family-defense"
track: "blue"
defends: "general/01-kernel/05-pintheft-io-uring-page-cache"
---
# PinTheft（RDS zcopy + io_uring 页缓存污染 LPE）防御

## 防御目标

切断 PinTheft 内核提权链（QVD-2026-27616）的两个核心依赖条件：一是通过 `kernel.io_uring_disabled=2` 与 Seccomp 阻断 `IORING_REGISTER_BUFFERS` / `IORING_OP_READ_FIXED` 的悬空页引用写入原语；二是通过禁用未使用的 `rds` / `rds_tcp` 内核协议模块阻止 `rds_message_zcopy_from_user()` 错误路径反复窃取 `FOLL_PIN` 引用计数。

## 分层防御矩阵

| 防御层级 | 控制机制 | 配置细节 | 阻断效果 |
|---|---|---|---|
| `io_uring` 全局限制 | `sysctl -w kernel.io_uring_disabled=2`（或至少 `1`） | `2` 对所有进程禁用 `io_uring_setup`；`1` 仅允许 `CAP_SYS_ADMIN` 使用 | 无法注册固定缓冲区（`FOLL_PIN`）及触发 `IORING_OP_READ_FIXED` |
| `RDS` 协议模块禁用 | `/etc/modprobe.d/` 禁止加载 `rds` 与 `rds_tcp` | `install rds /bin/false`、`install rds_tcp /bin/false` + `blacklist` | 非特权用户创建 `AF_RDS` socket 直接失败，无法触发 zcopy 多释放 |
| Seccomp-BPF 沙箱 | 容器默认策略拦截 `io_uring_*`（425/426/427） | Docker/containerd 默认已屏蔽 `io_uring_setup`、`io_uring_enter`、`io_uring_register` | 即使宿主机开启 `io_uring`，容器内仍无法利用 |
| 内核根因修复 | 修复 `rds_message_zcopy_from_user()` 错误清理与 `io_uring` 缓冲生命周期检查 | 在错误回滚后清零 `op_nents`/已释放 `sg` 项，避免 `rds_message_purge()` 二次释放 | 消除引用计数偏差（1024 FOLL_PIN 窃取失效） |
| 根分区完整性与 SUID 缩减 | `dm-verity` / IMA 与最小化 SUID 二进制 | 移除非必要 SUID 程序并启用内核内存/页完整性基线 | 即使存在内存篡改条件也缺少可利用提权目标 |

## 防御实现与校验示例

### 1. sysctl 与 modprobe 加固配置文件

```ini
# /etc/sysctl.d/99-io-uring-hardening.conf
kernel.io_uring_disabled = 2
```

```ini
# /etc/modprobe.d/99-disable-rds.conf
install rds /bin/false
install rds_tcp /bin/false
install rds_rdma /bin/false
blacklist rds
blacklist rds_tcp
blacklist rds_rdma
```

### 2. 主机 PinTheft 暴露面核验脚本（Python）

```python
def evaluate_pintheft_exposure(
    io_uring_disabled: int,
    rds_loaded: bool,
    rds_blacklisted: bool,
    seccomp_blocks_io_uring: bool,
) -> dict:
    # 任一主攻击原语未受限且组合暴露则存在风险
    io_uring_open = (io_uring_disabled == 0) and (not seccomp_blocks_io_uring)
    rds_open = rds_loaded or (not rds_blacklisted)
    reasons = []
    if io_uring_open:
        reasons.append("io_uring_enabled_without_restriction")
    if rds_open:
        reasons.append("rds_module_available_or_loaded")
    return {
        "hardened": (not io_uring_open) and (not rds_open),
        "mitigated_chain": (not io_uring_open) or (not rds_open),
        "reasons": reasons,
    }

if __name__ == "__main__":
    assert evaluate_pintheft_exposure(0, True, False, False)["mitigated_chain"] is False
    assert evaluate_pintheft_exposure(2, False, True, True)["hardened"] is True
    assert evaluate_pintheft_exposure(0, False, True, False)["mitigated_chain"] is True
    print("pintheft_defense_check: PASS")
```

## 防御工作流

```text
1. 立即禁用 RDS：在无 InfiniBand/RDS 业务需求的主机上将 rds/rds_tcp/rds_rdma 加入 modprobe 黑名单并卸载
2. 收敛 io_uring：将 kernel.io_uring_disabled 设为 2（或受控主机设为 1）并通过 sysctl 持久化
3. 核查容器策略：确认 Kubernetes/Docker/containerd 的默认 seccomp profile 保留拦截 io_uring_setup/register/enter
4. 升级内核补丁：跟踪发行版安全通告合入 RDS zerocopy 错误路径修复
5. 异常行为监控：监控非特权进程频繁调用 posix_fadvise(DONTNEED) + socket(AF_RDS) + io_uring 的组合特征
```

## 验证与判定标准

- **`io_uring` 禁用生效**：`cat /proc/sys/kernel/io_uring_disabled` 返回 `2`，测试调用 `io_uring_setup()` 返回 `EPERM`
- **RDS 阻断生效**：`lsmod | grep rds` 为空，非特权进程创建 `socket(21, SOCK_SEQPACKET, 0)`（`AF_RDS`）返回协议不支持
- **暴露面核验通过**：`evaluate_pintheft_exposure` 返回 `hardened == True`

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 关联内核防御卡检索 | `kb_router` | 检索页缓存污染与 Seccomp 加固方案 |
| 加固配置文件生成 | `workspace_write_text` | 将 sysctl 与 modprobe 黑名单写入部署模板 |
| 异常系统调用组合检测 | `make_sigma_stub` | 生成监控 `AF_RDS` 与 `io_uring_register` 高频异常的检测规则 |
