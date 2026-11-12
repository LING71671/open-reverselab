---
id: "general/01-kernel/01-page-cache-write-family-defense"
title: "Linux Page-Cache 原地写入漏洞家族防御（禁用高危零拷贝路径 / Seccomp / 只读根分区）"
title_en: "Defense Against Linux Kernel Page-Cache In-Place Write Family"
summary: >
  针对 Copy Fail (CVE-2026-31431)、Dirty Frag ESP/RxRPC (CVE-2026-43284/43500) 与 Fragnesia (CVE-2026-46300) 的内核级防御：限制 AF_ALG/RxRPC/ESP-in-TCP 模块加载、通过 Seccomp 阻断 splice/vmsplice 零拷贝送入协议栈、部署 dm-verity/IMA 只读根文件系统与补丁基线核查。
summary_en: >
  Kernel defense against Copy Fail (CVE-2026-31431), Dirty Frag ESP/RxRPC (CVE-2026-43284/43500), and Fragnesia (CVE-2026-46300): module blacklisting for AF_ALG/RxRPC/espintcp, seccomp filtering of splice/vmsplice, dm-verity/IMA integrity protection, and patch baseline verification.
board: "general"
category: "01-kernel"
signals:
  - "AF_ALG disable"
  - "seccomp splice block"
  - "dm-verity"
  - "rxrpc blacklist"
  - "espintcp hardening"
  - "page cache protection"
mcp_tools:
  - "kb_router"
  - "workspace_write_text"
  - "make_sigma_stub"
keywords:
  - "page cache defense"
  - "seccomp"
  - "AF_ALG"
  - "dm-verity"
  - "kernel hardening"
  - "KSPP"
difficulty: "advanced"
tags:
  - "kernel-defense"
  - "page-cache"
  - "seccomp"
  - "dm-verity"
  - "hardening"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "general/01-kernel/01-page-cache-write-family"
  - "general/01-kernel/05-pintheft-io-uring-page-cache-defense"
track: "blue"
defends: "general/01-kernel/01-page-cache-write-family"
---
# Linux Page-Cache 原地写入漏洞家族防御（禁用高危零拷贝路径 / Seccomp / 只读根分区）

## 防御目标

阻断非特权进程借由 `splice()` / `vmsplice()` 将只读可执行文件（如 `/usr/bin/su`）的页缓存页送入 `AF_ALG`（Copy Fail）、`xfrm-ESP`（Dirty Frag ESP）、`RxRPC`（Dirty Frag RxRPC）与 `espintcp`（Fragnesia）等内核原地解密路径，从内核模块收敛、系统调用过滤与页缓存只读保护三层切断提权链路。

## 分层防御矩阵

| 防御层级 | 对应漏洞家族共性 | 具体控制策略 | 阻断效果 |
|---|---|---|---|
| 内核模块黑名单 | `AF_ALG` / `rxrpc` / `espintcp` 自动按需加载 | `/etc/modprobe.d/hardening-net.conf` 使用 `install <mod> /bin/false` + `blacklist` | 非特权用户创建 `AF_ALG` 或 `AF_RXRPC` socket 直接返回 `EAFNOSUPPORT` |
| Seccomp-BPF 系统调用过滤 | 依赖 `splice`/`vmsplice` 构造零拷贝 SGL | 容器与服务沙箱默认策略拦截 `splice(275)`、`vmsplice(278)`、`af_alg(38)` | 切断只读文件页缓存进入管道与协议栈的零拷贝通道 |
| 内核补丁基线 | 原地解密未执行 COW 与先解密后验签 | 确保 `algif_aead` 禁用共享页 in-place、`skb_splice_from_iter` 标记 `SKBFL_SHARED_FRAG`、先验 MAC 后解密 | 从源码根因消除共享页缓存覆盖写漏洞 |
| 根文件系统与执行校验 | 仅篡改内存页缓存而不落盘 | 部署 `dm-verity` 或 `IMA Appraisal` 并移除非必要 SUID 二进制 | 即便页缓存异常也无法通过 SUID 完成权限跃迁，且内核拒绝执行未验签页 |

## 防御实现与校验示例

### 1. 内核模块黑名单与 Seccomp/容器策略配置

```ini
# /etc/modprobe.d/99-reverselab-kernel-hardening.conf
install algif_aead /bin/false
install af_alg /bin/false
install rxrpc /bin/false
install espintcp /bin/false
blacklist algif_aead
blacklist af_alg
blacklist rxrpc
blacklist espintcp
```

### 2. 主机运行态基线核验脚本（Python）

核查目标主机是否仍允许加载高危协议模块、SUID 暴露面与容器 seccomp 状态：

```python
from pathlib import Path

HIGH_RISK_MODULES = ("algif_aead", "af_alg", "rxrpc", "espintcp")

def check_modprobe_hardening(conf_dir: Path = Path("/etc/modprobe.d")) -> dict:
    blocked = set()
    if conf_dir.exists():
        for conf in conf_dir.glob("*.conf"):
            text = conf.read_text(encoding="utf-8", errors="ignore")
            for mod in HIGH_RISK_MODULES:
                if f"install {mod} /bin/false" in text or f"install {mod} /bin/true" in text:
                    blocked.add(mod)
    missing = [m for m in HIGH_RISK_MODULES if m not in blocked]
    return {"blocked": sorted(blocked), "missing_hardening": missing, "compliant": len(missing) == 0}

def evaluate_seccomp_profile(denied_syscalls: set[str]) -> bool:
    required_blocks = {"splice", "vmsplice", "add_key", "request_key"}
    return required_blocks.issubset(denied_syscalls)

if __name__ == "__main__":
    assert evaluate_seccomp_profile({"splice", "vmsplice", "add_key", "request_key", "ptrace"}) is True
    assert evaluate_seccomp_profile({"ptrace"}) is False
    res = check_modprobe_hardening(Path("nonexistent_test_dir"))
    assert res["compliant"] is False and len(res["missing_hardening"]) == 4
    print("page_cache_defense_check: PASS")
```

## 防御工作流

```text
1. 补丁对齐：核对内核版本是否已合入 Copy Fail / Dirty Frag / Fragnesia 上游修复补丁
2. 协议收敛：在无需 IPsec/RxRPC/AF_ALG 的服务器与容器宿主机禁用对应内核模块并阻止自动加载
3. 系统调用沙箱：为非特权服务与容器启用 Seccomp，阻断 splice/vmsplice 与 AF_ALG socket 创建
4. 减少 SUID 靶标：清理非必需的 SUID-root 可执行文件，并对关键系统分区启用 dm-verity / IMA
5. 异常监控：通过 auditd / eBPF 监控普通进程对 /usr/bin/su 等 SUID 文件配合 splice/AF_ALG 的调用组合
```

## 验证与判定标准

- **模块禁用生效**：`/etc/modprobe.d/` 配置加载并更新 initramfs 后，`lsmod` 中不出现 `algif_aead`/`rxrpc`/`espintcp`，普通用户调用 `socket(AF_ALG, SOCK_SEQPACKET, 0)` 返回错误
- **Seccomp 生效**：在目标服务或容器内执行 `splice()` 返回 `EPERM`
- **基线脚本通过**：`check_modprobe_hardening()` 返回 `missing_hardening == []` 且 SUID 文件列表符合最小权限基线

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 关联加固策略检索 | `kb_router` | 检索 `01-kernel` 目录下同家族内核加固文档 |
| 加固配置与基线输出 | `workspace_write_text` | 将 modprobe 黑名单与 seccomp 配置草案写入工作区 |
| 内核异常行为规则生成 | `make_sigma_stub` | 生成针对 `AF_ALG` / `splice` 异常序列的检测规则 |
