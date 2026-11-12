---
id: "general/cheating/04-anti-cheat-bypass-defense"
title: "反作弊绕过防御（内核回调加固 / 栈回溯 / ETW-Ti 与 HVCI）"
title_en: "Defense Against Anti-Cheat System Bypass"
summary: >
  防御面向 EAC/BattlEye/Vanguard/Ricochet 的用户态与内核态绕过：包含 ETW-Ti 内核威胁情报事件监控、调用栈返回地址与未签名内存校验、Manual Map/Direct Syscall 检出、HVCI/Secure Boot 强制启动校验及驱动黑名单（LOLDrivers）拦截。
summary_en: >
  Defense against usermode and kernel anti-cheat bypasses: ETW-Ti threat intelligence monitoring, call-stack return address verification for manual map and direct syscalls, HVCI/Secure Boot attestation, and vulnerable driver blocklist enforcement.
board: "general"
category: "cheating"
signals:
  - "ETW-Ti"
  - "call stack validation"
  - "HVCI"
  - "Secure Boot"
  - "LOLDrivers blocklist"
  - "handle stripping"
  - "anti-tamper"
mcp_tools:
  - "triage_pe"
  - "ghidra_headless_analyze"
  - "ghidra_summary_imports"
  - "make_sigma_stub"
  - "make_yara_stub"
  - "kb_router"
keywords:
  - "anti-cheat hardening"
  - "ETW-Ti"
  - "call stack walk"
  - "HVCI"
  - "BYOVD defense"
  - "manual map detection"
difficulty: "advanced"
tags:
  - "anti-cheat"
  - "kernel-defense"
  - "ETW-Ti"
  - "HVCI"
  - "defense"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "general/cheating/04-anti-cheat-bypass"
  - "pe-reverse/04-dynamic-analysis/06-manual-map-injection-defense"
  - "pe-reverse/04-dynamic-analysis/07-direct-syscall-defense"
track: "blue"
defends: "general/cheating/04-anti-cheat-bypass"
---
# 反作弊系统绕过防御（内核回调加固 / 栈回溯 / ETW-Ti 与 HVCI）

## 防御目标

对抗针对反作弊驱动的句柄规避（Handle Stripping 竞态 / DuplicateHandle）、线程隐藏（`NtSetInformationThread`）、Manual Map 注入、Direct Syscall、用户态 ETW Patching 以及自带易受攻击驱动（BYOVD）破坏内核态保护的绕过手段。

## 分层防御矩阵

| 绕过技术 | 攻击原理 | 纵深防御措施 | 检测信号 |
|---|---|---|---|
| 短暂句柄 / `DuplicateHandle` | 避开周期性句柄扫描或借道系统进程句柄 | 实时 `ObRegisterCallbacks` 拦截 + 跨进程 `DuplicateHandle` 回调过滤 | 非白名单源进程持有或复制目标进程句柄 |
| Manual Map 无模块注入 | 绕过 `LoadLibrary` 与 PEB 模块链表 | NMI/APC 线程栈回溯 + `VAD` 未映射可执行内存排查 | 线程 RIP 或栈帧返回地址落入无对应文件映射的 `MEM_PRIVATE` 页 |
| Direct Syscall | 绕过 `ntdll.dll` 用户态 Hook | 内核态 ETW-Ti / `InstrumentationCallback` + 栈帧检验 | 系统调用返回地址不位于 `ntdll.dll`/`win32u.dll` 代码段内 |
| ETW Patching | Patch `EtwEventWrite` 致盲遥测 | 启用内核态 ETW-Ti（`Threat-Intelligence` 提供程序）+ `ntdll.dll` `.text` 哈希校验 | 用户态 `ntdll!EtwEventWrite` 首页字节被改写为 `C3`/`B8 00` |
| BYOVD / 未签名驱动 | 加载漏洞驱动关闭回调或 Patch 内核 | 强制开启 HVCI / VBS / Secure Boot + Microsoft 易受攻击驱动阻止列表 | 驱动签名哈希命中黑名单或系统启动策略未满足 TPM 2.0 远程证明 |

## 防御实现与校验示例

### 1. 调用栈与用户态关键 Stub 完整性校验模型（Python）

模拟内核回调 / Instrumentation 回调对线程调用栈及 `ntdll` 敏感导出函数头字节的校验流程：

```python
SYSCALL_CALLER_ALLOWLIST = ("ntdll.dll", "win32u.dll")

def validate_syscall_stack(frames: list[dict]) -> tuple[bool, str]:
    if not frames:
        return False, "empty_stack"
    # 检查最接近内核态切换的用户态返回帧
    top_user_frame = frames[0]
    mod = (top_user_frame.get("module") or "").lower()
    if mod not in SYSCALL_CALLER_ALLOWLIST:
        return False, f"direct_or_indirect_syscall_bypass:{mod or 'unbacked_mem'}"
    for idx, f in enumerate(frames):
        if not f.get("backed_by_signed_image", False):
            return False, f"unbacked_code_in_stack_frame:{idx}"
    return True, "clean_stack"

def detect_etw_patch(etw_func_bytes: bytes) -> bool:
    # 常见致盲 patch: ret (0xC3), xor eax,eax; ret (33 C0 C3 / 31 C0 C3), mov eax,0; ret
    suspicious_prefixes = (b"\xc3", b"\x33\xc0\xc3", b"\x31\xc0\xc3", b"\xb8\x00\x00\x00\x00\xc3")
    return any(etw_func_bytes.startswith(p) for p in suspicious_prefixes)

if __name__ == "__main__":
    assert validate_syscall_stack([{"module": "ntdll.dll", "backed_by_signed_image": True}])[0] is True
    ok, reason = validate_syscall_stack([{"module": "", "backed_by_signed_image": False}])
    assert not ok and "unbacked_mem" in reason
    assert detect_etw_patch(b"\x33\xc0\xc3\x90") is True
    assert detect_etw_patch(b"\x4c\x8b\xdc\x48\x83\xec\x58") is False
    print("anticheat_bypass_defense: PASS")
```

## 防御工作流

```text
1. 平台完整性证明：启动前通过 TPM 2.0 + Secure Boot + HVCI 远端证明，拒绝关闭驱动签名强制的环境接入
2. BYOVD 阻断：启用 Microsoft Vulnerable Driver Blocklist（Wdac/CiPolicy）并在驱动初始化阶段核对已加载驱动列表
3. 实时回调联动：以 ObRegisterCallbacks 阻断跨进程内存读写句柄，以 PsSetCreateThreadNotifyRoutine 拦截隐藏或异常起始地址线程
4. 调用栈与 ETW-Ti 监控：内核侧结合 ETW-Ti 与周期性线程栈回溯（RtlWalkFrameChain），抓出 Manual Map 与 Direct Syscall
5. 用户态自检保护：多点交叉校验 ntdll!EtwEventWrite / NtContinue 等关键函数节区校验和，避免单点补丁致盲
```

## 验证与判定标准

- **栈回溯检出**：注入无模块背书的 Manual Map 线程或发起 Direct Syscall 时，栈校验逻辑在测试帧上返回 `direct_or_indirect_syscall_bypass` 或 `unbacked_code_in_stack_frame`
- **ETW 篡改检出**：当用户态 `EtwEventWrite` 入口被替换为 `xor eax,eax; ret` 时，`detect_etw_patch` 返回 `True` 并触发遥测告警
- **平台策略基线**：目标测试机确认开启 `HVCI`（Hypervisor-protected Code Integrity）与 `SecureBoot = Enabled`

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 驱动与客户端二进制检查 | `triage_pe` | 验证签名、ASLR/CFG/CET 编译缓解标志 |
| 关键回调与校验反编译 | `ghidra_headless_analyze` | 排查反作弊自检逻辑是否存在单点分支绕过 |
| 系统 API 导入核查 | `ghidra_summary_imports` | 识别敏感内核/系统调用及保护依赖 |
| 异常驱动与注入行为规则 | `make_sigma_stub` / `make_yara_stub` | 输出 BYOVD 加载与用户态 Patch 检出规则 |
