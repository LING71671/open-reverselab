---
id: "pe-reverse/04-dynamic-analysis/03-external-memory-rw-defense"
title: "跨进程内存读写防护与敏感数据混淆"
title_en: "Cross-Process Memory Read/Write Protection and Data Hardening"
summary: >
  针对外部修改器通过 OpenProcess(PROCESS_ALL_ACCESS)、ReadProcessMemory/WriteProcessMemory
  以及多级 DMA 指针链（FindDMAAddy）篡改内存状态的行为，提供进程句柄权限剥离（ObRegisterCallbacks
  与 DACL 收敛）、PPL 进程保护、内存页访问隔离及敏感变量动态异或/MAC 校验方案。
summary_en: >
  Defense against external trainers and cross-process memory tampering via OpenProcess,
  ReadProcessMemory/WriteProcessMemory, and multi-level DMA pointer chains. Covers kernel
  ObRegisterCallbacks handle stripping, process DACL/PPL hardening, and XOR+MAC-protected
  sensitive runtime variables.
board: "pe-reverse"
category: "04-dynamic-analysis"
signals:
  - "ReadProcessMemory"
  - "WriteProcessMemory"
  - "OpenProcess"
  - "ObRegisterCallbacks"
  - "PPL"
  - "DACL"
  - "ETW-Ti"
  - "内存篡改防护"
mcp_tools:
  - triage_pe
  - ghidra_summary_imports
  - make_sigma_stub
  - make_procmon_filters
  - kb_router
keywords:
  - "anti-cheat"
  - "ReadProcessMemory defense"
  - "WriteProcessMemory defense"
  - "ObRegisterCallbacks"
  - "process DACL"
  - "memory encryption"
  - "pointer obfuscation"
  - "blue-team"
difficulty: "intermediate"
tags:
  - "defense"
  - "blue-team"
  - "memory-protection"
  - "ObRegisterCallbacks"
  - "anti-tamper"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "pe-reverse/04-dynamic-analysis/03-external-memory-rw"
  - "pe-reverse/04-dynamic-analysis/01-dll-injection-defense"
track: "blue"
defends: "pe-reverse/04-dynamic-analysis/03-external-memory-rw"
---
# 跨进程内存读写防护与敏感数据混淆

## 防御目标与威胁面

在 [03-external-memory-rw.md](03-external-memory-rw.md) 中，攻击者从外部进程调用 `OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)` 获取目标句柄，利用 `CreateToolhelp32Snapshot` 获取基址，沿固定偏移链（`FindDMAAddy`）执行 `ReadProcessMemory` 读取关键变量，或通过 `WriteProcessMemory` 直接改写内存数值与标志位。

针对外部读写与内部指针篡改，需构建从内核句柄拦截到应用层数据验证的多层防护：

1. **句柄访问收敛**：通过内核 `ObRegisterCallbacks` 或收紧进程 DACL，剥离非授权进程的 `PROCESS_VM_READ`、`PROCESS_VM_WRITE`、`PROCESS_VM_OPERATION` 权限。
2. **运行时敏感状态防护**：对关键数值（权限标志、计数值、指针）进行动态异或加密与影子副本 MAC 校验，使静态偏移定位与单点 `WriteProcessMemory` 立即触发篡改检测。
3. **服务端裁决与遥测**：关键业务逻辑与授权状态在服务端核验；在客户端通过 ETW-Ti 捕获跨进程读写事件。

## 核心防御架构

| 攻击向量 | 防御控制措施 | 关键实现约束 |
|---|---|---|
| `OpenProcess(PROCESS_ALL_ACCESS)` | 内核驱动注册 `ObRegisterCallbacks` 过滤 `OB_OPERATION_HANDLE_CREATE/DUPLICATE` | 剥离 `PROCESS_VM_READ \| PROCESS_VM_WRITE \| PROCESS_VM_OPERATION`，仅放行系统服务与自身签名进程 |
| 非管理员同用户上下文读写 | 进程初始化时重置自身 DACL 拒绝常规进程访问，或以 PPL（Protected Process Light）运行 | DACL 需保留当前进程自身与必要系统组件权限；拥有 `SeDebugPrivilege` 的提权攻击需配合内核回调或 PPL 防御 |
| `FindDMAAddy` 固定偏移链扫描 | 关键指针动态重定位与随机化堆块，配合指针加密（`EncodePointer`） | 避免将核心状态长期固定在 `module_base + 固定RVA` 的全局静态链路 |
| `WriteProcessMemory` 直接改写数值 | 对敏感数据封装双槽异或 + 密钥化 MAC 校验，每次读取先验真再解密 | 修改单点内存即导致 MAC 失配，触发状态清零或熔断 |
| 外部 `VirtualAllocEx` 分配可执行页 | 结合 ACG（`ProcessDynamicCodePolicy`）阻止远程分配可执行内存 | 与内核 `EtwTiLogAllocExecVm` 联动记录跨进程内存操作 |

## 加固实现与检测代码

以下 C++ 示例实现两部分核心防护：一是利用 Windows `SetSecurityInfo` 收紧当前进程对象 DACL 以阻止同权限外部工具直接 `OpenProcess`；二是提供 `ProtectedValue<T>` 模板，采用每实例随机盐值异或与 SipHash/FNV 校验和抵抗 `ReadProcessMemory` 明文扫描与 `WriteProcessMemory` 篡改：

```cpp
// memory_rw_defense.cpp: 进程 DACL 收敛与敏感状态完整性保护
#include <windows.h>
#include <aclapi.h>
#include <cstdint>
#include <random>

bool HardenProcessDacl() {
    HANDLE hProc = GetCurrentProcess();
    // 仅允许 SYSTEM 与受限访问，移除常规用户进程的 PROCESS_VM_READ/WRITE
    EXPLICIT_ACCESSW ea = {};
    ea.grfAccessPermissions = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD;
    ea.grfAccessMode = DENY_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = const_cast<LPWSTR>(L"CURRENT_USER");

    PACL oldDacl = nullptr, newDacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetSecurityInfo(hProc, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                        nullptr, nullptr, &oldDacl, nullptr, &sd) != ERROR_SUCCESS) {
        return false;
    }
    DWORD res = SetEntriesInAclW(1, &ea, oldDacl, &newDacl);
    bool ok = (res == ERROR_SUCCESS) &&
              (SetSecurityInfo(hProc, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                               nullptr, nullptr, newDacl, nullptr) == ERROR_SUCCESS);
    if (newDacl) LocalFree(newDacl);
    if (sd) LocalFree(sd);
    return ok;
}

template <typename T>
class ProtectedValue {
    uint64_t enc_val_ = 0;
    uint64_t mac_ = 0;
    uint64_t key_ = 0;

    static uint64_t ComputeMac(uint64_t v, uint64_t k) {
        uint64_t x = v ^ (k * 0x9E3779B97F4A7C15ULL);
        x ^= x >> 30;
        x *= 0xBF58476D1CE4E5B9ULL;
        x ^= x >> 27;
        return x;
    }

public:
    explicit ProtectedValue(T initial = T{}) {
        std::random_device rd;
        key_ = (static_cast<uint64_t>(rd()) << 32) | rd() | 1ULL;
        Set(initial);
    }

    void Set(T val) {
        uint64_t raw = static_cast<uint64_t>(val);
        enc_val_ = raw ^ key_;
        mac_ = ComputeMac(raw, key_);
    }

    bool TryGet(T& out) const {
        uint64_t raw = enc_val_ ^ key_;
        if (ComputeMac(raw, key_) != mac_) {
            return false; // 检测到内存篡改
        }
        out = static_cast<T>(raw);
        return true;
    }
};
```

以下 Python 验证脚本模拟检测跨进程读写工具特征与验证抗篡改逻辑：

```python
"""verify_memory_protection.py: 校验加密状态抗 WriteProcessMemory 篡改及检测跨进程读写指标"""
from __future__ import annotations
import hmac
import hashlib
import os


class TamperResistantSlot:
    def __init__(self, initial: int):
        self._key = os.urandom(32)
        self._mask = int.from_bytes(os.urandom(8), "little")
        self.enc = 0
        self.tag = b""
        self.set(initial)

    def set(self, val: int) -> None:
        self.enc = (val ^ self._mask) & 0xFFFFFFFFFFFFFFFF
        self.tag = hmac.new(self._key, self.enc.to_bytes(8, "little"), hashlib.sha256).digest()

    def get(self) -> int:
        expected = hmac.new(self._key, self.enc.to_bytes(8, "little"), hashlib.sha256).digest()
        if not hmac.compare_digest(self.tag, expected):
            raise RuntimeError("Memory tampering detected: MAC mismatch")
        return (self.enc ^ self._mask) & 0xFFFFFFFFFFFFFFFF


def detect_external_rw_behavior(events: list[dict]) -> list[dict]:
    suspicious_access = 0x1F0FFF  # PROCESS_ALL_ACCESS
    alerts = []
    for ev in events:
        if ev.get("api") == "OpenProcess" and (ev.get("desired_access", 0) & 0x0038) == 0x0038:
            alerts.append({"reason": "vm_rw_openprocess", **ev})
        elif ev.get("api") in {"ReadProcessMemory", "WriteProcessMemory"} and ev.get("cross_process"):
            alerts.append({"reason": "cross_process_vm_rw", **ev})
        elif ev.get("desired_access") == suspicious_access:
            alerts.append({"reason": "process_all_access", **ev})
    return alerts


if __name__ == "__main__":
    slot = TamperResistantSlot(100)
    assert slot.get() == 100
    slot.enc ^= 0x1  # 模拟外部 WriteProcessMemory 单点改写
    try:
        slot.get()
        raise AssertionError("Tampering was not caught")
    except RuntimeError:
        pass
    hits = detect_external_rw_behavior([{"api": "OpenProcess", "desired_access": 0x0038, "src": "trainer.exe"}])
    assert len(hits) == 1
    print("External memory RW defense self-check passed.")
```

## 防御工作流

```text
1. 进程边界收敛：在程序启动早期调用 HardenProcessDacl 或配置 PPL 服务保护，阻断普通外部工具 OpenProcess
2. 内核态句柄过滤：高对抗场景部署基于 ObRegisterCallbacks 的驱动过滤模块，剥离非可信调用方的 VM_READ/VM_WRITE 权限
3. 状态结构加固：将核心数值、授权状态与关键指针迁移至 ProtectedValue/EncodePointer 容器，杜绝明文扫描定位
4. 消除静态偏移链：将关键对象置于随机偏移包装结构中，并把权威判定移至服务端
5. 遥测规则部署：开启 Sysmon Event ID 10 (ProcessAccess) 监控 GrantedAccess 包含 0x0010/0x0020 的非白名单进程
```

## 验证与判定标准

- **外部句柄拦截测试**：在非管理员/未授权外部进程执行 `OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid)` 或 `ReadProcessMemory` 时，调用必须失败（`ERROR_ACCESS_DENIED`）或返回被剥离 `VM_READ/VM_WRITE` 的受限句柄。
- **单点内存篡改检测**：使用调试器或模拟脚本直接修改运行时状态槽位中的编码值（未同步伪造密钥态 MAC），下一次 `TryGet` 必须返回 `false` 并触发告警/熔断。
- **明文扫描失效验证**：在内存中搜索关键常量明文数值（如 `100`、`9999`）不得直接匹配到受保护变量所在地址。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检查目标与潜在修改器导入表 | `triage_pe`、`ghidra_summary_imports` | 识别是否存在敏感全局明文访问或外部工具 `Read/WriteProcessMemory` 导入 |
| 生成 Sysmon ProcessAccess 规则 | `make_sigma_stub` | 生成针对 `GrantedAccess` 含 `0x1F0FFF` / `0x0038` 的告警规则 |
| 采集行为基线过滤 | `make_procmon_filters` | 构建跨进程句柄与内存访问过滤规则 |
| 检索红蓝成对参考 | `kb_router` | 对照 [03-external-memory-rw.md](03-external-memory-rw.md) 校验防护覆盖度 |
