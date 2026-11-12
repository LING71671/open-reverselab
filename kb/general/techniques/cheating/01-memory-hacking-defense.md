---
id: "general/cheating/01-memory-hacking-defense"
title: "内存搜索与篡改防御（ObRegisterCallbacks / 数值加密 / IOMMU）"
title_en: "Defense Against Memory Searching and Modification"
summary: >
  针对 External/Internal/Kernel/DMA 四层内存修改的防御方案：通过 ObRegisterCallbacks 剥离句柄权限、进程内关键状态动态异或加密与影子校验、VAD/模块完整性扫描以及 IOMMU/VT-d DMA 重映射拦截物理内存读取。
summary_en: >
  Defense against External/Internal/Kernel/DMA memory tampering: handle stripping via ObRegisterCallbacks, in-process encrypted state with shadow checksums, VAD and module integrity verification, and IOMMU/VT-d DMA remapping protection.
board: "general"
category: "cheating"
signals:
  - "ObRegisterCallbacks"
  - "handle stripping"
  - "memory encryption"
  - "shadow checksum"
  - "IOMMU VT-d"
  - "VAD integrity"
mcp_tools:
  - "triage_pe"
  - "rizin_imports"
  - "ghidra_headless_analyze"
  - "ghidra_summary_call_focus"
  - "make_yara_stub"
  - "kb_router"
keywords:
  - "memory protection"
  - "ObRegisterCallbacks"
  - "value obfuscation"
  - "DMA protection"
  - "IOMMU"
  - "anti-cheat defense"
difficulty: "intermediate"
tags:
  - "anti-cheat"
  - "memory-protection"
  - "defense"
  - "IOMMU"
  - "kernel-defense"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "general/cheating/01-memory-hacking"
  - "general/cheating/04-anti-cheat-bypass-defense"
track: "blue"
defends: "general/cheating/01-memory-hacking"
---
# 内存搜索与篡改防御（ObRegisterCallbacks / 数值加密 / IOMMU）

## 防御目标

阻断外部进程（`ReadProcessMemory` / `WriteProcessMemory`）、内部注入模块、内核驱动越权读写与 PCILeech 类 DMA 硬件对关键游戏/业务状态内存的定位、扫描与篡改，确保权威状态由服务端裁决或受完整性校验保护。

## 分层防御矩阵

| 攻击面 | 对应威胁 | 防御机制 | 核心实施要点 |
|---|---|---|---|
| External 句柄访问 | `OpenProcess` + RPM/WPM | `ObRegisterCallbacks` 权限剥离 | 注册 `OB_OPERATION_HANDLE_CREATE/DUPLICATE`，剥除 `PROCESS_VM_READ`/`PROCESS_VM_WRITE`/`PROCESS_VM_OPERATION` |
| 内存数值搜索 | 精确扫描/未知初值/指针链 | 动态密钥加密 + 影子副本 | 关键字段拆分为 `(enc_val ^ key) ^ rot(key)`，每次写入同步更新 MAC 或双份异或镜像 |
| Internal 模块扫描 | SIMD 特征码扫 `.text`/堆 | 栈上关键逻辑 + `.text` CRC/SHA 轮询 | 周期校验代码段页哈希，对比 VAD 私有可执行页（`MEM_PRIVATE` + `PAGE_EXECUTE_*`） |
| DMA 物理读取 | FPGA PCILeech 绕过 OS | Kernel DMA Protection + IOMMU | 启用 VT-d/AMD-Vi 设备隔离、禁止未认证 PCIe 设备的总线主控权限并校验 ACPI DMAR 表 |
| 逻辑作弊根治 | 客户端改写血量/坐标/冷却 | 服务端权威状态机 | 关键数值只做展示缓存，实际伤害、移动步长、消耗校验全部在服务端执行 |

## 防御实现与校验示例

### 1. 进程内数值加密与影子校验（C++）

通过轮换掩码与独立影子哈希检测非法内存写操作，即使攻击者通过外部工具直接修改明文缓存也会立即触发校验失败：

```cpp
#include <cstdint>
#include <atomic>

template <typename T>
class ProtectedValue {
public:
    explicit ProtectedValue(T init) {
        salt_ = 0x9E3779B9u ^ reinterpret_cast<uintptr_t>(this);
        set(init);
    }

    void set(T val) {
        uint64_t raw = static_cast<uint64_t>(val);
        salt_ = (salt_ * 6364136223846793005ULL) + 1442695040888963407ULL;
        encoded_ = raw ^ salt_;
        shadow_mac_ = mix64(raw ^ (salt_ >> 13));
    }

    bool verify_and_get(T& out) const {
        uint64_t raw = encoded_ ^ salt_;
        if (mix64(raw ^ (salt_ >> 13)) != shadow_mac_) {
            return false; // 检测到内存被外部篡改
        }
        out = static_cast<T>(raw);
        return true;
    }

private:
    static uint64_t mix64(uint64_t x) {
        x ^= x >> 30;
        x *= 0xbf58476d1ce4e5b9ULL;
        x ^= x >> 27;
        x *= 0x94d049bb133111ebULL;
        return x ^ (x >> 31);
    }

    uint64_t salt_{0};
    uint64_t encoded_{0};
    uint64_t shadow_mac_{0};
};
```

### 2. 服务端/客户端内存保护基线检查（Python）

验证内存页属性、句柄权限掩码与加密结构完整性逻辑：

```python
import struct
import hashlib

PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008

def verify_handle_mask(granted_access: int, is_whitelisted: bool) -> dict:
    dangerous = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
    exposed = granted_access & dangerous
    return {
        "allowed": is_whitelisted or exposed == 0,
        "exposed_bits": hex(exposed),
        "action": "pass" if (is_whitelisted or exposed == 0) else "strip_access",
    }

def check_vad_executable_regions(regions: list[dict]) -> list[dict]:
    anomalies = []
    for r in regions:
        is_exec = "X" in r.get("protect", "")
        is_private = r.get("type") == "MEM_PRIVATE"
        if is_exec and is_private and not r.get("jit_whitelisted", False):
            anomalies.append({
                "base": r["base"],
                "size": r["size"],
                "reason": "unbacked_executable_private_page",
            })
    return anomalies

if __name__ == "__main__":
    assert verify_handle_mask(0x1FFFFF, False)["action"] == "strip_access"
    assert verify_handle_mask(0x1000, False)["allowed"] is True
    hits = check_vad_executable_regions([
        {"base": "0x7ff60000", "size": 4096, "protect": "RWX", "type": "MEM_PRIVATE"},
    ])
    assert len(hits) == 1
    print("memory_defense_check: PASS")
```

## 防御工作流

```text
1. 资产分级：将游戏/客户端内存状态拆分为“仅服务端权威字段”与“本地受保护字段”
2. 句柄收敛：驱动层通过 ObRegisterCallbacks 剥离非白名单进程的 VM_READ/VM_WRITE/VM_OPERATION 权限
3. 内存硬化：客户端对敏感结构应用动态异或编码与影子 MAC，禁用纯静态全局偏移链
4. 页属性巡检：定时扫描 MEM_PRIVATE 可执行页与 .text 节区哈希，发现未签名映射立即上报或终止会话
5. DMA 隔离：开启操作系统 Kernel DMA Protection（IOMMU/VT-d）并核对 PCIe 枚举中的异常 FPGA 设备
```

## 验证与判定标准

- **句柄拦截验证**：外部进程调用 `OpenProcess(PROCESS_ALL_ACCESS)` 后，实际获得的访问掩码不含 `0x0038`（VM_READ/WRITE/OPERATION），`ReadProcessMemory` 返回拒绝访问
- **篡改触发验证**：修改内存中编码值或影子字段任一字节时，`verify_and_get()` 100% 返回 `false` 并记录告警事件
- **DMA 与未签名映射检查**：`msinfo32` 或内核策略确认 `Kernel DMA Protection = Enabled`，测试注入的未签名 `MEM_PRIVATE` RWX 页在巡检周期内被检出

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 二进制符号与导入检查 | `triage_pe` / `rizin_imports` | 核对客户端是否引入不必要的可调试/明文状态符号 |
| 反作弊与校验逻辑分析 | `ghidra_headless_analyze` | 检查校验函数是否易被单点 NOP 绕过 |
| 关键函数调用点核查 | `ghidra_summary_call_focus` | 追踪敏感数值读写路径是否均经过保护封装 |
| 检测特征规则生成 | `make_yara_stub` | 为已捕获的作弊注入器 DLL 生成静态检出规则 |
