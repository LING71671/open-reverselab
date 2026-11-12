---
id: "apk-reverse/06-dynamic/01-memory-rw-hook-defense"
title: "进程内存读写防护、反附加与敏感内存保护"
title_en: "Process Memory Read/Write Defense, Anti-Attach, and Sensitive Memory Protection"
summary: >
  针对 process_vm_readv/writev 系统调用、/proc/pid/mem 文件读取、内核 ioctl 驱动拷贝及 Frida Interceptor 内存监控，提供 prctl 禁转储、直连系统调用自检 TracerPid 与 /proc/self/maps 异常映射、动态库/memfd 识别及敏感变量内存掩码方案。
summary_en: >
  Defense-in-depth against process_vm_readv/writev syscalls, /proc/pid/mem file reads, kernel ioctl driver memory access, and Frida Interceptor hooks. Covers prctl(PR_SET_DUMPABLE, 0), direct-syscall TracerPid and /proc/self/maps scanning, memfd/Frida module detection, and runtime value masking.
board: "apk-reverse"
category: "06-dynamic"
signals:
  - "PR_SET_DUMPABLE"
  - "TracerPid"
  - "/proc/self/maps"
  - "memfd"
  - "process_vm_readv 防护"
  - "anti-Frida"
  - "内存掩码"
mcp_tools:
  - "android_app_baseline"
  - "ghidra_headless_analyze"
  - "make_yara_stub"
  - "kb_router"
keywords:
  - "反调试"
  - "内存保护"
  - "PR_SET_DUMPABLE"
  - "反Frida"
  - "maps检测"
  - "内存掩码"
  - "blue-team"
difficulty: "advanced"
tags:
  - "defense"
  - "blue-team"
  - "anti-debug"
  - "anti-frida"
  - "memory-protection"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "apk-reverse/06-dynamic/01-memory-rw-hook"
  - "apk-reverse/06-dynamic/02-overlay-rendering-hook-defense"
  - "apk-reverse/08-patch-repack/01-so-injection-repack-defense"
track: "blue"
defends: "apk-reverse/06-dynamic/01-memory-rw-hook"
---
# 进程内存读写防护、反附加与敏感内存保护

## 防御目标与威胁面

攻击者可通过三种路径读取或篡改进程内存：
1. **用户态跨进程 syscall**：调用 `process_vm_readv`/`process_vm_writev` 或打开 `/proc/<pid>/mem` 直接按 `/proc/<pid>/maps` 基址读写游戏数据与密钥。
2. **Frida 动态插桩**：注入 `frida-agent` 并在进程内通过 `Interceptor.attach` 挂钩关键函数或读写内存。
3. **内核驱动 `ioctl` 拷贝**：具备 Root 或加载自定义内核模块后，绕过用户态 `ptrace` 限制直接读取物理/虚拟内存。

单纯调用 libc `fopen("/proc/self/status")` 极易被 Frida Hook `openat`/`fopen` 伪造返回；针对内核驱动拷贝，用户态无法阻止物理读取，必须通过**敏感状态内存掩码加密**与**关键逻辑服务端校验**降低内存中明文资产的可用性。

## 核心防御矩阵

| 攻击向量 | 根治控制措施 | 关键实现约束 |
|---|---|---|
| 非 Root `process_vm_readv` / `/proc/pid/mem` | 初始化即执行 `prctl(PR_SET_DUMPABLE, 0)` + 独立守护进程双向 `ptrace` 占位 | 必须在 Release 构建关闭 `android:debuggable="true"`，否则系统允许附加 |
| libc `open`/`read` Hook 绕过检测 | 使用内联汇编直接发起 `SVC #0` 系统调用读取 `/proc/self/status` 与 `/proc/self/maps` | 不依赖可被 `Interceptor.attach` 的 libc 导出符号 |
| Frida / 匿名可执行内存注入 | 扫描 `/proc/self/maps` 检测 `frida`、`gum-js-loop`、`/memfd:` 及异常 `rwxp` 匿名页 | 同时检查 `/proc/self/task/*/comm` 中的 `gmain`/`gum-js-loop`/`pool-frida` 线程名 |
| 内核驱动 `ioctl` 跨进程读值 | 关键数值采用运行时随机密钥 XOR/拆片存储，并附带校验标签与多副本交叉核验 | 每次读写重新轮换掩码密钥，使用后立即 `explicit_bzero` 清零栈缓冲 |
| 核心状态被直接写内存篡改 | 关键数值与状态迁移上行服务端权威校验，客户端仅保留显示副本 | 本地篡改仅能影响客户端画面，无法通过服务端合法性检查 |

## 加固代码与离线映射检测示例

### 1. Native 层直连检测思路与动态密钥掩码存储（C++）

```cpp
// memory_shield.cpp — 敏感数值动态掩码与直连系统调用防 Hook 检查框架
#include <sys/prctl.h>
#include <cstdint>
#include <cstring>
#include <atomic>

template <typename T>
class MaskedValue {
public:
    explicit MaskedValue(T initial, uint64_t seed)
        : mask_(seed ^ 0x9E3779B97F4A7C15ULL) {
        set(initial, seed);
    }

    void set(T val, uint64_t next_entropy) {
        uint64_t raw = 0;
        std::memcpy(&raw, &val, sizeof(T));
        mask_ = next_entropy ^ 0xD6E8FEB86659FD93ULL;
        encoded_ = raw ^ mask_;
        checksum_ = (raw ^ 0xA5A55A5AA5A55A5AULL) + mask_;
    }

    bool get(T* out) const {
        uint64_t raw = encoded_ ^ mask_;
        uint64_t expected_chk = (raw ^ 0xA5A55A5AA5A55A5AULL) + mask_;
        if (checksum_ != expected_chk) {
            return false;  // 检测到跨进程单点写内存篡改
        }
        std::memcpy(out, &raw, sizeof(T));
        return true;
    }

private:
    uint64_t mask_{0};
    uint64_t encoded_{0};
    uint64_t checksum_{0};
};

extern "C" void harden_process_dumpable() {
    // 禁止非特权进程通过 process_vm_readv / /proc/pid/mem 读取本进程内存
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}
```

### 2. Python `/proc/<pid>/maps` 与 `/proc/<pid>/status` 异常注入扫描器

```python
import re
from typing import Dict, List


SUSPICIOUS_MAP_TOKENS = (
    "frida",
    "gadget",
    "gum-js-loop",
    "linjector",
    "/memfd:",
    "/data/local/tmp/",
)


def inspect_proc_snapshot(status_text: str, maps_text: str) -> Dict[str, List[str]]:
    """分析导出的 /proc/pid/status 与 /proc/pid/maps 快照中的注入与调试痕迹。"""
    findings: Dict[str, List[str]] = {"debugger": [], "suspicious_maps": [], "rwx_anon": []}

    m = re.search(r"^TracerPid:\s*(\d+)", status_text, re.M)
    if m and int(m.group(1)) != 0:
        findings["debugger"].append(f"nonzero_tracer_pid:{m.group(1)}")

    for line in maps_text.splitlines():
        low = line.lower()
        for tok in SUSPICIOUS_MAP_TOKENS:
            if tok in low:
                findings["suspicious_maps"].append(f"{tok} -> {line.strip()}")
                break
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "rwxp" and (len(parts) < 6 or parts[-1].startswith("[anon")):
            findings["rwx_anon"].append(line.strip())

    return findings


if __name__ == "__main__":
    sample_status = "Name:\tcom.example.app\nState:\tS (sleeping)\nTracerPid:\t4321\n"
    sample_maps = (
        "7a00000000-7a00004000 rwxp 00000000 00:00 0 \n"
        "7b10000000-7b10100000 r-xp 00000000 fd:01 9912 /data/local/tmp/frida-agent-64.so\n"
        "7c00000000-7c00002000 r-xp 00000000 00:05 102 /memfd:jit-cache (deleted)\n"
    )
    res = inspect_proc_snapshot(sample_status, sample_maps)
    assert res["debugger"] == ["nonzero_tracer_pid:4321"]
    assert len(res["suspicious_maps"]) == 2
    assert len(res["rwx_anon"]) == 1
    print("Memory protection snapshot check passed.")
```

## 防御工作流

```text
1. 进程不可转储配置：Release 关闭 debuggable，入口调用 prctl(PR_SET_DUMPABLE, 0) 阻断常规附加
2. 直连系统调用巡检：后台线程通过内联 SVC #0 轮询 /proc/self/status TracerPid 与 task 线程名
3. 内存映射核查：识别 /memfd:、/data/local/tmp/、frida 字符及未命名 rwxp Executable 页
4. 敏感数据掩码化：对本地密钥、状态标志与核心变量采用 MaskedValue 异或+校验和保护并及时擦除明文
5. 服务端权威兜底：防备内核驱动 ioctl 读取场景，高价值判定由服务端独立重算而非信任客户端内存
```

## 验证与判定标准

- **普通进程附加拦截**：在非 Root 环境以同一用户或外部调试器调用 `process_vm_readv` 或读取 `/proc/<pid>/mem` 时，系统调用必须返回 `EPERM` 失败。
- **Frida 与匿名页识别**：注入测试 `.so` 或启动 Frida 线程后，`inspect_proc_snapshot` 及 Native 直连探测线程必须检出异常映射或线程名。
- **单点内存写保护**：外部强行覆盖 `MaskedValue` 内部 `encoded_` 字节而不掌握动态 `mask_` 时，`get()` 校验必须返回 `false`。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 基线进程与属性采集 | `android_app_baseline` | 确认 `debuggable=false` 与常规进程状态 |
| 静态检查直连校验逻辑 | `ghidra_headless_analyze` | 核查防附加与映射检测未暴露单点返回分支 |
| 生成特征检测规则 | `make_yara_stub` | 为常见注入模块与异常载荷生成检测特征 |
| 检索关联红蓝文档 | `kb_router` | 对照 [01-memory-rw-hook.md](01-memory-rw-hook.md) 覆盖全部读写路径 |
