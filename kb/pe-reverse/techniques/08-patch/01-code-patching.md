# 代码 Patch 与字节修改

## 场景

需要修改目标进程的代码段（.text）或数据段，实现逻辑变更、函数禁用、常量替换。

## 输入信号

- 已定位需要修改的目标地址
- 代码段默认 RX（不可写），需先改页保护
- 需要确保修改不破坏指令边界

## VirtualProtect 改页保护

```cpp
// 核心: 修改内存页保护属性来实现写入
bool WriteProtectedBytes(void* addr, const void* newBytes, size_t size) {
    DWORD oldProtect;
    // 1. 改为可读写执行
    if (!VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;
    // 2. 写入新字节
    memcpy(addr, newBytes, size);
    // 3. 恢复原保护
    DWORD tmp;
    VirtualProtect(addr, size, oldProtect, &tmp);
    return true;
}

bool WriteProtectedJMP(void* addr, void* dst) {
    uint8_t jmpBytes[5];
    jmpBytes[0] = 0xE9;  // JMP rel32
    *(int32_t*)(jmpBytes + 1) = (int32_t)((uint8_t*)dst - (uint8_t*)addr - 5);
    return WriteProtectedBytes(addr, jmpBytes, 5);
}
```

## 常见 Patch 模式

### 模式 1: NOP 填充

```cpp
// 禁用某个功能: 把函数体或分支 NOP 掉
void NOPOut(void* addr, size_t count) {
    std::vector<uint8_t> nops(count, 0x90);
    WriteProtectedBytes(addr, nops.data(), count);
}

// 例: 禁用反调试检查
// IsDebuggerPresent() 调用 → 变为全 NOP
// 原始: FF 15 XX XX XX XX (call [IAT])
// Patch: 90 90 90 90 90 90
```

### 模式 2: 强制条件分支

```cpp
// 把 JE/JNE 改为 JMP 或 NOP
// 原始: 74 05  (JE +5, 跳转到成功分支)
// 改为: EB 05  (JMP +5, 强制走成功分支)
// 原始: 75 10  (JNE +0x10, 跳过失败处理)
// 改为: 90 90  (NOP NOP, 不跳过，必定执行失败处理)

void ForceJumpTaken(void* jccAddr) {
    uint8_t jmp = 0xEB;  // 无条件短跳转
    WriteProtectedBytes(jccAddr, &jmp, 1);
}

void ForceJumpNotTaken(void* jccAddr, size_t instrLen) {
    std::vector<uint8_t> nops(instrLen, 0x90);
    WriteProtectedBytes(jccAddr, nops.data(), instrLen);
}
```

### 模式 3: 立即数修改

```cpp
// 修改代码中的常量
// 原始: MOV EAX, 100  → B8 64 00 00 00
// Patch: MOV EAX, 9999 → B8 0F 27 00 00

template<typename T>
void PatchImmediate(void* addr, T newValue) {
    WriteProtectedBytes(addr, &newValue, sizeof(T));
}

// 例: 修改伤害乘数
// 原始指令: movss xmm0, [damage_multiplier]  (值为 1.0)
// → 修改常量池中的 1.0f 为 999.0f
float* damageMul = (float*)(base + 0x12345);
*damageMul = 999.0f;  // 需要确保该页可写
```

### 模式 4: 函数返回值劫持

```cpp
// 强制函数返回固定值
// 原始: push rbp; mov rbp,rsp; ...; ret
// Patch: mov eax, 1; ret
uint8_t returnTrue[] = {
    0xB8, 0x01, 0x00, 0x00, 0x00,  // MOV EAX, 1
    0xC3                             // RET
};
WriteProtectedBytes(funcAddr, returnTrue, sizeof(returnTrue));
// 该函数现在永远返回 1 (true)

// x64 版本:
uint8_t returnTrue64[] = {
    0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,  // MOV RAX, 1
    0xC3                                          // RET
};
```

### 模式 5: Xbyak 生成复杂 Patch

```cpp
// 当 patch 逻辑复杂时, 用 Xbyak 编写
std::vector<uint8_t> GenerateComplexPatch() {
    struct Code : Xbyak::CodeGenerator {
        Code() {
            cmp(ptr[rcx + 0x36C], 0);    // if (entity->health > 0)
            jle("skip");
            mov(ptr[rcx + 0x36C], 9999); // entity->health = 9999
            L("skip");
            ret();
        }
    } code;
    code.ready();
    return std::vector<uint8_t>(code.getCode(),
        code.getCode() + code.getSize());
}
```

## Patch 安装/卸载模板

```cpp
class CodePatch {
    void* target;
    std::vector<uint8_t> origBytes;
    std::vector<uint8_t> newBytes;
public:
    CodePatch(void* addr, const std::vector<uint8_t>& patch)
        : target(addr), newBytes(patch) {
        origBytes.resize(patch.size());
        memcpy(origBytes.data(), addr, patch.size());
    }

    void Install() {
        WriteProtectedBytes(target, newBytes.data(), newBytes.size());
    }

    void Uninstall() {
        WriteProtectedBytes(target, origBytes.data(), origBytes.size());
    }
};
```

## 防御性 Patch 检查

```cpp
// Patch 前验证: 确保目标地址还是原来的代码
bool VerifyBeforePatch(void* addr, const uint8_t* expected, size_t len) {
    return memcmp(addr, expected, len) == 0;
}

// 使用:
const uint8_t expected[] = {0x74, 0x05};  // JE +5
if (VerifyBeforePatch(addr, expected, 2)) {
    // 还是原始代码, 安全 patch
    ForceJumpTaken(addr);
} else {
    // 已被其他东西修改 ← 放弃
}
```

## 攻击链

```
Ghidra/x64dbg 定位目标指令 → 确定 patch 策略(NOP/JMP/立即数)
→ Xbyak 生成 patch 代码(如需要) → VerifyBeforePatch 确认原始字节
→ VirtualProtect 改 PAGE_EXECUTE_READWRITE → memcpy 写入
→ VirtualProtect 恢复原保护 → 验证 patch 生效
→ 退出时 Uninstall 恢复
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| RVA/VA → file offset 转换 | `pe_address_to_offset` | RVA/VA → file offset 转换 |
| 按 RVA/VA/file offset 打补丁 | `patch_pe_bytes` | 按 RVA/VA/file offset 打补丁（自动复制到 patches 目录） |
| 按 file offset 直接 patch | `patch_bytes` | 按 file offset 直接 patch |
| 写汇编→自动汇编为机器码→patch | `rizin_assemble_patch` | 写汇编 → 自动汇编为机器码 → patch 副本 |
| 一键全流程逆向自动化 | `sample_full_workup` | **一键全流程**：triage → Ghidra → 断点计划 → IOC → YARA/Sigma，patch 后进行自动化验证 |

## 证据与验证闭环

- 记录样本 SHA256、架构、映像基址、RVA/VA/文件偏移换算及工具版本。
- 静态结论绑定函数、Xref、导入、字符串和反编译片段；动态结论绑定断点、寄存器、栈、内存与调用时序。
- 原始样本只读保留，dump/patch 使用副本并记录前后哈希、原始字节、新字节和行为差异。
- 将 x64dbg/Frida/Procmon/Ghidra 输出保存到 `exports/windows/`，从干净基线最小化复现后再下结论。
