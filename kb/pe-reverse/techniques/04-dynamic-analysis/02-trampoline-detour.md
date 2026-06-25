# Trampoline Hook（函数劫持）

## 场景

需要在函数执行时插入自定义逻辑（记录参数、修改返回值、拦截调用）。在不破坏原始功能的前提下，劫持函数入口跳转到回调，执行后再跳回原位。

## 输入信号

- 已定位目标函数地址（Ghidra/x64dbg/特征码）
- 函数开头有 ≥5 字节的可覆盖空间（x86: ≥5, x64: ≥13 用于绝对跳转）
- 需要保持原始函数功能（不能直接 NOP 掉）

## Trampoline 核心流程

```
原始调用:
  caller → [func_entry: push rbp; mov rbp,rsp; ...]

Hook 后:
  caller → [func_entry: JMP trampoline] → trampoline:
    ├── save all registers
    ├── call callback(r)  ← 你的代码
    ├── restore all registers
    ├── execute original bytes (被 JMP 覆盖掉的指令)
    └── JMP func_entry+5  ← 回到原函数继续
```

## 标准实现

```cpp
struct Trampoline {
    void* gateway;      // 跳板代码地址
    uint8_t origBytes[16];  // 被覆盖的原始字节
    size_t detourSize;  // 覆盖长度 (≥5 for JMP)
    void* target;       // 目标函数地址
};

Trampoline* CreateTrampoline(void* targetAddr,
    std::function<void(Registers&)> callback, size_t detourSize) {

    Trampoline* t = new Trampoline();
    t->target = targetAddr;
    t->detourSize = detourSize;

    // 1. 保存原始字节
    memcpy(t->origBytes, targetAddr, detourSize);

    // 2. 分配可执行内存作为跳板
    t->gateway = VirtualAlloc(NULL, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // 3. 在跳板中写入:
    uint8_t* pos = (uint8_t*)t->gateway;

    // 3a. 保存所有寄存器 (pushad/push rax rbx rcx...)
    pos += SaveRegisters(pos);

    // 3b. CALL callback
    // PUSH callable_id; CALL CallbackDispatcher
    *(uint32_t*)(pos) = RegisterCallback(callback);
    pos += 4;
    *(uint8_t*)(pos++) = 0xE8;  // CALL
    *(uint32_t*)(pos) = (uint32_t)(CallbackDispatcher - (pos + 4));
    pos += 4;

    // 3c. 恢复所有寄存器
    pos += RestoreRegisters(pos);

    // 3d. 执行原始被覆盖的字节
    memcpy(pos, t->origBytes, detourSize);
    pos += detourSize;

    // 3e. JMP 回目标函数 + detourSize
    *(pos++) = 0xE9;  // JMP rel32
    *(uint32_t*)pos = (uint32_t)((uint8_t*)targetAddr + detourSize - pos - 4);

    // 4. 在目标函数入口写入 JMP → trampoline
    DWORD oldProt;
    VirtualProtect(targetAddr, detourSize, PAGE_EXECUTE_READWRITE, &oldProt);
    *(uint8_t*)targetAddr = 0xE9;  // JMP
    *(uint32_t*)((uint8_t*)targetAddr + 1) =
        (uint32_t)((uint8_t*)t->gateway - (uint8_t*)targetAddr - 5);
    VirtualProtect(targetAddr, detourSize, oldProt, &oldProt);

    return t;
}
```

## JMP 偏移计算

```cpp
// 相对 JMP (0xE9) 的偏移公式:
// rel32 = dst - src - 5
// 5 = 1 (opcode 0xE9) + 4 (rel32)

void WriteRelJMP(void* src, void* dst) {
    DWORD oldProt;
    VirtualProtect(src, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    *(uint8_t*)src = 0xE9;
    *(int32_t*)((uint8_t*)src + 1) = (int32_t)((uint8_t*)dst - (uint8_t*)src - 5);
    VirtualProtect(src, 5, oldProt, &oldProt);
}

void WriteRelCALL(void* src, void* dst) {
    DWORD oldProt;
    VirtualProtect(src, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    *(uint8_t*)src = 0xE8;  // CALL
    *(int32_t*)((uint8_t*)src + 1) = (int32_t)((uint8_t*)dst - (uint8_t*)src - 5);
    VirtualProtect(src, 5, oldProt, &oldProt);
}
```

## 卸载 Hook（恢复原始代码）

```cpp
void RemoveTrampoline(Trampoline* t) {
    DWORD oldProt;
    VirtualProtect(t->target, t->detourSize, PAGE_EXECUTE_READWRITE, &oldProt);
    // 写回原始字节
    memcpy(t->target, t->origBytes, t->detourSize);
    VirtualProtect(t->target, t->detourSize, oldProt, &oldProt);

    // 释放跳板内存
    VirtualFree(t->gateway, 0, MEM_RELEASE);
    delete t;
}
```

## x86 vs x64 差异

```
x86 (32-bit):
  JMP rel32: E9 XX XX XX XX  (5 bytes, 覆盖 5 字节即可)
  CALL rel32: E8 XX XX XX XX (5 bytes)
  pushad: 60 (1 byte, 保存所有通用寄存器)
  popad:  61 (1 byte, 恢复所有通用寄存器)

x64 (64-bit):
  JMP rel32: E9 XX XX XX XX  (5 bytes, 但 rel32 范围 ±2GB 受限)
  JMP [rip]: FF 25 00 00 00 00 + 8 字节绝对地址 (14 bytes)
  x64 无 pushad/popad, 需逐个 push/pop 16 个寄存器
```

## NOP 填充模式

```cpp
// 将目标地址开始的 N 字节填为 NOP
void WriteNOPSled(void* addr, size_t count) {
    DWORD oldProt;
    VirtualProtect(addr, count, PAGE_EXECUTE_READWRITE, &oldProt);
    memset(addr, 0x90, count);  // 0x90 = NOP
    VirtualProtect(addr, count, oldProt, &oldProt);
}

// 常见用途:
// 禁用条件跳转: 把 JE (0x74 XX) 改成 NOP NOP
// 强制返回:      NOP 掉整个函数体 → RET
// 去除反调试:    NOP 掉 IsDebuggerPresent() 调用
```

## 寄存器保存/恢复

```cpp
// x86 寄存器存取 (使用固定的全局变量做中转)
struct Registers_x86 {
    uint32_t EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI;
    uint32_t EFLAGS;
};
Registers_x86 g_regs_x86;

// Save: 每行一条 MOV [g_regs+offset], reg
uint8_t save_x86[] = {
    0xA3, 0x00,0x00,0x00,0x00,  // MOV [g_regs+0x00], EAX
    0x89,0x0D, 0x00,0x00,0x00,0x00,  // MOV [g_regs+0x04], ECX
    // ... 每条指令的偏移在运行时填充
};

// x64 寄存器存取
struct Registers_x64 {
    uint64_t RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI;
    uint64_t R8, R9, R10, R11, R12, R13, R14, R15;
    uint64_t XMM0[2], XMM1[2]; // ... XMM15
};
```

## 攻击链

```
Ghidra 定位目标函数 → 确定 detourSize ≥ 5（确保覆盖完整指令边界）
→ 保存原始字节 → VirtualAlloc 分配跳板 → 写 save→call→restore→orig→jmp_back
→ VirtualProtect 修改目标入口为 JMP → 验证 hook 生效
→ 退出前 RemoveTrampoline 恢复原始代码
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 定位目标函数 | `ghidra_headless_analyze` | 定位目标函数 |
| 按行为查找候选 Hook 函数 | `ghidra_summary_call_focus` | 按行为查找候选 Hook 函数 |
| 生成 JMP 跳板机器码 | `rizin_assemble_patch` | 生成 JMP 跳板机器码（注意: JMP 偏移计算需要手动） |

## 证据与验证闭环

- 记录样本 SHA256、架构、映像基址、RVA/VA/文件偏移换算及工具版本。
- 静态结论绑定函数、Xref、导入、字符串和反编译片段；动态结论绑定断点、寄存器、栈、内存与调用时序。
- 原始样本只读保留，dump/patch 使用副本并记录前后哈希、原始字节、新字节和行为差异。
- 将 x64dbg/Frida/Procmon/Ghidra 输出保存到 `exports/windows/`，从干净基线最小化复现后再下结论。
