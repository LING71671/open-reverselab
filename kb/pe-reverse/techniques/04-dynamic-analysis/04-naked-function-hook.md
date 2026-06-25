# Naked 函数 Hook（内联汇编）

## 场景

需要在 Hook 中保留完整的寄存器上下文，用最少的汇编开销实现函数拦截。Naked 函数（无 prologue/epilogue）让开发者完全控制生成的汇编。

## 输入信号

- 目标函数地址已确认
- 需要完整访问 CPU 状态（所有通用寄存器+标志位）
- hook 逻辑简单，不想引入 trampoline 框架

## Naked 函数声明

```cpp
// __declspec(naked): 编译器不生成 prologue/epilogue
// 开发者必须自己处理栈帧、寄存器、ret
__declspec(naked) void NakedHookGateway() {
    __asm {
        // 1. 保存所有寄存器（包括标志位）
        pushad        // 保存 EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI → 栈
        pushfd        // 保存 EFLAGS

        // 2. 从栈/寄存器中提取感兴趣的参数
        // 此时 ESP 指向 saved EFLAGS, ESP+4 指向 saved EDI
        mov eax, [ebp+0x8]  // 取第一个参数（假设使用 EBP 帧）

        // 3. 调用你的 C 函数
        push eax             // 传参
        call MyCallback      // stdcall: callee 清栈

        // 4. 恢复所有寄存器
        popfd               // 恢复 EFLAGS
        popad               // 恢复所有通用寄存器

        // 5. 执行原始被覆盖的指令
        // (原先在 detour 地址处的原始代码)

        // 6. 跳回原始函数 + detourLen
        jmp OriginalAddressPlusDetour
    }
}
```

## x64 Naked 实现

```cpp
// x64 不支持内联汇编 (MSVC), 需用 .asm 文件或 Xbyak

// Gateway.asm (MASM 语法)
extern MyCallback64: PROC

.code
NakedHookGateway64 PROC
    ; 保存 volatile 寄存器 (RCX, RDX, R8, R9, RAX, R10, R11)
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    sub rsp, 20h        ; x64 shadow space

    ; RCX 仍保留着原始函数的第一个参数
    ; 在不破坏 RCX 的前提下调用 callback
    mov rdx, rcx        ; 把 RCX 作为第二参数传过去
    mov rcx, [rsp+60h]  ; 取某个栈上的值作为第一参数
    call MyCallback64

    add rsp, 20h
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax

    ; 原始指令 (运行时填充)
    db 8 DUP (90h)     ; 占位, 安装时用原始字节覆盖

    ; 跳回
    jmp qword ptr [OriginalReturnAddress]
NakedHookGateway64 ENDP
END
```

## Detour32 安装

```cpp
// 从 mrowrpurr/RE: Vampire the Masquerade 风格
// 手动计算相对偏移, 写入 JMP
void Detour32(uintptr_t target, uintptr_t gateway) {
    DWORD oldProt;
    VirtualProtect((void*)target, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    *(uint8_t*)target = 0xE9;                    // JMP
    *(int32_t*)(target + 1) = gateway - target - 5;  // rel32
    VirtualProtect((void*)target, 5, oldProt, &oldProt);
}

// 写入原始字节 + JMP 回原位 (用于跳板)
void WriteTrampolineBack(uintptr_t trampoline, const uint8_t* orig,
    size_t len, uintptr_t jumpBack) {
    DWORD oldProt;
    size_t total = len + 5;  // 原始字节 + JMP
    VirtualProtect((void*)trampoline, total, PAGE_EXECUTE_READWRITE, &oldProt);
    memcpy((void*)trampoline, orig, len);
    uint8_t* pos = (uint8_t*)trampoline + len;
    *pos = 0xE9;
    *(int32_t*)(pos + 1) = jumpBack - (trampoline + len + 5);
    VirtualProtect((void*)trampoline, total, oldProt, &oldProt);
}
```

## Gateway 分配模式

```cpp
struct Gateway32 {
    uint8_t* code;
    size_t size;
    void* target;
    uint8_t origBytes[16];
    size_t detourLen;
};

Gateway32* CreateGateway32(void* target, void* callback, size_t detourLen) {
    Gateway32* gw = new Gateway32();
    gw->target = target;
    gw->detourLen = detourLen;

    // 保存原始字节
    memcpy(gw->origBytes, target, detourLen);

    // 分配 gateway 代码空间
    // 大小 = pushad(1) + pushfd(1) + push+call(6) + popfd(1) + popad(1)
    //      + origBytes(N) + jmp(5) + 额外对齐
    gw->size = 1+1+6+1+1 + detourLen + 5 + 16;
    gw->code = (uint8_t*)VirtualAlloc(NULL, gw->size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    uint8_t* p = gw->code;
    *p++ = 0x60;           // pushad
    *p++ = 0x9C;           // pushfd
    *p++ = 0x68;           // push imm32 (callback 参数)
    *(uint32_t*)p = (uint32_t)callback;
    p += 4;
    *p++ = 0xE8;           // CALL rel32
    *(uint32_t*)p = (uint32_t)(callback - (p + 4));
    p += 4;
    // pushfd 之后的 CALL: 需要从栈中取出保存的寄存器传给 callback
    // 实际项目用更复杂的中转机制...
    *p++ = 0x9D;           // popfd
    *p++ = 0x61;           // popad

    // 拷贝原始字节
    memcpy(p, gw->origBytes, detourLen);
    p += detourLen;

    // JMP 回原位
    *p++ = 0xE9;
    *(uint32_t*)p = (target + detourLen) - (p + 4);

    return gw;
}
```

## 热键驱动模式

```cpp
// 运行时按键切换 hook 开/关
void InputLoop(Gateway32* hook) {
    bool installed = false;
    while (true) {
        if (GetAsyncKeyState(VK_HOME) & 1) {  // HOME 键按下
            if (!installed) {
                Detour32((uintptr_t)hook->target, (uintptr_t)hook->code);
                printf("[+] Hook installed\n");
                installed = true;
            }
        }
        if (GetAsyncKeyState(VK_END) & 1) {    // END 键按下
            if (installed) {
                // 恢复原始字节
                WriteProtected(hook->target, hook->origBytes, hook->detourLen);
                printf("[-] Hook removed\n");
                installed = false;
            }
        }
        Sleep(50);
    }
}
// 注意: GetAsyncKeyState 返回的是按键的物理状态
// (返回值 & 1) = 自上次查询以来按下过
// (返回值 & 0x8000) = 当前正在被按下
```

## Naked vs Trampoline 对比

```
Naked Function Hook:
  优点: 最小开销, 完全控制汇编, 代码简洁
  缺点: x64 需 .asm 文件, 不可移植, 复杂逻辑难写
  适用: 简单拦截/过滤/日志

Trampoline-based Hook:
  优点: C++ lambda 回调, 框架化, 易扩展
  缺点: 框架开销大, 跳板内存多
  适用: 复杂逻辑, 需要访存/修改上下文
```

## 攻击链

```
Ghidra 定位目标函数 → 确定 detourLen ≥ 5 → 编写 Naked 函数
→ VirtualAlloc 分配 gateway → 写入 pushad→call→popad→orig→jmp
→ Detour32 安装 JMP → GetAsyncKeyState 热键控制 → 退出前恢复
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 定位目标函数 | `ghidra_headless_analyze` | 定位目标函数 |
| 查看函数参数和调用约定 | `ghidra_summary_function_detail` | 查看函数参数和调用约定 |
| 生成 hook stub 机器码 | `rizin_assemble_bytes` | 生成 hook stub 机器码 |

## 证据与验证闭环

- 记录样本 SHA256、架构、映像基址、RVA/VA/文件偏移换算及工具版本。
- 静态结论绑定函数、Xref、导入、字符串和反编译片段；动态结论绑定断点、寄存器、栈、内存与调用时序。
- 原始样本只读保留，dump/patch 使用副本并记录前后哈希、原始字节、新字节和行为差异。
- 将 x64dbg/Frida/Procmon/Ghidra 输出保存到 `exports/windows/`，从干净基线最小化复现后再下结论。
