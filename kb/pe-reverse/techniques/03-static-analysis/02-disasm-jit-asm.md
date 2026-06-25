# 反汇编（Zydis）与 JIT 汇编（Xbyak）

## 场景

需要将二进制字节解码为可读汇编，或将汇编指令即时编译为机器码。作为 Hook 工具链的基石，用于分析现场指令和生成跳板代码。

## 输入信号

- 已知某地址的原始字节
- 需要在 Hook 时替换/补充指令
- 需要精确控制生成的机器码

## 反汇编：Zydis

```cpp
#include <Zydis/Zydis.h>

// 解码单条指令
std::string DisassembleOne(uintptr_t addr) {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
                     ZYDIS_ADDRESS_WIDTH_64);

    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    ZydisDecodedInstruction instr;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
        &decoder, (void*)addr, 15,
        &instr, operands))) {

        char buffer[256];
        ZydisFormatterFormatInstruction(&formatter, &instr,
            operands, instr.operandCount,
            buffer, sizeof(buffer), addr);
        return buffer;
    }
    return "";
}

// 反汇编一段连续的字节
std::vector<std::string> DisassembleRange(uintptr_t start, size_t length) {
    std::vector<std::string> result;
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
                     ZYDIS_ADDRESS_WIDTH_64);
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    size_t offset = 0;
    ZydisDecodedInstruction instr;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    while (offset < length) {
        if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
            &decoder, (uint8_t*)start + offset, length - offset,
            &instr, operands))) {

            char buffer[256];
            ZydisFormatterFormatInstruction(&formatter, &instr,
                operands, instr.operandCount,
                buffer, sizeof(buffer), start + offset);
            result.push_back(buffer);
            offset += instr.length;
        } else {
            result.push_back("db " + to_hex(*(uint8_t*)(start + offset)));
            offset++;
        }
    }
    return result;
}
```

## JIT 汇编：Xbyak

```cpp
#include <xbyak/xbyak.h>

// 生成机器码: MOV RAX, 0x1234; RET
std::vector<uint8_t> AssembleMovRet() {
    struct Code : Xbyak::CodeGenerator {
        Code() {
            mov(rax, 0x1234);
            ret();
        }
    } code;

    code.ready();  // 完成汇编
    return std::vector<uint8_t>(code.getCode(),
        code.getCode() + code.getSize());
}

// 生成带 CALL 的跳板
std::vector<uint8_t> AssembleTrampoline(void* callback,
    uintptr_t jumpBack, const uint8_t* origBytes, size_t origLen) {
    struct Code : Xbyak::CodeGenerator {
        Code(void* cb, uintptr_t jb, const uint8_t* orig, size_t ol) {
            // 保存易失寄存器 (Windows x64 calling convention)
            push(rcx);
            push(rdx);
            push(r8);
            push(r9);
            sub(rsp, 0x20);  // shadow space

            // 调用 callback
            mov(rax, (uintptr_t)cb);
            call(rax);

            // 恢复寄存器
            add(rsp, 0x20);
            pop(r9);
            pop(r8);
            pop(rdx);
            pop(rcx);

            // 执行原始被覆盖的字节
            for (size_t i = 0; i < ol; i++)
                db(orig[i]);

            // 跳回
            jmp((void*)jb);
        }
    } code(callback, jumpBack, origBytes, origLen);

    code.ready();
    return std::vector<uint8_t>(code.getCode(),
        code.getCode() + code.getSize());
}
```

## 常见指令生成速查

```cpp
// Xbyak 快速参考
Xbyak::CodeGenerator c;

// 通用寄存器操作
c.mov(rax, rcx);              // MOV RAX, RCX
c.mov(rax, ptr[rcx + 0x10]);  // MOV RAX, [RCX+0x10]
c.mov(ptr[rcx], 0x1234);      // MOV [RCX], 0x1234
c.lea(rax, ptr[rcx + rdx]);   // LEA RAX, [RCX+RDX]

// 算术
c.add(rax, 8);                // ADD RAX, 8
c.sub(rsp, 0x28);             // SUB RSP, 0x28
c.xor_(eax, eax);             // XOR EAX, EAX (注意尾部下划线)
c.cmp(rax, 0);                // CMP RAX, 0

// 分支
c.test(rax, rax);             // TEST RAX, RAX
c.je("label_null");           // JE label_null
c.jmp(rax);                   // JMP RAX
c.ret();                      // RET

// 浮点 (SSE)
c.movss(xmm0, ptr[rcx]);      // MOVSS XMM0, [RCX]
c.mulss(xmm0, xmm1);          // MULSS XMM0, XMM1

// 函数调用 (Windows x64 ABI)
c.sub(rsp, 0x20);             // shadow space (必须)
c.mov(rcx, 123);              // 第一参数
c.mov(rdx, 456);              // 第二参数
c.call(ptr[rax]);             // CALL [RAX]
c.add(rsp, 0x20);             // 恢复

// 数据定义
c.db(0x90);                   // 定义单字节 (NOP)
c.dd(0x12345678);             // 定义 DWORD
c.dq(0x1234567890ABCDEF);    // 定义 QWORD
```

## 手动字节构造

```cpp
// 不需要 Xbyak 时的手工字节拼接
class Bytes {
    std::vector<uint8_t> data;
public:
    Bytes& Add(uint8_t b)  { data.push_back(b); return *this; }
    Bytes& Add16(uint16_t v) {
        data.push_back(v & 0xFF);
        data.push_back((v >> 8) & 0xFF);  // little-endian
        return *this;
    }
    Bytes& Add32(uint32_t v) {
        Add16(v & 0xFFFF);
        Add16(v >> 16);
        return *this;
    }
    Bytes& Add64(uint64_t v) {
        Add32(v & 0xFFFFFFFF);
        Add32(v >> 32);
        return *this;
    }

    // 构建相对 JMP
    Bytes& AddRelJMP(void* dst) {
        Add(0xE9);
        intptr_t src = /* 最终写到的地址 */;
        Add32((intptr_t)dst - src - 5);
        return *this;
    }

    const uint8_t* Ptr() { return data.data(); }
    size_t Size() { return data.size(); }
};
```

## 应用：用反汇编确定 Hook 安全边界

```cpp
// Hook 时需要覆盖 ≥5 字节 (JMP rel32)
// 但必须覆盖在指令边界上 (不能截断指令)
size_t FindHookBoundary(uintptr_t addr, size_t minBytes) {
    size_t total = 0;
    while (total < minBytes) {
        auto instr = Disassemble(addr + total);
        size_t len = GetInstructionLength(addr + total);
        total += len;
    }
    return total;  // 保证截断在完整指令边界
}
// 目的: 如果 addr+0 是 7 字节指令, addr+5 在指令中间 → 需要扩大覆盖到 7
```

## 攻击链

```
获取目标地址原始字节 → Zydis 反汇编查看完整指令
→ Xbyak 生成跳板/替换代码 → 计算完整指令边界
→ VirtualAlloc 分配执行内存 → 写入生成代码 → 安装 Hook
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 汇编文本→机器码 | `rizin_assemble_bytes` | 汇编文本→机器码（代替手写 `\x` 转义） |
| 汇编→patch 副本 | `rizin_assemble_patch` | 汇编→patch 副本 |

## 证据与验证闭环

- 记录样本 SHA256、架构、映像基址、RVA/VA/文件偏移换算及工具版本。
- 静态结论绑定函数、Xref、导入、字符串和反编译片段；动态结论绑定断点、寄存器、栈、内存与调用时序。
- 原始样本只读保留，dump/patch 使用副本并记录前后哈希、原始字节、新字节和行为差异。
- 将 x64dbg/Frida/Procmon/Ghidra 输出保存到 `exports/windows/`，从干净基线最小化复现后再下结论。
