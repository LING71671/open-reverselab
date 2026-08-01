---
id: "pe-reverse/03-static-analysis/01-struct-reconstruction"
title: "内存结构体逆向重建"
title_en: "Memory Structure Reverse Reconstruction"
summary: >
  从汇编模式反推 C/C++ 结构体定义的方法论，涵盖字段类型推断（汇编指令到类型映射）、指针链与内嵌对象区分、已知值反推、链表遍历及 Frida 辅助验证，附游戏 Entity 实战重建示例。
summary_en: >
  Methodology for reversing C/C++ struct definitions from assembly patterns, covering field type inference (asm-to-type mapping), pointer chain vs embedded object differentiation, value-based deduction, linked list traversal, and Frida-assisted verification with a real game Entity reconstruction example.
board: "pe-reverse"
category: "03-static-analysis"
signals:
  - "struct reconstruction"
  - "field offset"
  - "pointer chain"
  - "vtable"
  - "sizeof deduction"
  - "结构体重建"
  - "偏移推断"
  - "Frida dump"
mcp_tools:
  - ghidra_headless_analyze
  - ghidra_summary_function_detail
keywords:
  - "struct reconstruction"
  - "reverse engineering"
  - "offset"
  - "pointer chain"
  - "vtable"
  - "ReClass"
  - "Frida"
  - "Ghidra"
  - "memory layout"
  - "field inference"
difficulty: "intermediate"
tags:
  - "struct-reconstruction"
  - "memory-analysis"
  - "Ghidra"
  - "Frida"
  - "game-hacking"
  - "static-analysis"
language: "zh-CN"
last_updated: "2026-07-31"
related_articles:
  - "pe-reverse/03-static-analysis/04-reclass-reconstruction"
---
# 内存结构体逆向重建

## 场景

游戏/应用使用自定义结构体（玩家对象、实体、物品），需要根据内存布局反推出 C/C++ 结构体定义。

## 输入信号

- 已知某个基地址指向结构体
- 观察到代码反复用固定偏移访问字段
- Ghidra 中看到 `*(this + 0xXX)` 模式

## 从汇编到结构体

```asm
# Ghidra 反编译输出:
*(int*)(entity + 0x36C) = 100;           # → int health at +0x36C
*(float*)(root_component + 0x1A0) = x;   # → float x at +0x1A0
*(char**)(entity + 0x268) + 0x28 + 0x14  # → char* name 指针链

# 结构体推断:
struct GameEntity {
    char  pad_0x000[0x268];     // 未知/未访问区域
    char* pName;                // +0x268 (字符串指针)
    char  pad_0x270[0xFC];     //
    int   health;               // +0x36C
    int   maxHealth;            // +0x370
    int   level;                // +0x374
    float moveSpeed;            // +0x378
    int   gold;                 // +0x37C
};
```

## 逐步重建流程

### 1. 确定结构体大小

```cpp
// 方法1: sizeof 在汇编中 manifest 为 memcpy/memset 大小
// 方法2: new/malloc 分配大小
// 方法3: 数组遍历步长
for (int i = 0; i < count; i++) {
    Entity* e = *(Entity**)(array + i * sizeof(Entity*));
    // 如果 i*0x8 则是 Entity* 数组 (8字节指针)
    // 如果 i*0x20 则是 Entity[20] 数组 (0x20 字节结构体)
}
```

### 2. 字段类型推断

```
汇编模式 → 类型
─────────────────────────────
mov eax, [ecx+XXh]          → int / DWORD (4 bytes)
mov rax, [rcx+XXh]          → uintptr_t / pointer (8 bytes)
movss xmm0, [rcx+XXh]       → float (4 bytes, SSE 标量)
movups xmm0, [rcx+XXh]      → FVector / FMatrix (16 bytes, SSE 非对齐)
cmp byte ptr [rcx+XXh], 0   → bool / byte
movzx eax, byte ptr [rcx+XXh] → uint8_t (零扩展)
lea rax, [rcx+XXh]           → 取地址 → 内嵌结构体/数组
```

### 3. 指针链 vs 内嵌对象

```cpp
// 指针链 (多级间接访问):
// getZZ(getZZ(obj + 0x40) + 0x1C0) + 0x20
// → struct A { B* pB; };  // +0x40
// → struct B { C* pC; };  // +0x1C0
// → struct C { int data[5]; };  // +0x20

struct A {
    char pad_0x00[0x40];
    B* pB;  // +0x40 → 需要 * 解引用
};

// 内嵌对象 (直接偏移):
// obj + 0x190 → 就是一个 USceneComponent 内嵌在 Actor 中
struct Actor {
    char pad_0x00[0x190];
    USceneComponent rootComponent;  // +0x190 → 直接访问, 无需解引用
};
```

## 实战重建示例: 游戏 Entity

```cpp
// 从 Ghidra xrefs 和 Frida dump 综合重建:
struct FVector {
    float X;  // +0x00
    float Y;  // +0x04
    float Z;  // +0x08
};

struct FTransform {
    FVector Translation;  // +0x00
    FVector Scale;        // +0x0C
    FVector Rotation;     // +0x18
};

struct USceneComponent {
    char pad_0x00[0x1A0];
    FVector RelativeLocation;  // +0x1A0
};

struct AActor {
    // ... vtable 和基类数据 ...
    USceneComponent* RootComponent;  // +0x190 (指针!)
    char pad_0x198[0xD0];
    int   health;          // +0x268
    float moveSpeed;       // +0x26C
};

// 验证:
AActor* actor = ReadPtr<AActor*>(entityList + i * 8);
USceneComponent* root = actor->RootComponent;  // 读取 +0x190 的指针
FVector pos = root->RelativeLocation;          // 在 root 对象内部 +0x1A0
// 不是: *(USceneComponent**)((uintptr_t)actor + 0x190)
// 而是: 先读 actor+0x190 为指针, 再读那个指针+0x1A0
```

## 从已知值反推

```cpp
// 如果观察到:
// entity+0x36C 的值在 0..100 之间 → 可能是血量 (int)
// entity+0x378 的值是 5.5, 500.0 等 → 可能是速度 (float)
// entity+0x268 的值是个大地址 → 几乎一定是字符串指针 (char*)
// entity+0x370 的值和 +0x36C 等大或更大 → 可能是 maxHealth

// 快速确认:
float* ptr = (float*)((uintptr_t)entity + 0x378);
printf("Possible float at +0x378: %f\n", *ptr);
// 如果输出是 5.5 或 500.0 → 合理
// 如果输出是 1.4e-45 或 NaN → 可能是 int 或其他类型
```

## 链表遍历模式

```cpp
// 常见: 同一结构体自引用形成链表
struct InventoryItem {
    char pad_0x00[0x98];
    InventoryItem* pNext;    // +0x98 → 下一个节点
    char pad_0xA0[0x28];
    int   itemId;            // +0xC8
    int   quantity;          // +0xCC
};

// 遍历:
InventoryItem* item = GetInventoryHead();
while (item) {
    printf("Item %d x%d\n", item->itemId, item->quantity);
    item = item->pNext;  // 跟随链表
}
```

## 证据账本与置信度

在写出 `struct` 前，为每个字段维护一条证据账本。Ghidra 的反编译与 xref 是静态证据；受控运行时的 Frida/x64dbg/ReClass 观察才是动态佐证。不要因单次内存快照就把语义命名为 confirmed。

| Offset | Width / Read-Write | Candidate type / meaning | Function / Address | Static evidence | Dynamic evidence | Confidence |
|---:|---|---|---|---|---|---|
| `+0x190` | `8 / read` | `USceneComponent* RootComponent` | `FUN_... @ RVA ...` | `mov rax, [rcx+190h]`; 后续解引用 | 指针落在已知 heap object | Inferred |
| `+0x268` | `4 / write` | `int health` | `FUN_... @ RVA ...` | `mov [rcx+268h], eax`; 调用点与伤害流程相连 | 受控测试时值递减 | Confirmed |
| `+0x378` | `4 / read` | `float moveSpeed` | `FUN_... @ RVA ...` | `movss`; 与移动分支关联 | 尚未观察 | Inferred |

证据级别：

- **Observed**：原始反汇编、Ghidra 伪代码、xref 或运行时日志直接显示的事实。
- **Inferred**：由偏移、访问宽度、调用上下文或值域推导出的类型/语义；必须保留推导依据。
- **Confirmed**：至少有相互独立的静态证据，并在安全、授权的测试中获得动态一致性验证。

记录时始终同时保留样本 SHA256、模块 image base、RVA/VA/文件偏移换算、函数地址和工具版本，避免把 ASLR 下的运行时地址误写成静态偏移。

## Frida 辅助验证

```javascript
// 读取结构体并打印所有可能的字段
function dumpStruct(addr, size) {
    for (var i = 0; i < size; i += 4) {
        var intVal = Memory.readInt(addr.add(i))
        var floatVal = Memory.readFloat(addr.add(i))
        var ptrVal = Memory.readPointer(addr.add(i))
        console.log(`+0x${i.toString(16)}: int=${intVal} float=${floatVal} ptr=${ptrVal}`)
    }
}
```

## 攻击链

```
Ghidra 观察 *(this+0xXX) 模式 → 记录所有偏移和访问类型
→ Frida dump 运行时的偏移值 → 对比正常值范围 → 推断类型/语义
→ 观察数组遍历步长 → 确认 sizeof → 补齐结构体定义
→ 用 READ/WRITE 测试验证字段功能正确
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| Ghidra 自动分析生成 decompiled code | `ghidra_headless_analyze` | Ghidra 自动分析生成 decompiled code |
| 读单个函数 callers/callees/decompile | `ghidra_summary_function_detail` | 读单个函数的 callers/callees/decompile 证据，观察 `*(this+0xXX)` 模式 |
