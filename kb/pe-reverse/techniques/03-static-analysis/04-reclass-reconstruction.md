# ReClass 结构体实时重建

## 场景

运行时观察到游戏内存中有复杂的数据结构，需要实时交互地构建 C++ 结构体定义，直接观察字段变化。

## 输入信号

- 已知某实体的内存地址（Cheat Engine / x64dbg 找到）
- 知道该地址处是一个结构体/对象的起始
- 需要快速确定各字段偏移和类型

## ReClass 基础工作流

```
1. 附加到目标进程
2. 输入基地址 → 显示原始字节（hex dump）
3. 逐字段定义类型和名称
4. 观察游戏内变化 → 对应字段值变化 → 确认语义
5. 导出为 C++ struct 代码
```

## 典型分析过程

```
已知: 玩家对象地址 0x1A2B3C4D0000

ReClass 操作:
1. 新建 Class → Name: "Player"
2. 在 hex dump 窗口观察:
   +0x000: 48 8B 05 XX XX XX XX  → 可能是 vtable 指针
   +0x008~0x0FC: 看起来像 padding (全是 0 或重复模式)
   +0x100: 42 C8 00 00            → 200.0f! (float)
   +0x104: 42 C8 00 00            → 200.0f! → MaxHealth?
   +0x108: 41 A0 00 00            → 20.0f
   +0x10C: 00 00 00 00            → 0 → 可能是 int

3. 逐个添加字段:
   +0x000: VTable* pVTable        (作为 hex 64)
   +0x100: float health           (游戏内受伤确认下降)
   +0x104: float maxHealth        (始终 ≥ health)
   +0x108: float moveSpeed        (移动时非零)
   +0x10C: int   teamId           (0/1 对应两个队伍)
```

## 字段类型速查

```
ReClass 类型       → 对应 C++ 类型
Hex8               → uint8_t
Hex16              → uint16_t
Hex32              → uint32_t
Hex64              → uint64_t (常用于指针)
Int8/16/32/64      → signed int
Float              → float (32-bit IEEE754)
Double             → double
Vector2/3/4        → FVector2/3/4 (连续 2/3/4 个 float)
PChar              → char* (显示为字符串)
Pointer            → void* (灰色显示, 可展开跟踪)
Array              → 数组 (指定元素类型和 count)
UTF8/UTF16         → 宽字符/窄字符串
```

## 实战技巧

### 1. 向量类型确认

```
// 如果三个连续 float 一起变化 → Vector3
// 如果两个 float 独立变化 → 两个独立 float
+0x1A0: [ 1.0, 2.0, 3.0 ]  // 移动后 XYZ 都变 → Vector3 position
+0x100: [ 100.0 ]           // 单独变化
+0x104: [ 100.0 ]           // 不随移动变化 → 独立 float
```

### 2. 指针 vs 值类型

```
ReClass hex dump:
+0x190: 0x2B3C4D5E0000  → 64-bit 值, 格式像地址 → Pointer
        → 右键: Change Type → Pointer → 填入目标地址
        → ReClass 打开新 tab 显示指向的结构体

+0x190: 0x000000000064  → 小值 (0x64 = 100) → 可能是 int
        → 不是指针!
```

### 3. 数组识别

```
+0x200: [ptrA, ptrB, ptrC, ptrD, 0, 0, 0, 0]
        → 前 4 个是指针, 后 4 个是 NULL
        → 类型: Pointer[8] (最大 8 个元素的数组)
        → 或 Array of Pointer, count=4 (已知只有 4 个)

+0x200: [120.0, 0.0, 0.0, 120.0, ...]
        → 如果是矩阵: 4x4 float matrix (16 * 4 = 64 bytes)
        → 类型: float[16]
```

## 导出为 C++

```cpp
// ReClass 自动生成:
struct Player {
    char pad_0x0000[0x190];     // 0x0000
    USceneComponent* RootComp;  // 0x0190
    char pad_0x0198[0xD0];      // 0x0198
    int health;                 // 0x0268
    int maxHealth;              // 0x026C
    int teamId;                 // 0x0270
    char pad_0x0274[0x108];     // 0x0274
    float moveSpeed;            // 0x037C
}; // Size=0x0380
```

## 配合 Cheat Engine

```
1. CE 扫描: "Increased value" / "Decreased value" → 找到血量地址
2. CE "Find out what writes to this address" → 找到修改血量的代码
3. Ghidra 从这段代码反推结构体偏移
4. ReClass: 输入基地址, 用上述偏移定义字段
5. 验证: 游戏内改变状态 → ReClass 值同步变化
```

## 配合 Ghidra

```
Ghidra 发现: *(int*)(entity + 0x268) = health
→ ReClass 在 entity 地址定义:
   +0x268: Int32 health

Ghidra 发现: *(float*)(*(uintptr_t*)(entity + 0x190) + 0x1A0) = pos.X
→ ReClass 在 entity 地址定义:
   +0x190: Pointer → 跳转到新地址 → +0x1A0: Vector3 position
```

## 攻击链

```
Cheat Engine 找到基地址 → ReClass 新建 class → 输入基地址
→ Hex dump 观察原始字节 → 逐字段定义类型
→ 游戏内操作触发变化 → 确认字段语义 (血量/坐标/速度/Id)
→ 导出 C++ struct → Ghidra 中配合分析 → 完成结构体重建
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 查找目标函数地址 | `ghidra_summary_functions` | 查找目标函数地址 |
| 获取函数签名和参数类型 | `ghidra_summary_function_detail` | 获取函数签名和参数类型信息 |

## 证据与验证闭环

- 记录样本 SHA256、架构、映像基址、RVA/VA/文件偏移换算及工具版本。
- 静态结论绑定函数、Xref、导入、字符串和反编译片段；动态结论绑定断点、寄存器、栈、内存与调用时序。
- 原始样本只读保留，dump/patch 使用副本并记录前后哈希、原始字节、新字节和行为差异。
- 将 x64dbg/Frida/Procmon/Ghidra 输出保存到 `exports/windows/`，从干净基线最小化复现后再下结论。
