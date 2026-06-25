# PE 脱壳与内存 Dump

## 场景

目标 PE 被加壳（UPX/ASPack/VMProtect/Themida），静态分析无法看到真实代码。需在运行时等壳解密后 dump 出展开的内存镜像。

## 输入信号

- DiE/diec 检测到 "UPX(0)" 或 "ASPack" 等壳签名
- 节区名异常（UPX0/UPX1/.aspack/.vmp）
- 入口点在非 .text 节区
- 导入表极简（只有 LoadLibrary/GetProcAddress 等少数 API）

## 壳行为模型

```
正常 PE 加载:
  loader → 映射 PE → 填充 IAT → 跳转到 EntryPoint (原始代码)

加壳 PE 加载:
  loader → 映射 PE → 填充 IAT → 跳转到 EntryPoint (壳代码)
  → 壳解密原始节区 → 重建 IAT → 跳转到 OEP (Original Entry Point)
  → 原始代码执行
```

## 脱壳时机

```
关键时间窗口:
1. 壳解密完成 → 但尚未跳转到 OEP (最干净)
2. OEP 刚被执行 → 导入表已重建 (可直接用)
3. 任意稳定运行点 → 所有代码已展开

方法选择:
方法1: x64dbg → 运行到 OEP → Scylla dump + IAT rebuild
方法2: Frida → 在 OEP 处 dump 进程内存
方法3: ProcDump → 附加到运行中的进程 → 全内存 dump
```

## 方法 1: x64dbg + Scylla

```
1. x64dbg 加载加壳 PE
2. 设置断点: bp VirtualAlloc (壳常在此分配解密缓冲区)
3. F9 运行 → 断在 VirtualAlloc → 记录返回的地址 (解密缓冲区)
4. 关注大块内存分配 + 写入后执行
5. 在疑似 OEP 处设硬件断点
6. F9 → 到达 OEP → 此时所有原始代码已解密
7. Scylla: IAT Autosearch → Get Imports → Dump → Fix Dump
```

## 方法 2: Frida 运行时 Dump

```javascript
// Hook 模块加载, dump 解密后的 so/dll
function dumpModule(moduleName) {
    var mod = Process.findModuleByName(moduleName)
    if (!mod) {
        console.log("Module not found:", moduleName)
        return
    }
    var base = mod.base
    var size = mod.size
    console.log("Dumping", moduleName, "base:", base, "size:", size)
    var data = Memory.readByteArray(base, size)
    // send() 到 PC 端落盘
    send({
        type: 'dump',
        name: moduleName,
        base: base.toString(),
        size: size,
        data: Array.from(new Uint8Array(data))
    })
}

// 在进程初始化后调用
setTimeout(function() {
    dumpModule("target.dll")
    // 或 dump 主模块
    dumpModule(Process.enumerateModules()[0].name)
}, 3000)
```

```python
# PC 端接收 dump 数据
import frida, sys

def on_message(message, data):
    if message['type'] == 'send' and message['payload']['type'] == 'dump':
        payload = message['payload']
        with open(f"{payload['name']}.dumped", 'wb') as f:
            f.write(bytearray(payload['data']))
        print(f"Dumped {payload['name']} ({payload['size']} bytes)")

session = frida.attach("target.exe")
script = session.create_script(open("dump.js").read())
script.on('message', on_message)
script.load()
sys.stdin.read()
```

## 方法 3: ProcDump 全进程 Dump

```powershell
# Sysinternals procdump
procdump.exe -ma target.exe  # -ma: full memory dump with all sections

# 或任务管理器: 右键进程 → Create Dump File
# 会生成 .dmp 文件, 可用 WinDbg/x64dbg 打开分析
```

## 方法 4: 手动 API Hook Dump

```cpp
// Hook VirtualAlloc/VirtualProtect 追踪壳行为
// 壳在解密代码时必然调用 VirtualAlloc 或 VirtualProtect 改页属性
HANDLE WINAPI Hooked_VirtualAlloc(LPVOID addr, SIZE_T size,
    DWORD allocType, DWORD protect) {
    LPVOID result = Original_VirtualAlloc(addr, size, allocType, protect);

    if (protect == PAGE_EXECUTE_READWRITE ||
        protect == PAGE_EXECUTE_READ) {
        // 壳分配了可执行内存 → 可能是解密后的代码
        printf("[*] VirtualAlloc: addr=%p size=%zx protect=%s\n",
            result, size, protect & PAGE_EXECUTE ? "X" : "RW");

        // 自动 dump
        char filename[256];
        sprintf(filename, "dump_%p.bin", result);
        FILE* f = fopen(filename, "wb");
        fwrite(result, 1, size, f);
        fclose(f);
    }
    return result;
}
```

## IAT 修复

```
问题: dump 出的 PE 中的 IAT (Import Address Table) 可能不完整
原因: 壳自己解析 API 并填充了自定义 IAT, 位置可能与原始 PE 不同

修复:
1. Scylla: 自动搜索 IAT → 解析 → 修正 dump 中的导入表
2. 手动: 从运行中进程的 IAT 地址复制回 dump 文件
3. 替代: 不修复 IAT, 直接分析 dump 作为 raw binary (Ghidra 加载时选 raw)
```

## 检测常见壳

```bash
# DiE 命令行
diec -b target.exe
# 输出: UPX(0)[-] → UPX 压缩
#      ASPack(1.0) → ASPack
#      VMProtect(2.x) → VMProtect

# PEiD 特征检测
# 入口点节区判断:
# 如果 EntryPoint 不在 .text 而在 .upx0 → 确定是 UPX
```

## 攻击链

```
DiE 检测壳类型 → 确定脱壳策略
→ UPX/ASPack: x64dbg 运行到 OEP → Scylla dump + fix
→ VMProtect/Themida: Frida attach → dump 内存中解密模块
→ 加载 dump 到 Ghidra → 确认代码可读 → 开始静态分析
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| DiE 检测壳签名 | `die_scan` | DiE 检测壳签名 |
| 一键生成脱壳动态分析包 | `make_pe_crypto_unpack_plan` | **一键生成脱壳动态分析包**（x64dbg 断点 + Frida hook + 函数队列） |
| 从 dump buffer 自动 carve PE payload | `carve_payloads_from_dump` | 从 dump buffer 自动 carve PE payload → `samples/unpacked/` |

## 证据与验证闭环

- 记录样本 SHA256、架构、映像基址、RVA/VA/文件偏移换算及工具版本。
- 静态结论绑定函数、Xref、导入、字符串和反编译片段；动态结论绑定断点、寄存器、栈、内存与调用时序。
- 原始样本只读保留，dump/patch 使用副本并记录前后哈希、原始字节、新字节和行为差异。
- 将 x64dbg/Frida/Procmon/Ghidra 输出保存到 `exports/windows/`，从干净基线最小化复现后再下结论。
