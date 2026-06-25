# Unity IL2CPP 静态逆向与偏移发现

## 场景

目标 APK 使用 Unity IL2CPP，核心逻辑在 `libil2cpp.so`。需要定位关键数据结构偏移、函数地址，不依赖运行时 dump。

## 输入信号

- `lib/arm64-v8a/libil2cpp.so` 存在
- `assets/bin/Data/Managed/Metadata/global-metadata.dat` 存在
- jadx 中只有 Stub 方法，无实际 C# 逻辑

## 工具链

```
readelf/smaps → 模块基址 → Ghidra/IDA 载入 → 偏移表 → Frida 验证
```

## 核心步骤

### 1. 模块基址获取

运行时三种方式：

```c
// 方式1: /proc/pid/maps 解析 (最常用)
long get_module_base(pid_t pid, const char *name) {
    char maps[64]; sprintf(maps, "/proc/%d/maps", pid);
    FILE *fp = fopen(maps, "r");
    char line[512], perms[5], path[256];
    long start, end;
    while (fgets(line, sizeof(line), fp)) {
        sscanf(line, "%lx-%lx %s %*s %*s %*s %s", &start, &end, perms, path);
        if (strstr(path, name) && perms[0] == 'r' && perms[2] == 'x')
            { fclose(fp); return start; }
    }
    fclose(fp); return 0;
}

// 方式2: syscall (需要内核驱动)
// ioctl(fd, OP_MODULE_BASE, &mb)

// 方式3: dl_iterate_phdr 回调 (SO 内自定位)
```

### 2. IL2CPP 关键结构

`global-metadata.dat` 包含完整的类型/方法/字符串映射：

```
Magic: 0xFAB11BAF
→ stringLiteralOffset → stringLiteralData
→ metadataStrings → 类型名/方法名/字段名字符串池
→ typeDefinitions → TypeDefinitionIndex (含字段偏移)
→ methodDefinitions → 方法地址 index → 映射到 libil2cpp.so 中的函数
```

### 3. 偏移发现实战模式

```c
// 实战模式: 三指针链定位
// 例: Unity IL2CPP 游戏人物数组
long libbase = get_module_base(pid, "libil2cpp.so");
long staticRegion = libbase + 0xD9BA000;    // .data/.bss 静态区偏移
long root = *(long*)(staticRegion + 0x4BCB0); // 第1跳: 静态指针
long level2 = *(long*)(root + 0xB0);          // 第2跳: 管理器对象
long level3 = *(long*)(level2 + 0x50);        // 第3跳: 容器
long level4 = *(long*)(level3 + 0xA0);        // 第4跳: 数组头
long arrayHead = *(long*)(level4 + 0x30);     // 第5跳: 数据数组
// 遍历: arrayHead[i * 0x20] = 玩家对象指针
```

### 4. 偏移交叉验证

```
// Ghidra 静态: 找到疑似数组访问 → 记录偏移
// Frida 动态: hook 偏移读写 → 观察返回值变化
// 已知特征: 血量通常在 +0x360~0x380 附近 (int)
//          名字字符串指针在 +0x260~0x280 附近 (char*)
//          坐标 float 在 matrix 结构内
```

## Frida 快速验证

```javascript
var libbase = Module.findBaseAddress("libil2cpp.so")
var candidate = libbase.add(0xD9BA000)  // 静态区
var root = candidate.add(0x4BCB0).readPointer()
console.log("root:", root)
// 逐级验证直到找到有意义的数据
```

## 常见误判

- IL2CPP 版本不同，global-metadata 布局差异大 → 先确认 Unity 版本
- 静态区偏移随版本更新变化 → 用特征码替代硬编码地址
- `libil2cpp.so` 被混淆/加壳后函数边界模糊 → 先用 DiE 检测

## 攻击链

```
APK → 确认 Unity+IL2CPP → 提取 global-metadata.dat → Il2CppInspector/Ghidra 解析
→ 定位静态区基址偏移 → 指针链追踪 → Frida 动态验证 → 锁定数据结构
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| Ghidra 导入+自动分析 SO/DLL | `ghidra_headless_analyze` | 无头 Ghidra 导入+自动分析 SO/DLL |
| 函数阅读优先级推荐 | `ghidra_summary_call_focus` | 按行为推荐函数阅读优先级 |
| Frida 动态验证偏移 | `android_frida_run_script` | 运行 Frida 脚本验证偏移 |
| SO/DLL 初筛 | `triage_pe` | SO/DLL 初筛（hash/DiE/节区/导入表/字符串） |
