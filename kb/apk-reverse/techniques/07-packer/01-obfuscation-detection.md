# 编译期混淆检测与识别

## 场景

APK 中 native lib 被编译期混淆保护（字符串加密、控制流平坦化、常量隐藏），静态分析时函数逻辑不可读。需要识别混淆类型并选择对应的分析策略。

## 输入信号

- strings 命令输出 lib 中无可读字符串
- Ghidra 导入后函数体巨大、分支密集
- 反编译结果充满 `*(uint*)(&DAT_xxxx ^ mask)` 模式
- 节区名异常或入口点可疑

## 常见混淆类型

### 1. oxorany: 编译期 XOR 常量加密

```cpp
// 源码中调用 oxorany(常量) 会在编译期被 XOR 加密
// 运行时通过内联函数解密，静态分析中看到的是加密值
// 特征: 反编译中出现大量 xor 运算是立即数
// *(int*)(local_buf + 0x10) = 0x3C7A9B2D ^ 0x5A3C1F7E;
```

识别方法:
- Ghidra 中搜索 `XOR` 指令占比异常高 (>40%)
- 函数开头有固定解密的循环模式
- 字符串被拆散为字节数组 + 运行时拼接

### 2. OLLVM/Arkari: 控制流平坦化

```
// 特征: 函数开头有大 switch 分发器
// 每个基本块分配 case id, 块末尾跳回 switch
// Ghidra 图模式显示为"菊花状"结构
```

识别方法:
- IDA `findPrologue` 后函数体第一行是 `switch(stateVar)`
- 函数控制流图呈星型收敛到单一分发块
- 真实代码块被拆散, 通过 stateVar 顺序连接

### 3. UPX/壳变种

```bash
# 检测
diec -b $SO_PATH         # DiE 直接判断
readelf -S $SO_PATH      # 查看节区: UPX0/UPX1 节区
strings $SO_PATH | grep "UPX"
```

魔改 UPX 特征:
- UPX 标准 magic 被修改 (不再以 "UPX!" 开头)
- 解压 stub 入口被混淆
- 节区名改通用名但仍保留压缩节区比例异常

### 4. 字符串表加密

```
// .rodata 中字符串在链接后被 XOR/Cipher 加密
// .init_array 中有解密函数先于 main 执行
// 识别: .init_array 中函数引用了 .rodata 大量地址
```

## 逆向策略

| 混淆类型 | 策略 |
|---------|------|
| oxorany | 不跟 XOR 逻辑；用 Frida 在调用点 dump 明文参数 |
| OLLVM 平坦化 | 用 Ghidra 脚本反混淆 / `HexRaysDeob` (IDA) 插件 / angr 符号执行 |
| UPX 变种 | 动态: `frida -f` spawn + 在 `dlopen` 后 dump so |
| 字符串加密 | Frida hook `.init_array` 执行后的关键函数, 抓明文 |

## Frida 通用脱壳模板

```javascript
// 在 lib 加载后 dump 解密的内存
var lib = Process.findModuleByName("libtarget.so")
var base = lib.base
var size = lib.size
var data = Memory.readByteArray(base, size)
// send() 到 PC 落盘
```

## 攻击链

```
.so 文件 → DiE/diec 检测壳签名 → strings 判断明文率 → Ghidra 打开确认混淆类型
→ 有壳: Frida spawn + dump → 无壳: 反混淆插件处理 → 重新静态分析
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| DiE/diec 检测壳/混淆签名 | `die_scan` | DiE/diec 检测壳/混淆签名 |
| Frida spawn + dump 解密后 dex/so | `android_crypto_unpack_recipe` | Frida spawn + dump 解密后 dex/so |
| 从 dump 中自动 carve DEX payload | `carve_payloads_from_dump` | 从 dump 中自动 carve DEX payload |
| 分析 dump 出的 clean 文件 | `ghidra_headless_analyze` | 分析 dump 出的 clean 文件 |

## 证据与验证闭环

- 记录 APK/SO 的 SHA256、包名、版本、ABI、设备/Android/Frida 版本及原始样本路径。
- 静态结论必须绑定类名、方法签名、RVA/文件偏移、字符串或 Xref；动态结论绑定 hook 点、参数、返回值和时间戳。
- 在未修改样本与实验副本上分别复现，保存 Frida 日志、dump 哈希和重放脚本到 `exports/android/`。
- Patch/重打包必须记录原始字节、修改字节、签名方式和安装启动结果，不能以“构建成功”代替行为验证。
