# YARA 规则编写（逆向视角）

## 场景

分析完目标 PE 后，需要编写 YARA 规则标记该样本家族，用于后续快速分类和识别同类样本。

## 输入信号

- 已完成一个样本的静态/动态分析
- 提取了独特的字符串、字节序列、导入表特征
- 需要编写通用规则捕获变种

## YARA 规则结构

```yara
rule SampleFamily_Detector {
    meta:
        author = "analyst"
        description = "Detects SampleFamily RAT v2.x"
        date = "2025-06"
        hash = "a1b2c3d4e5f6..."

    strings:
        // 字符串特征
        $str1 = "C2PanelPassword" ascii wide
        $str2 = "svchost_helper.exe" ascii
        $str3 = "/api/upload.php" ascii

        // 十六进制特征 (唯一指令序列)
        $code1 = { 48 8B 05 ?? ?? ?? ?? 48 89 45 F8 48 8B 45 F8 48 8B 40 10 }
        $code2 = { 55 8B EC 83 EC 08 53 56 57 8B 7D 08 }

        // 正则表达式
        $re1 = /[a-f0-9]{32}-[0-9]{4}-[0-9a-f]{8}-[a-f0-9]{16}/  // UUID

    condition:
        // 条件逻辑
        uint16(0) == 0x5A4D and      // MZ 头
        filesize < 500KB and
        2 of ($str*) and             // 至少 2 个字符串匹配
        $code1                       // 必须匹配特征码
}
```

## 提取优质特征

### PE 结构特征

```yara
condition:
    uint16(0) == 0x5A4D and                          // MZ
    uint32(uint32(0x3C)) == 0x00004550 and            // PE\0\0
    pe.number_of_sections >= 3 and
    pe.sections[0].name == ".text" and
    pe.sections[1].name == ".rdata" and
    // 特征: .data 节区异常大 (加壳迹象)
    pe.sections[2].raw_data_size > 0x100000
```

### 导入表特征

```yara
import "pe"

condition:
    pe.imports("kernel32.dll", "VirtualAllocEx") and
    pe.imports("kernel32.dll", "WriteProcessMemory") and
    pe.imports("kernel32.dll", "CreateRemoteThread") and
    // DLL 注入三件套 → 高置信度判断行为意图
    pe.imports("kernel32.dll", "IsDebuggerPresent") and
    pe.imports("ntdll.dll", "NtQueryInformationProcess")
    // 反调试特征
```

### 字符串特征

```yara
strings:
    // 独特字符串 (从 Ghidra strings 视图提取)
    $c2 = "https://evil-c2.example.org/api/beacon" ascii
    $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" ascii
    $mutex = "Global\\AV_Update_Check_Mutex" ascii wide
    $cmd = "cmd.exe /c " ascii wide

    // 变异字符串 (变种常改值)
    // 不用绝对路径, 用路径片段
    $path = "\\AppData\\Roaming\\" ascii

condition:
    3 of them  // 至少匹配 3 个字符串
```

### 代码特征 (AOB)

```yara
strings:
    // 从 Ghidra 提取的独特指令序列
    // 例: 自定义加密函数的特征
    $rc4_init = {
        48 89 5C 24 08      // mov [rsp+8], rbx
        48 89 74 24 10      // mov [rsp+0x10], rsi
        57                  // push rdi
        48 83 EC 20         // sub rsp, 0x20
        48 8B F1            // mov rsi, rcx
        48 8B FA            // mov rdi, rdx
        C7 44 24 30 00 01 00 00  // mov [rsp+0x30], 0x100
    }

    // 例: 进程注入 stub
    $inject_stub = {
        55                     // push ebp
        8B EC                  // mov ebp, esp
        6A 00                  // push 0
        68 [4]                 // push dllPath (4-byte 占位)
        68 [4]                 // push LoadLibraryA
        FF 55 08               // call [ebp+8]
    }

condition:
    any of ($rc4_init, $inject_stub)
```

## 实战规则示例：DLL 注入器

```yara
rule HackTool_DLL_Injector_Generic {
    meta:
        description = "Generic DLL injector using CreateRemoteThread pattern"
        severity = "medium"

    strings:
        $s1 = "InjectDLL" ascii nocase
        $s2 = "CreateRemoteThread" ascii
        $code1 = { 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? }
        // VirtualAllocEx → WriteProcessMemory → CreateRemoteThread 连续调用

    condition:
        uint16(0) == 0x5A4D and
        filesize < 200KB and
        (2 of ($s*)) and
        $code1
}
```

## 测试规则

```bash
# 对已知样本集测试
yara64.exe rule.yara C:\samples\malware\ -r -s
# -r: 递归扫描
# -s: 显示匹配的字符串

# 输出:
# HackTool_DLL_Injector_Generic samples/malware/injector_v2.exe
# 0x12a4:$code1: 8B 45 08 50 FF 15 ...
# 0x3f00:$s1: InjectDLL
```

```powershell
# 扫描运行中进程 (需要 procdump 先 dump)
procdump.exe -ma <PID>
yara64.exe rule.yara target.dmp -s
```

## 规则演化

```
v1.0: 匹配原始样本 → 脱壳/混淆版本漏报
v1.1: 加入脱壳后代码特征 → 新版本添加新字符串, 修改规则
v2.0: 改为行为特征 (导入表 + 代码模式) → 覆盖更多变种
```

## 攻击链

```
完成样本分析 → 提取独特字符串 (Ghidra Defined Strings) 
→ 提取代码特征 (Ghidra 选中指令 → Copy Bytes)
→ 提取 PE 结构特征 → 编写 YARA 规则
→ yara64 扫描样本集测试 → 调整避免误报 → 部署规则
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 提取 IOC 作为 YARA/Sigma 素材 | `extract_iocs_from_summary` | 提取 IOC 作为 YARA/Sigma 素材 |
| 自动生成 YARA 规则草案 | `make_yara_stub` | 自动生成 YARA 规则草案 → `exports/windows/yara/` |
| 自动生成 Sigma 规则草案 | `make_sigma_stub` | 自动生成 Sigma 规则草案 → `exports/windows/sigma/` |

## 证据与验证闭环

- 记录样本 SHA256、架构、映像基址、RVA/VA/文件偏移换算及工具版本。
- 静态结论绑定函数、Xref、导入、字符串和反编译片段；动态结论绑定断点、寄存器、栈、内存与调用时序。
- 原始样本只读保留，dump/patch 使用副本并记录前后哈希、原始字节、新字节和行为差异。
- 将 x64dbg/Frida/Procmon/Ghidra 输出保存到 `exports/windows/`，从干净基线最小化复现后再下结论。
