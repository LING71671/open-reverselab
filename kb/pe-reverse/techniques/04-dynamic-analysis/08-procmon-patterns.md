# Procmon 行为监控与过滤

## 场景

需要对目标进程进行非侵入式行为监控——文件访问、注册表操作、进程/线程创建、网络连接。Procmon 是首选工具。

## 输入信号

- 目标 PE 运行时有文件/注册表/网络活动
- 需要关联时间线，确定初始化顺序
- 需要过滤噪音（系统进程、已知安全软件）

## Procmon 过滤规则生成

```
Procmon 默认捕获全系统事件 → 噪音巨大 → 必须过滤

基本过滤:
  1. Process Name → is → target.exe → Include
  2. Operation → is → WriteFile → Include (只看写文件)
  3. Path → contains → C:\Users → Include (只看用户目录)

组合过滤:
  1. Process Name → is → target.exe → Include
  2. Operation → is → RegSetValue → Include
  3. Path → contains → Run → Include  (只看 Run 键)
```

## 实战场景过滤集

### 场景 1: 追踪文件落盘

```
Include: Process Name is target.exe
Include: Operation is WriteFile
Include: Operation is CreateFile (仅 CreateDisposition=CREATE_ALWAYS)
Exclude: Path contains C:\Windows    (排除系统目录写入)
Exclude: Path contains .log         (排除日志)
Include: Path contains C:\Users     (只看用户目录)
Include: Path contains AppData
```

### 场景 2: 追踪注册表持久化

```
Include: Process Name is target.exe
Include: Operation is RegSetValue
Include: Path contains Run          (Run/RunOnce)
Include: Path contains Winlogon
Include: Path contains Services
Include: Path contains Image File Execution Options
```

### 场景 3: 追踪进程注入

```
Include: Process Name is target.exe
Include: Operation is ProcessCreate
Include: Operation is LoadImage     (DLL 加载)
Include: Operation is CreateRemoteThread
Include: Operation is VirtualAllocEx
Include: Detail contains target     (过滤相关进程)
```

### 场景 4: 追踪网络连接

```
Include: Operation is TCP Connect
Include: Operation is TCP Receive
Include: Operation is TCP Send
Include: Operation is UDP Send
Include: Operation is UDP Receive
Include: Path contains <target IP>  (如已知道 IP)
```

## 时间线分析

```
Procmon 输出示例:
Time        Operation    Path                    Detail
12:00:01    CreateFile   C:\data\config.dat      SUCCESS
12:00:03    RegOpenKey   HKLM\Software\App       SUCCESS
12:00:03    RegQueryValue                         "Version"="1.0"
12:00:05    TCP Connect  192.168.1.1:443          SUCCESS
12:00:10    WriteFile    C:\data\output.bin       Offset:0 Len:4096
12:00:15    ProcessCreate C:\Windows\temp\helper.exe

分析:
1. 首先读配置文件
2. 读注册表配置
3. 建立网络连接 (C2?)
4. 写数据文件 (exfil?)
5. 创建子进程 (dropper?)
```

## 导出与分析

```
Procmon → File → Save → CSV → 用 Python 分析

import pandas as pd
df = pd.read_csv('Logfile.CSV')

# 按操作类型统计
ops = df['Operation'].value_counts()
# RegOpenKey     234
# ReadFile       128
# WriteFile       15
# TCP Connect      2

# 唯一文件路径
paths = df[df['Operation']=='WriteFile']['Path'].unique()
# %USERPROFILE%\AppData\Local\Temp\tmp1234.dat
# %USERPROFILE%\AppData\Roaming\malware\config.enc

# 唯一网络目标
ips = df[df['Operation']=='TCP Connect']['Path'].unique()
# 45.67.89.123:443
```

## 过滤规则生成器

```cpp
// 根据目标的导入表生成 Procmon 过滤规则
struct ProcmonFilter {
    std::vector<std::string> includeOperations;
    std::vector<std::string> includePaths;
    std::vector<std::string> excludePaths;
};

ProcmonFilter GenerateFromImports(const char* targetPath) {
    ProcmonFilter filter;
    // 1. 用 PE parser 提取导入 API
    // 2. 按 API 类别生成规则:
    //    WriteFile → Include Operation: WriteFile, CreateFile
    //    RegSetValue → Include Operation: RegSetValue, RegCreateKey
    //    socket/connect → Include Operation: TCP/UDP Connect
    //    CreateProcess → Include Operation: ProcessCreate
    return filter;
}
```

## 攻击链

```
启动 Procmon BTN 开始捕获 → 运行目标 PE → 目标行为完成 → 停止捕获
→ 设置过滤: Process Name → Apply → 按 Operation 分类
→ 时间线分析: 操作类型/路径/结果 → 提取关键文件/注册表/网络 IOC
→ Export CSV → Python 聚合统计 → 理解完整行为链
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 启动 Procmon 采集 | `procmon_start_capture` | 启动 Procmon 采集 |
| 停止采集 | `procmon_stop_capture` | 停止采集 |
| 导出 CSV 分析 | `procmon_export_csv` | 导出 CSV 分析 |
| 自动生成 Procmon 过滤方案 | `make_procmon_filters` | **根据样本导入表自动生成 Procmon 过滤方案** → `scripts/windows/procmon/` |

## 证据与验证闭环

- 记录样本 SHA256、架构、映像基址、RVA/VA/文件偏移换算及工具版本。
- 静态结论绑定函数、Xref、导入、字符串和反编译片段；动态结论绑定断点、寄存器、栈、内存与调用时序。
- 原始样本只读保留，dump/patch 使用副本并记录前后哈希、原始字节、新字节和行为差异。
- 将 x64dbg/Frida/Procmon/Ghidra 输出保存到 `exports/windows/`，从干净基线最小化复现后再下结论。
