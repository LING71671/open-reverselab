# IOC 提取技巧

## 场景

分析目标 PE 后需要提取 Indicators of Compromise（C2 地址、文件路径、注册表键、互斥体名、User-Agent 等），用于后续检测和关联。

## 输入信号

- 已获取 PE 文件 + 可能的内存 dump
- 已有 Ghidra 分析结果（字符串表 + 导入表 + 反编译）
- 已有 Procmon/网络抓包日志

## IOC 分类提取

### 1. 网络 IOC

```bash
# 从 strings 输出提取 IP/域名/URL
strings target.exe | grep -oP '([a-zA-Z0-9-]+\.){1,}[a-zA-Z]{2,}'
# output:
# evil-c2.malware.net
# update-server.example.com
# api.stealer.org

strings target.exe | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
# 45.67.89.123
# 192.168.1.1        ← 可能不是 C2, 是 local debug

strings target.exe | grep -oP 'https?://[^"'\''\s]+'
# https://evil-c2.malware.net/api/upload
```

```python
# 用 Ghidra Python 提取
def extract_urls_from_ghidra():
    urls = set()
    sm = currentProgram.getListing()
    it = sm.getDefinedStrings(True)
    while it.hasNext():
        s = it.next()
        value = s.getValue()
        if 'http://' in value or 'https://' in value:
            urls.add(value)
        # IP 正则
        import re
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', value)
        for ip in ips:
            if not ip.startswith(('127.', '192.168.', '10.', '172.')):
                urls.add(ip)
    return urls
```

### 2. 文件路径 IOC

```bash
strings target.exe | grep -E '(C:|D:)\\\\|\\\\[\w]+\\\\|AppData|ProgramData|Temp'
# %USERPROFILE%\AppData\Roaming\malware\config.dat
# C:\ProgramData\Microsoft\svchost_helper.exe
# %APPDATA%\malware\
```

### 3. 注册表 IOC

```bash
strings target.exe | grep -iE 'HKEY|HKLM|HKCU|Software\\\\Microsoft\\\\Windows'
# SOFTWARE\Microsoft\Windows\CurrentVersion\Run
# SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
# HKEY_CURRENT_USER\Software\malware
```

### 4. 互斥体/管道 IOC

```bash
strings target.exe | grep -E 'Global\\\\|Local\\\\|\\\\\.\\\\pipe\\\\'
# Global\Malware_Update_Mutex
# Global\AV_Config_Sync
# \\.\pipe\malware_pipe
```

### 5. User-Agent / HTTP Header

```bash
strings target.exe | grep -iE 'User-Agent|Content-Type|Authorization'
# User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...
# 注意: UA 可能是 Chrome 默认值, 需结合上下文判断
```

## 从 Ghidra 导出结构化 IOC

```python
# Ghidra 脚本: 自动提取 IOC
from ghidra.program.model.listing import CodeUnit

def extract_iocs():
    iocs = {
        'ips': set(), 'domains': set(), 'urls': set(),
        'files': set(), 'regkeys': set(), 'mutexes': set(),
        'uas': set()
    }
    
    listing = currentProgram.getListing()
    data_it = listing.getDefinedData(True)
    
    import re
    while data_it.hasNext():
        data = data_it.next()
        if not data.hasStringValue():
            continue
        
        value = data.getValue()
        if not isinstance(value, str):
            continue
        
        # 域名
        if re.match(r'^[a-zA-Z0-9.-]+\.(com|org|net|info|io|xyz|top|cc)$', value):
            iocs['domains'].add(value)
        
        # IP
        for ip in re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', value):
            if not ip.startswith(('127.', '0.', '255.')):
                iocs['ips'].add(ip)
        
        # 文件路径
        if 'C:\\' in value or 'AppData' in value or 'ProgramData' in value:
            iocs['files'].add(value)
        
        # ... 其他 IOC 类型
        
    return iocs
```

## IOC 置信度标注

```python
# 三层置信度
def classify_confidence(ioc, analysis_results):
    """
    confirmed: Ghidra xref 确认该 IOC 被代码引用
    probable: 存在于 strings 中, 位置在可疑函数附近
    possible: 存在于 PE 中, 但无直接引用证据
    """
    if ioc in analysis_results['xref_targets']:
        return 'confirmed'
    if ioc in analysis_results['in_suspicious_function']:
        return 'probable'
    return 'possible'
```

## 输出 MISP 格式

```json
{
    "values": [
        {
            "value": "45.67.89.123",
            "type": "ip-dst",
            "comment": "C2 server IP, found in encrypted config at 0x40A230",
            "confidence": "confirmed",
            "tags": ["c2", "tcp/443"]
        },
        {
            "value": "Global\\Malware_Update_Mutex",
            "type": "mutex",
            "confidence": "confirmed",
            "tags": ["mutex", "persistence"]
        },
        {
            "value": "evil-c2.malware.net",
            "type": "domain",
            "confidence": "probable",
            "tags": ["c2", "dns"]
        }
    ]
}
```

## 攻击链

```
strings / Ghidra Defined Strings → 正则提取 IP/域名/URL/路径/注册表
→ Ghidra xref 验证 IOC 是否被代码引用 → 标注置信度
→ 分类: network / file / registry / mutex / UA
→ 导出 MISP/JSON → 用于 YARA 规则 / Sigma 规则 / TI 平台
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 从 Ghidra summary/triage/笔记自动提取 IOC | `extract_iocs_from_summary` | 从 Ghidra summary/triage/笔记自动提取 IOC → `exports/windows/iocs/` |
| IOC 分层 | `refine_ioc_sources` | IOC 按 static_confirmed/mixed/note_only 分层 |
| 提取 Defined Strings | `ghidra_summary_strings` | 提取 Defined Strings（URL/IP/注册表路径/mutex） |

## 证据与验证闭环

- 记录样本 SHA256、架构、映像基址、RVA/VA/文件偏移换算及工具版本。
- 静态结论绑定函数、Xref、导入、字符串和反编译片段；动态结论绑定断点、寄存器、栈、内存与调用时序。
- 原始样本只读保留，dump/patch 使用副本并记录前后哈希、原始字节、新字节和行为差异。
- 将 x64dbg/Frida/Procmon/Ghidra 输出保存到 `exports/windows/`，从干净基线最小化复现后再下结论。
