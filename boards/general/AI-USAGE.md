# General AI Usage

跨平台通用安全/逆向分析的 AI 工作约定。

## 板块定位

此板块处理不限于单一平台的通用技术问题。当目标涉及以下领域时，路由到此板块：

| 领域 | 典型信号 |
|------|---------|
| 密码学 | AES/DES/RSA/ECC 算法识别、自定义加密还原、侧信道 |
| 协议分析 | 未知协议逆向、抓包分析、状态机推断 |
| 固件/IoT | binwalk 解包、UBoot/SPL 分析、文件系统提取 |
| 硬件安全 | JTAG/SWD 调试、SPI Flash 读取、UART 日志 |
| 无线电 | BLE 抓包、ZigBee 分析、LoRa 信号解码 |
| 方法论 | 逆向效率优化、命名约定、笔记组织 |
| AI 安全 | Prompt injection、模型越狱、RAG 投毒 |

## MCP 工具

通用板块使用以下 MCP 工具：

| MCP 工具 | 用途 |
|---------|------|
| `kb_router` | 按信号搜索通用知识库（board="general"） |
| `kb_read_file` | 读取通用技术文件 |
| `kb_catalog` | 查看通用知识库目录 |
| `triage_pe` / `die_scan` / `rizin_*` | 二进制初筛（跨架构适用） |
| `ghidra_headless_analyze` | 多架构反编译分析 |
| `python_re_tool_install` | 安装 Python 逆向库（angr/z3/pycryptodome） |
| `hash_file` | 文件哈希计算 |

## 分析流程

1. **识别领域** — 根据目标特征选择对应知识库分类
2. **查知识库** — 调用 MCP `kb_router(query="信号", board="general")` 查找技术文件
3. **阅读技术文件** — `kb_read_file` 读取，关注攻击链和 MCP 工具映射
4. **工具选择** — 按技术文件的工具映射表选择 MCP 工具
5. **证据落盘** — 输出 → `exports/general/`，笔记 → `notes/general/`
