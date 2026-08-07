# 常见问题

关于 ReverseLab 项目、MCP 工具、知识库和贡献的常见问题解答。

## 1. 什么是 ReverseLab？

ReverseLab 是一个开源逆向工程实验环境，包含 **173 篇深度技术文章**组成的知识库、**100+ MCP (Model Context Protocol) 自动化工具**、以及 CTF/APK/PE 全链路自动化工作流。项目采用"目录即约定"设计，专为 AI Agent 辅助分析而构建。

## 2. ReverseLab 的知识库覆盖哪些领域？

- **CTF Website**（26 分类 113 篇）：JWT / SQLi / SSRF / XSS / CVE / DoS / Payment / Paywall / 签名攻击 / API / OAuth / 云原生 / IAM
- **APK Reverse**（8 分类 20 篇）：DEX / Native / JNI / IL2CPP / Frida / Pinning / 脱壳 / 重打包
- **PE Reverse**（9 分类 22 篇）：Ghidra 静态分析 / x64dbg 动态调试 / TLS Callback / API Resolver / IOC / YARA / Sigma / Patch / 免杀
- **General**（5 分类 17 篇）：Linux 内核利用 / 加密算法识别 / PRNG 破解 / 游戏作弊与反作弊 / 协议逆向 / 固件 / 硬件
- **Windows**（1 篇）：Windows 平台配置注入专项

## 3. 什么是 MCP 工具？为什么它很重要？

MCP (Model Context Protocol) 是 AI 模型与外部工具交互的**标准协议**。ReverseLab 的 MCP 工具让 AI Agent 可以**直接调用**逆向分析工具，无需人工手动执行。例如：AI 检测到 JWT Token → 自动调用 `kb_router` 查技术 → `kb_read_file` 读攻击方法 → `http_probe` 发探测请求 → 判断是否存在漏洞。这在整个开源工具生态中非常少见，是 ReverseLab 的核心差异化优势。

## 4. AI Agent 如何使用 ReverseLab 进行自动化分析？

AI Agent 加载项目后沿上下文链（`CLAUDE.md` → `AGENTS.md` → `AI-USAGE.md` → `boards/<board>/AI-USAGE.md`）理解约定。检测到信号后：

1. 调用 `kb_router` 查找相关技术文章
2. 调用 `kb_read_file` 读取文章内容和可运行代码
3. 按照文章中的 **MCP 工具映射表**自动调用对应工具
4. 收集证据、记录笔记、生成报告

## 5. 如何安装和使用 ReverseLab？

```powershell
git clone https://github.com/LING71671/open-reverselab.git
cd open-reverselab
.\scripts\misc\bootstrap.ps1
.\scripts\misc\install_tools.ps1 -CTF       # Web 工具
.\scripts\misc\install_tools.ps1 -Android   # APK 工具
.\scripts\misc\install_tools.ps1 -Windows   # PE 工具
.\scripts\misc\install_tools.ps1 -Common    # Ghidra + Maven

# 验证
python scripts/misc/lab_healthcheck.py
python scripts/misc/ai_toolcheck.py
```

## 6. ReverseLab 内置执行拦截吗？

不内置。ReverseLab 提供技术文档、目录约定和自动化工具链；具体请求是否执行由使用者所接入的 AI 大模型提供商、运行平台或组织策略处理。

## 7. ReverseLab 与 Ghidra/x64dbg/Frida 等工具的关系是什么？

ReverseLab 是一个**知识库和自动化编排层**，它集成但不捆绑这些外部工具。支持的工具有：Ghidra（反编译器）、x64dbg（Windows 调试器）、Frida（动态插桩）、JADX（APK 反编译）、sqlmap、Burp Suite、nmap、DirSearch、Cheat Engine、PE-bear、DiE、Procmon、HxD、Cutter/Rizin 以及各种 Python CTF 库。

## 8. 如何为 ReverseLab 贡献？

参考 [CONTRIBUTING.md](https://github.com/LING71671/open-reverselab/blob/main/CONTRIBUTING.md)。新增或修改内容后运行 `public_release_check.py`、`lab_healthcheck.py` 和 `kb_doc_audit.py`，确保目录、索引和文档结构保持一致。
