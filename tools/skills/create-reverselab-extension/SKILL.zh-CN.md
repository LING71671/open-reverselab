---
name: create-reverselab-extension
description: 创建或扩充 Open ReverseLab 知识包、攻击网、防御网、MCP 连接描述和 GitHub 扩展目录，按稳定 v1 协议生成可审阅源码与 ZIP。
---

# 创建 Open ReverseLab 扩展

[English](SKILL.md)

完成用户请求的扩展，保留已有知识和稳定 ID，使用桌面“扩展”页面支持的**稳定 v1 协议**。分别说明结构检查、实际导入导出检查和真实 MCP 检查结果。

## 选择输出

- **知识包：**文档、方法、攻防网络、证据条件及可选工具绑定。
- **MCP：**已有服务的连接描述及其配置输入。只有用户要求新建 MCP 服务时才实现服务本身。
- **仓库目录：**在 GitHub 仓库中用 `reverselab.registry.json` 列出知识包和 MCP 扩展，可同时提供两类内容。

按当前输出阅读[作者协议](references/contract.zh-CN.md)。知识包可基于 [assets/integrity-pack](assets/integrity-pack/) 的可用示例，将合成内容替换为实际所需知识。示例展示格式，不代表攻防覆盖深度要求。

[assets/http-mcp](assets/http-mcp/) 是需要用户填写端点的连接预设。[assets/reverselab.registry.json](assets/reverselab.registry.json) 使用仓库相对路径列出两种示例，需要创建目录仓库时可将 assets 内的内容复制到新仓库根目录。

## 编写扩展

从仓库和请求中确定命名空间、领域、语言及读者，仅在缺少关键信息时询问。转换已有知识库时保留工作副本，建立旧路径到稳定 ID 的映射。导出某个知识包的局部内容时使用派生包标识。

知识包将可读技术文档与结构化方法分开，写清实际前提、所需证据、预期输出、失败条件、工具要求和来源。保留有用的可运行示例，说明适用环境。不得编造运行结果、工具名、防御覆盖和核验状态。共享方法可供双方复用；red 与 blue 拥有独立网络入口并允许交叉引用，不强制固定两条路线，也不把所有 red 文档浅层改写成 blue 副本。

MCP 绑定应依据服务实际文档中的传输方式、安装版本要求和输入 Schema，沿用标准协议并独立配置连接。只存配置输入名称和凭据引用，不保存可用凭据。导入描述与启动服务分开；如果只检查了描述文件，应说明连接和工具调用尚未实测。

仓库目录引用实际包路径或版本化制品链接，来源、ref 和摘要应与交付包一致。不得编造 Release 下载链接或校验值。GitHub 仓库链接与下载得到的 ZIP 应解析到同一份清单和编写内容。

## 检查与打包

以下脚本路径相对于本 skill 目录，需要 Python 3.11+，不依赖第三方包：

```sh
python scripts/package_extension.py check path/to/pack
python scripts/package_extension.py build path/to/pack path/to/extension.zip
python scripts/package_extension.py check path/to/extension.zip
python scripts/package_extension.py migrate path/to/draft.zip path/to/v1.zip
```

工具复制桌面的规范实现 `scripts/misc/extension_protocol.py`，检查稳定协议结构、显式文件清单、ID、引用、条件、必需能力、MCP 描述和 ZIP 摘要。依赖使用精确版本，工具还提供三值 `evaluate_condition` 供本地检查。依赖激活与真实 MCP 行为由运行时服务负责。根据错误修正制品，不削弱检查。v1-draft 包必须显式迁移，转换前校验已有锁文件。

另行检查知识语义：引用证据是否支持方法、关系方向是否正确，检测方法不能写成预防能力。可运行示例按任务指定环境验证。真实任务证据、历史不进入复用包，仓库目录需检查 JSON、指定 commit 下的相对路径，以及引用包的标识、版本和摘要。

交付源码目录、ZIP、计算得到的 SHA256 和实际检查结果，沿用适用许可。发布仓库、Release 或对外消息按用户对应指令执行，编写扩展本身不代表发布授权。检查桌面的本地源码/ZIP 导入与导出后重新导入；存在用户指定的真实来源时再检查 GitHub 导入，不编造发布链接。导入器接受本地包目录，包括源码检出的 `kb` 包；克隆仓库不会自动将知识安装到桌面。
