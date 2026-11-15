# 知识库与 MCP 扩展

[English](EXTENSIONS.md)

桌面端提供“扩展”页面，可独立安装知识包和 MCP 描述。安装版与便携版使用运行时文件清单，不携带知识内容和 MCP 服务。

## 安装与管理

从侧栏打开“扩展”。“知识库”和“MCP”显示已安装条目，“市场源”保存可重复浏览的目录来源。

从 v2.0.0-beta2 起，应用在“市场源”中预置 **Open ReverseLab 官方知识库**，地址为 `https://github.com/LING71671/open-reverselab-knowledge`，点击“浏览”后即可安装。入口离线可见，也会补充到已有配置中；知识内容按需下载。移除后不会自动重新出现，也可以手动添加回来。已发布的 `v2.0.0-beta1` 需手动添加同一地址。

1. 粘贴 GitHub 仓库、子目录、清单或 Release ZIP 链接并“读取”，也可以“导入 ZIP”。本地包目录和 ZIP 路径同样可用。
2. 从读取结果中选择条目并安装。读取来源或安装 MCP 描述不会启动服务。
3. 对已安装条目启用、停用、移除或导出。整包 ZIP 可重新导入；知识包也可选择网络，导出包含本地方法/文档闭包及依赖引用的派生 ZIP。
4. MCP 安装后打开“配置”，填写预设输入并保存，再“验证连接”读取工具/资源。“添加连接”可直接填写 stdio 命令/参数或 Streamable HTTP 地址，无需安装预设。

浏览器开发预览与原生应用调用相同的 Python 服务。浏览器上传 ZIP 内容，原生应用使用文件选择器；导出分别触发浏览器下载和原生保存窗口。耗时操作可以取消，不设默认任务总时限；单次网络和协议交换仍保留连接、读取等待限制。

来源可以只包含一个扩展，也可以提供同时列出两类内容的静态 `reverselab.registry.json`。在“市场源”添加后选择“浏览”；刷新目录不会替换已安装版本。目前没有中心化市场账号或私有仓库凭据编辑页。

导入器解析 GitHub 分支/标签与路径，支持含斜杠的 ref，记录最终 commit 和子目录，并校验选定文件。目录条目引用同一 commit 下的目录、通过 `repository` 指向的独立 GitHub 包仓库，或带 SHA256 的 HTTPS 制品。独立仓库条目解析到目标仓库的来源标识和 commit，通过目录与直接安装采用同一来源。普通 Markdown 需要先编写成有清单的文档集合，导入器不会替其编造方法与关系。

## 稳定 v1 协议

[作者协议](tools/skills/create-reverselab-extension/references/contract.zh-CN.md)与[规范校验器](scripts/misc/extension_protocol.py)定义以下文件：

| 文件 | 协议 | 用途 |
| --- | --- | --- |
| `reverselab.extension.json` | `open-reverselab.extension/v1` | 知识/MCP 元数据及显式内容清单 |
| `reverselab.registry.json` | `open-reverselab.registry/v1` | 仓库目录条目 |
| `reverselab.lock.json` | `open-reverselab.lock/v1` | 清单与内容文件的精确摘要 |

内容版本使用 SemVer。依赖声明来源标识、包 ID 与**精确版本**，需先安装必需依赖。缺少必需依赖/实体、不支持的 `requiredFeatures` 和协议版本会阻止激活。未知可选元数据导出时保留。草案包需显式执行 `migrate`，在转换前检查原有摘要。

安装标识由来源、包 ID、版本和摘要确定。稳定实体 ID 解析为 `reverselab://<installationId>/<entityId>`。不同来源声明相同包 ID 时可共存，不会静默覆盖。旧路径可保留为别名；别名有歧义时使用带来源的 URI。

知识记录包含文档、方法、领域、网络及可选工具绑定。`red` 与 `blue` 保留独立入口，`shared` 可供任一方使用；`both` 选择已安装的两方知识，领域来自安装数据。

关系包括 `depends_on`、`enables`、`composes_with`、`defends`、`detects`、`verifies`、`conflicts`。条件采用 `all`、`any`、`not` 与证据判断；校验器提供三值求值，缺失证据为未知。这些记录可用于路由和 Goal 上下文，尚不表示任意图都能自动编译成完整的条件驱动执行计划。旧文档网络映射记录迁移来源，并保留原始文章。

## 存储、更新与导出

从 GitHub 安装的知识包可在已安装条目上点击**检查更新**，发现新版后点击**更新到…**。检查读取原仓库默认分支与原包路径，通过固定目录提交安装的包也遵循此规则。只提供更高的 SemVer 内容版本，实际安装固定为检查时找到的提交。检查本身不替换内容，更新失败时原版本保持可用；已停用的包更新后仍保持停用。本地文件夹与 ZIP 通过手动导入新内容更新。

扩展优先存放在 `REVERSELAB_EXTENSIONS_DIR`，其次为 `REVERSELAB_DATA_DIR/extensions`，默认使用用户目录的 `.open-reverselab/extensions`。MCP 配置值属于本机应用数据，与包内容分开保存。Python 和第三方工具单独安装。

导入先检查路径、压缩成员、摘要、引用、能力和依赖，再原子激活登记条目。拒绝目录穿越、绝对路径、链接、重名与大小写冲突。同一来源安装新版本后停用旧版本并保留文件。Goal 固定安装 ID 与摘要。移除扩展后不再供新任务选择，保留固定内容，并停用必需依赖者。停用仍被其他启用包依赖的扩展时会拒绝操作并返回依赖者 ID。

整包导出保留清单与声明文件。所选网络导出使用派生包 ID，并记录原 ID、摘要和来源；外部依赖保留精确引用。导出不包含工作区目标、历史、证据和已保存 MCP 凭据，也不覆盖已有输出文件。再分发时保留内容许可。

## MCP 运行方式

独立客户端支持 stdio、Streamable HTTP、初始化、工具/资源分页发现、`connectionId/toolName` 工具标识，以及明确的工具调用与资源读取。“已验证”表示目录发现成功；会话随后关闭，后续每次请求建立新会话。

调用前重新发现 Schema，可在预期 Schema 不匹配时阻止发送。结果未知的调用不会自动重放。取消或调用方明确设置的时间预算会结束子进程树。安装预设不会安装外部程序或执行安装钩子，服务前提按其文档单独准备。

无 MCP 也可阅读知识，无知识包也可使用通用 MCP 连接。绑定将方法与能力、实际发现的工具关联。包元数据和文章属于任务数据，不替换宿主指令。

## 创建与检查

[create-reverselab-extension](tools/skills/create-reverselab-extension/SKILL.zh-CN.md) 用于创建知识包、MCP 描述和目录。便携作者工具复制运行时校验实现，需要 Python 3.11+，不依赖第三方库：

```sh
python scripts/misc/extension_protocol.py check path/to/source
python scripts/misc/extension_protocol.py build path/to/source path/to/extension.zip
python scripts/misc/extension_protocol.py check path/to/extension.zip
python scripts/misc/extension_protocol.py migrate path/to/draft.zip path/to/v1.zip
```

`desktop_extensions.py` 从 stdin 接受一个 JSON 请求，`operation` 可为 `list`、`inspect`、`install`、`updates/check`、`updates/install`、`enable`、`remove`、`export`、`sources/list`、`sources/add`、`sources/remove`、`sources/refresh`、`pin`、`catalog`、`graph`、`get`、`read`、`resolve`、`neighbors`。导出所选网络在 `export` 请求中增加 `networkIds`。`desktop_mcp.py` 支持 `list`、`configure`、`remove`、`connect`、`disconnect`、`call`、`read`。每次返回一个 JSON 结果。

先检查结构，再分别测试实际导入、导出后重新导入及所需 MCP 行为。描述文件检查不代表服务可达或工具调用成功。发布包、桌面版本和来源目录仍属于单独操作。
