# 扩展作者协议：v1 草案

[English](contract.md)

本文是提案，尚未成为正式桌面导入 API。使用下述完整草案标识。附带工具的 `check` 只实现文中说明的结构检查；运行时依赖解析、条件求值和工具调用单独实现。

## 通用清单

根文件名为 `reverselab.extension.json`：

```json
{
  "protocol": "open-reverselab.extension/v1-draft",
  "kind": "knowledge",
  "id": "example.integrity",
  "version": "0.1.0",
  "title": "文件完整性方法",
  "description": "读取文件并将摘要与声明值进行比较。",
  "license": "Apache-2.0",
  "files": ["knowledge.json", "docs/read.md", "docs/compare.md"],
  "requires": [],
  "knowledge": "knowledge.json"
}
```

`kind` 为 `knowledge` 或 `mcp`。包使用小写点分命名空间，内容版本遵循 SemVer。`files` 显式列出所有内容文件，不包含清单自身和生成的 `reverselab.lock.json`。路径为相对 POSIX 路径，不能对整个工作区通配打包。文本使用 UTF-8。可选扩展元数据放在 `extensions` 中，未知可选值保持原样。

`requires` 每项包含 `id`、`version`（精确值或 SemVer 范围）、`source`（仓库链接）、`optional`（布尔值）。宿主激活前将范围解析到精确版本、摘要、commit 和子目录；作者工具只检查条目结构，不下载解析。`requiredFeatures` 可声明所需能力，运行时遇到未知必需能力不能激活。

## 知识记录

`knowledge` 文件是对象，包含 `domains`、`documents`、`methods`、`networks` 及可选 `bindings` 数组。领域为非空字符串，增加领域无需改桌面代码。实体 ID 形如 `pack.namespace/local-name`，局部名称可按斜杠分段，不依赖文件名和语言。`track` 为 `red`、`blue`、`shared`；`both` 属于运行时组合模式。

| 记录 | 字段 |
| --- | --- |
| 文档 | `id`、`title`、`path`（清单中的 Markdown 文件）、`track`、`domain`；可选 `locale`、`aliases`、`provenance` |
| 方法 | `id`、`title`、`document`（文档 ID）、`track`、`domain`、`signals`（字符串）、`requiresEvidence`（证据键）、`produces`（预期证据键）、`toolRequirements`（能力名）；可选 `when`、`provenance`、`validation` |
| 网络 | `id`、`title`、`track`、`entrypoints`（方法 ID）、`nodes`（方法 ID）、`relations` |
| 绑定 | `method`（方法 ID）、`capability`、`server`（连接/预设引用）、`tool`、`inputMapping`，可选 `outputMapping`；映射为声明式数据，不执行表达式 |

方法可以引用依赖包中的文档，网络节点可以引用依赖包中的方法。外部引用通过显式依赖来源解析，不根据包名猜全局来源。激活时检查外部关系，作者工具只核对是否声明对应依赖。

关系包含 `from`、`to`、`type` 和可选 `when`，方向含义如下：

| 关系 | `from → to` 的含义 |
| --- | --- |
| `depends_on` | 起点方法需要终点方法的结果 |
| `enables` | 起点方法产生终点方法所需条件 |
| `composes_with` | 两方法在记录条件下可以组合 |
| `defends` / `detects` | 起点方法预防/观察终点技术 |
| `verifies` | 起点方法检查终点关联的声明或结果 |
| `conflicts` | 两方法或其结果在记录条件下不能共同支持同一声明 |

可选 `when` 为 `{"all": [condition]}`、`{"any": [condition]}`、`{"not": condition}` 或 `{"evidence": "key", "state": "observed|absent|unobservable"}`。未知与已记录不存在不同；空 `all` 为真，空 `any` 为假。`not` 保留未知；`all`/`any` 遇到决定性的假/真可确定结果，否则传播未知。草案工具不求值这些条件。

`provenance` 记录来源和版本；`validation` 记录实际测过什么、使用何种环境。`produces` 仅表示预期证据。实际观察写入工作区，关联方法/包 ID、调用和证据引用，不在复用包中把预期结果写成实际发现。

知识反馈环允许存在，规划器必须将所选方法解析成当轮无环执行图；JSON 中的关系排列不代表执行顺序。子网导出包含所需本地实体与文档，使用派生包 ID 并记录 `origin` 引用；必需外部依赖锁随导出保存，不能再分发的依赖保留引用。

## MCP 描述

MCP 扩展使用相同清单，设置 `kind: "mcp"`、`mcp: "connection.json"`，并将文件加入 `files`。它说明如何连接已有服务，不重新定义 JSON-RPC、MCP 协商或工具 Schema。

`connection.json` 包含 `transport`、`inputs`；`stdio` 使用 `command`/`args`，`streamable-http` 使用 `url`。`inputs` 为 `{name, type, required}` 数组，`type` 可取 `string`、`url`、`path`、`secret`。`${inputs.name}` 在本机解析。可选 `env`、`headers` 将名称映射到输入引用，包内不存凭据值。`args` 为参数数组，不拼接 shell 命令。服务前提和固定版本的安装步骤放在已列出的文档中，由应用单独执行所选服务的连接或安装。

HTTP 预设可以要求用户填写端点，无需编造示例服务器：

```json
{
  "transport": "streamable-http",
  "url": "${inputs.endpoint}",
  "inputs": [{"name": "endpoint", "type": "url", "required": true}]
}
```

工具绑定使用实际发现的名称和输入/输出 Schema。完整连接行为遵循上游 MCP 规范；描述检查通过不代表服务可达或工具可用。

## ZIP 与锁定文件

使用标准 ZIP，建议命名为 `pack-id-version.kbpack.zip` 或 `pack-id-version.mcp.zip`，这只是命名约定。ZIP 包含清单与显式内容文件，可位于一个外包目录中。`reverselab.lock.json` 记录清单及每个内容文件的 SHA256，不包含它自身；外层 ZIP 的 SHA256 放在制品旁或目录条目中，避免摘要自引用。

源码检查不要求锁定文件，构建时按实际打包字节生成，ZIP 检查要求有锁。工具拒绝额外文件、多个包根目录、目录穿越、链接、重复或大小写冲突路径及内容变化。摘要可检测字节变化，不证明发布者身份。

## GitHub 仓库目录

根目录 `reverselab.registry.json` 使用 `protocol: "open-reverselab.registry/v1-draft"`、`id`、`title` 和 `entries`。每项包含 `id`、`kind`、`title`、`version`，以及恰好一种位置：

- `path`：同一个已解析 commit 下的扩展相对目录；或
- `artifact`：HTTPS ZIP 链接，同时提供由实际制品计算的 `sha256`。

条目可补充 `description`、`domains`、`tracks`、`license`。一个仓库可同时列出知识和 MCP。条目标识、版本必须与引用清单一致；解析记录来源仓库、commit 和路径。刷新目录只发现版本，不直接更新已安装扩展。

打包工具不负责打包市场目录，需检查目录 JSON 并逐个解析条目。本机配置和凭据不进入目录。准备本地目录文件与发布 GitHub 仓库、Release 分开处理。
