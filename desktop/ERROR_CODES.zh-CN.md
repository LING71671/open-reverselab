# 健康事件与错误码

[English](ERROR_CODES.md) · [Agent 运行规则](AGENT_SYSTEM.zh-CN.md)

运行通过 [HealthEvent](src/core/contracts/health.ts) 发出事件，由 [HealthMonitor](src/services/health/healthMonitor.ts) 汇总。界面按 Goal、Agent、模型、知识库、工具和存储六层展示，没有观察的层保持 `unknown`。

事件包含 `eventId`、`goalId`、`layer`、`status` 与时间戳，也可携带分支、Agent、节点、关联 ID、耗时、错误码、恢复建议和详情。每个监测器只接收自己 Goal 的事件，默认保留 256 条历史，可通过 `maxHistory` 配置；累计观察数量与保留窗口分别统计。

快照汇总保留窗口中各 branch/agent/node trace 的最新事件。一条 trace 恢复不会覆盖另一条的失败；某层在窗口中已无事件时，使用该层最后记录的事件。

## 错误码

| Code | 层 | 含义 | 恢复建议 |
| --- | --- | --- | --- |
| INPUT_INVALID | goal | 输入不满足执行要求 | 调整输入 |
| MODEL_AUTH | model | 模型认证或访问失败 | 检查提供商配置 |
| MODEL_QUOTA | model | 账户额度不足 | 检查余额或额度 |
| MODEL_RATE_LIMIT | model | 提供商请求限流 | 限流结束后重试 |
| MODEL_TIMEOUT | model | 模型响应超时 | 检查连接后重试 |
| MODEL_UNAVAILABLE | model | 模型或连接不可用 | 使用其他服务或路线 |
| PROXY_CONFIG | model / tool | 代理配置无效 | 修改代理池配置 |
| PROXY_CONNECT | model / tool | 连接代理失败 | 选择其他节点 |
| PROXY_AUTH | model / tool | 代理认证失败 | 修改节点凭据 |
| PROXY_UNAVAILABLE | model / tool | 没有可用的启用节点 | 检查节点或等待冷却结束 |
| NETWORK_TIMEOUT | model / tool | 网络请求超时 | 检查连接后重试 |
| NETWORK_FAILED | model / tool | 已开始的请求中断 | 检查结果后再决定是否重发 |
| KB_UNAVAILABLE | kb | 知识库服务不可用 | 检查知识库配置 |
| KB_DOC_MISSING | kb | 索引对应文档缺失 | 选择其他资料 |
| TOOL_MISSING | tool | 执行依赖缺失 | 检查本机工具配置 |
| TOOL_TIMEOUT | tool | 工具执行超时 | 调整预算或路线 |
| TOOL_FAILED | tool | 工具实际执行失败 | 尝试其他路线 |
| TOOL_UNAVAILABLE | tool | 执行服务无法连接或拒绝请求 | 恢复服务后重试 |
| EVIDENCE_INVALID | agent | 证据不足或未通过验收检查 | 补充独立观察 |
| LOOP_DETECTED | agent | 动作或不变失败重复出现 | 选择不同路线 |
| BUDGET_TIME | goal | 设置的时间预算耗尽 | 停止并保留记录 |
| BUDGET_TOKENS | goal | 设置的 Token 预算耗尽 | 停止并保留记录 |
| USER_CANCELLED | goal | 用户停止运行 | 取消执行 |
| STORAGE_FAILED | storage | 报告或 Goal 保存失败 | 检查磁盘与权限 |
| UNKNOWN | 原始层 | 错误尚未分类 | 查看详情 |

`retryable` 与 `recovery` 是调度建议，不代表已经执行了重试。恢复值包括 `retry`、`alternate`、`configure`、`revise`、`stop`、`inspect`。认证失败和账户额度不足不会被分类为可重试的请求限流。

错误源可以抛出带明确 code 的 `HealthFault`。分类器优先采用显式 code，再处理 HTTP 状态与已知错误文本。代理和网络错误沿用调用所在的层。Goal 预算可选，存在预算错误码不代表默认设置了上限。

## 状态与结果

| 状态 | 含义 |
| --- | --- |
| `unknown` | 没有可用观察，仅用于快照状态 |
| `running` | 观察的操作已开始 |
| `healthy` | 观察的操作成功 |
| `degraded` | 观察记录了告警或阻碍 |
| `failed` | 观察记录了失败 |
| `cancelled` | 观察的操作已取消 |

工具执行、证据接受和 Goal 完成分别记录。模型阶段、知识库读取、Python 执行、报告写入和 Goal 停止原因各自发送事件。本机工具检测实际调用 Python 检查运行时、模块与 PATH。工作区异步写入失败单独显示在健康视图，内存记录继续可用。

恢复的事件描述上一次运行。健康监测器不周期探测外部服务是否就绪。可选原生性能采样和 Sentry 上报使用独立开关与生命周期，详见[诊断说明](DIAGNOSTICS.zh-CN.md)；存储与恢复行为见[工作区说明](WORKSPACES.zh-CN.md)。
