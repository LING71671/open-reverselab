# 健康监控与错误码

运行事件统一使用 [HealthEvent](src/core/contracts/health.ts)，由 [HealthMonitor](src/services/health/healthMonitor.ts) 汇总。界面按 Goal、Agent、模型、知识库、工具、存储六层展示；没有真实观测的层为 `unknown`。

事件携带 `eventId`、`goalId`、`layer`、`status`、时间，以及可选 branch/agent/node/correlation、耗时、错误码、恢复建议和原始细节。同一 Goal 只接收自己的事件，历史最多保留 256 条。快照聚合保留窗口各 trace 的最新状态；一条分支成功不会覆盖另一条分支的失败。

## 错误码

| code | 层 | 含义 | 默认建议 |
| --- | --- | --- | --- |
| INPUT_INVALID | goal | 输入不满足执行条件 | 调整输入 |
| MODEL_AUTH | model | 模型认证或授权失败 | 检查配置 |
| MODEL_QUOTA | model | 账户额度不足 | 检查额度 |
| MODEL_RATE_LIMIT | model | 请求限流 | 有界重试 |
| MODEL_TIMEOUT | model | 模型响应超时 | 有界重试 |
| MODEL_UNAVAILABLE | model | 模型或网络不可用 | 备用服务或路线 |
| PROXY_CONFIG | model / tool | 代理配置无效 | 修改代理池配置 |
| PROXY_CONNECT | model / tool | 连接代理失败 | 切换节点 |
| PROXY_AUTH | model / tool | 代理认证失败 | 修改节点账号密码 |
| PROXY_UNAVAILABLE | model / tool | 没有可用的启用节点 | 检查节点或等待冷却结束 |
| NETWORK_TIMEOUT | model / tool | 网络请求超时 | 检查连接后重试 |
| NETWORK_FAILED | model / tool | 已开始的网络请求中断 | 检查结果，避免自动重发 |
| KB_UNAVAILABLE | kb | 知识库服务不可用 | 检查知识库配置 |
| KB_DOC_MISSING | kb | 索引对应文档缺失 | 选择其他文档 |
| TOOL_MISSING | tool | 执行依赖缺失 | 检查工具配置 |
| TOOL_TIMEOUT | tool | 工具执行超时 | 缩小范围或换路线 |
| TOOL_FAILED | tool | 工具实际执行失败 | 换路线 |
| TOOL_UNAVAILABLE | tool | 执行服务无法连接或拒绝请求 | 保留结果，恢复服务后重试 |
| EVIDENCE_INVALID | agent | 证据不足或不满足验收 | 补充独立观察 |
| LOOP_DETECTED | agent | 重复动作或无进展循环 | 剪除重复路线 |
| BUDGET_TIME | goal | 时间上限已到 | 停止并保留记录 |
| BUDGET_TOKENS | goal | Token 上限已到 | 停止并保留记录 |
| USER_CANCELLED | goal | 用户停止 | 取消执行 |
| STORAGE_FAILED | storage | 报告或任务记录保存失败 | 检查磁盘或权限 |
| UNKNOWN | 原始层 | 未分类错误 | 查看原始细节 |

`retryable` 与 `recovery` 是调度建议，不代表已经执行了重试。401/403 与账户额度不足不作为普通限流持续重试。原始调用可抛出带明确 code 的 HealthFault，分类器再处理 HTTP 状态与已知错误文本。

## 状态与结果

`running` 是已开始的观测，`healthy` 是成功结果，`degraded/failed` 保留阻塞与错误，`cancelled` 对应取消。工具执行成功、证据被接受、用户 Goal 完成分别记录。

模型阶段、知识库读取、Python 执行、报告写入和 Goal 停止原因都有对应事件。本机工具“检测”实际调用 Python 检查运行时、模块和 PATH，不使用固定的工具数量或预设“已就绪”。工作区快照异步写入失败单独显示在健康视图，内存中的任务可以继续查看。

进程恢复时，历史健康事件表示上一次运行的观测，不代表当前外部服务仍然可用。当前没有守护进程式的周期健康探针；页面显示事件与用户发起的本机检测。
