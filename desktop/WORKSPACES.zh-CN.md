# 工作区与样本

[English](WORKSPACES.md) · [桌面指南](README.zh-CN.md)

Open ReverseLab 首次使用时创建默认工作区，也支持新建和打开其他工作区。每个工作区拥有自己的样本、Goal、执行记录与分析产物。

## 目录

默认位置为用户目录下的 `.open-reverselab/workspaces/Default`，可用 `REVERSELAB_WORKSPACE_DIR` 覆盖。工作区登记表位于 `.open-reverselab/workspaces.json`，本机数据根目录可用 `REVERSELAB_DATA_DIR` 覆盖。测试使用临时目录。

在已有目录中创建工作区会添加受管理的 `.reverselab` 目录；打开已有工作区需要有效 manifest。

```text
<workspace>/
  .reverselab/
    workspace.json           # version, id, name, createdAt
    goals.json               # Goal 快照与执行记录
    samples/<sample-id>/
      sample.json            # 文件列表、大小与 SHA256
      original/              # 导入的原件副本
      working/               # 分析工作副本
    reports/<goal-id>/<track-attempt>/analysis.md
    exports/<goal-id>/<track-attempt>/observation.py
```

## 样本导入与目标

导入会复制来源，不移动或删除来源文件。文件以 SHA256 标识；目录清单记录每个文件的相对路径、大小与哈希。导入器当前接受最多 2 GiB 和 10,000 个条目，不支持链接条目。这些导入限制与 Goal 预算独立。

原件与工作副本分别存放，导入样本的默认 target 指向工作副本。执行器使用所选目标与当前账户权限。

URL 可以直接作为 Goal target，外部文件和目录也可以直接引用；通过样本导入才会创建受管理的副本。

## 生命周期与服务接口

[workspaceRuntime](src/services/goals/workspaceRuntime.ts) 为每个已加载工作区保留独立 GoalManager，切换视图后其执行器继续运行。运行时将绑定的报告路径传给 pipeline 和存储适配器。同一 target 的报告按 Goal ID、策略和尝试次数分开。

Tauri 的 `workspace_operation` 命令与开发服务的 `POST /api/workspace` 接口使用同一份 [Python 实现](../scripts/misc/desktop_workspace.py)。JSON 请求通过 `action` 选择操作：

| Action | 输入 | 结果 |
| --- | --- | --- |
| `default` | 无 | 创建或打开默认工作区 |
| `list` | 无 | 已登记工作区 |
| `create` | `root`，可选 `name` | 初始化 manifest 和管理目录 |
| `open` | `root` | 校验并打开 manifest |
| `samples` | `root` | 样本记录 |
| `import` | `root`、`source` | 原件、工作副本及清单 |
| `load` | `root` | Goal 快照，首次保存前为 `null` |
| `save` | `root`、`snapshot` | 原子替换 Goal 快照 |
| `report` | `root`、`report` | 保存报告与观察脚本 |

JSON 持久化先写临时文件、刷新，再原子替换目标文件。共享登记表与快照写入使用本机文件锁，前端也按工作区串行写入。文件锁防止写入重叠，不合并多个实例的竞争记录；同一工作区使用一个应用实例写入。

报告、脚本与 Goal 快照分别保存，保存失败会显示为存储故障。安装应用更新前，运行时等待已加载工作区完成写入，详见[更新说明](UPDATES.zh-CN.md)。

## 恢复与迁移

加载历史时，原先 `running` 或 `queued` 的 Goal 转为 `cancelled`，进展与步骤相应标记为中断，不会重新启动外部进程。继续分析需创建新的 Goal。正常操作异步保存记录，进程结束时仍待写入的数据可能丢失。

工作区包含私人样本、目标、日志与报告，不进入公共仓库。备份时保留整个 `.reverselab` 目录。当前快照包含绝对目标和报告路径，移动工作区后需要重新选择 target，尚未实现自动路径重定位。

模型凭据与应用偏好单独保存在本机 WebView 存储，复制工作区不会复制这些设置。执行与故障契约见 [Agent 生命周期](AGENT_SYSTEM.zh-CN.md)与[健康事件](ERROR_CODES.zh-CN.md)。
