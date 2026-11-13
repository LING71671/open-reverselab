# 工作区与样本

已确定的产品方案：首次提供默认工作区，同时允许用户新建、打开其他工作区。软件管理工作区内的样本、Goal 与分析产物。

## 目录

默认位置为本机用户目录下 `.open-reverselab/workspaces/Default`，可用 `REVERSELAB_WORKSPACE_DIR` 覆盖。工作区登记表位于 `.open-reverselab/workspaces.json`，本机数据根目录可用 `REVERSELAB_DATA_DIR` 覆盖。测试使用临时目录。

选择一个已有目录创建工作区，仅建立软件管理的 `.reverselab` 子目录；打开操作要求它已经有有效 manifest。

```text
<workspace>/
  .reverselab/
    workspace.json           # version, id, name, createdAt
    goals.json               # 本工作区 Goal 与执行记录
    samples/<sample-id>/
      sample.json            # 文件列表、大小与 SHA256
      original/              # 导入时的原件副本
      working/               # 用于分析的工作副本
    reports/<goal-id>/<track-attempt>/analysis.md
    exports/<goal-id>/<track-attempt>/observation.py
```

样本导入不移动或删除来源文件。文件计算 SHA256，目录按每个文件的相对路径、大小和哈希形成清单。导入上限为 2 GiB 和 10,000 个条目，链接条目不支持。原件与工作副本独立存储；原件目录不作为默认执行 target。此目录约定不等价于操作系统沙箱。

URL 可以直接作为 Goal target，不执行“复制网站到样本库”。外部文件也可以直接引用；只有使用导入入口才会创建受管理的样本副本。

## 生命周期与接口

`workspaceRuntime` 为每个打开的工作区持有独立 GoalManager，切换视图不销毁后台 runner。报告路径由提交任务所属的 runtime 闭包传给 pipeline，再传到存储适配器。Goal 结果和相同 target 的并行报告按 Goal ID、track 和尝试次数分离。

Tauri 的 `workspace_operation` 与开发服务的 `POST /api/workspace` 使用同一个 Python 实现，JSON 请求的 `action` 为：

| action | 输入 | 结果 |
| --- | --- | --- |
| `default` | 无 | 创建或打开默认工作区 |
| `list` | 无 | 最近使用的工作区 |
| `create` | root, name 可选 | 初始化 manifest 和管理目录 |
| `open` | root | 校验并打开 manifest |
| `samples` | root | 样本清单 |
| `import` | root, source | 原件、工作副本及清单 |
| `load` | root | Goal 快照，首次为空 |
| `save` | root, snapshot | 原子替换 Goal 快照 |
| `report` | root, report | 保存报告及观察脚本 |

JSON 文件使用临时文件、刷新及原子替换；共享写入口有本机文件锁。前端按工作区串行写入。文件锁避免半写文件，不提供多个应用实例间的记录合并，因此同一工作区当前按单实例写入使用。

## 恢复与迁移限制

恢复历史时，原有 running/queued 任务标为中断，不会自动重启外部进程。继续分析应创建新的 Goal。正常操作会异步保存任务记录；进程突然终止前尚未完成的写入可能丢失。报告独立保存，存储失败必须显示具体错误。

工作区包含样本、target、日志和报告等私有信息，不加入公共仓库。备份时保留整个 `.reverselab` 目录。现有快照包含绝对 target/报告路径，迁移位置后需要重新选择 target；自动路径重定位尚未实现。
