# open-reverselab Codex 使用说明

## 1. 这套东西现在怎么理解

- `START_HERE.bat`
  - 原作者入口。
  - 继续保留。
  - 主要给原版流程 / 其他 CLI 用。

- `LAUNCHER.bat`
  - 总工作台入口。
  - 用于在 `Codex / Claude / 其他 CLI / 全部` 之间分流。
  - 其中 `Claude` 和 `其他 CLI` 当前只是回到原版 `START_HERE` 流程。

- `CODEX.bat`
  - 现在唯一的 Codex 专用入口。
  - 启动时会先做一轮快速检查。
  - 关于 Codex 的安装、修复、项目管理、备份恢复，都从这里进入。

## 2. 第一次使用

按这个顺序来：

1. 双击 `CODEX.bat`
2. 选 `1. 安装/修复 全局 Codex MCP`
3. 等它完成
4. 完全关闭并重新打开 `Codex App`
5. 如果你也用 `Codex CLI`，也重新开一次
6. 打开你真正要工作的目标项目
7. 在那个项目的 Codex 会话里输入：

```text
启用 open-reverselab Codex 模式
```

首次接入时：

- 会先预览要改哪些文件
- 会要求你输入精确确认短语
- 确认后才会真正写入
- 会在目标项目生成 `.codex/` 受管运行层

## 3. 日常使用

### 3.1 启用当前项目

在目标项目会话里输入：

```text
启用 open-reverselab Codex 模式
```

英文也可以：

```text
enable open-reverselab codex mode
```

### 3.2 查看当前项目状态

```text
查看 open-reverselab Codex 状态
```

或：

```text
show open-reverselab codex status
```

### 3.3 停用当前项目

```text
停用 open-reverselab Codex 模式
```

或：

```text
disable open-reverselab codex mode
```

## 4. 产物会写到哪里

绑定成功后，当前项目会生成这些目录：

- `.codex/`
- `.open-reverselab-codex/`
- `notes/open-reverselab/`
- `reports/open-reverselab/`
- `exports/open-reverselab/`

按需才会出现这些目录：

- `patches/open-reverselab/`
- `projects/open-reverselab/`
- `samples/open-reverselab/`
- `cases/open-reverselab/`

这表示：

- 产物写回当前项目
- 不再默认写回 `open-reverselab` 仓库本身

## 5. 如果你要手动管理别的项目

运行 `CODEX.bat`，进入：

- `4. 项目管理`

里面可以做：

- 绑定指定项目
- 查看指定项目状态
- 修复指定项目接入
- 解绑指定项目

适合这几种情况：

- 某个项目的接入状态乱了
- 你想手工给另一个项目接入
- 你想不用会话命令，直接从菜单修复

## 6. 备份和恢复

运行 `CODEX.bat`，进入：

- `5. 备份 / 恢复`

这里恢复的是：

- 接入配置
- 接入状态
- 受管块
- 本地注册表

这里不会恢复或覆盖：

- 分析报告
- 导出文件
- 业务产物

也就是说：

- 恢复接入状态
- 不碰你的分析结果

## 7. 当前会改哪些全局内容

安装后会改：

- 用户目录下的 `.codex/config.toml`

会加入：

- 全局 MCP：`open_reverselab_codex`
- 全局说明层：识别启用 / 停用 / 状态 这几句固定短语

不会再依赖：

- 工作区 `.codex/config.toml` 的删除式改动

并且：

- 如果当前仓库本身已经有 `.codex/config.toml`，会保留，不会被 `CODEX.bat` 删除

## 8. 当前项目里会写哪些说明文件

项目第一次绑定后，会在项目里生成：

- `.open-reverselab-codex/README.md`
- `.open-reverselab-codex/QUICK_START.md`
- `.open-reverselab-codex/TASK_TEMPLATE.md`
- `.codex/config.toml`
- `.codex/open-reverselab.config.toml`
- `.codex/open-reverselab.ctf.config.toml`
- `.codex/open-reverselab.ctf_optimized.md`

如果项目里没有 `AGENTS.md`，会创建最小版。

如果有 `AGENTS.md`，会在文件末尾追加一个受管块。

停用时：

- 会移除 `.codex/config.toml` 里的 open-reverselab 受管块
- 但默认保留 `.codex/` 里的这些文件，方便后续重新启用或排查

## 9. 最短使用口诀

只记这一套就够了：

1. `CODEX.bat`
2. `1. 安装/修复 全局 Codex MCP`
3. 重启 Codex
4. 打开目标项目
5. 会话里输入：`启用 open-reverselab Codex 模式`

## 10. 常见问题

### Q1. 以后还要先启动很多 BAT 吗？

不用。

关于 Codex，只认：

- `CODEX.bat`
- 如果你想通过总菜单来选入口，再用：
  - `LAUNCHER.bat`

### Q2. `START_HERE.bat` 还要不要用？

如果你是走原作者原版流程 / 其他 CLI，可以继续用。

如果你现在只是在做 Codex 这套，就优先用：

- `CODEX.bat`

### Q3. 如果 Codex 里还显示旧 MCP 怎么办？

先做这几个动作：

1. 运行 `CODEX.bat`
2. 选 `2. 启动前自检 / 状态查看`
3. 完全关闭并重新打开 Codex App

### Q4. 怎么知道当前项目已经接入成功？

看两处：

1. 会话里输入：
   - `查看 open-reverselab Codex 状态`
2. 当前项目里是否存在：
   - `.open-reverselab-codex/`
