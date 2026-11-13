# Contributing

## 快速了解

- 项目首页: <https://github.com/LING71671/open-reverselab>
- 知识库结构: [kb/README.md](../kb/README.md)
- 公开/私有边界: [PUBLICATION.md](../PUBLICATION.md)

## 提交规则

1. 只提交通用实现、模板、安装说明和合成 fixtures。
2. 不要从私人实验室整目录复制；按文件白名单迁移并人工审查 diff。
3. URL 示例使用 `example.com` / `example.test` / localhost。
4. 凭据仅使用环境变量名和空值示例。
5. 提交前运行 public release check、offline smoke test 和 PowerShell parser。
6. 为避免泄露个人邮箱，建议为本仓库配置 GitHub noreply 地址：
   `git config user.email "<account>@users.noreply.github.com"`。

```powershell
python scripts/misc/public_release_check.py
python scripts/misc/lab_healthcheck.py
.\scripts\ctf-website\smoke_cve_pipeline.ps1
```

## 按模块开发

| 模块 | 入口 | 验证 |
| --- | --- | --- |
| 桌面端 | [开发指南](../desktop/DEV_GUIDE.md) | `pnpm build`、Goal/流水线与调度测试、相关 Python 测试 |
| 知识库 | [写作约定](../kb/AI-USAGE.md) | 文档结构、frontmatter、索引与关联路径 |
| 官网 | [站点说明](../site/README.md) | `pnpm build`、中英文与深浅主题、桌面和窄屏操作 |
| 发布 | [RELEASING.md](../RELEASING.md) | 提交内容扫描、离线检查、干净克隆、版本和制品哈希 |

JavaScript 项目统一使用 pnpm 和提交的 lockfile。Python 依赖使用 uv 管理的隔离环境。产品截图仅允许合成数据，不得包含用户路径、真实目标或凭据。
