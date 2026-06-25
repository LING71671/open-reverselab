# Contributing

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
