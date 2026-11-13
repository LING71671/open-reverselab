# 知识库

技术文档按策略和领域组织，red 与 blue 分别维护完整操作流程，通用方法只保留一份。

- [Red](red/README.md)：攻击网、分析路径与复现方法。
- [Blue](blue/README.md)：防御网、检测、控制措施与验证。
- [共享方法](shared/README.md)：两边都会使用的识别、调试、算法和协议方法。

`both` 分别检索 red、blue 与共享文档，通过关联链接交换证据，不复制第三套技术文档。

| 领域 | red | blue | 共享 |
| --- | --- | --- | --- |
| Web / CTF | [Red](red/ctf-website/README.md) | [Blue](blue/ctf-website/README.md) | [共享方法](shared/ctf-website/README.md) |
| Android / APK | [Red](red/apk-reverse/README.md) | [Blue](blue/apk-reverse/README.md) | [共享方法](shared/apk-reverse/README.md) |
| Windows / PE | [Red](red/pe-reverse/README.md) | [Blue](blue/pe-reverse/README.md) | [共享方法](shared/pe-reverse/README.md) |
| General | [Red](red/general/README.md) | [Blue](blue/general/README.md) | [共享方法](shared/general/README.md) |
| Windows 专项 | [Red](red/windows/README.md) | — | [共享方法](shared/windows/README.md) |

## 检索与维护

```sh
python scripts/misc/kb_router.py "JWT" --track blue
python scripts/misc/desktop_kb.py list --track both
```

`catalog/<领域>.json` 维护信号、轨道、工具和配对关系，`files` 使用仓库相对路径。文档仍通过 `defends` / `defended_by` 关联。`path-aliases.json` 将旧路径映射到当前文档，供桌面、MCP 和官网保留历史链接。

写作约定见 [AI-USAGE.md](AI-USAGE.md)，贡献方式见 [贡献指南](../.github/CONTRIBUTING.md)。
