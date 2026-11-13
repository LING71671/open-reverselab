# 知识库

这里保存可复用的分析、检测和防御方法。单个目标的日志、样本和报告保存在私有工作区，写作约定见 [AI-USAGE.md](AI-USAGE.md)。

| 领域 | 内容 |
| --- | --- |
| [Web / CTF](ctf-website/README.md) | Web 攻击面、认证、数据库、协议、CVE 与对应防御 |
| [Android / APK](apk-reverse/README.md) | DEX、Native、混合框架、动态分析与加固验证 |
| [Windows / PE](pe-reverse/README.md) | PE、静态／动态分析、检测、逆向与防御 |
| [General](general/README.md) | 密码学、签名、协议、固件、内核与跨领域分析 |
| [Windows 专项](windows/README.md) | 平台配置等专项参考 |

## red / blue / both

文档按 `track` 分类；`both` 表示共享知识。防御文档通过 `defends` 关联攻击文档，桌面端将这些关系展示为“关联文档”。保留领域目录，不建立两套重复的根目录。实际配对由索引决定，不要求所有共享或专项文档都有一对一对应项。

```sh
python scripts/misc/kb_router.py "JWT" --track blue
python scripts/misc/desktop_kb.py list --track both
```

前者面向信号检索，后者输出桌面使用的完整目录。桌面分类与命令行工具门控分别使用自身运行上下文。

## 更新后检查

```sh
python scripts/misc/kb_doc_audit.py
python scripts/misc/add_frontmatter.py --verify
python scripts/misc/generate_llms_txt.py --check
```

文章、索引和衍生文档的具体维护方式见 [贡献指南](../.github/CONTRIBUTING.md)。
