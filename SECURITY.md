# Security and privacy

请通过 GitHub Security Advisory 私下报告仓库自身的安全问题，不要在公开 issue 中
粘贴真实凭据、目标数据、未公开漏洞或个人信息。

本仓库只接受可公开复用的框架、模板和合成测试数据。以下内容不得提交：

- `.env`、API key、token、Cookie、私钥、抓包中的认证头；
- 真实目标域名/IP、客户或比赛私有题目数据；
- 用户目录、绝对工作区路径、用户名、邮箱、手机号；
- `samples/`、`cases/`、`exports/`、`reports/` 中的实际任务产物；
- 受第三方许可限制的工具二进制或样本。

提交前运行：

```powershell
python scripts/misc/public_release_check.py
```

## 滥用举报

如发现本项目或其知识库内容被用于未授权攻击、拒绝服务、恶意软件投放，或被第三方包装为收费服务并冒用本项目名义，请通过同一 GitHub Security Advisory 渠道私下举报，**标题前缀 `[abuse]`**。

举报属实且内容处于维护者控制范围内时，维护者可以更新、加注或移除相关内容。本项目不监控第三方使用，也不对第三方行为承担责任；接收举报不构成对相关行为承担责任的自认。

---

## Security Policy (English)

Please report security vulnerabilities in this repository privately via
GitHub Security Advisory. Do not paste real credentials, target data,
undisclosed vulnerabilities, or personal information into public issues.

This repository only accepts publicly reusable frameworks, templates, and
synthetic test data. The following must **never** be committed:

- `.env` files, API keys, tokens, cookies, private keys, authentication headers;
- Real target domain names / IPs, client or competition proprietary data;
- User directories, absolute workspace paths, usernames, emails, phone numbers;
- Actual task artifacts in `samples/`, `cases/`, `exports/`, `reports/`;
- Tool binaries or samples restricted by third-party licenses.

Before committing, run:

```powershell
python scripts/misc/public_release_check.py
```

## Abuse reporting

If you find that this project or its knowledge-base content is being used for
unauthorized access, denial-of-service, malware deployment, or is being
repackaged for a fee under this project's name, report it privately through the
same GitHub Security Advisory channel with the **subject prefix `[abuse]`**.

Where a report is substantiated and the content is within the maintainers'
control, the maintainers may update, annotate, or remove it. The project does
not monitor third-party use and assumes no responsibility for third-party
conduct; receipt of a report is not an admission of responsibility.
