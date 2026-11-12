---
id: "ctf-website/11-supply-chain/dependency-confusion-defense"
title: "Dependency Confusion 与供应链投毒防御：私有源隔离、锁文件校验与脚本禁用"
title_en: "Dependency Confusion & Supply Chain Defense: Scoped Registries, Lockfile Integrity & Script Hardening"
summary: >
  针对 Dependency Confusion（依赖混淆）、Typosquatting、Manifest/Tarball 不一致与安装脚本投毒的蓝队防御指南。覆盖 npm Scope 强制绑定私有源与禁用公共回退、pip 移除 --extra-index-url 改用私有代理源、Lockfile（integrity sha512/hash）强制冻结、CI 中禁用 preinstall/postinstall 自动执行（--ignore-scripts）以及公开命名空间占位与发布 Token 最小化，附带 Python 配置检查脚本。
summary_en: >
  Blue-team defense guide against dependency confusion, typosquatting, manifest-tarball mismatch, and install-script poisoning. Covers scoped npm registries without public fallback, replacing pip --extra-index-url with isolated private index proxies, strict lockfile integrity hash enforcement, disabling lifecycle scripts (--ignore-scripts) in CI, public namespace claiming, publish token scoping, and a Python manifest/config validator.
board: "ctf-website"
category: "11-supply-chain"
signals: ["dependency confusion defense", "scoped registry", "extra-index-url risk", "lockfile integrity", "ignore-scripts", "supply chain hardening"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["依赖混淆防御", "供应链加固", "npm私有源绑定", "pip extra-index-url风险", "lockfile完整性校验", "ignore-scripts", "包发布Token保护"]
difficulty: "advanced"
tags: ["defense", "blue-team", "supply-chain", "dependency-confusion", "npm", "pypi"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/11-supply-chain/dependency-confusion", "ctf-website/10-cloud/ci-cd-pipeline-defense", "ctf-website/10-cloud/github-actions-abuse-paths-defense"]
track: "blue"
defends: "ctf-website/11-supply-chain/dependency-confusion"
---
# Dependency Confusion 与供应链投毒防御：私有源隔离、锁文件校验与脚本禁用

## 1. 威胁模型与依赖解析失控根因

Dependency Confusion 与构建期供应链投毒利用的是包管理器在“私有源 vs 公共源”及“安装期生命周期脚本”上的默认宽松策略：
1. **无作用域包名与公共回退**：内部包未使用 `@org/` Scope，或在 `.npmrc` 未将 `@org:registry` 绑定到私有库；Python `pip` 配置 `--extra-index-url` 后，当公共 PyPI 出现更高版本号同名包时，`pip` 会优先下载公共源恶意包。
2. **安装期任意代码执行**：`npm install` 默认触发包内 `preinstall`/`postinstall`，`pip install` 编译 `sdist` 时执行 `setup.py` / PEP 517 后端代码，直接读取 CI Runner 的环境变量、云元数据或 `~/.ssh`、`~/.npmrc` 凭证。
3. **Manifest 与 Tarball 差异绕过**：攻击者在 registry metadata 展示无害 `package.json`，实际 tarball 却嵌有恶意安装脚本，绕过仅看 metadata 的静态检查。
4. **锁文件松散与前端泄露**：CI 未采用 `--frozen-lockfile` / `npm ci` / `--require-hashes`，或前端 `package.json`/source map 暴露内部包名清单，且内部包名未在公共 registry 占位注册。

## 2. 分层防御与包管理加固规范

| 攻击向量 | 加固措施 | 关键配置 | 阻断效果 |
|---|---|---|---|
| npm 私有源错位 | 全部内部包使用组织 `@scope/`，`.npmrc` 绑定 `@org:registry`；私有源代理屏蔽上游同名内部前缀 | `@org:registry=https://pkg.internal.example/npm/` | 阻止向 `registry.npmjs.org` 回退查询内部包 |
| PyPI `--extra-index-url` 混淆 | 严禁混用 `--index-url` 与 `--extra-index-url`；仅使用单个私有代理源（在制品库侧做白名单上游隔离） | `pip.conf` 仅设唯一 `index-url` | 消除公共 PyPI 高版本号抢占内部包 |
| 安装期脚本投毒 | CI 构建默认启用 `ignore-scripts=true`；Python 仅允许可信来源预编译 Wheel（`--only-binary=:all:`） | `npm ci --ignore-scripts` | 阻断 `preinstall`/`postinstall`/`setup.py` 自动执行 |
| 锁文件与 Tarball 篡改 | 强制使用 Lockfile 并在 CI 用 `--frozen-lockfile` / `npm ci` / `pip --require-hashes` 安装 | 校验 Lockfile `integrity`（SHA-512/SHA-256） | 防止解析漂移及未核准包版本被引入 |
| 包名暴露与抢占 | 不向公网发布 `package.json`/`package-lock.json`/source map；对既有未加 scope 内部包名在公共源注册安全占位包 | 启用 NPM/PyPI Trusted Publishing（OIDC），移除静态发布 Token | 消除外部抢注与包发布凭据长期暴露 |

### 安全 `.npmrc` 与 `pip.conf` 配置模板

```ini
# .npmrc — 强制绑定组织 scope 并禁用安装期任意脚本执行
@myorg:registry=https://artifacts.internal.example/repository/npm-internal/
registry=https://artifacts.internal.example/repository/npm-group/
ignore-scripts=true
strict-ssl=true
```

```ini
# pip.conf — 仅使用唯一内部制品库代理，禁止 extra-index-url 回退公网 PyPI
[global]
index-url = https://artifacts.internal.example/repository/pypi-group/simple
no-cache-dir = true
```

## 防御工作流

1. **内部包清单与暴露清理**：从全仓锁文件、源码与 CI 配置提取全部内部依赖名称，检查是否使用了组织 Scope，并关闭生产 Web 服务对 `package.json`、`package-lock.json` 与 `.map` 文件的公网访问。
2. **制品库与客户端策略改造**：在 Artifactory/Nexus/Verdaccio 侧配置内部包前缀白名单（禁止从上游公共源代理匹配内部命名规则的包），同时清理各项目中的 `--extra-index-url` 并配置 `ignore-scripts=true`。
3. **CI 冻结安装与哈希校验**：将构建命令统一为 `npm ci --ignore-scripts`、`pnpm install --frozen-lockfile --ignore-scripts` 或 `pip install --require-hashes`，结合下方检测脚本拦截新引入的非规范源配置。
4. **发布凭据与公共占位**：对不可立即重命名的无 Scope 内部包在 npm/PyPI 官方源完成组织占位；将包发布流程迁移为基于 GitHub OIDC Trusted Publisher 的短时凭据发布。

## 3. Python 依赖配置混淆与锁文件合规检测脚本

```python
#!/usr/bin/env python3
"""npm/PyPI 依赖混淆风险配置（extra-index-url、无 scope、ignore-scripts）检测脚本。"""

import json
import re


def check_pip_requirements(req_text: str) -> list[str]:
    issues: list[str] = []
    for lineno, line in enumerate(req_text.splitlines(), start=1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "--extra-index-url" in s:
            issues.append(f"line {lineno}: --extra-index-url introduces PyPI dependency confusion risk")
        if s.startswith(("http://", "https://")) is False and not s.startswith("-"):
            if "==" not in s and "--hash=" not in s:
                issues.append(f"line {lineno}: unpinned/unhashed requirement ({s})")
    return issues


def check_npmrc_and_pkg(npmrc_text: str, pkg_json_text: str) -> list[str]:
    issues: list[str] = []
    if "ignore-scripts=true" not in npmrc_text:
        issues.append("npmrc: missing ignore-scripts=true")
    pkg = json.loads(pkg_json_text)
    name = pkg.get("name", "")
    if pkg.get("private") is True and not name.startswith("@"):
        issues.append(f"package.json: private package '{name}' lacks @org/ scope")
    if pkg.get("private") is True and name.startswith("@"):
        scope = name.split("/", 1)[0]
        if f"{scope}:registry=" not in npmrc_text:
            issues.append(f"npmrc: missing explicit {scope}:registry= binding")
    return issues


if __name__ == "__main__":
    bad_req = "--extra-index-url https://internal.example/simple\ninternal-auth>=1.0.0\n"
    good_req = "--index-url https://artifacts.internal.example/simple\nrequests==2.32.3 --hash=sha256:0000\n"
    assert len(check_pip_requirements(bad_req)) == 2
    assert len(check_pip_requirements(good_req)) == 0

    bad_npmrc = "registry=https://registry.npmjs.org/\n"
    bad_pkg = json.dumps({"name": "@myorg/core", "private": True})
    good_npmrc = "@myorg:registry=https://artifacts.internal.example/npm/\nignore-scripts=true\n"
    print("bad npm:", check_npmrc_and_pkg(bad_npmrc, bad_pkg))
    assert len(check_npmrc_and_pkg(bad_npmrc, bad_pkg)) == 2
    assert check_npmrc_and_pkg(good_npmrc, bad_pkg) == []
```

## 验证与判定标准

| 检查项 | 判定为已加固（PASS） | 判定为存在风险（FAIL） | 验证方式 |
|---|---|---|---|
| PyPI 源配置 | 仅使用单一私有代理 `index-url`，无 `--extra-index-url` 且带哈希锁 | 存在 `--extra-index-url` 或未锁定版本/哈希 | `check_pip_requirements` 零告警 |
| npm Scope 与脚本 | 私有包均带 `@scope/` 并绑定私有 registry，CI 启用 `ignore-scripts=true` | 私有包无 scope 绑定或构建默认执行 `preinstall` | `check_npmrc_and_pkg` 与 CI YAML 核查 |
| 锁文件与 Tarball 一致性 | CI 使用 `npm ci`/`--frozen-lockfile` 校验 `integrity` | 允许自动解析升级版本或跳过 `integrity` 核对 | 检查 CI 日志中实际解析的 registry URL |
| 前端与发布边界 | 公网不可下载 `package-lock.json`/source map；发布改用 OIDC Trusted Publisher | 静态站点暴露源码锁文件或 CI 长期存放通用 `NPM_TOKEN` | 生产静态路径检查与发布配置核查 |

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索供应链加固文档 | `kb_router` | 按 `dependency confusion` / `supply chain` / `npm` 搜索 |
| 对照投毒与枚举路径 | `kb_read_file` | 读取 `ctf-website/11-supply-chain/dependency-confusion` 核对判定矩阵 |
| 关联 CI/CD 流水线防护 | `kb_catalog` | 查看 `ci-cd-pipeline-defense` 与 `github-actions-abuse-paths-defense` |
