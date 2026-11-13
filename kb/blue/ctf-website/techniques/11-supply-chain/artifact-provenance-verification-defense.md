---
id: "ctf-website/11-supply-chain/artifact-provenance-verification-defense"
title: "构建制品来源防御：签名身份、Provenance 策略与消费绑定"
title_en: "Artifact Provenance Defense: Signer Identity, Policy and Consumption Binding"
summary: >
  在下载、部署和更新入口核验制品字节、attestation 签名、signer/issuer、builder、source/ref、构建参数及期望版本，避免只检查签名或下载后换用可变标签。提供 SLSA v1 provenance 的合成策略实验和真实验证器集成检查点。
summary_en: >
  Verify artifact bytes, attestation signatures, signer/issuer, builder, source/ref, build parameters, and release expectations at download and deployment boundaries. Includes a synthetic SLSA v1 policy experiment and integration checks for real verifiers.
board: "ctf-website"
category: "11-supply-chain"
signals: ["artifact provenance", "SLSA", "attestation", "subject digest", "builder identity", "Sigstore", "TOCTOU"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["制品来源防御", "构建证明", "SLSA验证", "Sigstore", "供应链防御", "摘要绑定", "构建身份"]
difficulty: "advanced"
tags: ["defense", "blue-team", "supply-chain", "provenance", "ci-cd", "attestation"]
language: "zh-CN"
last_updated: "2026-11-13"
related_articles: ["ctf-website/11-supply-chain/artifact-provenance-verification", "ctf-website/10-cloud/github-actions-abuse-paths-defense", "ctf-website/11-supply-chain/dependency-confusion-defense"]
track: "blue"
defends: "ctf-website/11-supply-chain/artifact-provenance-verification"
---
# 构建制品来源防御：签名身份、Provenance 策略与消费绑定

## 1. 防守对象与部署前提

适用于从 CI artifact、release、包仓库、对象存储或 OCI registry 取得文件并运行、安装或部署的系统。先建立独立于下载响应的**期望策略**：允许的项目与发布渠道、signer/issuer、builder、工作流、source revision、构建类型、参数及最低接受版本。

SLSA v1.2 将来源验证与对 builder、构建类型和输入参数的预期校验结合；参见 [Verifying artifacts](https://slsa.dev/spec/v1.2/verifying-artifacts)。provenance 的存在、密码学验证结果和业务接受决定应作为三个字段记录。

| 输入信号 | 需要保留的证据 | 可能缺失的边界 |
|---|---|---|
| “有签名”但来自其他工作流 | 验证后的证书/身份、issuer、仓库/工作流标识 | signer 身份策略过宽 |
| provenance 中 subject 指向另一文件 | 下载字节摘要、subject digest、文件类型 | statement 与真实制品未绑定 |
| 同项目非发布分支的制品进入生产 | source/ref/revision、trigger、发布期望 | 仅检查项目名称，未限定构建入口 |
| 校验后部署了不同字节 | 校验时摘要、安装/部署时摘要、可变 tag/URL | 校验与使用之间发生替换 |
| 旧版有合法 attestation 却不应再部署 | 受信版本策略、发布时间和目标环境 | 来源验证缺少回滚/版本策略 |
| provenance 参数与发布行为不符 | buildType、externalParameters、resolvedDependencies | 输入参数或 builder 信任被错误解释 |

## 2. 防御工作流

```text
受控发布策略
  → 下载到隔离位置，固定实际字节/OCI digest
  → 获取对应 attestation 与受信根
  → 成熟验证器校验签名、证书身份与必要时间/透明日志证明
  → 校验 predicate 类型、subject、builder、source/ref 与构建参数
  → 生成绑定 digest 和策略版本的接受记录
  → 部署同一摘要的制品 → 独立读取实际部署摘要
验证失败 → 不进入消费步骤 → 保存失败原因 → 回溯 CI 或分发来源
```

### 控制矩阵

| 控制 | 实施要点 | 反例测试 |
|---|---|---|
| 信任根与身份 | 从可信配置提供根、issuer、确切 signer/工作流，避免无边界身份正则 | 同 issuer 下另一个项目/工作流的合法签名必须拒绝 |
| Payload 类型 | 检查 attestation/statement 类型及期望 `predicateType` | SBOM 或其他声明不能冒充 build provenance |
| 制品绑定 | 从本地实际字节计算 digest，与正确 subject 匹配 | 同名不同内容、另一个架构或版本的包不能通过 |
| Builder 策略 | 将经过验证的 signer 与允许 builder 组合绑定，了解谁能影响构建和证明内容 | statement 自称可信 builder 但 signer 不符时拒绝 |
| Source 与参数 | 按该 `buildType` 定义校验源、revision、ref、配置与外部参数 | 未批准分支、不同源地址、额外危险参数必须拒绝 |
| 消费绑定 | 校验后按不可变 digest/已打开文件消费，保持访问权限与独立摘要复核 | 不重新以 `latest`、同名 URL 或可替换路径下载 |
| 发布生命周期 | 发布期望来自受控渠道；旧版本使用有明确规则 | 合法旧签名不能自动满足新的版本要求 |

`externalParameters` 的结构由具体 buildType 定义；不要假设所有生产者都使用 `repository`、`ref` 等同名字段。[SLSA Build Provenance](https://slsa.dev/spec/v1.2/build-provenance)定义通用结构，生产者的 buildType 文档决定参数语义。

## 3. 离线合成实验：对已验签结果执行接受策略

保存为 `exports/ctf-website/provenance-defense/policy.py`。示例采用一个自行定义的合成 buildType。`verified_identity` 模拟受信验证器的输出，不能由下载的 JSON 自报；此代码不执行 Sigstore、DSSE、证书或透明日志的密码学验证。

```python
import hashlib
from copy import deepcopy

ARTIFACT = b"synthetic-release-artifact\n"
EXPECTED = {"issuer": "https://issuer.example.test", "signer": "release-workflow-v1",
            "builder": "https://build.example.test/builders/release",
            "build_type": "https://build.example.test/types/release/v1",
            "source": "https://source.example.test/team/project", "ref": "refs/tags/v1.0.0",
            "revision": "a" * 40, "config": "release"}
IDENTITY = {"issuer": EXPECTED["issuer"], "signer": EXPECTED["signer"]}
STATEMENT = {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [{"name": "release.bin", "digest": {"sha256": hashlib.sha256(ARTIFACT).hexdigest()}}],
    "predicateType": "https://slsa.dev/provenance/v1",
    "predicate": {
        "buildDefinition": {
            "buildType": EXPECTED["build_type"],
            "externalParameters": {"source": EXPECTED["source"], "ref": EXPECTED["ref"],
                                   "config": EXPECTED["config"]},
            "resolvedDependencies": [{"uri": EXPECTED["source"],
                                      "digest": {"gitCommit": EXPECTED["revision"]}}],
        },
        "runDetails": {"builder": {"id": EXPECTED["builder"]}},
    },
}


def accept(data, statement, verified_identity):
    if verified_identity != IDENTITY:
        return "deny:identity"
    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        return "deny:statement-type"
    if statement.get("predicateType") != "https://slsa.dev/provenance/v1":
        return "deny:predicate-type"
    wanted = hashlib.sha256(data).hexdigest()
    if not any(s.get("digest", {}).get("sha256") == wanted for s in statement.get("subject", [])):
        return "deny:subject"
    predicate = statement.get("predicate", {})
    if predicate.get("runDetails", {}).get("builder", {}).get("id") != EXPECTED["builder"]:
        return "deny:builder"
    build = predicate.get("buildDefinition", {})
    if build.get("buildType") != EXPECTED["build_type"]:
        return "deny:build-type"
    params = {k: EXPECTED[k] for k in ("source", "ref", "config")}
    if build.get("externalParameters") != params:
        return "deny:parameters"
    dependencies = [{"uri": EXPECTED["source"], "digest": {"gitCommit": EXPECTED["revision"]}}]
    if build.get("resolvedDependencies") != dependencies:
        return "deny:revision"
    return "accept:" + wanted


assert accept(ARTIFACT, STATEMENT, None) == "deny:identity"
assert accept(ARTIFACT, STATEMENT, {**IDENTITY, "signer": "other-workflow"}) == "deny:identity"
assert accept(ARTIFACT + b"changed", STATEMENT, IDENTITY) == "deny:subject"
mutations = [
    (("predicateType",), "https://example.test/other-predicate"),
    (("predicate", "runDetails", "builder", "id"), "https://other.example.test/builder"),
    (("predicate", "buildDefinition", "externalParameters", "ref"), "refs/heads/dev"),
    (("predicate", "buildDefinition", "externalParameters", "extra"), "unapproved"),
    (("predicate", "buildDefinition", "resolvedDependencies"), []),
]
for path, value in mutations:
    changed = deepcopy(STATEMENT)
    node = changed
    for component in path[:-1]:
        node = node[component]
    node[path[-1]] = value
    assert accept(ARTIFACT, changed, IDENTITY).startswith("deny:"), path
receipt = accept(ARTIFACT, STATEMENT, IDENTITY)
assert receipt == "accept:" + hashlib.sha256(ARTIFACT).hexdigest()
assert receipt != "accept:" + hashlib.sha256(ARTIFACT + b"replaced").hexdigest()
print("Artifact identity, subject, build-policy and consumption fixtures passed")
```

本例刻意只接受一个已知 schema 的参数集合；真实系统先做结构校验，再按具体 buildType 的规范处理兼容字段，未知类型明确拒绝或转人工处理。对多 subject、多 dependency 和多架构包单独写测试，避免把示例的一项数组要求直接套到所有构建者。

## 4. 与真实验证器衔接

GitHub 的 `gh attestation verify` 可限定 repo、signer workflow、source ref/digest 并输出验证结果；复用工作流时要核对真正签署证明的工作流身份。参数及行为参见 [GitHub CLI 官方文档](https://cli.github.com/manual/gh_attestation_verify)。使用前记录 `gh version` 与支持的 flags。

```sh
gh attestation verify release.bin --repo example-org/example-project --signer-workflow example-org/example-project/.github/workflows/release.yml --source-ref refs/tags/v1.0.0 --format json
```

此命令是操作示意，项目名与文件均为占位；没有在真实仓库执行。精确 revision 应来自受控发布记录并按所用工具支持方式校验。离线验证还要提前保存适合该信任实例的 bundle 和 trust root，流程见 [GitHub 离线验证](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline)。

Sigstore 场景也应配置预期身份与 issuer，blob 签名和 attestation 使用适配的验证命令；见 [Cosign verification](https://docs.sigstore.dev/cosign/verifying/verify/)。验证器成功退出后，仍执行本应用的构建/发布策略，并把校验结果绑定到实际消费 digest。

GitHub 特别区分证书中的受验证身份与工作流可控制的 statement 内容。因此 `builder.id`、source 和参数还需要可信构建边界支撑；攻击者能控制签署工作流时，不应仅因为其 predicate 声称正确就接受。修复入口连到 [Actions 防御](../10-cloud/github-actions-abuse-paths-defense.md)。

## 5. 独立验证、误报与证据

| 对照 | 独立确认点 | 解释与下一步 |
|---|---|---|
| 合法制品 + 正确身份/来源 | 接受记录与实际部署 digest 一致 | 记录策略、验证器、trust root 和制品版本 |
| 同名改字节或错 subject | 不进入部署步骤 | 只有报错文字不足，检查真实部署动作 |
| 同 issuer 的另一个合法 signer | 身份策略拒绝 | 不能把 issuer 一致等同于项目可信 |
| 正确项目的非发布构建/额外参数 | 发布策略拒绝 | 排查来源/ref 绑定与触发器权限 |
| 下载/校验间或校验/消费间替换 | 最终消费摘要仍匹配接受记录，或被拒绝 | 固定字节与访问权限；避免再次解析可变 tag |
| 验证器不可用/根过期/离线缺数据 | 明确失败，不自动跳过验证 | 修复证据供应或信任配置，保留正常对照 |
| 合法旧版或重建版本 | 按显式版本/回滚策略处理 | 重建可能有不同摘要，不能只比较文件名或版本字符串 |

旧版允许回滚、仓库迁移、复用工作流和多架构产物都是正常变化来源；将受控变更加入预期策略后回归，不用宽泛通配替代精确边界。源码安全、依赖漏洞和运行行为继续走对应分析路径；本篇判定的是来源和消费链是否符合预期。

本地 Evidence 输出 `exports/ctf-website/provenance-defense/<run-id>/`：制品摘要、bundle/验证输出、工具与策略版本、受信根来源、接受/拒绝原因、实际部署摘要和未覆盖构建类型。公开库只保留合成 fixture。

## MCP 工具映射

| 阶段 | 工具 | 用途与边界 |
|---|---|---|
| 路由供应链信号 | `kb_router` | 检索 SLSA、artifact、subject digest 等词 |
| 对照分析路径 | `kb_read_file` | 读取[制品来源核验分析](../../../../red/ctf-website/techniques/11-supply-chain/artifact-provenance-verification.md) |
| 查 CI/依赖防护 | `kb_catalog` | 连接 Actions 与[依赖混淆](dependency-confusion-defense.md)，不验证签名 |

真实密码学验证使用已确认可用的 `gh`、`cosign` 或相应实现；本篇离线 Python 仅验证策略逻辑。
