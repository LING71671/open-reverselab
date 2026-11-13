---
id: "ctf-website/11-supply-chain/artifact-provenance-verification"
title: "构建产物来源验证：摘要、构建身份与消费绑定"
title_en: "Artifact Provenance Verification: Digests, Build Identity, and Consumption"
summary: >
  分析签名或 attestation 已存在时的产物来源验证缺口，覆盖 subject digest、可信构建者、证书身份、source/ref、predicate、版本回退与验证后替换，提供离线策略差分试件与 GitHub CLI 核验入口。
summary_en: >
  Analyze provenance gaps despite existing signatures or attestations: subject digest, trusted builders, certificate identity, source/ref, predicates, rollback, and replacement after verification. Includes an offline policy matrix and GitHub CLI verification entry points.
board: "ctf-website"
category: "11-supply-chain"
signals: ["artifact attestation", "SLSA", "Sigstore", "provenance", "subject digest", "builder.id", "gh attestation verify", "构建来源"]
mcp_tools: ["kb_router", "kb_read_file"]
keywords: ["产物来源验证", "artifact provenance", "attestation", "SLSA", "Sigstore", "构建身份", "版本回退", "TOCTOU"]
difficulty: "advanced"
tags: ["supply-chain", "attestation", "ci-cd", "sigstore", "red-team"]
language: "zh-CN"
last_updated: "2026-11-13"
related_articles: ["ctf-website/11-supply-chain/artifact-provenance-verification-defense", "ctf-website/10-cloud/github-actions-abuse-paths", "ctf-website/11-supply-chain/dependency-confusion", "ctf-website/10-cloud/presigned-object-storage"]
track: "red"
---
# 构建产物来源验证：摘要、构建身份与消费绑定

## 1. 场景与信任前提

部署系统、安装器或更新器下载二进制、包或镜像，并检查签名/attestation。此时要验证“此次实际使用的字节，是否来自被信任的构建身份及允许的源码版本”，并追踪检查之后到安装/执行之前是否发生替换。

[SLSA v1.2 的验证方法](https://slsa.dev/spec/v1.2/verifying-artifacts)要求将签名、产物 subject 摘要、可信 builder、predicate 类型和构建参数与预先建立的期望比较。可信根及允许的 builder 来自消费者策略；声明里的 `builder.id` 不能自行决定它被信任到什么程度。

使用实验构建输出对消费者的验证行为做差分。若需要分析不可信 workflow 如何获得签名资格，关联 [GitHub Actions 滥用路径](../10-cloud/github-actions-abuse-paths.md)。

## 2. 输入信号与工作流

| 信号 | 先查看 | 候选缺口 |
|---|---|---|
| `.sigstore.json`、in-toto statement、SLSA predicate | 实际验证器、可信根、policy | 只解析声明，未验证签名 |
| 只显示“签名通过” | 证书身份与实际约束 | 任意合法签名者被接受 |
| 验证以组织为范围 | repo/workflow/ref/commit 条件 | 同组织非发布构建被接受 |
| digest 仅记录在日志，后续用可变 URL/tag 下载 | 检查和消费时各自摘要 | 验证后替换 |
| 历史 release 也有合法证明 | 允许版本/更新顺序 | 合法旧产物回退 |
| JSON 声称高 SLSA 等级 | builder 信任映射与构建隔离证据 | 自声明被当作可信属性 |

```text
固定允许的 repo / signer / builder / source / ref / 参数
  → 取得产物、证明及可信根
  → 密码学验证 → 可信身份与 provenance 策略
  → 绑定验证摘要 → 安装/部署时再次对应实际字节
    ├─ digest 不符 → 分发完整性路径
    ├─ 签名合法但身份/来源不符 → 策略范围路径
    ├─ 历史证明合法但版本不允许 → 回退路径
    └─ 验证后消费摘要改变 → 检查使用时间差
```

## 3. 多路径差分矩阵

### 3.1 产物和证明是否属于同一对象

保留合成 `demo-v1` 文件与其证明，再仅修改产物一个字节。核验消费者是否在使用前拒绝，记录本地摘要和 statement 的 subject 摘要。若重新打包改变压缩包字节，应判断证明面向整个压缩包还是其中某个文件；对多 subject 证明，匹配实际消费对象，不能取数组首项就结束。

镜像要区分 tag、index digest 与平台 manifest digest。记录验证对象和运行时实际拉取对象；若平台选择需要跨层映射，保留 index 到 manifest 的关系，不能直接比较不同层次的 digest 字符串。

### 3.2 合法签名者与允许发布者

从两个实验构建身份生成内容相同的产物，保持摘要相同，只改变签名主体或 workflow。再分别改变源仓库、ref、源码提交或构建参数。这样可区分“签名可验证”与“当前发布策略允许”的判断。

对于 GitHub attestations，验证结果中的证书信息与签名时间信息、statement 内可由 workflow 提供的字段具有不同可信来源。攻击者若控制 workflow 执行上下文，可能影响 predicate 内容；因此不能用 predicate 中自写的身份来替代证书约束。[GitHub CLI 验证说明](https://cli.github.com/manual/gh_attestation_verify)

可复用 workflow 还要区分 caller 仓库与实际 signer workflow。保留其固定版本或 digest，并依据可信构建器的参数约定核验 source 与构建选项。[SLSA Build Provenance](https://slsa.dev/spec/v1.2/build-provenance)定义的 `buildType` 决定参数结构及含义；不能假定所有构建器都使用同一组 JSON 键。

### 3.3 历史合法产物与验证后替换

准备当前和旧版两个合成产物，证明都有效。向测试更新器提供旧版，观察版本策略、允许来源和安装结果；签名有效并不自动表达当前业务允许回退。

在本地测试下载器中，验证文件 A 后，把消费引用切到文件 B，比较验证摘要与最终打开/部署的摘要。该试验无需执行 B；记录“准备消费的字节”即可证明绑定是否存在。对 OCI 流程使用 digest 引用做对照，记录 tag 在验证到拉取期间的解析结果。

## 4. 真实验证器入口与能力范围

先运行 `gh --version` 和 `gh attestation verify --help`，按安装版本确认参数。下例变量由实验配置提供，路径指向本地产物；不运行安装或发布：

```powershell
gh attestation verify $artifactPath --repo $expectedRepo --signer-workflow $expectedWorkflow --source-ref $expectedRef --source-digest $expectedCommit --format json
```

`--repo`、`--signer-workflow`、`--source-ref` 与 `--source-digest` 对应不同约束。默认命令会获取关联 attestation；本地 bundle、离线可信根及可复用 workflow 的处理应遵循已安装版本帮助和前述官方 CLI 文档，不能把网络失败直接记录成策略拒绝。

普通 blob 签名也可用 `cosign verify-blob` 搭配 bundle、明确 certificate identity 和 OIDC issuer；它检查的是对应签名格式及身份，SLSA 的来源和参数约束仍需另外检查。[Sigstore 验证文档](https://docs.sigstore.dev/cosign/verifying/verify/)

### 4.1 固定实际 run 和下载的文件

先从发布记录或 CI 界面取得明确的 run ID、artifact 名、文件名、源码 commit 与允许的 signer workflow。期望值来自发布策略或已经确定的构建记录，不能从待验证证明中读取后又把它当成预期值。

GitHub Actions 产物可这样取得。`LAB_ARTIFACT_REPO` 格式为 `owner/repo`，其余变量来自该次实验构建：

```powershell
$provOut = Join-Path (Get-Location).Path 'exports/ctf-website/demo-provenance'
New-Item -ItemType Directory -Path $provOut -Force | Out-Null
$provRun = & gh run view $env:LAB_RUN_ID --repo $env:LAB_ARTIFACT_REPO --json databaseId,headSha,headBranch,event,workflowName,conclusion
if ($LASTEXITCODE -ne 0) { throw 'Unable to read the selected build run' }
$provRun | Set-Content -LiteralPath "$provOut/run.json"
& gh run download $env:LAB_RUN_ID --repo $env:LAB_ARTIFACT_REPO --name $env:LAB_ARTIFACT_NAME --dir "$provOut/download"
if ($LASTEXITCODE -ne 0) { throw 'Artifact download failed' }
$artifactPath = (Resolve-Path -LiteralPath (Join-Path "$provOut/download" $env:LAB_ARTIFACT_FILE)).Path
$provDigestBefore = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
$provDigestBefore | Set-Content -LiteralPath "$provOut/artifact.sha256"
```

若证明面向压缩包本身，应保留发布时的压缩包原字节；不能用解压后某个文件替代 subject。镜像流程记录完整 OCI digest 引用，并选择实际运行的平台，不以会变化的 tag 字符串作为唯一证据。

### 4.2 运行验证器并保留可追溯结果

```powershell
$provVerified = & gh attestation verify $artifactPath --repo $env:LAB_ARTIFACT_REPO --signer-workflow $env:LAB_SIGNER_WORKFLOW --source-ref $env:LAB_SOURCE_REF --source-digest $env:LAB_SOURCE_COMMIT --format json
$provVerifyExit = $LASTEXITCODE
$provVerified | Set-Content -LiteralPath "$provOut/verification.json"
if ($provVerifyExit -ne 0) { throw "Attestation rejected or unavailable: exit $provVerifyExit" }
$provItems = $provVerified | ConvertFrom-Json
foreach ($item in $provItems) {
  $item.verificationResult.signature.certificate | ConvertTo-Json -Depth 30
  $item.verificationResult.statement.subject | ConvertTo-Json -Depth 20
  $item.verificationResult.statement.predicate.buildDefinition | ConvertTo-Json -Depth 30
  $item.verificationResult.statement.predicate.runDetails.builder | ConvertTo-Json -Depth 20
}
```

确认命中的 subject digest 与 `artifact.sha256` 一致，检查实际 signer、source commit/ref、buildType 和外部参数。可复用 workflow 的 signer 与 caller 来源分别核对。验证器成功后，仍需按该 buildType 的定义检查发布参数；不要把未知参数直接忽略。

使用普通 Sigstore blob bundle 时，调用对应接口并保存输出和退出码：

```powershell
$provBlobResult = & cosign verify-blob $artifactPath --bundle $env:LAB_SIGSTORE_BUNDLE --certificate-identity $env:LAB_SIGNER_IDENTITY --certificate-oidc-issuer $env:LAB_OIDC_ISSUER 2>&1
$provBlobExit = $LASTEXITCODE
$provBlobResult | Set-Content -LiteralPath "$provOut/blob-verification.txt"
if ($provBlobExit -ne 0) { throw "Blob signature verification failed: exit $provBlobExit" }
```

这里的 bundle 必须是该验证命令支持的签名类型。SLSA attestation 与普通 blob signature 的 payload 不同，不能为了得到成功输出而把一种格式换成另一种。若证据或可信根缺失，记录所缺文件/来源，先取得它们再验证。

### 4.3 四组实际差分及消费端证据

1. **字节变更**：复制已验证文件，改变副本一个字节，对该副本重新运行同样的验证命令。保留副本摘要与拒绝输出，原文件继续用于正常对照。
2. **身份变更**：从另一个实验 workflow 取得合法签名产物；用原发布策略验证，再用其自身实验策略作正常对照。若仅原策略拒绝，可定位到身份或来源约束。
3. **版本回退**：取得历史实验 run 的合法产物和证明，保持消费者当前允许的 source/ref/版本策略不变。记录验证器、版本策略和安装决策各自结果。
4. **验证后替换**：在消费端测试入口仅替换文件引用或可变下载地址，记录消费者实际打开文件的 SHA256。安装器若先验证再解压，分别记录被验证包和解压输入的摘要，而不是拿包摘要去比较里面的可执行文件。

文件副本的字节变更可这样生成，不执行副本：

```powershell
$provChangedPath = Join-Path $provOut 'changed-artifact.bin'
$provBytes = [System.IO.File]::ReadAllBytes($artifactPath)
if ($provBytes.Length -eq 0) { throw 'Choose a non-empty artifact' }
$provBytes[0] = $provBytes[0] -bxor 1
[System.IO.File]::WriteAllBytes($provChangedPath, $provBytes)
Get-FileHash -LiteralPath $provChangedPath -Algorithm SHA256
```

在真实消费者准备安装/执行前，对它实际打开的文件记录摘要，与 `provDigestBefore` 比较；若消费者会再下载，捕获那次下载后的摘要。无法取得消费端路径或 digest 时，结论止于验证器对输入文件的结果，下一步接入消费者日志。

## 5. 可运行的离线策略差分试件

保存为 `provenance_policy_fixture.py`，运行 `python provenance_policy_fixture.py`。该试件模拟**真实验证器已成功之后**的策略输入，`verified_identity` 是测试数据；没有签名或证书验证，不能接收不可信 JSON 就据此放行文件。

```python
from copy import deepcopy
import hashlib
import json


def digest(data):
    return hashlib.sha256(data).hexdigest()


def policy_failures(blob, statement, verified_identity, expected):
    predicate = statement["predicate"]
    definition = predicate["buildDefinition"]
    params = definition["externalParameters"]
    checks = {
        "subject": any(s.get("digest", {}).get("sha256") == digest(blob)
                       for s in statement["subject"]),
        "predicate-type": statement["predicateType"] == "https://slsa.dev/provenance/v1",
        "identity": verified_identity == expected["identity"],
        "builder": predicate["runDetails"]["builder"]["id"] == expected["builder"],
        "build-type": definition["buildType"] == expected["build_type"],
        # 这些参数名由本例的 synthetic buildType 自行定义。
        "parameters": params == expected["parameters"],
    }
    return [name for name, ok in checks.items() if not ok]


def main():
    artifact = b"SYNTHETIC_RELEASE_V2\n"
    expected = {
        "identity": "https://ci.example.test/workflows/release@fixed",
        "builder": "https://ci.example.test/builders/isolated-v1",
        "build_type": "https://ci.example.test/build-types/demo/v1",
        "parameters": {"source": "https://code.example.test/demo",
                       "commit": "1" * 40, "ref": "refs/tags/demo-v2"},
    }
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "demo.bin", "digest": {"sha256": digest(artifact)}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {"buildType": expected["build_type"],
                                "externalParameters": deepcopy(expected["parameters"])},
            "runDetails": {"builder": {"id": expected["builder"]}},
        },
    }
    identity = expected["identity"]
    assert policy_failures(artifact, statement, identity, expected) == []
    cases = {}
    cases["different-bytes"] = policy_failures(artifact + b"changed", statement, identity, expected)
    cases["other-signer"] = policy_failures(artifact, statement, "other-signer", expected)
    older = deepcopy(statement)
    older["predicate"]["buildDefinition"]["externalParameters"]["ref"] = "refs/tags/demo-v1"
    cases["old-ref"] = policy_failures(artifact, older, identity, expected)
    extra = deepcopy(statement)
    extra["predicate"]["buildDefinition"]["externalParameters"]["debug"] = True
    cases["unknown-parameter"] = policy_failures(artifact, extra, identity, expected)
    assert all(cases.values())
    verified_digest = digest(artifact)
    consumed = b"SYNTHETIC_OTHER_ARTIFACT\n"
    assert digest(consumed) != verified_digest
    print(json.dumps({"kind": "policy-only-fixture", "rejected": cases,
                      "replacement_detected": True}, indent=2))


if __name__ == "__main__":
    main()
```

真实接入还要检查 statement 格式、证明链、证书与签名时间、可信根、builder 声明的完整参数集合。测试输出中的 `replacement_detected` 只说明合成字节不同；要证明目标存在检查使用缺口，必须记录目标验证的摘要与实际消费的摘要。

## 6. 证据、失败与反证

| 结果 | 可下的结论 | 补充证据 |
|---|---|---|
| 修改产物被拒绝 | 该验证路径绑定了产物摘要 | 检查最终消费是否仍用同一摘要 |
| 其他 workflow 的合法证明也被接受 | 可能是身份约束过宽 | 明确预设允许集合及证书身份 |
| JSON 中改 source 后仍显示“验证成功” | 可能仅验证了另一层对象 | 检查真正被签名 payload 与被消费 predicate |
| 获取证明超时 | 证据获取失败 | 离线 bundle 对照；记录是否错误放行 |
| 合法旧版被接受 | 仅说明旧版满足已配置条件 | 对照回退政策与实际安装状态 |
| artifact 无证明 | 无法完成来源验证 | 记录产品对缺失证明的处理策略 |
| 签名和来源都满足策略 | 本次来源约束成立 | 内容行为分析另行处理，不由来源检查推导 |

输出到 `exports/ctf-website/<case>/artifact-provenance/`：产物摘要、证明文件摘要、验证器版本、可信根标识、策略、证书身份、builder/source/ref、验证退出码、消费摘要及安装决策。结论必须区分密码学失败、策略不匹配、证据缺失、网络失败与消费绑定错误。

蓝队关联：[构建产物来源验证防御](../../../../blue/ctf-website/techniques/11-supply-chain/artifact-provenance-verification-defense.md)。若下载链使用预签名对象，继续检查 [对象版本与消费绑定](../10-cloud/presigned-object-storage.md)；若身份来源可被不可信 workflow 控制，继续检查 CI 权限链。

## 7. MCP 工具映射

| 步骤 | 工具 | 能力边界 |
|---|---|---|
| 信号路由 | `kb_router(query="artifact attestation SLSA", board="ctf-website", track="red")` | 查来源与 CI 技术路径 |
| 读取关联篇 | `kb_read_file` | 读取 CI、对象存储及供应链方法 |
| 验签与 provenance 策略 | 已安装的 `gh` / `cosign` 与对应 verifier | 按版本和格式选择；仓库未假设有自动覆盖全部证明格式的 MCP 工具 |
| 离线策略矩阵 | 本地 Python | 不执行密码学验证、不访问 registry、不部署产物 |
