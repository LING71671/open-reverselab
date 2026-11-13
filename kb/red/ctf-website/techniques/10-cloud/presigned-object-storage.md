---
id: "ctf-website/10-cloud/presigned-object-storage"
title: "对象存储预签名授权：签发、上传与消费链"
title_en: "Presigned Object Storage Authorization: Issuance, Upload, and Consumption"
summary: >
  以 S3 SigV4 预签名 URL 与 POST policy 为基准，分析签发接口的对象归属、key 范围、期限、重复使用、覆盖及扫描后消费的版本绑定，提供合成 POST 条件矩阵与失败证据要求。
summary_en: >
  Analyze S3 SigV4 presigned URLs and POST policies across issuance, object ownership, key scope, expiry, reuse, overwrite, and post-scan consumption. Includes a synthetic POST-condition matrix and evidence requirements.
board: "ctf-website"
category: "10-cloud"
signals: ["presigned URL", "X-Amz-Signature", "X-Amz-Expires", "POST policy", "预签名", "object key", "uploadId", "signed upload"]
mcp_tools: ["kb_router", "kb_read_file"]
keywords: ["S3预签名", "presigned URL", "POST policy", "对象越权", "签发接口", "上传覆盖", "versionId", "消费链"]
difficulty: "advanced"
tags: ["cloud", "s3", "authorization", "file-upload", "red-team"]
language: "zh-CN"
last_updated: "2026-11-13"
related_articles: ["ctf-website/10-cloud/presigned-object-storage-defense", "ctf-website/14-idor/01-idor-enumeration", "ctf-website/06-file-attacks/file-upload-xxe-lfi", "ctf-website/10-cloud/aws-iam-privesc"]
track: "red"
---
# 对象存储预签名授权：签发、上传与消费链

## 1. 场景与协议边界

应用先为用户签发对象存储 URL 或表单，浏览器再直接下载/上传，业务后端最后确认或处理对象。分析链应从签发 API 延伸到存储服务与最终消费者。

S3 预签名 URL 使用签发主体的权限，指定 bucket、key、方法及期限；持有者可在有效期间重复使用。临时凭据提前失效会缩短 URL 的实际有效期；向同一 key 上传会改变当前对象。参见 [AWS 预签名 URL 说明](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html)。签发成功、URL 可用和业务允许该用户操作此对象，是三个需分别核验的状态。

本篇事实以 Amazon S3 为准。S3-compatible 产品可能有不同签名、条件或缓存实现，先保存服务产品、SDK 与接口版本，用正常请求确认兼容能力。

## 2. 输入信号与工作流

| 信号 | 记录内容 | 下一跳 |
|---|---|---|
| `/upload/sign`、`/download-url` 等接口 | 当前主体、object ID、key、方法、返回期限 | 签发对象授权 |
| 查询参数含 `X-Amz-*` | 日期、Expires、SignedHeaders、签发范围 | 签名覆盖与有效期 |
| 表单返回 base64 policy | 解码后的 expiration/conditions | POST key、长度与表单字段约束 |
| 客户端确认上传时只传 key | 服务端上传记录与租户 | 对象归属替换 |
| 扫描完再按同一个 key 读取 | 扫描版本与消费版本 | 覆盖/检查使用时间差 |
| multipart 返回 uploadId/part URL | uploadId 的 owner、key、part 映射 | 完成操作的归属与重放 |

```text
A/B 各自拥有实验对象
  → 正常签发、上传/下载、业务确认
  → 单变量替换 object ID / key / method / expiry / policy 范围
    ├─ A 为 B 对象取得可用 URL → 签发授权缺口
    ├─ 已签 URL 改 key 后被拒绝 → 签名覆盖生效
    ├─ POST 条件允许其他租户前缀 → 授权范围过宽
    ├─ URL 重复使用 → 对照产品一次性语义
    └─ 扫描版本与消费版本不同 → 内容绑定缺口
```

## 3. 签发与消费的多路径实验

### 3.1 先区分“改签名前的输入”与“改签名后的请求”

用 A 的有效会话，请签发接口为 B 的合成对象生成 URL；同时保留 A 自己对象的正常对照。若接口返回 URL，继续检验它是否真实可用，以及业务结果确属 B。部分 SDK 能在未验证对象存在或运行时权限的情况下构造字符串，因此“拿到 URL”只能证明签发行为发生。

随后对正常 URL 只改变 key 或 HTTP 方法，观察存储错误。签名不匹配说明请求绑定的一部分生效，但不能排除签发接口此前给错了对象。记录签发请求与存储请求的对应关系。

对象 key 是完整、区分大小写的字符串，S3 使用平面数据模型，`/` 只参与逻辑前缀；参见 [AWS object key 说明](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html)。应用若把它当作本地路径解码、规范化或拼接，应记录**输入 key → 签名 key → 存储 key → 消费 key**，不能直接把含 `../` 的 key 判为存储层路径穿越。

### 3.2 URL 期限、退出登录与重复使用

记录签发时间、URL 期限、签发凭据有效期、bucket policy 和发起请求时间。实际测试至少包含正常有效期、过期后新请求、成功后重复请求三个点。下载在过期前已开始可继续传输，不能据此判定存储服务忽略期限；这一语义由 AWS 预签名说明定义。

应用退出登录后，已经签发的 bearer URL 不必随应用 cookie 自动失效。若业务明确承诺退出、撤权或“一次下载”后失效，再验证该承诺由何处实现；其结果需和 URL 自身正常可重复使用的语义分开。

### 3.3 POST policy 与上传属性

POST policy 支持 exact match、`starts-with` 和 `content-length-range`，表单变量先展开再匹配条件；一般表单字段需要出现在条件中，规范列有 `file`、`policy`、签名和 `x-ignore-` 等例外。[AWS POST Policy](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-HTTPPOSTConstructPolicy.html)

核验 key 前缀是否属于已认证用户，且包含正确分隔符。`tenants/a` 同时匹配 `tenants/ab/...`；`tenants/a/` 才表达本例的租户边界。对 Content-Type 的约束只能限制提交声明，文件解析器仍需观察实际内容。长度策略测试使用几字节的合成文本即可，无须上传大文件。

### 3.4 上传确认、覆盖与后续处理

上传 `DEMO_VERSION_1`，完成扫描，记录摘要及 versionId；随后通过仍有效的上传权限写入 `DEMO_VERSION_2`，触发业务读取。比较消费者取得的版本与被扫描版本。若 bucket 启用 versioning，覆盖会建立新版本，历史版本仍可恢复；参见 [S3 Versioning](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html)。消费者只按 key 读取当前版本时，历史版本存在并不会替它绑定到扫描结果。

对分片上传还应绑定 uploadId、对象 key、主体及完成动作。测试其他用户替换合成 uploadId 的完成请求，记录最终对象归属；存储层的分片成功不代表业务层已正确接收。

完整性证据使用明确的 checksum 算法或本地计算的对象摘要。ETag 在不同上传和加密方式下不能一概视为 MD5；参见 [AWS 上传完整性说明](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html)。

### 3.5 从签发接口取得 URL 并执行实际对象请求

在应用 Network 中取得正常签发请求与响应，将请求 body 保存为 `sign-request.json`。用 A 的实验会话重放正常 body，然后仅替换实验对象 ID/key，保存两次响应。可复用[HTTP 重放脚本](../../../general/techniques/ai-security/01-indirect-prompt-injection.md)，将 `LAB_AGENT_URL` 设置为实际签发接口；响应结构沿用应用原格式，不假定一定叫 `url`。

从返回值取得预签名 URL、HTTP 方法及必须携带的 headers。把完整 URL 放入 `LAB_PRESIGNED_URL`，不要手工重新编码或重新拼接查询字符串。先运行 `curl.exe --version` 确认当前 curl 可用，再按签发方法执行：

```powershell
$objectOut = 'exports/ctf-website/demo-storage'
New-Item -ItemType Directory -Path $objectOut -Force | Out-Null
$objectOut = (Resolve-Path -LiteralPath $objectOut).Path
# GET URL 的正常对照；不跟随重定向。
curl.exe --silent --show-error --fail-with-body --max-time 60 --request GET --dump-header "$objectOut/get.headers" --output "$objectOut/get.body" --write-out '%{http_code}' "$env:LAB_PRESIGNED_URL"
$objectGetExit = $LASTEXITCODE
Get-FileHash -LiteralPath "$objectOut/get.body" -Algorithm SHA256
```

输出中同时记录 HTTP 状态与 `$objectGetExit`；错误响应的 XML/JSON 留在 `get.body`，不要把错误页摘要当作目标对象摘要。若服务返回 redirect，先对照 endpoint/region 与签名目的地，不能靠自动重定向掩盖请求变化。

PUT 使用签发响应要求的 headers。以下例子假定签名要求 `Content-Type: text/plain`；如果实际有 checksum、metadata 或其他已签 header，应按原值一并传入：

```powershell
[System.IO.File]::WriteAllBytes("$objectOut/version-1.txt", [System.Text.Encoding]::UTF8.GetBytes('DEMO_VERSION_1'))
[System.IO.File]::WriteAllBytes("$objectOut/version-2.txt", [System.Text.Encoding]::UTF8.GetBytes('DEMO_VERSION_2'))
curl.exe --silent --show-error --fail-with-body --max-time 60 --request PUT --header 'Content-Type: text/plain' --upload-file "$objectOut/version-1.txt" --dump-header "$objectOut/put-1.headers" --output "$objectOut/put-1.body" --write-out '%{http_code}' "$env:LAB_PRESIGNED_URL"
$objectPut1Exit = $LASTEXITCODE
```

完成应用本来的上传确认和扫描流程，保存它实际扫描的 key、versionId、checksum。然后在同一 URL 仍有效时，使用第二份文本重复 PUT，保存到另一组文件：

```powershell
curl.exe --silent --show-error --fail-with-body --max-time 60 --request PUT --header 'Content-Type: text/plain' --upload-file "$objectOut/version-2.txt" --dump-header "$objectOut/put-2.headers" --output "$objectOut/put-2.body" --write-out '%{http_code}' "$env:LAB_PRESIGNED_URL"
$objectPut2Exit = $LASTEXITCODE
```

比较两次响应中的 `x-amz-version-id`，再通过应用实际的下载/处理入口读取对象。消费的是 v1、v2，还是确认接口明确拒绝重复上传，要以读取字节和业务记录判定。如果 URL 签了 v1 的 checksum，第二次内容变化可能先因 checksum/签名拒绝；这属于内容绑定已生效的分支，不能把它归为 URL 已经一次性失效。

### 3.6 POST 表单与 policy 条件的实际对照

保存应用原始签发表单响应为 `post-sign.json`。以下以返回 `{url, fields}` 为例，字段名称不同则按原响应修改；`fields` 里的值保持原样：

```powershell
$objectForm = Get-Content -LiteralPath "$objectOut/post-sign.json" -Raw | ConvertFrom-Json
$objectPolicyText = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($objectForm.fields.policy))
$objectPolicyText | Set-Content -LiteralPath "$objectOut/post-policy.json"
$objectCurlArgs = @('--silent','--show-error','--fail-with-body','--max-time','60',
                    '--dump-header',"$objectOut/post.headers",'--output',"$objectOut/post.body",
                    '--write-out','%{http_code}')
foreach ($field in $objectForm.fields.PSObject.Properties) {
  $objectCurlArgs += @('--form-string', "$($field.Name)=$($field.Value)")
}
$objectCurlArgs += @('--form', "file=@$objectOut/version-1.txt", $objectForm.url)
& curl.exe @objectCurlArgs
$objectPostExit = $LASTEXITCODE
```

保留签名 policy，仅修改允许范围内/范围外的 `key` 表单值，分别提交；随后使用边界两侧的文件长度测试 `content-length-range`。不要直接改 policy JSON 后还沿用旧签名，否则只测到签名完整性。签发接口若允许调用者控制 policy 范围，再从签发前的请求参数测试它是否为 A 生成了 B 的范围。

将每个存储请求关联到签发请求、原始字段和应用确认动作。发生 `SignatureDoesNotMatch` 时先比较请求方法、URL 原字节、SignedHeaders 及表单字段，恢复正常对照后再推进对象授权分支。

## 4. 可运行的 POST 条件合成矩阵

保存为 `presigned_policy_fixture.py`，运行 `python presigned_policy_fixture.py`。它演示本例几种条件的授权差异，不计算 SigV4、不校验真实签名，也没有实现 S3 的完整 POST 语义。

```python
from copy import deepcopy
from datetime import datetime, timezone
import json


def evaluate_demo_policy(policy, fields, size, now):
    expires = datetime.fromisoformat(policy["expiration"].replace("Z", "+00:00"))
    failures = []
    if now >= expires:
        failures.append("expired")
    for condition in policy["conditions"]:
        if isinstance(condition, dict):
            for key, expected in condition.items():
                if fields.get(key) != expected:
                    failures.append("exact:" + key)
        elif condition[0] == "starts-with":
            key = condition[1].removeprefix("$")
            if not fields.get(key, "").startswith(condition[2]):
                failures.append("prefix:" + key)
        elif condition[0] == "content-length-range":
            if not condition[1] <= size <= condition[2]:
                failures.append("length")
        else:
            raise ValueError("condition not supported by this fixture")
    return failures


def main():
    policy = {"expiration": "2030-01-01T00:10:00Z", "conditions": [
        {"bucket": "example-lab-bucket"},
        ["starts-with", "$key", "tenants/a/"],
        {"Content-Type": "text/plain"},
        ["content-length-range", 1, 64],
    ]}
    fields = {"bucket": "example-lab-bucket", "key": "tenants/a/demo.txt",
              "Content-Type": "text/plain"}
    now = datetime(2030, 1, 1, 0, 0, tzinfo=timezone.utc)
    assert evaluate_demo_policy(policy, fields, 16, now) == []
    cross_tenant = {**fields, "key": "tenants/ab/demo.txt"}
    assert evaluate_demo_policy(policy, cross_tenant, 16, now) == ["prefix:key"]
    weak = deepcopy(policy)
    weak["conditions"][1][2] = "tenants/a"
    assert evaluate_demo_policy(weak, cross_tenant, 16, now) == []
    assert evaluate_demo_policy(policy, fields, 65, now) == ["length"]
    expired = datetime(2030, 1, 1, 0, 11, tzinfo=timezone.utc)
    assert evaluate_demo_policy(policy, fields, 16, expired) == ["expired"]
    # 策略每次独立匹配，没有业务上的一次性消费状态。
    repeated = [evaluate_demo_policy(policy, fields, 16, now) for _ in range(2)]
    assert repeated == [[], []]
    versions = {"v1": b"DEMO_VERSION_1", "v2": b"DEMO_VERSION_2"}
    scanned_version, current_version = "v1", "v2"
    assert versions[scanned_version] != versions[current_version]
    print(json.dumps({"kind": "unsigned-policy-fixture",
                      "weak_prefix_accepts_other_tenant": True,
                      "repeated_requests_match": len(repeated),
                      "scanned_version": scanned_version,
                      "current_version": current_version}, indent=2))


if __name__ == "__main__":
    main()
```

本例 `bucket` 是为了检查目的地而加入的上下文，不是要求客户端把 bucket 作为任意表单字段提交；实际请求应按 SDK 返回的 URL 和 fields 构造。本例亦未检查字段条件覆盖、逗号型 Content-Type 或变量展开，真实 policy 验证以存储服务结果为准。

## 5. 证据与失败分支

保存到 `exports/ctf-website/<case>/presigned-storage/`：业务主体、对象归属、签发请求、policy 条件、期限、存储请求 ID、响应错误码、对象摘要/versionId、扫描任务和消费记录。完整预签名 URL 具有访问能力，只留在本地案件资料；公开示例用固定字符串和合成条件。

| 观察 | 判定 | 下一步 |
|---|---|---|
| URL 已生成但存储返回拒绝 | 签发请求到达；未证明对象访问 | 区分无对象、权限、期限、签名与 region |
| 改 key 后 `SignatureDoesNotMatch` | 签名覆盖该请求变化 | 回到签发前的对象归属测试 |
| 正常请求也失败 | 对照无效 | 检查 SignedHeaders、编码、时间与 HTTP 方法 |
| 过期前开始的下载仍继续 | 与服务语义相符 | 过期后新建请求再验证 |
| 重复 PUT 产生新版本 | 存储操作成功 | 对照业务一次性要求及消费版本 |
| 浏览器 CORS 报错但对象已写入 | 浏览器读响应受限 | 检查实际对象与服务端记录 |
| 对象上传成功但确认被拒绝 | 存储与业务边界结果不同 | 保留两阶段证据，检查孤立对象回收 |

蓝队关联：[预签名对象存储防御](../../../../blue/ctf-website/techniques/10-cloud/presigned-object-storage-defense.md)。跨用户签发继续查看 [IDOR](../14-idor/01-idor-enumeration.md)；后续解析继续查看 [文件上传攻击面](../06-file-attacks/file-upload-xxe-lfi.md)。

## 6. MCP 工具映射

| 步骤 | 工具 | 能力边界 |
|---|---|---|
| 信号路由 | `kb_router(query="presigned URL POST policy", board="ctf-website", track="red")` | 检索授权与文件消费路径 |
| 读取关联技术 | `kb_read_file` | 读取对象越权、IAM 或文件处理文档 |
| 真实签发和对象请求 | 原应用客户端、已配置的 SDK 或 HTTP 测试入口 | 需要正确方法、headers、body 和业务会话；通用 GET 探针不能替代上传验证 |
| 合成条件检查 | 本地 Python | 不连接云账户，不生成可用访问凭据 |
