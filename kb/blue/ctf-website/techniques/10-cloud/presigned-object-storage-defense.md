---
id: "ctf-website/10-cloud/presigned-object-storage-defense"
title: "对象存储预签名防御：签发授权、上传隔离与版本绑定"
title_en: "Presigned Object Storage Defense: Issuance Authorization, Quarantine and Version Binding"
summary: >
  以 S3 为参照区分预签名 GET/PUT 与 POST policy，覆盖签发端租户授权、固定 object key、临时凭据与有效期、重复上传覆盖、上传后内容校验、版本绑定和消费幂等；附不访问云服务的合成上传状态实验。
summary_en: >
  Use S3 to distinguish presigned GET/PUT from POST policies and cover tenant authorization at issuance, fixed object keys, credential lifetimes, repeated writes, content validation, version-bound consumption, and idempotency with an offline upload-state experiment.
board: "ctf-website"
category: "10-cloud"
signals: ["presigned URL", "S3 POST policy", "object overwrite", "upload ticket", "versionId", "signatureAge"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["预签名防御", "对象存储授权", "S3上传", "POST policy", "跨租户对象", "版本绑定", "上传隔离"]
difficulty: "advanced"
tags: ["defense", "blue-team", "cloud", "s3", "object-storage", "authorization"]
language: "zh-CN"
last_updated: "2026-11-13"
related_articles: ["ctf-website/10-cloud/presigned-object-storage", "ctf-website/10-cloud/aws-iam-privesc-defense", "ctf-website/14-idor/01-idor-enumeration-defense", "ctf-website/06-file-attacks/file-upload-xxe-lfi-defense"]
track: "blue"
defends: "ctf-website/10-cloud/presigned-object-storage"
---
# 对象存储预签名防御：签发授权、上传隔离与版本绑定

## 1. 适用范围与关键语义

本篇以 AWS S3 的预签名 GET/PUT 和浏览器 POST 为参照，S3 兼容服务需逐项核实支持的签名、条件、日志与版本特性。预签名 URL 在有效期内可重复使用；PUT 到已有 key 会替换当前对象。临时凭据到期也会使 URL 提前失效。具体语义见 [S3 预签名文档](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html)。

因此防守同时检查三处：**谁可申请 URL、URL 允许访问什么、上传的哪一版内容最终被业务消费**。

| 入口信号 | 首轮观测字段 | 初步假设 |
|---|---|---|
| 修改 key/tenant 就拿到另一对象 URL | 签发主体、对象归属、method、bucket/key 摘要、签发决定 | 签发端对象授权缺失 |
| 同一上传 URL 再次使用后内容变化 | ticket、object key、version ID、checksum、写入时间 | URL 仍有效且存在覆盖路径 |
| 上传成功但业务接受了不符内容 | 实际字节、对象 metadata、扫描结果与消费回执 | 只验证 Content-Type 或客户端完成通知 |
| 已撤销业务权益，旧下载 URL 仍可用 | URL 到期、签发凭据生命周期、对象/缓存策略 | 业务撤权与存储 bearer 授权生命周期不同 |
| 对象日志找不到请求 | 日志配置、事件选择器、请求 ID 与采集时段 | 没启用该对象范围的 data events 或采集遗漏 |

预签名 URL 自身携带访问能力；日志保存内部 ticket ID 和必要字段，避免把完整查询串、签名和临时安全令牌写入通用日志或分析平台。

## 2. 配置前提与防御工作流

```text
已认证用户申请上传/下载
  → 应用检查当前对象归属、用途、配额
  → 服务端分配固定 key、method、有效期与必要条件
  → 专用低权限角色签发 → 客户端访问私有存储
上传完成通知
  → 服务端读取指定对象版本与内容
  → 检查大小、格式、checksum、扫描状态及 ticket 归属
  → 原子绑定已验证版本 / 转存到受控发布对象
  → 下游仅消费该版本 → 独立核查对象与业务状态
```

| 控制点 | 建议措施 | 需要另测的条件 |
|---|---|---|
| 签发 API | 账号和 tenant 来自认证上下文；服务端生成上传 key，下载先查目标归属 | 批量签发、旧 ticket、跨租户和管理员例外 |
| 签发角色 | 每个环境/用途限制 bucket、prefix 和操作，上传角色无删除或任意读取能力 | 有效权限、KMS/策略影响、跨账号配置 |
| URL 生命周期 | 采用业务能接受的短时有效期；需要时结合存储策略限制签名年龄 | 凭据先到期、时钟偏差、已开始的传输和重试 |
| 上传区 | 新对象先进入私有隔离 prefix，最终消费路径不直接读可继续覆盖的“最新 key” | 后台转码、缩略图、消息队列等是否也遵守 |
| 完成 API | 服务端核实对象实际内容与版本；幂等消费 ticket | 重复/乱序/并发完成通知及覆盖后的版本变化 |
| 撤销 | 明确存量 URL、对象访问策略和缓存的处置方式 | 应用账号撤权是否同步影响已签发 URL |

### POST policy 与 PUT 的区别

POST policy 可描述精确匹配、前缀和 `content-length-range` 等条件；条件在表单变量展开后的值上生效，空前缀意味着允许任意值。使用实际 SDK 生成完整 policy，并检查其条件，格式见 [AWS POST Policy](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-HTTPPOSTConstructPolicy.html)。

```json
{
  "example_conditions_only": [
    {"bucket": "example-private-uploads"},
    {"key": "incoming/tenant-a/ticket-a/object"},
    ["content-length-range", 1, 1048576],
    {"Content-Type": "application/octet-stream"}
  ]
}
```

以上只展示业务条件，缺少实际 expiration、SDK 签名字段，不能直接提交 S3。PUT URL 没有 POST policy 的这套范围表达方式；检查实际签入的 headers/参数，并在完成端按存储中的真实字节重新验证。Content-Type 是声明，内容格式和安全扫描另行完成。

## 3. 离线实验：上传与消费绑定到版本

保存为 `exports/ctf-website/storage-defense/upload_state.py`。示例用不可变对象版本模拟存储，只验证应用侧状态机。需要版本化语义的方案应先确认存储支持并已开启；S3 的覆盖会生成新版本，版本保留行为见 [S3 Versioning](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html)。

```python
from dataclasses import dataclass
import hashlib


@dataclass(frozen=True)
class ObjectVersion:
    key: str
    version: str
    data: bytes


def digest(data):
    return hashlib.sha256(data).hexdigest()


# Server-issued ticket; these values are not copied from client object metadata.
ticket = {"owner": ("tenant-a", "user-a"), "key": "incoming/tenant-a/ticket-a/object",
          "expires": 200, "max_size": 64, "expected_sha256": digest(b"synthetic-upload"),
          "accepted": None}
receipts = []


def complete(ticket, caller, observed_version, now):
    # observed_version must come from a trusted storage read for the exact version.
    if caller != ticket["owner"]:
        return "deny:owner"
    if observed_version.key != ticket["key"]:
        return "deny:key"
    observed = (observed_version.key, observed_version.version, digest(observed_version.data))
    if ticket["accepted"] is not None:
        return "already-complete" if ticket["accepted"] == observed else "deny:version"
    if now >= ticket["expires"]:
        return "deny:expired"
    if not 1 <= len(observed_version.data) <= ticket["max_size"]:
        return "deny:size"
    if digest(observed_version.data) != ticket["expected_sha256"]:
        return "deny:checksum"
    # A real pipeline also validates content format and required scan results.
    ticket["accepted"] = observed  # Production: transaction / compare-and-set.
    receipts.append(observed)
    return "accepted"


good = ObjectVersion(ticket["key"], "version-1", b"synthetic-upload")
assert complete(ticket, ("tenant-b", "user-b"), good, 100) == "deny:owner"
assert complete(ticket, ticket["owner"], ObjectVersion("other-key", "v1", good.data), 100) == "deny:key"
assert complete(ticket, ticket["owner"], ObjectVersion(ticket["key"], "v2", b"x" * 65), 100) == "deny:size"
assert complete(ticket, ticket["owner"], ObjectVersion(ticket["key"], "v3", b"different"), 100) == "deny:checksum"
assert complete(ticket, ticket["owner"], good, 200) == "deny:expired"
assert receipts == []
assert complete(ticket, ticket["owner"], good, 100) == "accepted"
assert complete(ticket, ticket["owner"], good, 101) == "already-complete"
later = ObjectVersion(ticket["key"], "version-2", b"synthetic-upload")
assert complete(ticket, ticket["owner"], later, 102) == "deny:version"
assert receipts == [(good.key, "version-1", digest(good.data))]
print("Upload ownership, content and version-consumption fixtures passed")
```

这段代码不生成或验证 SigV4，也不阻止存储接受 URL 有效期内的第二次 PUT；它约束业务只消费已接受的版本。生产中还需测试版本读取、扫描结果归属、原子状态更新和所有下游消费者。客户端声明 checksum 只绑定其声明的字节；若内容本身不可信，仍需格式校验与扫描。

## 4. 检测与独立验证

| 测试分支 | 必须记录 | 通过条件 |
|---|---|---|
| 跨租户签发 | 认证主体、申请对象、签发决定、对象归属 | 不产生可访问其他租户对象的 URL |
| 改 method/key/签入 header | 规范化请求字段、存储响应和请求 ID | 实际约束生效；合法对照可传输 |
| 重复 PUT/POST | 同 key 的版本与内容、完成/消费记录 | 覆盖不会替换已验证的业务消费版本 |
| 过期/撤权 | 服务端时间、凭据/URL 到期、策略变化与请求结果 | 符合设计的生命周期，记录已开始传输的边界 |
| 伪造完成通知 | ticket、对象大小/内容、版本、扫描状态 | 未上传、不匹配、未扫描版本不会发布 |
| 并发与乱序 | 多次完成请求及最终账本 | 原子消费、可解释的幂等结果 |

S3 对象读写的 CloudTrail data events 需要配置，默认事件历史不提供这些对象事件；先确认采集范围再解释“没有日志”。见 [S3 CloudTrail events](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html)。签发 URL 常在应用 SDK 本地完成，签发决定应由应用另行记录。

证据保存到本地 `exports/ctf-website/storage-defense/<run-id>/`：ticket、身份引用、key 的受控引用、method、有效期、签入条件、version ID、checksum、请求 ID、消费回执。原始 URL 限制访问，公开资料不携带签名查询串。

## 5. 误报与失败分支

- 同 URL 被再次使用可能是合法重试；按业务约定判断是否发生重复发布或错误版本消费。
- `403` 可能来自到期、签入字段不匹配、凭据、区域或策略问题；先用正常对照区分配置故障和授权拒绝。
- 浏览器 CORS 拒绝影响浏览器访问，并不取代存储端权限校验；用存储响应和对象状态复核。
- 按存储文档确认 `ETag` 在当前上传和加密方式下的语义；完整性校验使用明确的 checksum 或实际字节摘要。
- 扫描后对象发生覆盖，优先查消费是否仍按“最新 key”读取；已确认版本的绑定要贯穿扫描、转码、下载与发布。
- 发现签发角色过宽转入 [IAM 防御](aws-iam-privesc-defense.md)，业务对象归属错误转入 [IDOR](../14-idor/01-idor-enumeration-defense.md)，恶意内容消费转入[文件上传防御](../06-file-attacks/file-upload-xxe-lfi-defense.md)。

## 6. 真实 S3 实验：重复 PUT 与指定版本读取

准备专用测试 bucket，启用 Versioning，并配置当前 AWS SDK 身份只访问测试前缀及必要的版本查询。下面程序会在 `lab-presign/` 下新建随机 key，使用同一个短时 PUT URL 写入两份合成文本，然后分别读取两个明确版本。它不碰已有业务 key，也不打印完整预签名 URL。保留生成对象和结果供独立复核；清理由测试资源生命周期策略另行处理。

前提：当前 Python 环境已有官方 `boto3`；AWS 身份通过 SDK 标准凭据链取得，`S3_LAB_BUCKET` 指定真实测试 bucket。缺依赖或权限时先按环境约定补齐，不写入代码中的静态密钥。保存为 `exports/ctf-website/storage-defense/probe_versions.py`。

```python
import hashlib
import json
import os
import uuid
from pathlib import Path
from urllib.request import Request, urlopen
import boto3
from botocore.config import Config

client = boto3.client("s3", config=Config(signature_version="s3v4"))
bucket = os.environ["S3_LAB_BUCKET"]
if client.get_bucket_versioning(Bucket=bucket).get("Status") != "Enabled":
    raise SystemExit("The test bucket must have Versioning enabled")
key = "lab-presign/" + uuid.uuid4().hex + "/object.txt"
url = client.generate_presigned_url(
    "put_object", Params={"Bucket": bucket, "Key": key, "ContentType": "text/plain"},
    ExpiresIn=120, HttpMethod="PUT")
versions = []
for body in (b"synthetic-first-version\n", b"synthetic-second-version\n"):
    request = Request(url, data=body, method="PUT", headers={"Content-Type": "text/plain"})
    with urlopen(request, timeout=30) as response:
        version = response.headers.get("x-amz-version-id")
        if not version or version == "null":
            raise RuntimeError("No immutable version ID returned by the test storage")
        versions.append({"version_id": version, "sha256": hashlib.sha256(body).hexdigest()})
for expected in versions:
    stored = client.get_object(Bucket=bucket, Key=key, VersionId=expected["version_id"])
    try:
        observed = hashlib.sha256(stored["Body"].read()).hexdigest()
    finally:
        stored["Body"].close()
    if observed != expected["sha256"]:
        raise RuntimeError("Version content does not match the uploaded bytes")
result = {"bucket": bucket, "key": key, "versions": versions,
          "latest_version": client.head_object(Bucket=bucket, Key=key).get("VersionId")}
out = Path("exports/ctf-website/storage-defense/version-observation.json")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(result, indent=2), encoding="utf-8")
print("Recorded", len(versions), "uploaded versions in", out.as_posix())
```

```sh
python exports/ctf-website/storage-defense/probe_versions.py
```

该实验直接观察存储的重复写入与版本语义，尚未覆盖应用签发端的租户权限。将实际应用签发接口返回的 URL 用于同类对照时，固定测试账号并保存应用 ticket 与存储 key/版本的关联。随后让完成接口尝试消费第一版、第二版和不属于该用户的 ticket，读取应用最终发布的对象版本与账本。若下游只记录 key 而无版本/摘要，先补这个观测字段再判断上传后替换是否被控制。

本文提供操作脚本，未连接真实 bucket 执行；S3 兼容存储使用前核对 SDK endpoint、签名和版本返回格式。

## MCP 工具映射

| 阶段 | 工具 | 用途与边界 |
|---|---|---|
| 定位存储信号 | `kb_router` | 检索预签名、POST policy、版本覆盖 |
| 对照攻击条件 | `kb_read_file` | 读取[预签名对象存储分析](../../../../red/ctf-website/techniques/10-cloud/presigned-object-storage.md) |
| 查看相关控制 | `kb_catalog` | 连接 IAM、IDOR 与文件消费；不检查真实 bucket 或签发 URL |

离线实验通过本地 Python 运行；真实 S3/兼容存储权限、签名和版本行为需要隔离测试资源复核。
