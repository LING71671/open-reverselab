---
id: "ctf-website/02-auth/webauthn-passkey"
title: "WebAuthn / Passkey 认证与凭据绑定分析"
title_en: "WebAuthn and Passkey Authentication and Credential Binding Analysis"
summary: >
  覆盖 WebAuthn 注册、认证、发现式凭据和恢复流程的挑战绑定、Origin/RP ID、UP/UV、凭据归属与重放分析，给出双账号差分矩阵、离线字段检查试件及有效签名负例的构造条件。
summary_en: >
  Analyze challenges, Origin/RP ID, UP/UV, credential ownership, and replay across WebAuthn registration, authentication, discoverable credentials, and recovery. Includes a two-account matrix, offline field checks, and prerequisites for validly signed negative cases.
board: "ctf-website"
category: "02-auth"
signals: ["WebAuthn", "passkey", "navigator.credentials", "clientDataJSON", "authenticatorData", "rpIdHash", "userHandle", "userVerification"]
mcp_tools: ["kb_router", "kb_read_file"]
keywords: ["WebAuthn", "Passkey", "通行密钥", "RP ID", "challenge replay", "UV", "凭据绑定", "discoverable credential"]
difficulty: "advanced"
tags: ["authentication", "webauthn", "passkey", "authorization", "red-team"]
language: "zh-CN"
last_updated: "2026-11-13"
related_articles: ["ctf-website/02-auth/webauthn-passkey-defense", "ctf-website/20-oauth-deep/02-session-fixation-attacks", "ctf-website/14-idor/02-bac-business-logic"]
track: "red"
---
# WebAuthn / Passkey 认证与凭据绑定分析

## 1. 场景与输入信号

页面通过 `navigator.credentials.create()` 注册凭据，通过 `navigator.credentials.get()` 认证；后端处理 `clientDataJSON`、`authenticatorData`、credential ID 和签名。需要同时检查密码学验证、服务端交易状态、账号归属，以及新增/删除 passkey 的业务权限。

协议基准为 [WebAuthn Level 3，2026-08-25 Recommendation](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/)。认证验证涉及 challenge、type、origin、RP ID hash、用户存在/验证标志、凭据及用户关联，并使用存储的凭据公钥验证 `authenticatorData || SHA256(clientDataJSON)` 的签名。具体实现还要处理扩展及应用声明的跨源场景。

| 信号 | 立即记录 | 候选分支 |
|---|---|---|
| `PublicKeyCredentialRequestOptions` | challenge、rpId、allowCredentials、userVerification | 挑战与交易绑定 |
| 注册 options 包含 `user.id` | 当前登录用户与服务端生成的 user ID | 注册到错误账号 |
| 无用户名即可选择 passkey | credential ID、返回的 userHandle、最终登录主体 | 发现式凭据映射 |
| `userVerification: required` | 实际签名中的 UV 位与服务端策略 | 前后端要求不一致 |
| 重置密码后可以新增 passkey | 恢复会话、重新认证要求、绑定记录 | 恢复链降级 |
| 扫码跨设备登录 | RP、浏览器 origin、最终凭据记录 | 设备运输方式与 RP 验证分别检查 |

## 2. 双账号工作流与攻击路径

使用两个实验账号 A/B，各自注册独立凭据，保存 credential ID 到账号的映射。测试素材只包含合成账号和本地虚拟认证器。

```text
正常注册 A/B → 正常认证 A/B → 记录服务端 ceremony 状态
  ├─ A 的响应交给 B 的交易 → challenge/session/owner 绑定
  ├─ 同一成功响应再次提交 → challenge 消费与重放
  ├─ 改变 userHandle/用户名外层字段 → 凭据与账号映射
  ├─ 有效但 UV=0 的响应 → 服务端 UV 策略
  ├─ 合法签名来自另一允许测试 origin → origin 精确约束
  └─ 恢复/新增/删除凭据 → 业务授权与会话更新
```

每次变体应有新 challenge；重放测试是刻意复用同一交易。记录服务端是在哪一步拒绝，而不只看前端提示。

### 2.1 挑战、账号和目的绑定

先保存 A/B 两次独立认证的合法响应。把 A 响应提交到 B 的待完成交易；若后端只从响应选择一个仍有效的 challenge，而不核验对应的会话与登录意图，可能出现身份混淆。核验最终 session 的用户 ID、凭据归属及允许访问的合成对象。

注册与认证的响应类型不同，业务交易也应区分登录、新增凭据和敏感操作确认。在这些入口间交叉提交时，记录真实签名验证结果和交易 purpose，避免把通用 JSON 格式错误当作目的绑定有效。

成功后再次发送同一响应，再以同一 challenge 生成第二个有效响应测试事务消费。若第二次只返回幂等的既有状态，应检查是否产生了新的会话或额外业务动作；网络层 200 不能代替这项检查。

### 2.2 Origin、RP ID、UP/UV

直接修改 `clientDataJSON.origin` 或 authenticatorData 的 flags 会破坏原签名。这样的失败只覆盖篡改路径，无法单独说明 origin/UV 检查存在。要隔离该检查，应使用可控制的实验认证器和服务端验证器试件产生签名有效的负例，或从另一实际测试 origin 完成一次合法 ceremony 后比较服务端的接受条件。

浏览器也会约束 RP ID 与 origin；浏览器拒绝创建凭据发生在前端路径。RP ID 与 URL origin 的概念不同，不能把“同 RP ID”直接当作“任意子域都允许登录此应用”。存在 related-origin 或嵌入式场景时，先记录产品配置与对应规范策略，再检查实际允许范围。

UP 表示用户存在，UV 表示用户验证；服务端应按交易要求解释。签名计数异常也需结合认证器类型、并发及备份状态判断，Level 3 将计数回退视为风险信号而非克隆的确定证据。相关规范步骤见前述 Level 3 的认证验证与 signature counter 章节。

### 2.3 凭据生命周期与恢复

以 A 会话分别尝试向 B 的账号标识注册凭据、删除 B 的 credential ID、重命名 B 的凭据；只修改外层业务字段，保留 ceremony 数据。观察注册记录所属用户是否由可信会话派生，以及是否检查 credential ID 的归属。

对发现式凭据流程，核验 server 最终选择的公钥、credential ID 与 userHandle 指向同一个账号。对用户名先行流程，还要核验该凭据是否属于先前选定的账号。恢复流程应记录“恢复成功 → 新凭据注册 → 登录新 session”的每次身份强度与权限变化，不能仅凭主登录使用 passkey 推断恢复入口同等严格。

### 2.4 浏览器中取得真实 options 和响应

先在实验应用完成正常注册和登录，打开 Chrome DevTools 的 Network 与 WebAuthn 面板。Network 记录注册 options、注册完成、认证 options、认证完成四类真实接口及请求格式；名称以实际请求为准。WebAuthn 面板启用 virtual authenticator，选择 CTAP2，根据测试分支配置 resident keys 和 user verification，记录 authenticator 配置。

分别使用 A/B 浏览器 profile 或独立会话注册凭据，保存各自 credential ID、userHandle、RP ID 和服务端归属。需要测试 `UV=0` 时，通过虚拟认证器配置取得相应响应，检查真实 authenticatorData 的 UV 位。若页面 `userVerification=required` 导致浏览器先拒绝，可在实验页面改变发给认证器的 request options，同时保留服务端交易原本的 required 策略；这样才能测到后端是否再次执行该策略。

下面在实验页面 Console 使用，作用是将从 options 接口取得的 JSON 转成浏览器 API 所需的二进制字段，并导出真实凭据响应。`rawOptions` 必须是本轮新取得的 options，不要复用已消费的 challenge。

```javascript
function fromBase64url(value) {
  const text = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = text + "=".repeat((4 - text.length % 4) % 4);
  return Uint8Array.from(atob(padded), char => char.charCodeAt(0));
}

function toBase64url(value) {
  if (value == null) return null;
  let text = "";
  for (const byte of new Uint8Array(value)) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function captureWebAuthn(rawOptions, mode = "get") {
  // 若应用包裹 options 的字段不同，在此改为实际字段。
  const publicKey = structuredClone(rawOptions.publicKey ?? rawOptions);
  publicKey.challenge = fromBase64url(publicKey.challenge);
  if (publicKey.user?.id) publicKey.user.id = fromBase64url(publicKey.user.id);
  for (const field of ["allowCredentials", "excludeCredentials"]) {
    if (publicKey[field]) {
      publicKey[field] = publicKey[field].map(item => ({...item, id: fromBase64url(item.id)}));
    }
  }
  const credential = mode === "create"
    ? await navigator.credentials.create({publicKey})
    : await navigator.credentials.get({publicKey});
  if (!credential) throw new Error("No credential returned");
  const response = {};
  for (const field of ["clientDataJSON", "authenticatorData", "signature", "userHandle", "attestationObject"]) {
    if (field in credential.response) response[field] = toBase64url(credential.response[field]);
  }
  return {id: credential.id, rawId: toBase64url(credential.rawId), type: credential.type,
          authenticatorAttachment: credential.authenticatorAttachment,
          clientExtensionResults: credential.getClientExtensionResults(), response};
}

// rawOptions 为 Network 中本轮 options 响应对象。
// const assertion = await captureWebAuthn(rawOptions, "get");
// copy(JSON.stringify(assertion, null, 2));
```

这段代码覆盖常见 base64url JSON 字段，启用了需要额外二进制值的扩展时继续沿用应用现有序列化器。不要将 Chrome 的 `copy()` 用在服务器脚本中；它是 DevTools Console 辅助函数。导出的响应放入应用原来认证完成请求的对应字段，保留其 ceremony ID、CSRF 和外层字段格式，再用原客户端或[HTTP 重放脚本](../../../general/techniques/ai-security/01-indirect-prompt-injection.md)提交。

### 2.5 按拒绝阶段组织实际请求

| 操作 | 实际输入的取得方法 | 预期观察 |
|---|---|---|
| 正常登录 | 新 options → 真实认证器响应 → 原完成接口 | session 用户、认证器 credential ID 与目标账号一致 |
| challenge 重放 | 成功完成后再次发送同一完成请求 | 交易已消费的拒绝或明确幂等行为，核对是否创建额外状态 |
| 交易串线 | A/B 各取新 options，将 A 的未消费响应放入 B 的完成交易 | 拒绝发生在 challenge、会话或账号绑定，而非 body 解析 |
| UV 策略 | 服务端保持 required，实验认证器产生 UV=0 的签名有效响应 | 检查后端 UV 拒绝；记录是否只有浏览器阻止 |
| userHandle/owner | 保留签名响应，改变应用允许提交的外层用户字段 | 服务端仍按凭据记录绑定账号，或明确拒绝不一致 |
| 凭据管理 | A 的有效管理会话提交 B 的实验 credential ID | 无删除、替换或归属变化；用 B 会话重新列出凭据确认 |

为每个操作建立独立交易，按 `options 请求 → challenge/交易 → credential 响应 → 完成请求 → session/凭据列表` 保存文件。若改 origin 后只报签名错误，下一步取得签名有效的 origin 负例或直接检查真实服务端验证库的 origin 配置；不要把这个结果改写成 origin 检查已单独验证。

## 3. 离线字段差分试件

保存为 `webauthn_field_fixture.py`，运行 `python webauthn_field_fixture.py`。该代码检查合成字段之间的约束，并解析 authenticatorData 的固定头部；**没有执行签名/COSE/attestation 验证，不能用于建立登录态**。末尾的负例仅是检查器自测，不代表真实服务已拒绝它们。

```python
import base64
from copy import deepcopy
import hashlib
import json


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64u(value):
    return base64.b64decode(value + "=" * (-len(value) % 4),
                            altchars=b"-_", validate=True)


def precheck(response, tx, credential, now):
    data = json.loads(unb64u(response["clientDataJSON"]))
    auth = unb64u(response["authenticatorData"])
    if len(auth) < 37:
        return ["authenticator-data-short"]
    flags = auth[32]
    checks = {
        "type": data.get("type") == "webauthn.get",
        "challenge": unb64u(data["challenge"]) == tx["challenge"],
        "origin": data.get("origin") in tx["origins"],
        # 本试件策略不支持嵌入式跨源流程。
        "cross-origin": data.get("crossOrigin", False) is False,
        "rp-id": auth[:32] == hashlib.sha256(tx["rp_id"].encode()).digest(),
        "up": bool(flags & 0x01),
        "uv": not tx["require_uv"] or bool(flags & 0x04),
        "owner": credential["owner"] == tx["expected_user"],
        "credential-id": response["id"] == credential["id"],
        "user-handle": response["userHandle"] == credential["user_handle"],
        "fresh": now < tx["expires"] and not tx["used"],
    }
    return [key for key, ok in checks.items() if not ok]


def main():
    tx = {"challenge": b"synthetic-challenge-32-bytes-demo!",
          "origins": ["https://login.example.test"], "rp_id": "example.test",
          "require_uv": True, "expected_user": "alice", "expires": 1000,
          "used": False}
    cred = {"id": "demo-credential-a", "owner": "alice", "user_handle": "demo-a"}
    client = {"type": "webauthn.get", "challenge": b64u(tx["challenge"]),
              "origin": tx["origins"][0], "crossOrigin": False}
    auth = hashlib.sha256(tx["rp_id"].encode()).digest() + b"\x05" + b"\0\0\0\0"
    response = {"id": cred["id"], "userHandle": cred["user_handle"],
                "clientDataJSON": b64u(json.dumps(client).encode()),
                "authenticatorData": b64u(auth)}
    assert precheck(response, tx, cred, 900) == []
    results = {}
    for name, patch in {
        "other-user": {"expected_user": "bob"},
        "other-challenge": {"challenge": b"different-challenge"},
        "replay": {"used": True},
        "expired": {"expires": 800},
    }.items():
        failures = precheck(response, {**tx, **patch}, cred, 900)
        assert failures
        results[name] = failures
    changed = deepcopy(response)
    changed["authenticatorData"] = b64u(auth[:32] + b"\x01" + auth[33:])
    assert precheck(changed, tx, cred, 900) == ["uv"]
    wrong_origin = {**client, "origin": "https://other.example.test"}
    changed = {**response, "clientDataJSON": b64u(json.dumps(wrong_origin).encode())}
    assert precheck(changed, tx, cred, 900) == ["origin"]
    print(json.dumps({"kind": "unsigned-field-fixture", "rejected": results}, indent=2))


if __name__ == "__main__":
    main()
```

该试件为 username-first 且带 userHandle 的固定案例。真实允许空 userHandle 的流程应按所用验证库和规范处理；缺字段、非法编码、重复 JSON 键、扩展与非法 flags 等解析负例也要交给真实验证器，而不是把本例扩成自制认证库。

浏览器层可用 [Chrome DevTools 的 WebAuthn 面板](https://developer.chrome.com/docs/devtools/webauthn)建立虚拟认证器，选择 resident key、user verification 能力并观察 credential ID、user handle 和 sign count。保存浏览器版本和实际设置；离线字段试件通过与浏览器 ceremony 成功是两个独立证据。

## 4. 证据与失败分支

输出到 `exports/ctf-website/<case>/webauthn/`：options、交易 ID、挑战来源/期限/消费状态、响应字节、验证阶段、credential owner、最终 session 用户、业务对象变化。实验密钥只留在本地虚拟认证器环境，不放入公开文档。

| 结果 | 判定范围 | 补充验证 |
|---|---|---|
| 修改 flags 后签名失败 | 拒绝被篡改响应 | 使用签名有效的 UV 负例定位 UV 策略 |
| 浏览器报 RP ID 不合法 | 浏览器校验生效 | 继续检查后端来源限制与账号绑定 |
| A 凭据完成 B 交易但登录为 A | 可能存在交易混淆 | 对照产品选账号流程、会话与外层用户名 |
| B 的凭据被 A 添加/删除 | 凭据生命周期授权越界 | 保存前后归属记录与动作权限 |
| 签名计数为零或未递增 | 单一认证器特征/风险信号 | 检查备份、并发和验证库策略 |
| HTTP 200 但无新 session/动作 | 可能是错误包装或幂等响应 | 检查业务状态与 cookie 更新 |

蓝队关联：[WebAuthn / Passkey 防御](../../../../blue/ctf-website/techniques/02-auth/webauthn-passkey-defense.md)。会话切换异常继续查看 [会话固定](../20-oauth-deep/02-session-fixation-attacks.md)；对象归属错误继续查看 [业务授权](../14-idor/02-bac-business-logic.md)。

## 5. MCP 工具映射

| 步骤 | 工具 | 能力边界 |
|---|---|---|
| 信号路由 | `kb_router(query="WebAuthn userHandle UV", board="ctf-website", track="red")` | 检索对应技术篇 |
| 阅读相关篇 | `kb_read_file` | 读取认证与业务权限方法 |
| 真实 ceremony | 浏览器 WebAuthn 面板或现有应用测试框架 | 需浏览器/认证器与后端共同参与；普通 HTTP GET 不生成 WebAuthn 签名 |
| 离线字段试件 | 本地 Python | 没有密码学验证，不代表完成认证 |
