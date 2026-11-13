---
id: "ctf-website/02-auth/webauthn-passkey-defense"
title: "WebAuthn 与 Passkey 防御：Ceremony 绑定、凭据归属与恢复流程"
title_en: "WebAuthn and Passkey Defense: Ceremony Binding, Credential Ownership and Recovery"
summary: >
  覆盖 WebAuthn 注册与登录的 challenge、Origin、RP ID、UP/UV、credential owner 和 userHandle 校验，连接绑定新凭据、恢复、撤销与会话管理。提供服务端 ceremony 状态的离线合成回归，并区分协议验证、业务授权和真实浏览器测试范围。
summary_en: >
  Cover challenge, Origin, RP ID, UP/UV, credential ownership, and userHandle checks across registration and authentication, plus credential enrollment, recovery, revocation, and sessions. Includes an offline ceremony-state regression model.
board: "ctf-website"
category: "02-auth"
signals: ["WebAuthn defense", "passkey", "challenge replay", "rpIdHash", "userVerification", "credential owner", "userHandle"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["Passkey防御", "WebAuthn校验", "challenge绑定", "RP ID", "Origin验证", "凭据恢复", "凭据归属"]
difficulty: "advanced"
tags: ["defense", "blue-team", "authentication", "webauthn", "passkey"]
language: "zh-CN"
last_updated: "2026-11-13"
related_articles: ["ctf-website/02-auth/webauthn-passkey", "ctf-website/02-auth/oauth-sso-defense", "ctf-website/20-oauth-deep/02-session-fixation-attacks-defense"]
track: "blue"
defends: "ctf-website/02-auth/webauthn-passkey"
---
# WebAuthn 与 Passkey 防御：Ceremony 绑定、凭据归属与恢复流程

## 1. 部署前置条件与证据入口

协议基线为 [WebAuthn Level 3，2026-08-25 Recommendation](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/)。采用实现该规范的服务端库处理二进制解析、COSE 密钥、签名与 attestation，业务层负责账号、ceremony、会话及恢复策略。先列清注册、普通登录、无用户名登录、添加/删除凭据、敏感操作再认证、账号恢复各端点。

| 配置项 | 服务端明确保存的内容 | 观测字段 |
|---|---|---|
| RP 配置 | 固定 RP ID、允许 Origin 集合、部署环境与嵌入策略 | `rp_config_version`、收到的 Origin、验证阶段 |
| Ceremony | 随机 challenge、用途、发起会话、账号上下文、有效期、消费状态 | ceremony ID、challenge 摘要、开始/完成时间、拒绝原因 |
| 凭据 | credential ID、公钥、算法、所属账号、userHandle、状态和必要认证器属性 | 凭据内部引用、账号引用、UP/UV、计数与备份状态 |
| 注册授权 | 当前账号和本次添加凭据所需的再认证状态 | 发起主体、授权动作、是否发生账号变化 |
| 恢复与撤销 | 恢复方式、通知、旧凭据与会话处置策略 | 凭据生命周期事件、恢复后实际可用的认证路径 |

challenge 使用密码学随机源，按业务风险设置服务器有效期；示例的固定值仅用于离线 fixture。Origin 白名单由部署配置产生，不能从不受信任的请求 Host 或客户端字段临时推导。

## 2. 防御工作流与协议/业务分工

```text
发起 ceremony → 服务端记录 challenge、用途与账号/会话
  → 浏览器/认证器交互 → 服务端库解析并验证响应
  → 比较已保存的 RP/Origin/challenge/UP/UV 与凭据归属
  → 原子消费 ceremony → 创建登录会话或完成指定绑定动作
  → 独立查询凭据表、会话和敏感业务结果
恢复/撤销 → 更新凭据状态和会话策略 → 旧凭据/旧会话对照
```

| 边界 | 必须检查的对象 | 反例与观察点 |
|---|---|---|
| Ceremony 类型与 challenge | 注册 `webauthn.create`、登录 `webauthn.get`；与本次服务器 challenge 匹配 | 注册响应不能提交给登录端点；重用旧 challenge 无新会话 |
| Origin 与 RP ID | 与服务器配置的允许 Origin 和 `rpIdHash` 相符；按产品策略处理 `crossOrigin/topOrigin` | 子串/后缀近似 Origin、错误 RP、非允许嵌入上下文被拒绝 |
| UP 与 UV | 按该操作的服务器策略检查实际签名覆盖的标志 | 客户端请求 `userVerification: required` 后仍须验证返回标志 |
| Credential owner | 已知账号只能使用该账号拥有的 credential；`userHandle` 与归属匹配 | 账号 A 的 challenge 不能由 B 的凭据建立 A 的会话 |
| 无用户名登录 | 用返回的 userHandle 与 credential 记录交叉确认账号 | 不能相信额外传来的 `user_id` 来切换最终登录主体 |
| 绑定新凭据 | 账号来自已认证会话和动作授权；校验重复 credential 归属 | 客户端替换绑定目标不应影响另一账号 |
| Signature/attestation | 由库验证原始响应和预期参数，按明确 attestation 策略处理注册 | 不接受调用者上传的 `signature_valid=true` 或只解码 JSON |

协议验证步骤见规范的 [注册](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-registering-a-new-credential)与[认证断言校验](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-verifying-assertion)。本篇将这些检查串入应用状态机；具体库的参数、默认值和支持版本需按其官方文档确认。

## 3. 离线合成实验：账号与 ceremony 状态绑定

保存为 `exports/ctf-website/passkey-defense/ceremony_state.py` 后运行。`proof` 模拟解析后的认证断言，`signature_ok` 模拟可信验证器的结果。实验只检查外围状态和约束，没有实现 WebAuthn 密码学验证，不能作为服务端认证库使用。

```python
import hashlib
from copy import deepcopy

RP_ID = "login.example.test"
ORIGIN = "https://login.example.test"
RP_HASH = hashlib.sha256(RP_ID.encode()).hexdigest()
CREDENTIALS = {"credential-a": {"owner": "account-a", "handle": "handle-a", "active": True}}
BASE = {"id": "ceremony-a", "session": "session-a", "account": "account-a",
        "challenge": "SYNTHETIC-CHALLENGE-A", "expires": 200, "used": False,
        "require_uv": True, "purpose": "login"}
PROOF = {"credential": "credential-a", "user_handle": "handle-a",
         "type": "webauthn.get", "challenge": BASE["challenge"],
         "origin": ORIGIN, "rp_id_hash": RP_HASH, "cross_origin": False,
         "up": True, "uv": True}


def finish(ceremony, proof, session, now, signature_ok):
    if ceremony["used"] or now >= ceremony["expires"]:
        return "deny:state"
    if session != ceremony["session"] or ceremony["purpose"] != "login":
        return "deny:ceremony"
    if not signature_ok:
        return "deny:signature"
    if proof.get("type") != "webauthn.get" or proof.get("challenge") != ceremony["challenge"]:
        return "deny:challenge"
    if proof.get("origin") != ORIGIN or proof.get("rp_id_hash") != RP_HASH:
        return "deny:rp-origin"
    # This fixture models a product that does not support cross-origin ceremonies.
    if proof.get("cross_origin") is not False:
        return "deny:embedding"
    if proof.get("up") is not True or (ceremony["require_uv"] and proof.get("uv") is not True):
        return "deny:flags"
    cred = CREDENTIALS.get(proof.get("credential"))
    if not cred or not cred["active"] or cred["owner"] != ceremony["account"]:
        return "deny:owner"
    if proof.get("user_handle") not in (None, cred["handle"]):
        return "deny:handle"
    ceremony["used"] = True  # Production: atomic consume and session creation.
    return "session-for:" + cred["owner"]


for field, value in [("type", "webauthn.create"), ("challenge", "old-challenge"),
                     ("origin", "https://login.example.test.attacker.test"),
                     ("rp_id_hash", "wrong"), ("uv", False), ("up", False),
                     ("cross_origin", True), ("user_handle", "handle-b"),
                     ("credential", "unknown")]:
    state = deepcopy(BASE)
    result = finish(state, {**PROOF, field: value}, "session-a", 100, True)
    assert result.startswith("deny:") and not state["used"], field
assert finish(deepcopy(BASE), PROOF, "session-b", 100, True) == "deny:ceremony"
assert finish(deepcopy(BASE), PROOF, "session-a", 200, True) == "deny:state"
assert finish(deepcopy(BASE), PROOF, "session-a", 100, False) == "deny:signature"
assert finish({**BASE, "account": "account-b"}, PROOF, "session-a", 100, True) == "deny:owner"
state = deepcopy(BASE)
assert finish(state, PROOF, "session-a", 100, True) == "session-for:account-a"
assert finish(state, PROOF, "session-a", 101, True) == "deny:state"
print("WebAuthn ceremony and ownership fixtures passed")
```

生产实现将消费状态、账号状态和会话创建放入合适的原子操作，并对并发提交做测试。此 fixture 未覆盖 discoverable 登录、注册 attestation、密码学签名、备份标志及扩展；这些必须由真实库和浏览器/认证器测试补齐。

## 4. 注册、恢复和撤销的控制路径

- **添加凭据**：按当前会话解析账号；必要的再认证授权只允许本次添加动作。完成后独立查凭据所属账号，记录可供用户查看的新增设备事件。
- **账号恢复**：列出邮件、恢复码、人工支持等可改变凭据的入口，与主要登录路径一起测试。恢复后按产品策略处理旧凭据、旧会话和恢复令牌，不允许失败的恢复流程留下已绑定凭据。
- **删除凭据**：执行端验证当前主体与 credential owner；同一凭据撤销后不能继续登录，已经建立的会话是否失效由明确会话策略决定。
- **敏感操作再认证**：将本次挑战绑定到具体用途，防止一次登录证明被用于未授权的凭据绑定或账号变更。

这些是应用流程控制建议。WebAuthn 协议验证通过后，仍需由应用完成正确的账号及动作处理。

## 5. 检测、独立验证与误报

| 测试 | 独立确认点 | 失败分支 |
|---|---|---|
| 两账号交叉提交 credential 与 userHandle | 会话主体、凭据归属表均未串线 | 若客户端先拒绝，再直测服务端验证器覆盖 |
| 并发提交同一合法响应 | challenge 只消费一次，不重复创建敏感动作 | 检查数据库并发和重试幂等 |
| 错 Origin/RP、UV 缺失、错误签名 | 拒绝阶段明确且无新会话/凭据 | 只看到 HTTP 错误时继续查状态变更 |
| 凭据撤销与恢复后重放 | 新登录与旧会话按既定策略处理 | 区分登录拒绝和会话续存两个现象 |
| 正常平台/漫游/同步凭据 | 支持的浏览器与认证器流程可完成 | 记录兼容性差异，不用全拒绝换取通过 |

`signCount` 不增加是风险信号，需结合认证器行为、并发处理和已保存状态；部分认证器不实现计数并保持零值，不能单凭该值认定克隆。相关语义见[签名计数器](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-sign-counter)。用户取消、设备无可用凭据、浏览器策略拒绝也可能表现为前端错误，需与服务端校验失败分开统计。

本地 Evidence：`exports/ctf-website/passkey-defense/<run-id>/`，记录库/浏览器版本、配置版本、测试身份引用、响应验证阶段、挑战状态与会话/凭据结果。不要在公开文档保存真实账号、credential ID、设备标识或完整认证响应。

## 6. 真实浏览器流程与服务端落点

在测试站点使用两个普通测试账号和浏览器的真实 passkey/安全密钥功能。先从 Network 找到生成 request options 和提交 authentication assertion 的实际端点，保留应用原有 CSRF 头、请求体及返回结构。

以下代码在该测试站点的 DevTools Console 运行。填入实际的 options/completion URL；`startBody` 与 `appHeaders` 来自应用正常请求。该示例使用 WebAuthn Level 3 JSON 转换 API，浏览器未支持时使用应用现有 SDK 的转换函数，不手工猜测 Base64URL 编码。

```javascript
// Replace these with the observed endpoints and application request fields.
const startURL = "/replace-with-real-options-endpoint";
const finishURL = "/replace-with-real-completion-endpoint";
const appHeaders = {"Content-Type": "application/json"};
const startBody = {}; // Preserve the actual account/ceremony fields required by the app.
if (!PublicKeyCredential.parseRequestOptionsFromJSON || !PublicKeyCredential.prototype.toJSON) {
  throw new Error("Use the application's existing WebAuthn JSON conversion adapter");
}
const started = await fetch(startURL, {
  method: "POST", credentials: "same-origin", headers: appHeaders,
  body: JSON.stringify(startBody)
});
if (!started.ok) throw new Error(`Options endpoint returned ${started.status}`);
const optionsEnvelope = await started.json();
const optionsJSON = optionsEnvelope.publicKey ?? optionsEnvelope; // Adapt to the real response envelope.
const credential = await navigator.credentials.get({
  publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(optionsJSON)
});
if (!credential) throw new Error("No assertion returned");
const assertionJSON = credential.toJSON();
// If the app requires a ceremony ID/envelope, preserve it here as in its real request.
const completed = await fetch(finishURL, {
  method: "POST", credentials: "same-origin", headers: appHeaders,
  body: JSON.stringify(assertionJSON)
});
console.log({stage: "completion", httpStatus: completed.status});
```

它运行的是一次真实认证流程，没有覆盖注册或攻击对照。获取正常成功样本后，以应用自己的测试接口或 HTTP 客户端重放完整 completion 请求，按第 5 节一次改变一个变量；记录服务器拒绝原因与会话状态。改过签名覆盖字段后可能先触发签名失败，要验证某项校验本身，使用测试认证器/库夹具生成**签名有效但该字段不符**的响应，不能把任意篡改后的拒绝都归功于该字段检查。

服务端需要取得以下真实落点：验证库版本和结果、期望 RP/Origin、ceremony 状态读取/消费、credential 查找的账号范围、最终会话主体。库若只返回一个布尔值，增加测试环境可读的阶段性事件，同时避免记录原始私钥、真实用户标识或完整认证数据到公共日志。运行前后的凭据表和会话查询是独立效果来源。

## MCP 工具映射

| 阶段 | 工具 | 用途与边界 |
|---|---|---|
| 检索认证防护 | `kb_router` | `board="ctf-website"`，按 WebAuthn、passkey、challenge 检索 |
| 对照攻击测试 | `kb_read_file` | 读取 [WebAuthn/passkey 分析](../../../../red/ctf-website/techniques/02-auth/webauthn-passkey.md) |
| 查会话关联 | `kb_catalog` | 连接 [会话固定防御](../20-oauth-deep/02-session-fixation-attacks-defense.md)；不提供认证器仿真 |

离线 Python 模型通过本地解释器运行，真实签名和浏览器交互另行验证。
