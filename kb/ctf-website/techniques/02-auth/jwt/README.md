# JWT 攻击技术库

## 文件索引

| # | 文件 | 攻击 | 一句话 |
|---|------|------|--------|
| 00 | `00-overview.md` | 全景 | 攻击面地图、决策树、结构速览 |
| 01 | `01-alg-none.md` | 无签名绕过 | `alg:none` 诱导跳过验证，含变种 |
| 02 | `02-algorithm-confusion.md` | 算法混淆 | RS256公钥当HS256密钥用 |
| 03 | `03-weak-key-bruteforce.md` | 弱密钥爆破 | hashcat/john/c-jwt-cracker |
| 04 | `04-kid-injection.md` | kid注入 | 路径穿越 / SQLi / 命令注入 三种注入点 |
| 05 | `05-jku-x5u-abuse.md` | 密钥源劫持 | jku/x5u 指向攻击者JWKS |
| 06 | `06-claim-missing.md` | Claim缺失+混用 | exp/aud/iss未验证，ID Token当Access Token |
| 07 | `07-theft-replay.md` | 窃取与重放 | XSS/日志/Referer泄露 + 无撤销 |
| 08 | `08-cve-library.md` | CVE/依赖库 | 10个高危CVE + 指纹识别 + 利用决策树 |
| 09 | `09-toolchain-defense.md` | 工具链+防御 | jwt_tool/流程/一键脚本/防御矩阵 |

## 快速使用

```bash
# 1. 拿到 token 先解码
python3 jwt_tool.py <token>

# 2. 看 alg 决策
# RS256/ES256 → 02 算法混淆 + 05 jku劫持
# HS256       → 03 弱密钥爆破
# 有 kid      → 04 注入
# 有 jku      → 05 劫持

# 3. 执行攻击后验证
curl https://target.com/api/me -H "Authorization: Bearer <forged>"
```
