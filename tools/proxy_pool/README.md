# Proxy Pool

代理池配置和来源管理，为 Web CTF/扫描工具提供代理轮换能力。

## 快速开始

```powershell
# 1. 复制并编辑配置文件
Copy-Item tools/proxy_pool/proxy_sources.example.json tools/proxy_pool/proxy_sources.json

# 2. 编辑 sources.json，填入你的代理来源
#    - manual_list: 手动配置本地代理 (如 Burp/Clash)
#    - local_file: 从 proxies.local.txt 读取
#    - api: 从免费/付费 API 获取

# 3. 抓取代理并验证
python tools/proxy_pool/proxy_pool.py fetch --sources tools/proxy_pool/proxy_sources.json --validate

# 4. 查看代理池状态
python tools/proxy_pool/proxy_pool.py stats

# 5. 获取下一个可用代理
python tools/proxy_pool/proxy_pool.py rotate --protocol socks5

# 6. 测试单个代理
python tools/proxy_pool/test_proxy.py socks5://127.0.0.1:1080
```

## 子命令

| 命令 | 说明 |
|---|---|
| `fetch` | 从配置的来源抓取代理，可选验证后存入代理池 |
| `list` | 列出代理池中的代理，支持 `--alive` / `--protocol` 过滤 |
| `validate` | 验证代理可用性，支持 `--proxy` 直接测试或 `--pool` 批量 |
| `rotate` | 按策略 (round_robin/random/lowest_latency) 获取下一个代理 |
| `stats` | 代理池统计信息 |

## 文件结构

| 文件 | 用途 |
|---|---|
| `proxy_pool.py` | 主入口，包含所有子命令 |
| `proxy_sources.example.json` | 代理来源配置模板 |
| `proxy_sources.json` | 实际配置文件 (需从 example 复制) |
| `pool_state.json` | 代理池运行时状态 (自动生成) |
| `proxies.local.txt` | 本地代理列表 (一行一个) |
| `test_proxy.py` | 单代理快速测试 |
| `merge_sources.py` | 合并多个来源配置 |

## 配置: proxy_sources.json

```json
{
  "schema": "reverselab.proxy_sources.v1",
  "test_url": "https://httpbin.org/ip",
  "validation": {
    "timeout_sec": 8.0,
    "concurrency": 10,
    "min_anon_level": "anonymous"
  },
  "pool": {
    "max_size": 50,
    "strategy": "round_robin",
    "cooldown_sec": 60,
    "max_failures": 3
  },
  "sources": [
    {
      "id": "manual_list",
      "type": "inline",
      "proxies": ["socks5://127.0.0.1:1080"],
      "enabled": true
    }
  ]
}
```

### 来源类型

| type | 说明 |
|---|---|
| `api` | HTTP API 获取代理列表，支持 `geonode` / `proxyscrape` / `json_list` / `raw` 格式 |
| `file` | 从本地文本文件读取，每行一个代理 |
| `inline` | 直接在配置中列出代理 URL |

### 代理 URL 格式

```
http://host:port
https://host:port
socks4://host:port
socks5://host:port
```

### 验证策略

- `anonymous` — 至少不泄露原始 IP (无 X-Forwarded-For)
- `elite` — 完全不泄露代理身份
- `transparent` — 会转发原始 IP (通常不适合敏感场景)

## 与其他工具集成

```powershell
# 为 sqlmap 提供代理
$proxy = python tools/proxy_pool/proxy_pool.py rotate --protocol http | ConvertFrom-Json
python sqlmap -u "http://target.com/vuln.php?id=1" --proxy=$proxy.url

# 为 curl 提供代理
$proxy_url = (python tools/proxy_pool/proxy_pool.py rotate --protocol socks5 | ConvertFrom-Json).url
curl --proxy $proxy_url http://httpbin.org/ip
```
