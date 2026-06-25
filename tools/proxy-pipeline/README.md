# Proxy Pipeline

代理管道配置，用于代理请求串联/路由。

## 快速开始

```powershell
# 1. 复制并编辑配置文件
Copy-Item tools/proxy-pipeline/pipeline_config.example.json tools/proxy-pipeline/pipeline_config.json

# 2. 本地转发 — 所有流量通过上游代理
python tools/proxy-pipeline/pipeline.py forward --listen 127.0.0.1 --port 9090 --via socks5://127.0.0.1:1080

# 3. 使用命名路由规则启动
python tools/proxy-pipeline/pipeline.py route --config pipeline_config.json --rule rule_pool_round_robin

# 4. 测试代理链路连通性
python tools/proxy-pipeline/pipeline.py test api.ipify.org --port 443 --via socks5://127.0.0.1:1080

# 5. 查看配置的链路
python tools/proxy-pipeline/pipeline.py chain --config pipeline_config.json
```

## 子命令

| 命令 | 说明 |
|---|---|
| `forward` | 启动本地 HTTP 转发代理 → 上游代理 |
| `chain` | 显示配置中的代理链 (JSON 输出) |
| `route` | 按命名路由规则启动转发代理 |
| `test` | 测试通过代理链到目标主机的连通性 |

## 配置: pipeline_config.json

```json
{
  "schema": "reverselab.proxy_pipeline_config.v1",
  "hops": [
    {
      "id": "hop1_local",
      "proxy": "socks5://127.0.0.1:1080",
      "timeout_sec": 10,
      "retries": 2,
      "enabled": true
    }
  ],
  "rules": [
    {
      "id": "rule_burp",
      "listen": { "host": "127.0.0.1", "port": 8081 },
      "target": "hop1_local",
      "match": { "protocol": ["http", "https"] },
      "enabled": false
    }
  ]
}
```

### 与 proxy_pool 联动

`route` 子命令支持 `target: "pool"` 模式，自动从代理池选择最快的代理：

```json
{
  "id": "rule_pool_round_robin",
  "listen": { "host": "127.0.0.1", "port": 9090 },
  "target": "pool",
  "pool_config": "tools/proxy_pool/proxy_sources.json",
  "pool_state": "tools/proxy_pool/pool_state.json",
  "match": { "protocol": ["http", "https"] }
}
```

### 典型拓扑

```
浏览器 → localhost:8081 (pipeline) → SOCKS5 本地 → 远程出口
                                                      
Burp → localhost:9090 (pipeline) → 代理池轮转 → 目标站点
                                                      tools (sqlmap/nuclei/ffuf) → 
                                                      proxy_pool rotate → 目标
```

## 限制

- 当前版本支持单跳代理转发（本地 → 上游）
- 多跳代理链需要额外依赖（proxychains 或 asyncio 实现）
- 仅支持 HTTP CONNECT 和 SOCKS5 隧道
