# MITM Proxy Capture

基于 mitmproxy 12.x 的自动化抓包/改包/发包工具。

## 快速开始

```powershell
# 1. 安装 mitmproxy (一次性)
pip install mitmproxy

# 2. 安装 CA 证书 (一次性 — 浏览器/系统信任 mitmproxy 才能抓 HTTPS)
mitmdump
# 首次运行后, 证书在 %USERPROFILE%\.mitmproxy\
# Windows: certmgr.msc → 受信任的根证书颁发机构 → 导入 mitmproxy-ca-cert.cer
# Android: 设置 → 安全 → 加密与凭据 → 安装证书 → CA 证书

# 3. 设置客户端代理
# 系统代理: 设置 → 网络和 Internet → 代理 → 127.0.0.1:8080
# 或只代理特定应用 (如浏览器用 SwitchyOmega 插件)

# 4. 抓包
python tools/mitmproxy_capture/mitmproxy_capture.py capture -p 8080 -t 30

# 5. 查看结果
cat exports/mitmproxy/capture.json | python -m json.tool
```

## 子命令

| 命令 | 说明 |
|------|------|
| `capture` | 启动代理抓包，自动保存全量 HTTP/HTTPS flow 到 JSON |
| `modify` | 启动代理 + Python addon 实时改包 |
| `replay` | 从 JSON 重放已抓的包 |
| `craft` | 从 JSON 模板构造 HTTP 请求并发送 |
| `status` | 检查 mitmproxy 安装状态 |

## 抓包 (capture)

```powershell
# 基础抓包 — 30 秒自动停止
python tools/mitmproxy_capture/mitmproxy_capture.py capture -p 8080 -o flows.json -t 30

# 只抓特定主机的流量
python tools/mitmproxy_capture/mitmproxy_capture.py capture -p 8080 --host api.example.com -t 60

# 不保存 body (只记录请求/响应头)
python tools/mitmproxy_capture/mitmproxy_capture.py capture -p 8080 --no-body

# 输出格式 (flows.json)
# [
#   {
#     "id": "...",
#     "timestamp": 1234567890.123,
#     "method": "POST",
#     "url": "https://api.example.com/v1/login",
#     "host": "api.example.com",
#     "port": 443,
#     "path": "/v1/login",
#     "request_headers": {...},
#     "request_body": "...",
#     "response_headers": {...},
#     "response_body": "...",
#     "status_code": 200,
#     "duration_ms": 123.4
#   }
# ]
```

## 改包 (modify)

```powershell
# 生成改包规则模板
python tools/mitmproxy_capture/mitmproxy_capture.py modify --gen-rule my_rules.py

# 编辑 my_rules.py 添加自定义逻辑, 然后启动
python tools/mitmproxy_capture/mitmproxy_capture.py modify -r my_rules.py -p 8080
```

改包规则示例 (`my_rules.py`):

```python
"""自定义改包规则"""
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    """修改发出的请求"""
    # 修改 User-Agent
    flow.request.headers["User-Agent"] = "CustomAgent/1.0"

    # 给所有请求添加自定义头
    flow.request.headers["X-Injected"] = "true"

    # 修改 POST body 中的字段
    if flow.request.content and b"old_value" in flow.request.content:
        flow.request.content = flow.request.content.replace(b"old_value", b"new_value")

    # 拦截特定 API 并修改参数
    if "/api/login" in flow.request.path:
        flow.request.content = flow.request.content.replace(b"admin", b"guest")

def response(flow: http.HTTPFlow) -> None:
    """修改返回的响应"""
    # 修改响应状态码
    if flow.response and flow.response.status_code == 403:
        flow.response.status_code = 200

    # 替换响应体内容 (如绕过 license 验证)
    if flow.response and b'"valid":false' in flow.response.content:
        flow.response.content = flow.response.content.replace(
            b'"valid":false', b'"valid":true'
        )

    # 注入 JS 到 HTML 响应
    if flow.response and b"</body>" in flow.response.content:
        flow.response.content = flow.response.content.replace(
            b"</body>",
            b"<script>console.log('injected by mitmproxy')</script></body>"
        )
```

也可以通过 `capture_addon.py` 的 `ModifyAddon` 类用声明式规则改包:

```python
from tools.mitmproxy_capture.capture_addon import ModifyAddon

addons = [ModifyAddon(
    response_mods=[
        {
            "host_pattern": "api.example.com",
            "path_pattern": "/license/verify",
            "status_override": 200,
            "body_override": '{"valid": true, "expiry": "2099-12-31"}',
        }
    ]
)]
```

## 重放发包 (replay)

```powershell
# 直接 HTTP 重放 (不需要代理, 适合本地测试)
python tools/mitmproxy_capture/mitmproxy_capture.py replay -f flows.json --direct

# 重放到不同目标
python tools/mitmproxy_capture/mitmproxy_capture.py replay -f flows.json --direct -t staging.example.com

# 只重放 POST 请求
python tools/mitmproxy_capture/mitmproxy_capture.py replay -f flows.json --direct --filter-method POST

# 只重放前 5 个 flow
python tools/mitmproxy_capture/mitmproxy_capture.py replay -f flows.json --direct --limit 5
```

## 构造发包 (craft)

```powershell
# 命令行直接构造
python tools/mitmproxy_capture/mitmproxy_capture.py craft -d '{"url":"https://httpbin.org/post","method":"POST","headers":{"X-Test":"1"},"body":"hello"}'

# 从 JSON 文件读取 (支持批量)
python tools/mitmproxy_capture/mitmproxy_capture.py craft -f requests.json

# 跳过 SSL 验证
python tools/mitmproxy_capture/mitmproxy_capture.py craft -d '{"url":"https://self-signed.badssl.com/"}' --no-verify
```

请求 JSON 格式:

```json
{
  "url": "https://api.example.com/v1/data",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json",
    "Authorization": "Bearer token123"
  },
  "body": {"key": "value"}
}
```

批量格式 (数组):

```json
[
  {"url": "https://httpbin.org/get", "method": "GET"},
  {"url": "https://httpbin.org/post", "method": "POST", "body": "test1"},
  {"url": "https://httpbin.org/post", "method": "POST", "body": "test2"}
]
```

## 编程使用

```python
from tools.mitmproxy_capture.capture_addon import CaptureAddon, ModifyAddon

# 抓包 addon — 传给 mitmdump
addons = [CaptureAddon(
    save_path="my_capture.json",
    filter_host="api.example.com",
    collect_body=True,
    max_body=500000,
)]

# 改包 addon — 声明式规则
addons = [ModifyAddon(
    request_mods=[
        {
            "host_pattern": ".*",
            "header_set": {"X-Custom": "injected"},
        }
    ],
    response_mods=[
        {
            "host_pattern": ".*example.com",
            "body_replace": [("old_secret", "REDACTED")],
        }
    ],
)]
```

## 文件结构

| 文件 | 用途 |
|------|------|
| `mitmproxy_capture.py` | 主 CLI 工具 (capture/modify/replay/craft) |
| `capture_addon.py` | 可复用的 mitmproxy addon 类库 |
| `README.md` | 本文件 |

## 与其他工具集成

```powershell
# 1. 抓包 → 保存
python tools/mitmproxy_capture/mitmproxy_capture.py capture -p 8080 -t 30 -o flows.json

# 2. 分析抓包结果
cat flows.json | python -c "import json,sys; flows=json.load(sys.stdin); [print(f['method'],f['url']) for f in flows]"

# 3. 改包重放到测试环境
python tools/mitmproxy_capture/mitmproxy_capture.py replay -f flows.json --direct -t staging.example.com

# 4. 与 Frida 联动 (Android 抓包)
#    先用 Frida hook bypass SSL pinning, 再用本工具抓 HTTPS 流量
```

## CA 证书安装

### Windows
```powershell
# mitmproxy CA 证书位置
ls $env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.cer

# 安装到受信任的根证书颁发机构
certutil -addstore Root $env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.cer
```

### Android
```powershell
# 推送证书到设备
adb push $env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.cer /sdcard/

# 在设备上: 设置 → 安全 → 加密与凭据 → 安装证书 → CA 证书
# Android 7+: 需 root 或把证书放到 /system/etc/security/cacerts/
```

## 典型拓扑

```
浏览器/App → localhost:8080 (mitmproxy) → 目标服务器
                                        → 自动保存 flow (capture)
                                        → 实时修改请求/响应 (modify)
                                        → 重放已保存 flow (replay)

App (Frida SSL unpin) → localhost:8080 (mitmproxy) → 目标 API
                                                    → 抓包分析 API 格式
                                                    → 改包绕过验证
```

## 限制

- 需要客户端信任 mitmproxy CA 证书才能抓 HTTPS
- 部分应用使用 SSL pinning 需要先绕过 (Frida hook)
- mitmproxy 12.x Python API 与旧版本不兼容
- Windows 上部分系统应用使用非标准代理设置可能无法被代理
