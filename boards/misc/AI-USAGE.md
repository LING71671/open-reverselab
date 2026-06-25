# Misc AI Usage

环境和工具链维护的 AI 工作约定。

## 自动路由规则

当用户提到以下关键词时，自动路由到对应工具：

| 关键词 | 工具 | 命令 |
|--------|------|------|
| 抓包/捕获/capture/拦截流量 | mitmproxy_capture | `python tools/mitmproxy_capture/mitmproxy_capture.py capture` |
| 改包/修改请求/修改响应/modify | mitmproxy_capture | `python tools/mitmproxy_capture/mitmproxy_capture.py modify` |
| 重放/重发/replay/发包(已抓) | mitmproxy_capture | `python tools/mitmproxy_capture/mitmproxy_capture.py replay` |
| 构造请求/自定义发包/craft | mitmproxy_capture | `python tools/mitmproxy_capture/mitmproxy_capture.py craft` |

## 常用命令

```powershell
# 环境健康检查
python scripts/misc/lab_healthcheck.py

# 工具可用性检查
python scripts/misc/ai_toolcheck.py

# Web CTF 工具巡检
.\scripts\ctf-website\ctf_toolcheck.ps1

# MITM 抓包 — 启动代理抓包 30s
python tools/mitmproxy_capture/mitmproxy_capture.py capture -p 8080 -t 30

# MITM 改包 — 用自定义规则启动代理
python tools/mitmproxy_capture/mitmproxy_capture.py modify -r my_rules.py -p 8080

# MITM 重放 — 从 JSON 重放已抓的包
python tools/mitmproxy_capture/mitmproxy_capture.py replay -f flows.json --direct

# MITM 构造发包
python tools/mitmproxy_capture/mitmproxy_capture.py craft -d '{"url":"https://target.com","method":"POST","body":"test"}'
```
