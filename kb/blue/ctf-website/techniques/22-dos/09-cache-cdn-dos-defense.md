---
id: "ctf-website/22-dos/09-cache-cdn-dos-defense"
title: "缓存穿透、源站暴露与 CDN 拒绝服务防御"
title_en: "Cache Busting, Origin Exposure, and CDN DoS Defense"
summary: >
  系统防御针对 CDN 与缓存层的拒绝服务攻击：包括 Cache Busting 随机参数穿透源站、历史 DNS/证书透明度导致的源站真实 IP 暴露、Range Header 分片放大、基于未键控 Header（如 X-Forwarded-Host）的 Cache Poison DoS，以及 CDN 边缘 PoP 节点资源耗尽。提供源站 mTLS 认证隔离、Nginx 缓存键归一化与 Python 弹性校验代码。
summary_en: >
  Comprehensive defense against CDN and cache-layer DoS: Cache Busting parameter bypass, origin IP exposure via DNS history and CT logs, Range header cache bypass and multipart amplification, Cache Poisoning DoS via unkeyed headers (X-Forwarded-Host), and CDN edge PoP exhaustion. Covers Authenticated Origin Pulls (mTLS), Nginx cache-key normalization, and runnable Python checks.
board: "ctf-website"
category: "22-dos"
signals:
  - "Origin IP mTLS 双向认证与防火墙隔离"
  - "Cache Key 查询参数白名单归一化"
  - "max_ranges=1 防多 Range 放大"
  - "禁止缓存 4xx/5xx/空响应体"
  - "剥离未键控 X-Forwarded-Host 头部"
  - "Origin Shield 层级收敛回源流量"
mcp_tools:
  - "http_probe"
  - "kb_router"
  - "kb_read_file"
  - "kb_catalog"
keywords:
  - "Cache Busting 防御"
  - "源站隐藏"
  - "CDN 源站保护"
  - "Cache Poison 防护"
  - "CPDoS 缓解"
  - "Range 攻击防御"
  - "Authenticated Origin Pulls"
  - "cache cdn dos defense"
difficulty: "intermediate"
tags:
  - "defense"
  - "blue-team"
  - "resilience"
  - "dos-protection"
  - "cache"
  - "cdn"
  - "cache-poisoning"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "ctf-website/22-dos/09-cache-cdn-dos"
track: "blue"
defends: "ctf-website/22-dos/09-cache-cdn-dos"
---
# 缓存穿透、源站暴露与 CDN 拒绝服务防御

## 防御目标与对抗矩阵

缓存与 CDN 层攻击（对应攻击技术见 [09-cache-cdn-dos.md](../../../../red/ctf-website/techniques/22-dos/09-cache-cdn-dos.md)）旨在废除边缘缓存过滤能力或将污染响应固化给全体用户。防御必须同时锁定**源站网络可达性、边缘缓存键规范化、非正常状态码禁存以及单节点压力分流**。

| 攻击向量 | 攻击效果 | 核心防御策略 | 关键配置 / 机制 |
|---|---|---|---|
| Cache Busting（随机参数/头/大小写） | 缓存命中率归零、流量直击源站 | 边缘缓存键忽略无关 Query 参数与任意 `Vary` 头，路径统一小写化；开启回源合并 (`proxy_cache_lock`) | CDN 参数白名单 + `proxy_cache_lock on` + Origin Shield |
| 源站真实 IP 暴露 | 绕过 CDN/WAF 直打源站 | 源站防火墙仅放行 CDN 回源 CIDR + 强制 Authenticated Origin Pulls (mTLS) + 迁移新 IP 并分离邮件服务器 | 防火墙白名单 + 源站 mTLS + 通配符证书（避免子域泄露至 CT） |
| Range Header 穿透与多 Range 放大 | 每次不对齐 Range 回源拉取或生成百万分片 | 边缘缓存预取完整对象并切片服务，源站限制单请求最大 Range 数量 | Nginx `max_ranges 1` + CDN 切片缓存 (`Slice`) |
| Cache Poison DoS (CPDoS) | 404/500/302 循环/空响应被 CDN 缓存 | 绝对禁止缓存 `4xx/5xx/0字节` 响应，剥离未参与 Cache Key 的 `X-Forwarded-Host` 等代理头 | `proxy_cache_valid 200 10m` + 清理不可信覆盖头 |
| CDN 边缘 PoP 资源耗尽 | 局部边缘节点过载引发区域降级 | 启用 Anycast BGP 自动牵引与边缘节点过载跨区调度（Failover PoP） | 多级 Origin Shield + 边缘连接限流 |

---

## 防御工作流

### 阶段一：彻底隐藏与隔离源站（防绕过 CDN）

1. **网络层与 mTLS 双重锁定**：即使源站 IP 曾因历史 DNS 或 CT 日志暴露，必须立即迁移源站公网 IP（或仅通过专线/VPN 接入 CDN），并在源站防火墙（Security Group / nftables）**仅放行 CDN 官方回源网段**；同时开启 CDN 回源双向 TLS（Authenticated Origin Pulls），确保任何直接 IP 请求在 TLS 握手层即被拒绝。
2. **禁止默认虚拟主机与回显泄露**：源站关闭 IP 直接访问的默认响应，使用 `default_server` 返回 `444`；邮件服务器（MX/SPF）与测试环境（`dev`/`staging`）独立部署于隔离网段，证书使用通配符证书 `*.example.internal` 以减少内部子域暴露于 `crt.sh`。

```nginx
# /etc/nginx/conf.d/origin_shield_isolation.conf
# 1. 拒绝对源站 IP 或未知 Host 的直接探测
server {
    listen 80 default_server;
    listen 443 ssl default_server;
    ssl_reject_handshake on;
    return 444;
}

# 2. 仅允许经 CDN 回源客户端证书认证的流量访问源站
server {
    listen 443 ssl;
    server_name www.example.internal;

    ssl_certificate     /etc/ssl/certs/origin.pem;
    ssl_certificate_key /etc/ssl/private/origin.key;
    ssl_client_certificate /etc/ssl/certs/cdn-origin-pull-ca.pem;
    ssl_verify_client on;

    # 防止多 Range 放大攻击（最多允许 1 个 Range 段；静态小资源可设为 0 禁用）
    max_ranges 1;

    # 剥离不可信前端代理头，防止 Cache Poison DoS
    proxy_set_header X-Forwarded-Host "";
    proxy_set_header X-Original-URL "";
    proxy_set_header X-Rewrite-URL "";
    proxy_set_header X-HTTP-Method-Override "";
}
```

### 阶段二：缓存键归一化与回源合并（防 Cache Busting 与 CPDoS）

1. **标准化 Cache Key**：在 CDN 规则或 Nginx 缓存层仅保留业务必需的查询参数白名单（丢弃 `cb`、`_`、`r`、`utm_*` 等随机/追踪参数），对路径统一转小写，禁止使用客户端可控头（如 `Accept-Language`、`Cookie`）对公共静态资源分片。
2. **开启回源锁（Request Coalescing）与 Stale-While-Revalidate**：同一键未命中时仅放行 1 个回源请求，其余并发请求等待缓存填充，防止并发缓存击穿；且仅缓存 `200`/`206` 非空响应，严禁将 `400/404/500/502` 写入长期缓存。

```nginx
# /etc/nginx/conf.d/cache_hardening.conf
proxy_cache_path /var/cache/nginx/edge levels=1:2 keys_zone=STATIC_CACHE:100m max_size=10g inactive=60m use_temp_path=off;

# 仅提取业务白名单参数（例如仅保留 page 与 lang），丢弃随机 cache-busting 参数
map $arg_page $clean_page { default ""; "~^[0-9]+$" "page=$arg_page"; }

server {
    listen 443 ssl;
    server_name edge.example.internal;

    location /assets/ {
        proxy_cache STATIC_CACHE;
        # 缓存键不包含随机查询参数与大小写差异
        proxy_cache_key "$scheme$host$uri$clean_page";

        # 防止并发穿透回源（同 Key 仅 1 个请求回源）
        proxy_cache_lock on;
        proxy_cache_lock_timeout 5s;

        # 严格仅缓存正常响应，阻止 CPDoS 缓存错误页或空页面
        proxy_cache_valid 200 206 30m;
        proxy_cache_valid any 0;
        proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;

        # 忽略后端可能意外输出的过大 Vary 维度
        proxy_ignore_headers Vary Set-Cookie;
        proxy_pass http://origin_shield;
    }
}
```

---

## 弹性校验代码（可运行 Python 自检）

以下 Python 脚本实现三项核心校验：（1）缓存键归一化器（剔除随机 Cache Busting 参数并规范路径大小写）；（2）多 Range 头部滥用与重叠区间拦截器；（3）CPDoS 响应安全缓存判定与 Nginx 策略核验。

```python
#!/usr/bin/env python3
"""Cache/CDN DoS defense verifier: cache-key normalizer, Range guard, and CPDoS filter."""

from urllib.parse import parse_qsl, urlencode, urlsplit


ALLOWED_QUERY_PARAMS = {"page", "v", "lang"}


def normalize_cache_key(raw_url: str, allowed_params: set[str] = ALLOWED_QUERY_PARAMS) -> str:
    """Normalize URI case and strip random cache-busting query parameters."""
    parts = urlsplit(raw_url)
    norm_path = parts.path.lower() or "/"
    filtered_qs = [
        (k, v)
        for k, v in parse_qsl(parts.query, keep_blank_values=False)
        if k in allowed_params
    ]
    filtered_qs.sort()
    qs = urlencode(filtered_qs)
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{norm_path}" + (f"?{qs}" if qs else "")


def validate_range_header(range_header: str, max_ranges: int = 1, max_span: int = 10 * 1024 * 1024) -> tuple[bool, str]:
    """Block multi-range amplification and malformed/reversed byte ranges."""
    if not range_header:
        return True, "no_range"
    if not range_header.startswith("bytes="):
        return False, "unsupported_unit"
    specs = [s.strip() for s in range_header[6:].split(",") if s.strip()]
    if len(specs) > max_ranges:
        return False, f"too_many_ranges:{len(specs)}"
    for spec in specs:
        if "-" not in spec:
            return False, "malformed_range"
        start_s, end_s = spec.split("-", 1)
        if start_s and end_s:
            start, end = int(start_s), int(end_s)
            if start > end or (end - start + 1) > max_span:
                return False, "invalid_or_oversized_range"
        elif not start_s and end_s:
            if int(end_s) > max_span:
                return False, "oversized_suffix_range"
    return True, "ok"


def is_cacheable_response(status_code: int, body_bytes: bytes, headers: dict[str, str]) -> tuple[bool, str]:
    """Prevent Cache Poison DoS by rejecting error codes, empty bodies, and reflected poison headers."""
    if status_code not in (200, 206):
        return False, f"non_cacheable_status:{status_code}"
    if len(body_bytes) == 0:
        return False, "empty_body_rejected"
    if "X-Forwarded-Host" in headers and headers["X-Forwarded-Host"].encode() in body_bytes:
        return False, "reflected_unkeyed_header"
    return True, "cacheable"


def run_self_checks() -> None:
    # 1. Cache Busting 参数剥离与大小写归一化校验
    k1 = normalize_cache_key("https://CDN.Example.com/Assets/App.JS?cb=981273&_=170000&v=2")
    k2 = normalize_cache_key("https://cdn.example.com/assets/app.js?v=2&rand=xyz")
    assert k1 == k2 == "https://cdn.example.com/assets/app.js?v=2", f"Mismatch: {k1} vs {k2}"

    # 2. 多 Range 放大与反转 Range 拦截校验
    ok, reason = validate_range_header("bytes=0-1,2-3,4-5", max_ranges=1)
    assert not ok and "too_many_ranges" in reason
    ok, reason = validate_range_header("bytes=1000-500")
    assert not ok and reason == "invalid_or_oversized_range"
    assert validate_range_header("bytes=0-1023")[0]

    # 3. CPDoS 防投毒校验（空响应、500 错误、未键控头回显均不得缓存）
    assert not is_cacheable_response(500, b"Internal Error", {})[0]
    assert not is_cacheable_response(200, b"", {})[0]
    assert not is_cacheable_response(200, b"link: evil.com", {"X-Forwarded-Host": "evil.com"})[0]
    assert is_cacheable_response(200, b"valid static asset", {})[0]
    print("[PASS] All Cache/CDN DoS defense checks passed.")


if __name__ == "__main__":
    run_self_checks()
```

---

## 验证与判定标准

| 验证项 | 达标判定标准 | 可观测指标 |
|---|---|---|
| 源站隔离不可直连 | 绕过 CDN 直接连接源站 IP 在 TLS 握手或防火墙阶段被丢弃 | 直连 IP 超时或返回 TLS Alert（零 200 回显） |
| Cache Busting 失效 | 携带随机 `?cb=...` 参数和大小写变体请求全部返回 `X-Cache: HIT` | 缓存命中率维持 `> 90%`，源站 QPS 无放大 |
| Range 请求受控 | 多段 `Range: bytes=0-1,2-3,...` 返回 `416` 或降级为完整响应 | 源站无 `multipart/byteranges` CPU 毛刺 |
| 零 CPDoS 污染 | 构造 `X-Forwarded-Host` 或触发 404/500 错误后，后续正常用户仍命中健康缓存 | 正常请求 200 比例 `100%` |

---

## MCP 工具映射

| 防御阶段 | MCP 工具 | 说明 |
|---|---|---|
| 缓存头与源站回显核验 | `http_probe` | 检查 `X-Cache` / `CF-Cache-Status`、Range 响应及未键控头反射 |
| 蓝队技术搜索 | `kb_router` | 以 `track="blue"` 搜索 `cache` / `cdn` / `cpdos` 防御条目 |
| 攻防文档对照 | `kb_read_file` | 读取本文件及配对攻击文档 `ctf-website/22-dos/09-cache-cdn-dos` |
| 分类目录查看 | `kb_catalog` | 列举 `22-dos` 全部防御文档 |
