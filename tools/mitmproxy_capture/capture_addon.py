"""
MITM Proxy Capture Addon — 可复用的 mitmproxy addon 模块。

可作为 `--scripts` 参数直接传给 mitmdump/mitmproxy/mitmweb,
也可被其他 Python 脚本 import 后扩展。

Usage:
  # 作为 mitmdump addon 运行
  mitmdump -s tools/mitmproxy_capture/capture_addon.py --listen-port 8080

  # 在 Python 中扩展
  from tools.mitmproxy_capture.capture_addon import CaptureAddon, ModifyAddon
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from mitmproxy import http, ctx


class CaptureAddon:
    """
    通用抓包 addon — 记录所有 HTTP/HTTPS flow 到 JSON 文件。

    配置项 (通过 mitmproxy options 或脚本内设置):
      save_path:  输出 JSON 文件路径
      filter_host: 只记录匹配主机的请求 (空=全部)
      collect_body: 是否保存请求/响应体
      max_body:   单个 body 最大字节数
    """

    def __init__(
        self,
        save_path: str = "exports/mitmproxy/capture.json",
        filter_host: str = "",
        collect_body: bool = True,
        max_body: int = 102400,
    ) -> None:
        self.save_path = save_path
        self.filter_host = filter_host
        self.collect_body = collect_body
        self.max_body = max_body
        self.flows: list[dict[str, Any]] = []

    def _should_capture(self, flow: http.HTTPFlow) -> bool:
        if not self.filter_host:
            return True
        return self.filter_host in flow.request.pretty_host

    def _trim(self, body: bytes) -> str:
        if not self.collect_body:
            return ""
        try:
            s = body.decode("utf-8", errors="replace")
        except Exception:
            s = repr(body)
        max_n = max(1, self.max_body)
        return s[:max_n] if len(s) > max_n else s

    def response(self, flow: http.HTTPFlow) -> None:
        if not self._should_capture(flow):
            return
        entry: dict[str, Any] = dict(
            id=flow.id,
            timestamp=flow.request.timestamp_start,
            method=flow.request.method,
            url=flow.request.pretty_url,
            host=flow.request.pretty_host,
            port=flow.request.port,
            path=flow.request.path,
            request_headers=dict(flow.request.headers),
            response_headers=dict(flow.response.headers) if flow.response else None,
            status_code=flow.response.status_code if flow.response else None,
            request_body=self._trim(flow.request.content or b""),
            response_body=self._trim(flow.response.content or b"") if flow.response else "",
            duration_ms=(
                (flow.response.timestamp_end - flow.request.timestamp_start) * 1000
                if flow.response and flow.response.timestamp_end
                else None
            ),
        )
        self.flows.append(entry)

    def done(self) -> None:
        if not self.flows:
            ctx.log.info("[capture] no flows captured")
            return
        out = Path(self.save_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(self.flows, ensure_ascii=False, indent=2), encoding="utf-8")
        ctx.log.info(f"[capture] saved {len(self.flows)} flow(s) -> {out.resolve()}")


class ModifyAddon:
    """
    通用改包 addon — 支持正则批量替换请求/响应内容。

    配置:
      request_mods:  list[dict]  请求修改规则
      response_mods: list[dict]  响应修改规则

    每条规则格式:
      {
        "host_pattern": ".*",           # 匹配 host 的正则
        "path_pattern": ".*",           # 匹配 path 的正则
        "header_set": {"X-Custom": "v"},     # 设置请求/响应头
        "header_del": ["X-Unwanted"],         # 删除请求/响应头
        "body_replace": [("old", "new")],     # 请求/响应体替换
        "status_override": 200,               # (仅 response) 覆盖状态码
        "body_override": "custom body",       # (仅 response) 覆盖响应体
      }
    """

    def __init__(
        self,
        request_mods: list[dict[str, Any]] | None = None,
        response_mods: list[dict[str, Any]] | None = None,
    ) -> None:
        self.request_mods = request_mods or []
        self.response_mods = response_mods or []

    def _match_rule(self, flow: http.HTTPFlow, rule: dict[str, Any]) -> bool:
        host_pat = rule.get("host_pattern", ".*")
        path_pat = rule.get("path_pattern", ".*")
        return bool(
            re.search(host_pat, flow.request.pretty_host)
            and re.search(path_pat, flow.request.path)
        )

    def _apply_header_mods(self, headers: Any, rule: dict[str, Any]) -> None:
        for k, v in (rule.get("header_set") or {}).items():
            headers[k] = v
        for k in (rule.get("header_del") or []):
            headers.pop(k, None)

    def _apply_body_mods(self, content: bytes | None, rule: dict[str, Any]) -> bytes | None:
        if content is None:
            return None
        text = content
        for old, new in (rule.get("body_replace") or []):
            if isinstance(old, str):
                old = old.encode("utf-8")
            if isinstance(new, str):
                new = new.encode("utf-8")
            text = text.replace(old, new)
        return text

    def request(self, flow: http.HTTPFlow) -> None:
        for rule in self.request_mods:
            if not self._match_rule(flow, rule):
                continue
            self._apply_header_mods(flow.request.headers, rule)
            if flow.request.content:
                flow.request.content = self._apply_body_mods(flow.request.content, rule)
            ctx.log.info(f"[modify] request: {flow.request.method} {flow.request.pretty_url}")

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        for rule in self.response_mods:
            if not self._match_rule(flow, rule):
                continue
            self._apply_header_mods(flow.response.headers, rule)
            if rule.get("status_override") is not None:
                flow.response.status_code = rule["status_override"]
            if rule.get("body_override") is not None:
                body = rule["body_override"]
                flow.response.content = body.encode("utf-8") if isinstance(body, str) else body
            elif flow.response.content:
                flow.response.content = self._apply_body_mods(flow.response.content, rule)
            ctx.log.info(f"[modify] response: {flow.response.status_code} {flow.request.pretty_url}")


# ---- Default addon instances for direct mitmdump usage ----
# 当作为 mitmdump -s capture_addon.py 直接运行时使用。
# 可通过环境变量配置:
#   CAPTURE_SAVE_PATH: 输出路径
#   CAPTURE_FILTER_HOST: 过滤主机

_save_path = os.environ.get("CAPTURE_SAVE_PATH", "exports/mitmproxy/capture.json")
_filter_host = os.environ.get("CAPTURE_FILTER_HOST", "")

addons = [CaptureAddon(save_path=_save_path, filter_host=_filter_host)]
