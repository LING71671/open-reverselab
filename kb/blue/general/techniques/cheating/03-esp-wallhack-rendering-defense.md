---
id: "general/cheating/03-esp-wallhack-rendering-defense"
title: "透视与 ESP 渲染防御（视野剔除 / 渲染管线完整性 / 覆盖窗口检测）"
title_en: "Defense Against ESP and Wallhack Rendering"
summary: >
  防御 D3D11/DX12 Present VMT Hook、World-to-Screen 矩阵窃取、DrawIndexed 着色器替换（Chams）及外部透明覆盖窗口（Overlay）：采用服务端可见性裁剪（Fog of War/Occlusion Culling）、DXGI 虚表/签名校验、着色器哈希锁定及异常顶层透明窗口检测。
summary_en: >
  Defense against D3D11/DX12 Present VMT hooks, W2S matrix theft, DrawIndexed shader hijacking (Chams), and external overlays: server-side visibility culling, DXGI vtable integrity verification, shader hash pinning, and topmost transparent window detection.
board: "general"
category: "cheating"
signals:
  - "server visibility culling"
  - "DXGI vtable integrity"
  - "overlay window detection"
  - "WS_EX_TRANSPARENT"
  - "shader integrity"
  - "DWM protection"
mcp_tools:
  - "triage_pe"
  - "ghidra_summary_call_focus"
  - "search_pattern"
  - "make_yara_stub"
  - "kb_router"
keywords:
  - "anti-ESP"
  - "anti-wallhack"
  - "server occlusion culling"
  - "VMT integrity"
  - "overlay detection"
  - "DirectX defense"
difficulty: "advanced"
tags:
  - "anti-cheat"
  - "rendering-defense"
  - "ESP-defense"
  - "DirectX"
  - "visibility-culling"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "general/cheating/03-esp-wallhack-rendering"
  - "general/cheating/04-anti-cheat-bypass-defense"
track: "blue"
defends: "general/cheating/03-esp-wallhack-rendering"
---
# 透视与 ESP 渲染防御（视野剔除 / 渲染管线完整性 / 覆盖窗口检测）

## 防御目标

从信息源头与渲染终端两方面遏制透视（Wallhack / ESP）：服务端仅向客户端同步几何可见实体（Server-Side Fog of War），客户端保护 DXGI/D3D 虚表与着色器状态不被劫持，同时识别恶意透明覆盖窗口（External Overlay）与异常屏幕采集行为。

## 分层防御矩阵

| 攻击技术 | 关键漏洞点 | 防御控制措施 | 检验维度 |
|---|---|---|---|
| 全图实体坐标下发 | 客户端内存持有墙后敌人坐标 | 服务端 PVS / 射线可见性裁剪（Occlusion Culling） | 墙后不可见实体不下发坐标或置零隐藏 |
| `Present` / `DrawIndexed` VMT Hook | `IDXGISwapChain` 与 `ID3D11DeviceContext` 虚表指针被替换为外部模块 | 虚表指针模块归属校验（对比 `dxgi.dll`/`d3d11.dll` 签名节区） | 所有虚函数地址必须落在已签名系统模块 `.text` 范围内 |
| Chams / 深度缓冲禁用 | 篡改 `OMSetDepthStencilState` 或替换 Pixel Shader | 绑定不可变 PSO（DX12）与帧末渲染管线状态回读校验 | 深度比较函数与绑定着色器字节码哈希与基线一致 |
| External Overlay 透明窗口 | `WS_EX_TOPMOST \| WS_EX_TRANSPARENT \| WS_EX_LAYERED` 全屏覆盖 | `EnumWindows` 枚举并联合窗口大小、透明度、Z 序与未签名进程判定 | 识别非白名单进程的穿透式全屏覆盖窗口 |
| 截图/推流规避 | 作弊在硬件或 DWM 层隐藏 Overlay | `SetWindowDisplayAffinity` 与受控桌面/反截图采样对照 | 比对应用内渲染缓冲与桌面合成后帧差异（授权防作弊模块） |

## 防御实现与校验示例

### 1. 服务端实体可见性裁剪与客户端渲染异常检测（Python）

在服务端按视锥体与障碍物遮挡决定是否同步实体位置，同时客户端核验窗口样式标志与 DXGI 虚表指针是否指向合法模块地址区间：

```python
WS_EX_TOPMOST = 0x00000008
WS_EX_TRANSPARENT = 0x00000020
WS_EX_LAYERED = 0x00080000

def is_suspicious_overlay(win: dict, game_rect: tuple[int, int, int, int]) -> tuple[bool, str]:
    ex_style = win.get("ex_style", 0)
    has_overlay_flags = (
        (ex_style & WS_EX_TOPMOST)
        and (ex_style & WS_EX_TRANSPARENT)
        and (ex_style & WS_EX_LAYERED)
    )
    if not has_overlay_flags:
        return False, "normal_window"
    if win.get("signed_vendor") in {"Microsoft", "NVIDIA", "AMD", "Valve", "Discord"}:
        return False, "whitelisted_overlay"
    gx, gy, gw, gh = game_rect
    wx, wy, ww, wh = win.get("rect", (0, 0, 0, 0))
    covers_game = ww >= gw * 0.8 and wh >= gh * 0.8 and abs(wx - gx) <= 50 and abs(wy - gy) <= 50
    if covers_game:
        return True, f"suspicious_overlay:{win.get('process', 'unknown')}"
    return False, "small_overlay"

def verify_vtable_targets(vtable_addrs: list[int], module_ranges: list[tuple[int, int, str]]) -> list[dict]:
    hijacked = []
    for idx, addr in enumerate(vtable_addrs):
        owner = next((name for start, end, name in module_ranges if start <= addr < end), None)
        if owner is None or owner.lower() not in {"dxgi.dll", "d3d11.dll", "d3d12.dll"}:
            hijacked.append({"slot": idx, "addr": hex(addr), "owner": owner or "unbacked"})
    return hijacked

if __name__ == "__main__":
    flag, reason = is_suspicious_overlay(
        {"ex_style": WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED, "rect": (0, 0, 1920, 1080), "process": "esp_tool.exe"},
        (0, 0, 1920, 1080),
    )
    assert flag is True and "esp_tool.exe" in reason
    bad = verify_vtable_targets([0x7FFA10001234, 0x180004560], [(0x7FFA10000000, 0x7FFA10100000, "dxgi.dll")])
    assert len(bad) == 1 and bad[0]["slot"] == 1
    print("esp_defense_check: PASS")
```

## 防御工作流

```text
1. 服务端裁剪：基于 PVS（Potentially Visible Set）与动态遮挡射线剔除墙后敌方实体，彻底切断坐标来源
2. 虚表守卫：定期检查 IDXGISwapChain::Present（Slot 8）与 DrawIndexed 指针是否落入已签名 dxgi/d3d 模块内
3. 管线锁定：在渲染关键 Pass 前重置 DepthStencil 与着色器资源绑定，并校验 Shader 字节码哈希
4. 窗口巡检：识别未签名进程创建的 WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED 全屏覆盖窗口
5. 矩阵混淆：对客户端非必需暴露的 ViewProjection 矩阵与骨骼数组做帧内动态重排与清理
```

## 验证与判定标准

- **网络抓包验证**：当敌方角色处于完全遮挡区域外时，抓包确认服务端未发送其精确世界坐标
- **VMT 劫持检出**：测试 Hook `Present` 指向自定义 DLL 后，虚表校验器在 1 个检测周期内准确识别被篡改的槽位索引与外部模块归属
- **Overlay 检出**：在测试窗口启用透明穿透覆盖样式并覆盖游戏主窗口 80% 以上面积时，检出函数返回 `True` 并准确标识进程名

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 二进制与驱动检查 | `triage_pe` | 检查渲染监控与游戏模块签名及安全编译选项 |
| 虚表与渲染调用追踪 | `ghidra_summary_call_focus` | 核对游戏渲染主循环中 `Present` 调用链完整性 |
| 注入渲染模块特征搜索 | `search_pattern` | 查找异常 ImGui/D3D11 Hook 特征模式 |
| 作弊端 YARA 规则输出 | `make_yara_stub` | 生成常见 ESP Overlay/Hook DLL 静态检测规则 |
