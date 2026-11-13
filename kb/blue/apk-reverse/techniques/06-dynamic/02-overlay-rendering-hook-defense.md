---
id: "apk-reverse/06-dynamic/02-overlay-rendering-hook-defense"
title: "悬浮窗覆盖与图形渲染管线劫持防御"
title_en: "Overlay Window and Graphics Rendering Pipeline Hook Defense"
summary: >
  针对 ANativeWindow 外部悬浮窗、ImGui 渲染帧注入以及 eglSwapBuffers/vkQueuePresentKHR Hook，提供 FLAG_SECURE 与 setHideOverlayWindows 系统防遮挡、触摸遮挡过滤、图形 API 入口前导码校验及 SurfaceFlinger/Window 异常层排查方案。
summary_en: >
  Defense-in-depth against ANativeWindow external overlays, ImGui rendering loops, and eglSwapBuffers/vkQueuePresentKHR hooks. Covers FLAG_SECURE and setHideOverlayWindows(true), obscured touch filtering, graphics API prologue/GOT integrity checks, and SurfaceFlinger/Window layer verification.
board: "apk-reverse"
category: "06-dynamic"
signals:
  - "FLAG_SECURE"
  - "setHideOverlayWindows"
  - "TYPE_APPLICATION_OVERLAY 防护"
  - "eglSwapBuffers 完整性"
  - "vkQueuePresentKHR 校验"
  - "SurfaceFlinger 排查"
mcp_tools:
  - "android_app_baseline"
  - "android_capture_screenshot"
  - "ghidra_headless_analyze"
  - "kb_router"
keywords:
  - "悬浮窗防御"
  - "ImGui检测"
  - "FLAG_SECURE"
  - "HIDE_OVERLAY_WINDOWS"
  - "渲染Hook防护"
  - "blue-team"
difficulty: "advanced"
tags:
  - "defense"
  - "blue-team"
  - "overlay"
  - "opengles"
  - "vulkan"
  - "android-ui"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "apk-reverse/06-dynamic/02-overlay-rendering-hook"
  - "apk-reverse/06-dynamic/03-touch-input-hook-defense"
  - "apk-reverse/06-dynamic/01-memory-rw-hook-defense"
track: "blue"
defends: "apk-reverse/06-dynamic/02-overlay-rendering-hook"
---
# 悬浮窗覆盖与图形渲染管线劫持防御

## 防御目标与威胁面

外挂或恶意辅助常通过两条路径在应用画面上方呈现内容：
1. **外部独立窗口 Overlay**：借助 `ANativeWindow` / `TYPE_APPLICATION_OVERLAY` 创建覆盖层窗口绘制透视或作弊菜单，同时配置触摸穿透以干扰正常交互或诱骗点击。
2. **进程内渲染管线注入**：通过 Frida 或注入 `.so` 挂钩 `libEGL.so!eglSwapBuffers` 或 `libvulkan.so!vkQueuePresentKHR`，在应用自己的渲染帧循环内叠加 ImGui 菜单。

防御需同时覆盖**系统窗口隔离策略（阻止外部叠加）**与**Native 图形函数完整性验证（发现进程内渲染劫持）**。

## 核心防御矩阵

| 攻击向量 | 根治控制措施 | 关键实现约束 |
|---|---|---|
| `TYPE_APPLICATION_OVERLAY` 外部悬浮窗遮挡 | Android 12+ 声明 `HIDE_OVERLAY_WINDOWS` 并调用 `window.setHideOverlayWindows(true)` | 在密码、支付及高敏页面同时启用 `FLAG_SECURE` 防截屏/录屏与虚拟显示捕获 |
| 触摸穿透欺骗与劫持交互 | 关键控件启用 `filterTouchesWhenObscured = true` 并校验 `FLAG_WINDOW_IS_OBSCURED` | 检测到部分或完全遮挡事件直接丢弃并提示用户关闭悬浮层 |
| Hook `eglSwapBuffers` / `vkQueuePresentKHR` | Native 定时核验 `dlsym` 解析出的图形符号前导指令与所属映射路径 | 发现函数入口被改写为跳转跳板或调用栈源自未知 `.so`/匿名页即上报风控 |
| 进程内 ImGui 线程与帧率异常 | 监控 `/proc/self/maps` 与线程表异常模块，核对是否存在未注册渲染线程 | 结合服务端动作/视野数据一致性校验，避免纯客户端渲染隔离被绕过 |

## 加固代码与层检测示例

### 1. Android Kotlin 窗口防悬浮窗遮挡与截屏加固

```kotlin
// SecureOverlayActivity.kt — 启用 FLAG_SECURE、隐藏非系统悬浮窗及遮挡触摸过滤
package com.example.security

import android.os.Build
import android.os.Bundle
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import androidx.appcompat.app.AppCompatActivity

class SecureOverlayActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 1. 阻止非安全屏幕录制、截屏及虚拟 Display 采集
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)

        // 2. Android 12 (API 31)+ 强制隐藏覆盖在当前窗口上的非系统悬浮窗
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            window.setHideOverlayWindows(true)
        }
    }

    fun hardenSensitiveButton(view: View) {
        view.filterTouchesWhenObscured = true
        view.setOnTouchListener { _, event ->
            val obscured = (event.flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0
            val partial = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                (event.flags and MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED) != 0
            } else {
                false
            }
            obscured || partial  // 被遮挡时消费并拦截点击事件
        }
    }
}
```

### 2. Python 解析 `dumpsys window` 排查异常 `TYPE_APPLICATION_OVERLAY` 窗口

```python
import re
from typing import List, Tuple


def find_rogue_overlays(dumpsys_window_output: str, allowed_packages: set[str]) -> List[Tuple[str, str]]:
    """从 dumpsys window windows 输出中识别非白名单的 TYPE_APPLICATION_OVERLAY 窗口。"""
    rogue: List[Tuple[str, str]] = []
    blocks = re.split(r"(?=Window #\d+\s+Window\{)", dumpsys_window_output)
    for block in blocks:
        if "TYPE_APPLICATION_OVERLAY" not in block:
            continue
        pkg_match = re.search(r"package=([^\s]+)", block)
        win_match = re.search(r"Window\{[^\s]+\s+u\d+\s+([^}]+)\}", block)
        pkg = pkg_match.group(1) if pkg_match else "unknown"
        title = win_match.group(1) if win_match else "unknown"
        if pkg not in allowed_packages:
            rogue.append((pkg, title))
    return rogue


if __name__ == "__main__":
    sample_dumpsys = """
    Window #1 Window{abc123 u0 com.android.systemui}:
      mAttrs={(0,0)(fillxfill) ty=STATUS_BAR}
    Window #2 Window{def456 u0 overlay_name}:
      mAttrs={(0,0)(1080x2400) gr=TOP LEFT ty=TYPE_APPLICATION_OVERLAY fl=NOT_FOCUSABLE|NOT_TOUCHABLE}
      package=com.rogue.overlay
    """
    detected = find_rogue_overlays(sample_dumpsys, allowed_packages={"com.android.systemui"})
    assert detected == [("com.rogue.overlay", "overlay_name")]
    print("Overlay window detection check passed:", detected)
```

## 防御工作流

```text
1. 权限与窗口加固：在 Manifest 声明 android.permission.HIDE_OVERLAY_WINDOWS，高敏界面开启 FLAG_SECURE 与 setHideOverlayWindows(true)
2. 触摸遮挡拦截：为确认、支付、操作类 View 强制配置 filterTouchesWhenObscured 与 FLAG_WINDOW_IS_OBSCURED 检查
3. 图形入口核验：Native 层周期性检查 libEGL.so!eglSwapBuffers 与 libvulkan.so!vkQueuePresentKHR 前导字节及 PLT/GOT 表
4. 渲染线程巡检：结合 /proc/self/maps 扫描未授权图形中间层库与匿名可执行块
5. 运行态复验：采集 dumpsys window 与截图比对，确认开启屏蔽后外部悬浮层不再可见
```

## 验证与判定标准

- **系统防悬浮窗生效**：在测试机开启第三方 `TYPE_APPLICATION_OVERLAY` 窗口后打开加固页面，非系统悬浮层必须自动隐藏，且按钮遮挡点击返回拦截。
- **截图与录屏阻断**：执行 `android_capture_screenshot` 或录屏时，`FLAG_SECURE` 界面应返回黑屏或受保护拒绝结果。
- **进程内渲染 Hook 检出**：当 `eglSwapBuffers` 或 `vkQueuePresentKHR` 被 Frida `Interceptor.attach` 修改前导字节后，Native 完整性检查必须识别出入口跳板。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 验证 `FLAG_SECURE` 拦截效果 | `android_capture_screenshot` | 核对受保护界面无法被外部截屏采集 |
| 收集窗口与包基线 | `android_app_baseline` | 获取当前包名、前台 Activity 与系统状态 |
| 核查 Native 渲染检测函数 | `ghidra_headless_analyze` | 确认图形入口完整性检测未留明文单点开关 |
| 检索对应红蓝文档 | `kb_router` | 对照 [02-overlay-rendering-hook.md](../../../../red/apk-reverse/techniques/06-dynamic/02-overlay-rendering-hook.md) 覆盖全部渲染路径 |
