---
id: "apk-reverse/06-dynamic/03-touch-input-hook-defense"
title: "触摸输入注入防护与异常手势识别"
title_en: "Touch Input Injection Defense and Synthetic Gesture Detection"
summary: >
  针对 /dev/input/eventX 直接写入、InputManager.injectInputEvent 注入及 AccessibilityService.dispatchGesture 自动点击/自瞄，提供 MotionEvent 标志位核验、无障碍服务感知、触控时序方差/抖动特征识别与服务端风控联动方案。
summary_en: >
  Defense-in-depth against /dev/input/eventX injection, InputManager.injectInputEvent, and AccessibilityService.dispatchGesture automation. Covers MotionEvent flag verification, accessibility service inspection, touch-stream jitter/timing classification, and server-side behavioral telemetry.
board: "apk-reverse"
category: "06-dynamic"
signals:
  - "MotionEvent 校验"
  - "AccessibilityService 检测"
  - "filterTouchesWhenObscured"
  - "触摸注入防护"
  - "自瞄行为识别"
  - "InputDevice 元数据"
mcp_tools:
  - "android_app_baseline"
  - "ghidra_headless_analyze"
  - "kb_router"
keywords:
  - "触摸注入防御"
  - "自瞄检测"
  - "MotionEvent"
  - "AccessibilityService"
  - "外挂识别"
  - "blue-team"
difficulty: "intermediate"
tags:
  - "defense"
  - "blue-team"
  - "touch-security"
  - "anti-cheat"
  - "behavioral-detection"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "apk-reverse/06-dynamic/03-touch-input-hook"
  - "apk-reverse/06-dynamic/02-overlay-rendering-hook-defense"
  - "apk-reverse/05-network/01-game-protocol-hook-defense"
track: "blue"
defends: "apk-reverse/06-dynamic/03-touch-input-hook"
---
# 触摸输入注入防护与异常手势识别

## 防御目标与威胁面

Android 自动化脚本与游戏自瞄外挂主要通过三层入口注入触摸事件：
1. **Linux `/dev/input/eventX` 注入（Root）**：直接向内核输入设备写入 `EV_ABS`/`EV_SYN` 结构，绕过上层部分权限控制。
2. **Framework `InputManager.injectInputEvent`**：借助系统签名或 `INJECT_EVENTS` 权限伪造 `MotionEvent`。
3. **无障碍 `AccessibilityService.dispatchGesture`（免 Root）**：常见于连点器与自动化脚本，可无需 Root 分发手势路径。

由于 `/dev/input` 注入在内核层看起来仍接近硬件事件，纯单点拦截并不现实，必须将**设备与事件源校验**、**无障碍与遮挡状态检查**、**触控微行为统计检测**与**服务端速率/反应时间风控**结合。

## 核心防御矩阵

| 攻击向量 | 根治控制措施 | 关键实现约束 |
|---|---|---|
| `AccessibilityService.dispatchGesture` 免 Root 自动点击 | 查询 `AccessibilityManager.getEnabledAccessibilityServiceList` 并结合 `MotionEvent` 元数据检查 | 区分系统无障碍服务（TalkBack）与可疑第三方非系统点击服务；对高敏操作触发挑战 |
| `InputManager.injectInputEvent` / 虚拟输入设备 | 校验 `event.deviceId` 对应的 `InputDevice` 源、是否为 `isVirtual()` 或缺失触控面积/压力 | 注意部分合规外设与辅助模式差异，采用评分制而非直接崩溃 |
| 极短按压与固定坐标机器点击 | 采集 `ACTION_DOWN`→`ACTION_UP` 驻留时长、事件间隔标准差与坐标微抖动 | 人类操作存在自然微小抖动与 >30ms 驻留，脚本常呈现 <10ms 或零方差规律 |
| 线性插值自瞄轨迹 | 监控平滑度、瞬时角速度突变与重复精准命中同一像素中心 | 特征摘要经会话签名后随操作上报服务端，由服务端完成裁决与降权 |

## 加固代码与行为分类示例

### 1. Android Kotlin `MotionEvent` 源与基础异常特征采集

```kotlin
// TouchGuard.kt — 校验 MotionEvent 源设备、遮挡标志与无障碍状态
package com.example.security

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.pm.ApplicationInfo
import android.view.InputDevice
import android.view.MotionEvent
import android.view.accessibility.AccessibilityManager

data class TouchSignal(
    val obscured: Boolean,
    val virtualDevice: Boolean,
    val nonSystemAccessibilityActive: Boolean,
    val toolType: Int,
    val pressure: Float
)

object TouchGuard {
    fun inspectEvent(context: Context, event: MotionEvent): TouchSignal {
        val device = InputDevice.getDevice(event.deviceId)
        val isVirtual = device == null || device.isVirtual
        val obscured = (event.flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0

        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
        val enabled = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
        val hasThirdPartyA11y = enabled.any { info ->
            val appInfo = info.resolveInfo?.serviceInfo?.applicationInfo
            appInfo != null && (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) == 0
        }

        return TouchSignal(
            obscured = obscured,
            virtualDevice = isVirtual,
            nonSystemAccessibilityActive = hasThirdPartyA11y,
            toolType = event.getToolType(0),
            pressure = event.pressure
        )
    }
}
```

### 2. Python 触摸事件序列人工/合成行为统计检测器

```python
import math
import statistics
from dataclasses import dataclass
from typing import List, Tuple


@dataclass(frozen=True)
class TouchSample:
    t_ms: float
    x: float
    y: float
    action: str  # "DOWN", "MOVE", "UP"


def evaluate_touch_stream(samples: List[TouchSample]) -> Tuple[bool, List[str]]:
    """基于驻留时长、间隔方差与微抖动识别机器注入/自瞄触摸序列。"""
    reasons: List[str] = []
    if len(samples) < 4:
        return False, reasons

    intervals = [b.t_ms - a.t_ms for a, b in zip(samples, samples[1:])]
    if intervals:
        mean_dt = statistics.mean(intervals)
        std_dt = statistics.pstdev(intervals)
        if std_dt < 1.5 and mean_dt < 20.0:
            reasons.append("synthetic_uniform_interval")

    down_times = [s.t_ms for s in samples if s.action == "DOWN"]
    up_times = [s.t_ms for s in samples if s.action == "UP"]
    for dt_down, dt_up in zip(down_times, up_times):
        if 0 <= (dt_up - dt_down) < 10.0:
            reasons.append("superhuman_press_duration")
            break

    moves = [s for s in samples if s.action == "MOVE"]
    if len(moves) >= 3:
        # 直线零抖动插值检测：所有 MOVE 点共线且步长几乎完全一致
        steps = [math.hypot(b.x - a.x, b.y - a.y) for a, b in zip(moves, moves[1:])]
        if steps and statistics.pstdev(steps) < 0.05 and max(steps) > 5.0:
            reasons.append("linear_constant_step_aim")

    return len(reasons) > 0, reasons


if __name__ == "__main__":
    bot_stream = [
        TouchSample(0.0, 100.0, 200.0, "DOWN"),
        TouchSample(8.0, 120.0, 220.0, "MOVE"),
        TouchSample(16.0, 140.0, 240.0, "MOVE"),
        TouchSample(24.0, 160.0, 260.0, "MOVE"),
        TouchSample(32.0, 160.0, 260.0, "UP"),
    ]
    flagged, why = evaluate_touch_stream(bot_stream)
    assert flagged is True
    assert "synthetic_uniform_interval" in why
    assert "linear_constant_step_aim" in why

    fast_tap = [
        TouchSample(0.0, 500.0, 800.0, "DOWN"),
        TouchSample(3.0, 500.0, 800.0, "UP"),
        TouchSample(6.0, 500.0, 800.0, "DOWN"),
        TouchSample(9.0, 500.0, 800.0, "UP"),
    ]
    flagged_tap, why_tap = evaluate_touch_stream(fast_tap)
    assert flagged_tap is True and "superhuman_press_duration" in why_tap

    human_stream = [
        TouchSample(0.0, 100.0, 200.0, "DOWN"),
        TouchSample(28.0, 114.5, 211.2, "MOVE"),
        TouchSample(63.0, 139.0, 238.4, "MOVE"),
        TouchSample(109.0, 158.2, 259.1, "MOVE"),
        TouchSample(148.0, 159.0, 260.4, "UP"),
    ]
    assert evaluate_touch_stream(human_stream) == (False, [])
    print("Touch behavioral detection check passed:", why)
```

## 防御工作流

```text
1. 控件源头过滤：高敏按钮统一配置 filterTouchesWhenObscured 并检测 FLAG_WINDOW_IS_OBSCURED
2. 输入设备与无障碍核查：采集 InputDevice.isVirtual 与非系统 AccessibilityService 启用状态
3. 触控序列特征提取：计算按压驻留时长、采样间隔标准差及 MOVE 轨迹线性度/微抖动特征
4. 签名上行与风控联动：将触控统计摘要绑定会话时间戳与签名上报服务端，避免本地单一判断被 Hook 抹除
5. 渐进式响应：对疑似自动化/自瞄会话触发二次滑块校验或服务端对局隔离，不直接暴露本地检测阈值
```

## 验证与判定标准

- **机器均匀序列检出**：回放固定 8ms 间隔、匀速线性插值或 <10ms 按压抬起序列时，`evaluate_touch_stream` 必须稳定标记异常原因。
- **人类操作误报控制**：正常带有自然抖动与 >40ms 驻留的触控序列不得触发高危标记。
- **无障碍异常识别**：启用非系统包名的测试无障碍点击服务时，`TouchGuard.inspectEvent` 必须准确返回 `nonSystemAccessibilityActive=true`。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 获取前台活动与服务状态 | `android_app_baseline` | 查看设备输入服务与已启用无障碍组件基线 |
| 检查 Native 采集与上报逻辑 | `ghidra_headless_analyze` | 核实行为特征摘要构造未暴露固定阈值常量 |
| 检索对应红蓝文档 | `kb_router` | 对照 [03-touch-input-hook.md](03-touch-input-hook.md) 覆盖全部注入层级 |
