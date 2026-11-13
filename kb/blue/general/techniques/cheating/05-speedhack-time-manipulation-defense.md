---
id: "general/cheating/05-speedhack-time-manipulation-defense"
title: "加速与时间操控防御（多源时钟交叉校验 / 服务端 Tick 预算）"
title_en: "Defense Against Speedhack and Time Manipulation"
summary: >
  防御 GetTickCount/QPC/RDTSC Hook、Clock Interpolation、Unity Time.timeScale 与 Unreal TimeDilation 篡改：采用硬件独立时钟交叉比对、服务端权威 Tick 预算与滑动时间漂移检测、以及只读时间全局偏移保护。
summary_en: >
  Defense against GetTickCount/QPC/RDTSC hooks, clock interpolation, Unity Time.timeScale and Unreal TimeDilation tampering: multi-clock cross-validation, server-authoritative tick budgeting with drift detection, and memory protection for engine time globals.
board: "general"
category: "cheating"
signals:
  - "multi-clock cross-check"
  - "server tick budget"
  - "clock drift detection"
  - "Time.timeScale integrity"
  - "RDTSC vs QPC"
  - "timeGetTime"
mcp_tools:
  - "ghidra_summary_call_focus"
  - "ghidra_summary_function_detail"
  - "rizin_imports"
  - "search_pattern"
  - "kb_router"
keywords:
  - "anti-speedhack"
  - "time validation"
  - "tick budget"
  - "clock drift"
  - "server-side validation"
  - "Time.timeScale"
difficulty: "intermediate"
tags:
  - "anti-cheat"
  - "time-defense"
  - "speedhack-defense"
  - "server-validation"
language: "zh-CN"
last_updated: "2026-11-12"
related_articles:
  - "general/cheating/05-speedhack-time-manipulation"
  - "general/cheating/02-packet-interception-defense"
track: "blue"
defends: "general/cheating/05-speedhack-time-manipulation"
---
# 加速与时间操控防御（多源时钟交叉校验 / 服务端 Tick 预算）

## 防御目标

阻止客户端通过 Hook `GetTickCount`/`QueryPerformanceCounter`/`timeGetTime`/`clock_gettime`、插值缩放时间流、或改写 Unity `Time.timeScale` / Unreal `TimeDilation` 来获得移动加速、射速翻倍或冷却缩减，在客户端多时钟源检测的同时由服务端执行严格的 Tick 时间预算裁决。

## 分层防御矩阵

| 操控手段 | 攻击特征 | 防御机制 | 判定依据 |
|---|---|---|---|
| 用户态时间 API Hook | Hook `GetTickCount64`/`QPC`/`timeGetTime` 乘以倍率 | 多时间源交叉校验 + 内核时钟比对 | 客户端 QPC 增量与 `KUSER_SHARED_DATA.InterruptTime` / 服务端 RTT 校正时钟出现持续偏差 |
| 部分时钟源 Hook | 仅 Hook QPC 而未同步修改 `RDTSC` 或内核时间戳 | 跨时钟漂移率检查 | `|ΔT_qpc / ΔT_kuser - 1.0| > 0.03` 持续多个采样窗口 |
| 引擎时间全局篡改 | 修改 Unity `Time.timeScale` 或 Unreal `WorldSettings::TimeDilation` | 引擎全局变量哈希/只读校验 + 服务端动作节拍 | `Time.timeScale != expected` 或客户端每物理秒上报的 Tick 数超额 |
| 蓄力/Tick 注入攻击 | 客户端积攒或伪造历史时间戳批量发送指令 | 服务端漏桶/令牌桶 Tick 预算 | 单位服务端物理时间内接收的客户端输入帧数及位移积分超出物理上限 |

## 防御实现与校验示例

### 1. 服务端 Tick 预算与客户端多时钟源漂移检测器（Python）

同时验证客户端上报的本地多源时钟一致性，并在服务端使用物理时间窗口限制输入帧积累：

```python
class ServerTimeGuard:
    def __init__(self, tick_rate_hz: int = 60, max_burst_ticks: int = 5):
        self.tick_dt = 1.0 / tick_rate_hz
        self.max_burst = max_burst_ticks
        self.last_server_ts: float | None = None
        self.tick_credit: float = 0.0

    def consume_client_ticks(self, server_now: float, client_ticks: int) -> tuple[bool, str]:
        if client_ticks <= 0:
            return False, "non_positive_ticks"
        if self.last_server_ts is None:
            self.last_server_ts = server_now
            self.tick_credit = float(self.max_burst)
        else:
            elapsed = max(0.0, server_now - self.last_server_ts)
            self.last_server_ts = server_now
            # 按服务端真实流逝时间补充可执行 Tick 预算，封顶防止囤积
            self.tick_credit = min(
                self.tick_credit + (elapsed / self.tick_dt),
                float(self.max_burst) + (elapsed / self.tick_dt),
            )
            self.tick_credit = min(self.tick_credit, 20.0)

        if client_ticks > self.tick_credit + 1e-6:
            return False, f"speedhack_budget_exceeded(req={client_ticks},avail={self.tick_credit:.2f})"
        self.tick_credit -= client_ticks
        return True, "ok"

def check_clock_drift(qpc_delta_ms: float, kuser_delta_ms: float, tolerance: float = 0.05) -> tuple[bool, float]:
    if kuser_delta_ms <= 0:
        return False, 1.0
    ratio = qpc_delta_ms / kuser_delta_ms
    drift = abs(ratio - 1.0)
    return drift <= tolerance, round(drift, 4)

if __name__ == "__main__":
    guard = ServerTimeGuard(tick_rate_hz=60, max_burst_ticks=5)
    assert guard.consume_client_ticks(100.0, 2)[0] is True
    # 仅过 0.1s (约 6 ticks) 却请求 30 ticks -> 判定加速
    ok, msg = guard.consume_client_ticks(100.1, 30)
    assert not ok and "speedhack_budget_exceeded" in msg
    clean, drift = check_clock_drift(1000.0, 500.0)  # 2x speedhack
    assert not clean and drift == 1.0
    print("speedhack_defense_check: PASS")
```

## 防御工作流

```text
1. 服务端权威时钟：所有移动积分、技能冷却、射速间隔均由服务端物理时钟与 Tick 预算驱动，客户端仅做预测渲染
2. 令牌桶限速：服务端按真实流逝时间补充每连接的输入帧额度，上限封顶防囤积突发
3. 多源交叉核验：客户端周期性对比 QPC、GetTickCount64、RDTSC 与内核共享时间页（KUSER_SHARED_DATA），检测比例漂移
4. 引擎参数保护：对 Unity Time.timeScale / Unreal TimeDilation 写入受保护封装或校验钩子，异常非 1.0 值立即回正并上报
5. 网络平滑容错：结合连接 RTT 抖动设定合理 burst 阈值，避免高延迟抖动导致误判
```

## 验证与判定标准

- **2x 加速阻断**：当客户端加速至 2.0 倍率提交输入帧时，服务端 `consume_client_ticks` 在预算耗尽后 100% 返回 `speedhack_budget_exceeded` 并拒绝推进状态
- **单源 Hook 检出**：仅 Hook `QueryPerformanceCounter` 返回 2 倍增量而系统中断时间正常时，`check_clock_drift` 计算漂移率 `1.0 > 0.05` 并判定异常
- **无误杀基线**：正常网络抖动（±3 帧突发）内，合法连接通过率保持 100%

## MCP 工具映射

| 防御环节 | MCP 工具 | 用途 |
|---|---|---|
| 时间函数导入核查 | `rizin_imports` | 排查客户端依赖的时间源 API 列表 |
| 时间更新循环定位 | `ghidra_summary_call_focus` | 确认游戏主循环 `deltaTime` 计算是否直接信任未校验 API |
| Hook 特征模式检查 | `search_pattern` | 检索时间函数 IAT/Inline Hook 常用跳转模式 |
| 关键校验函数分析 | `ghidra_summary_function_detail` | 检查 `Time.timeScale` 与心跳时间上报函数的保护强度 |
