# 加速/时间操控

## 场景

通过操纵游戏客户端的时间感知函数来获得速度优势——移动加速、攻击频率倍增、技能冷却重置。现代反作弊在服务器端验证时间一致性，并使用多时间源交叉校验检测时间操控。

## 输入信号

- 单机/局域网游戏无服务器时间校验，可直接 hook 时间函数
- 在线游戏存在 client-side 动画加速漏洞，但服务器可能执行独立的时间模拟
- 反作弊使用 RDTSC + QueryPerformanceCounter + GetTickCount 多源校验
- Unity/Unreal 游戏使用引擎内 Time.deltaTime 管理帧率无关逻辑

## GetTickCount / QueryPerformanceCounter Hook

### IAT Hook — GetTickCount

```cpp
#include <Windows.h>
#include <MinHook.h>

// 速度倍率 (1.0 = 正常, 2.0 = 2x 加速)
float g_speedMultiplier = 1.0f;

// 原始函数
DWORD (WINAPI* Original_GetTickCount)(void);
ULONGLONG (WINAPI* Original_GetTickCount64)(void);
BOOL (WINAPI* Original_QueryPerformanceCounter)(LARGE_INTEGER*);

// 基准值 — 用于计算插值后的时间
DWORD g_baseTickCount = 0;
ULONGLONG g_baseTickCount64 = 0;
LARGE_INTEGER g_basePerformanceCounter = {0};
DWORD g_realStartTime = 0;

DWORD WINAPI Hooked_GetTickCount() {
    DWORD realTick = Original_GetTickCount();
    
    if (g_speedMultiplier == 1.0f)
        return realTick;
    
    // 算法: 真实流逝时间 × 速度倍率
    // 但 GetTickCount 是绝对时间, 需要从基准计算
    if (g_baseTickCount == 0) {
        g_baseTickCount = realTick;
        return realTick;
    }
    
    DWORD elapsed = realTick - g_baseTickCount;
    DWORD modifiedElapsed = (DWORD)(elapsed * g_speedMultiplier);
    
    return g_baseTickCount + modifiedElapsed;
}

ULONGLONG WINAPI Hooked_GetTickCount64() {
    ULONGLONG realTick = Original_GetTickCount64();
    
    if (g_speedMultiplier == 1.0f)
        return realTick;
    
    if (g_baseTickCount64 == 0) {
        g_baseTickCount64 = realTick;
        return realTick;
    }
    
    ULONGLONG elapsed = realTick - g_baseTickCount64;
    ULONGLONG modifiedElapsed = (ULONGLONG)(elapsed * g_speedMultiplier);
    
    return g_baseTickCount64 + modifiedElapsed;
}

BOOL WINAPI Hooked_QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount) {
    BOOL result = Original_QueryPerformanceCounter(lpPerformanceCount);
    
    if (g_speedMultiplier == 1.0f || !result)
        return result;
    
    if (g_basePerformanceCounter.QuadPart == 0) {
        g_basePerformanceCounter = *lpPerformanceCount;
        return result;
    }
    
    LONGLONG elapsed = lpPerformanceCount->QuadPart - g_basePerformanceCounter.QuadPart;
    LONGLONG modifiedElapsed = (LONGLONG)(elapsed * g_speedMultiplier);
    
    lpPerformanceCount->QuadPart = g_basePerformanceCounter.QuadPart + modifiedElapsed;
    return result;
}

void InstallTimeHooks() {
    MH_Initialize();
    
    MH_CreateHookApi(L"kernel32.dll", "GetTickCount",
        Hooked_GetTickCount, (void**)&Original_GetTickCount);
    MH_CreateHookApi(L"kernel32.dll", "GetTickCount64",
        Hooked_GetTickCount64, (void**)&Original_GetTickCount64);
    MH_CreateHookApi(L"kernel32.dll", "QueryPerformanceCounter",
        Hooked_QueryPerformanceCounter, (void**)&Original_QueryPerformanceCounter);
    
    MH_EnableHook(MH_ALL_HOOKS);
}
```

### timeGetTime Hook

```cpp
// winmm.dll!timeGetTime — 多媒体定时器
// 某些游戏使用此函数获取高精度时间

typedef DWORD (WINAPI* timeGetTime_t)(void);
timeGetTime_t Original_timeGetTime = nullptr;

DWORD WINAPI Hooked_timeGetTime() {
    DWORD real = Original_timeGetTime();
    
    if (g_speedMultiplier == 1.0f)
        return real;
    
    static DWORD base = 0, realBase = 0;
    if (base == 0) {
        base = real;
        realBase = real;
        return real;
    }
    
    DWORD realElapsed = real - realBase;
    DWORD modified = (DWORD)(realElapsed * g_speedMultiplier);
    return base + modified;
}
```

### RDTSC Hook (Ring-3 模拟)

```cpp
// __rdtsc() 读取时间戳计数器 (CPU 周期数)
// 某些反作弊使用 RDTSC 作为独立时间源做校验

uint64_t g_rdtscBase = 0;
uint64_t g_rdtscRealBase = 0;
float g_rdtscMultiplier = 1.0f;

// Hook rdtsc 指令 (通过 patch 目标代码或模拟)
// 方法: 在游戏代码中搜索 RDTSC (0F 31) 并 patch 为 JMP 到我们的模拟函数

// RDTSC 仿真:
uint64_t HookedRdtsc() {
    uint64_t real = __rdtsc();
    
    if (g_rdtscMultiplier == 1.0f)
        return real;
    
    if (g_rdtscBase == 0) {
        g_rdtscBase = real;
        g_rdtscRealBase = real;
        return real;
    }
    
    uint64_t elapsed = real - g_rdtscRealBase;
    uint64_t modified = (uint64_t)(elapsed * g_rdtscMultiplier);
    return g_rdtscBase + modified;
}
```

## Clock Interpolation Attack

### Hook 游戏自身的时钟系统

```cpp
// 游戏引擎通常封装了多层时间函数:
// 游戏帧循环:
//   deltaTime = currentTime - lastFrameTime
//   游戏逻辑 *= deltaTime
//
// Hook 游戏自身的 GetDeltaTime() 或类似函数
// 通过 pattern scan 定位:
//   函数特征: 返回 float, 调用 QueryPerformanceCounter/GetTickCount

// Unreal Engine 4/5:
// UWorld::GetDeltaSeconds() → AWorldSettings::GetDeltaSeconds()
// → 返回 WorldSettings->TimeDilation

// Unity:
// Time.time → Time.get_time() → UnityPlayer.dll 导出
// 或: UnityEngine.CoreModule!Time_get_time

// 直接修改 Time.timeScale:
float g_newTimeScale = 2.0f;

void ApplyTimeScale(void* timeManager) {
    // Unity: Time.timeScale 是 static 全局变量
    // 通过 IL2CPP Class::Instance 定位
    
    // Unity 结构:
    // TimeManager +0x00: timeScale (float) ← 修改此项
    // TimeManager +0x04: maximumDeltaTime
    // TimeManager +0x08: fixedDeltaTime
    // TimeManager +0x0C: realtimeSinceStartup
    
    *(float*)((uint8_t*)timeManager + 0x00) = g_newTimeScale;
}

// Unreal Engine: 通过控制台命令修改
// "slomo 2.0" — 但不保证在线模式可用
```

## Server-Side Validation 与绕过

### 客户端预测 vs 服务器回滚

```
在线游戏时间线架构:

客户端发送: [timestamp, position, velocity, input_sequence]
服务器收到: 
  ├─ 验证 timestamp 是否在合理范围内
  ├─ 验证 position 是否可达 (物理/碰撞检测)
  └─ 回滚/预测后广播给所有玩家

速度操控检测:
  1. 位置跳跃检测: 两帧之间移动距离超过速度上限
     → 服务器回滚到上一个合法位置
  2. 时间戳异常: 客户端报告的 clock 与服务器 clock 偏差过大
     → 断开连接或标记异常
  3. 移动预测冲突: 客户端移动路径与服务端物理模拟不一致
     → 服务器强制纠正 (rubber banding)
```

### Tick 操作欺骗

```cpp
// 针对服务器端回滚的攻击:
// 原理: 客户端发送过时的时间戳 → 服务器回滚到更早状态
// → 玩家在回滚窗口中的操作不可见 (子弹穿过无反应的敌人)

// 延迟射击攻击:
// 1. 正常移动 (发送实时位置)
// 2. 看到敌人后, 发送一个过去时间戳的射击包
// 3. 服务器回滚到该时间戳 → 命中判定时敌人没在掩体后
// 4. 服务器认为命中

// 实现: 控制客户端发送的数据包时间戳
void InterpolatePacketTimestamp(uint8_t* packet, size_t len, int timeOffsetMs) {
    // 查找包中的时间戳字段 (通常 4 或 8 字节)
    // 减去 timeOffsetMs 毫秒
    
    // 注意: 防重放机制使用加密时间戳 + 序列号
    // 需要逆向出时间戳加密算法
}
```

### 服务器端校验绕过

```cpp
// 服务器一致性校验通常检查:
// - deltaTime = serverTime - lastServerTime
// - clientDeltaTime = clientTime - lastClientTime
// - 如果 clientDeltaTime / deltaTime 超出 [0.9, 1.1] → 速度操控

// 绕过思路:
// 1. 在正常时间窗口内执行加快操作
//    - 平时正常发送时标, 只在需要加速时短暂操控
//    - 每次操控后等待"冷却"使偏差归零
    
// 2. 补偿发送:
//    - 发送两套时间戳: 真实时间戳给服务器验证
//    - 修改后的时间戳给游戏逻辑
//    - 需要在 hook 中分离两个用途
    
// 3. 网络时间协议 (NTP) 干扰:
//    - 一些游戏使用 NTP 同步客户端服务器时间
//    - 干扰 NTP 响应使服务器认为客户端时间正常
```

## Frida Time Hook (Android/iOS)

```javascript
// Android SystemClock 时间操控
var SystemClock = Java.use('android.os.SystemClock');

// elapsedRealtime() — 系统启动以来的毫秒数
// 游戏常用此函数做 deltaTime 计算
var g_realBase = 0;
var g_fakeBase = 0;
var g_speed = 1.0;

SystemClock.elapsedRealtime.implementation = function() {
    var real = this.elapsedRealtime.call(this);
    
    if (g_speed === 1.0) return real;
    
    if (g_realBase === 0) {
        g_realBase = real;
        g_fakeBase = real;
        return real;
    }
    
    var elapsed = real - g_realBase;
    return g_fakeBase + (elapsed * g_speed);
};

// uptimeMillis() — 同上, 但不包含睡眠时间
SystemClock.uptimeMillis.implementation = function() {
    var real = this.uptimeMillis.call(this);
    // 同样应用速度倍率
};

// currentThreadTimeMillis() — 仅当前线程 CPU 时间
SystemClock.currentThreadTimeMillis.implementation = function() {
    var real = this.currentThreadTimeMillis.call(this);
    // 可以选择不修改, 作为真实时间参考
};

// iOS: mach_absolute_time()
// var mach_time = Module.findExportByName(null, "mach_absolute_time");
// Interceptor.attach(mach_time, { ... });

// Unity IL2CPP Time.get_time():
// var timeClass = Il2Cpp.Domain.assembly("UnityEngine").class("Time");
// var get_time = timeClass.method("get_time");
// 或 hook libunity.so 中的 Time_get_time 导出
```

## Tick Anomaly Detector

```cpp
// 反作弊端的时间操控检测器 (逆向视角)
// 理解检测算法才能绕过

class TickAnomalyDetector {
    // 反作弊维护多个时间源的冗余
    std::deque<TimeSample> history;
    
    struct TimeSample {
        DWORD tickCount;
        LARGE_INTEGER qpc;
        uint64_t rdtsc;
        DWORD realTime;      // 服务器下发的参考时间
        DWORD frameCount;
    };
    
public:
    bool IsSuspicious(const TimeSample& current) {
        history.push_back(current);
        if (history.size() < 10) return false;
        
        // 检查 1: QPC vs TickCount 比例一致性
        double qpcRatio = (double)(current.qpc.QuadPart - history[0].qpc.QuadPart)
                        / (current.tickCount - history[0].tickCount);
        if (qpcRatio < 1000.0 || qpcRatio > 15000.0) {
            // QPC 频率通常在 10MHz 左右
            // 异常比例 → 其中一个被操控
            return true;
        }
        
        // 检查 2: RDTSC vs 经过时间
        uint64_t cycleDiff = current.rdtsc - history[0].rdtsc;
        uint64_t msDiff = current.tickCount - history[0].tickCount;
        double cpuGHz = (double)cycleDiff / msDiff / 1e6;
        if (cpuGHz < 1.0 || cpuGHz > 6.0) {
            // CPU 频率不在合理范围内
            // 可能 rdtsc 被 patch
            return true;
        }
        
        // 检查 3: 帧时间一致性
        double frameTime = (current.tickCount - history.back().tickCount)
                         / (double)(current.frameCount - history.back().frameCount);
        if (frameTime > 50.0) {
            // 帧间隔超过 50ms → 可能暂停或加速
            // (但低帧率也可能是真实)
            return true;
        }
        
        // 检查 4: 服务器时间偏差
        int64_t serverDrift = (int64_t)(current.tickCount - current.realTime);
        if (abs(serverDrift) > 5000) {
            // 客户端与服务器时间偏差超过 5 秒
            // 高度可疑
            return true;
        }
        
        return false;
    }
};

// 绕过: 所有被 hook 的时间函数必须返回协调一致的值
// 不能只 hook QPC 而不管 RDTSC
// 必须同时控制: GetTickCount, GetTickCount64, QPC, RDTSC, timeGetTime
// 反作弊会在多个时间源交叉校验
```

## Unity/Unreal 引擎特定操控

### Unity Time.timeScale

```cpp
// Unity 引擎时间结构 (IL2CPP):
// TimeManager 全局实例:
// +0x00: float timeScale
// +0x04: float maximumDeltaTime
// +0x08: float fixedDeltaTime
// +0x0C: float realtimeSinceStartup
// +0x10: float timeSinceLevelLoad
// +0x14: float captureDeltaTime
// +0x18: int32 frameCount

// 通过 IL2CPP 偏移定位:
// TimeManager 通常在 .data 段
// 特征: 连续 5-10 个 float 值, 其中 timeScale = 1.0 是默认

// 修改 timeScale:
float* FindTimeScale() {
    // 搜索 .data 段
    // 寻找 float 值 1.0f 附近的连续浮点数组
    // 验证: 修改并检查游戏速度变化
}
```

### Unreal Engine TimeDilation

```cpp
// Unreal Engine 时间层级:
// UWorld->GetWorldSettings()->TimeDilation
// 每个 UWorld 实例的 AWorldSettings

// 通过控制台变量 (CVar):
// t.MaxFPSCutoff — 最大 FPS
// t.FixedDeltaTime — 固定 deltaTime 用于确定性

// Unreal 安全考虑:
// 在线游戏 slomo 被禁止或服务器覆盖
// 需要 Hook:
//   UWorld::GetDeltaSeconds()
//   或 AWorldSettings::GetEffectiveTimeDilation()
```

## 攻击链

```
确定游戏使用的时间 API (GetTickCount/QPC/RDTSC/引擎函数)
→ 选择 hook 方式 (IAT/VMT/Inline/Frida)
→ 实现速度倍率逻辑 (记录基准 → 插值)
→ 实现所有时间源的协同修改 (反交叉校验)
→ 实现热切换 (按快捷键切换速度)
→ 测试: 确保游戏不崩溃, 时间不被服务器拒绝
→ 进阶: 针对服务器回滚的 tick 操纵
```

## MCP 工具映射

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 搜索时间相关函数 | `ghidra_summary_call_focus` | behavior="time" 或 "clock" |
| PE 导入表确认时间 API | `rizin_imports` | 过滤 GetTickCount/QPC/timeGetTime |
| 引擎特定函数定位 | `search_pattern` | 搜索 timeScale/deltaTime 相关特征码 |
| 函数阅读与反编译 | `ghidra_summary_function_detail` | 查看时间函数调用链 |
| 验证汇编修改 | `rizin_assemble_bytes` | 验证跳转/JMP 指令 |
| 字节补丁 | `patch_bytes` | 修改时间校验逻辑 |

## 证据与验证闭环

- 固定输入样本、SHA256、工具版本和全部参数，先保存未处理 baseline。
- 每个假设至少绑定一个可观察量：已知明密文对、协议字段、状态转移、时间分布、偏移或重放输出。
- 用独立脚本重放核心变换，并以断言、输出哈希或逐字段 diff 验证，不以“看起来合理”作为结论。
- 原始抓包/样本进入 `exports/general/`，派生文件与原件分离并记录转换链。
