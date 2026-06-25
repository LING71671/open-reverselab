# 触摸输入 Hook 与注入分析

## 场景

应用/游戏使用了触摸注入或触摸监听（自瞄绘制、模拟点击）。需要检测、分析触摸事件流。

## 输入信号

- 屏幕上出现非人为的点击/滑动
- 触摸事件处理速度异常快（毫秒级瞄准切换）
- `/dev/input/event*` 或 InputReader 有异常活动

## Android 触摸体系层级

```
屏幕硬件
→ Linux kernel /dev/input/eventX (原始事件)
→ InputReader (framework native)
→ InputDispatcher → ViewRootImpl (Java 分发)
→ Activity.dispatchTouchEvent (应用层)
```

## 触摸注入检测

### 1. 检测 /dev/input 注入

```bash
# 查看输入设备和事件
adb shell getevent -lp   # 列出所有输入设备
adb shell getevent        # 实时输出事件流

# 异常信号: 事件间隔 < 10ms (超人手速)
# 异常信号: 坐标精准落在 UI 按钮中心
```

```c
// 注入端代码模式
// 直接向 /dev/input/eventX 写入事件
int fd = open("/dev/input/event5", O_RDWR);
struct input_event ev;
ev.type = EV_ABS;
ev.code = ABS_MT_POSITION_X;
ev.value = targetX;
write(fd, &ev, sizeof(ev));
// → 检测: lsof | grep "/dev/input/event"
```

### 2. Frida Hook InputReader

```javascript
// Hook InputReader 层 (libinputflinger.so)
var InputReader = Module.findExportByName("libinputflinger.so",
    "_ZN7android11InputReader23loopOnceEv")  // InputReader::loopOnce
Interceptor.attach(InputReader, {
    onEnter: function(args) {
        // 将注入的事件与原始事件做对比
        // 注入事件通过 InputPublisher 而非 InputListener
    }
})
```

### 3. 触摸事件注入 Hook

```javascript
// Hook InputManager.injectInputEvent (Java)
var InputManager = Java.use("android.hardware.input.InputManager")
InputManager.injectInputEvent.implementation = function(event, mode) {
    console.log("[injectInput] mode:", mode)
    var motion = Java.cast(event, Java.use("android.view.MotionEvent"))
    console.log("  x:", motion.getX(), "y:", motion.getY())
    return true  // 注入方期望返回 true
}
```

## 触摸事件分析 (自瞄检测)

```javascript
// Hook onTouchEvent 分析触摸模式
Java.perform(function() {
    var View = Java.use("android.view.View")
    View.onTouchEvent.implementation = function(event) {
        var action = event.getActionMasked()
        var x = event.getX()
        var y = event.getY()
        // 自瞄特征: 每帧都在移动, 坐标变化方差小, 路径平滑
        // 人工: 抖动多, 偶发大跳, 按下-抬起间隔 > 100ms
        return this.onTouchEvent(event)
    }
})
```

```python
# 离线分析: 判断触摸序列是否人工
def is_ai_touch(events):
    intervals = [e2.t - e1.t for e1, e2 in zip(events, events[1:])]
    distances = [dist(e1, e2) for e1, e2 in zip(events, events[1:])]
    # 指标1: 间隔方差 → AI 极低
    # 指标2: 路径平滑度 → AI 极高
    # 指标3: 按下到抬起时间 → AI < 10ms 不可能
    if np.std(intervals) < 5 and np.mean(intervals) < 20:
        return True  # 疑似 AI
    return False
```

## 触摸注入实现原理

```cpp
// 方法1: Linux Input 子系统 (需要 root)
int fd = open("/dev/input/event5", O_RDWR);
struct input_event ev[3];
// ABS 坐标
ev[0].type = EV_ABS; ev[0].code = ABS_MT_POSITION_X; ev[0].value = x;
// 同步事件
ev[1].type = EV_SYN; ev[1].code = SYN_MT_REPORT; ev[1].value = 0;
ev[2].type = EV_SYN; ev[2].code = SYN_REPORT; ev[2].value = 0;
write(fd, ev, sizeof(ev));

// 方法2: InputManager.injectInputEvent (Java, 需要 INJECT_EVENTS 权限)
InputManager im = (InputManager) getSystemService(INPUT_SERVICE);
MotionEvent event = MotionEvent.obtain(...);
im.injectInputEvent(event, InputManager.INJECT_INPUT_EVENT_MODE_ASYNC);

// 方法3: AccessibilityService.dispatchGesture (无需 root)
GestureDescription.Builder builder = new GestureDescription.Builder();
builder.addStroke(new StrokeDescription(path, 0, 1));
service.dispatchGesture(builder.build(), null, null);
```

## 攻击链

```
发现自瞄/自动点击 → dumpsys input 查看注入源
→ Frida Hook InputManager.injectInputEvent → 确认注入调用栈
→ Hook MotionEvent.obtain 获取注入坐标 → 分析模式 (平滑度/间隔)
→ 追踪注入源进程 → 确定是否有 overlay + touch 联动
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| Frida Hook InputManager/MotionEvent | `android_frida_run_script` | 运行 Frida Hook InputManager/MotionEvent |

## 证据与验证闭环

- 记录 APK/SO 的 SHA256、包名、版本、ABI、设备/Android/Frida 版本及原始样本路径。
- 静态结论必须绑定类名、方法签名、RVA/文件偏移、字符串或 Xref；动态结论绑定 hook 点、参数、返回值和时间戳。
- 在未修改样本与实验副本上分别复现，保存 Frida 日志、dump 哈希和重放脚本到 `exports/android/`。
- Patch/重打包必须记录原始字节、修改字节、签名方式和安装启动结果，不能以“构建成功”代替行为验证。
