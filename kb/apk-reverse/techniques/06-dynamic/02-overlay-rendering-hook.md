# Overlay 渲染与 ImGui 检测

## 场景

APK 内存在悬浮窗/覆盖层（Overlay），用于显示调试信息或作弊 UI。需检测其存在、分析渲染管线、判断是哪种图形 API（OpenGL ES / Vulkan）。

## 输入信号

- 应用运行时出现未知悬浮窗或覆盖层
- `dumpsys window windows` 显示额外的 `TYPE_APPLICATION_OVERLAY` 窗口
- 性能异常（持续高帧率刷新）
- 屏幕上有非应用 UI 元素

## Overlay 创建全链路

### 1. 窗口创建: ANativeWindow

```cpp
// Android Native Overlay 标准创建路径
#include <android/native_window.h>

// 核心: 通过 native_surface 创建独立窗口
ANativeWindow *window = ANativeWindowCreator::Create(
    "overlay_name",        // 窗口标题 (检测线索)
    screen_width,
    screen_height,
    permeate_record         // 触摸穿透配置
);

// 窗口属性设置
ANativeWindow_setBuffersGeometry(window, width, height, format);
// format: AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM (常见)
```

### 2. 图形 API 选择

```cpp
// 自动检测可用渲染后端
enum { OPENGL_ES = 1, VULKAN = 2 };

GraphicsInterface *getGraphicsInterface(int mode) {
    if (mode == VULKAN && hasVulkan()) {
        return new VulkanGraphics();
    }
    return new OpenGLESGraphics();  // 回退
}

// Vulkan: 需要 VkInstance → VkSurfaceKHR → VkSwapchainKHR
// OpenGLES: EGLDisplay → EGLSurface → EGLContext
```

### 3. ImGui 注入循环

```cpp
// 每帧渲染循环
while (running) {
    drawBegin();             // 清屏 + 开始新帧
    graphics->NewFrame();    // API 层: vkBeginCommandBuffer / eglMakeCurrent
    ImGui::NewFrame();       // ImGui 逻辑帧

    Layout_tick_UI(&running); // 业务: 绘制菜单/数据显示

    ImGui::EndFrame();
    ImGui::Render();          // 生成顶点/索引缓冲
    graphics->EndFrame();     // vkQueueSubmit / eglSwapBuffers
}
```

## Frida 渲染管线分析

```javascript
// OpenGLES: hook eglSwapBuffers 确认帧刷新
var eglSwap = Module.findExportByName("libEGL.so", "eglSwapBuffers")
var count = 0
Interceptor.attach(eglSwap, {
    onEnter: function(args) { count++ }
})

// Vulkan: hook vkQueuePresentKHR
var vkPresent = Module.findExportByName("libvulkan.so", "vkQueuePresentKHR")
Interceptor.attach(vkPresent, {
    onEnter: function(args) {
        // dump VkQueue, VkPresentInfoKHR
    }
})
```

## 游戏内 Overlay 逆向流程

```bash
# 分析 overlay 渲染管线
adb shell dumpsys window windows | grep -A5 "Window{#"   # 定位窗口
adb shell dumpsys SurfaceFlinger                         # 列 Layer
```

## 攻击链

```
观察到悬浮窗 → Frida hook ANativeWindow 创建 → trace 渲染 API
→ 确定图形后端 (Vulkan/GLES) → hook 对应端 swap/present
→ 定位 ImGui 帧循环 → 分析 UI 逻辑 → 提取显示数据/绘制参数
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| Frida Hook ANativeWindow/eglSwapBuffers | `android_frida_run_script` | 运行 Frida Hook ANativeWindow/eglSwapBuffers |
| 抓取截图验证 overlay 效果 | `android_capture_screenshot` | 抓取截图验证 overlay 效果 |

## 证据与验证闭环

- 记录 APK/SO 的 SHA256、包名、版本、ABI、设备/Android/Frida 版本及原始样本路径。
- 静态结论必须绑定类名、方法签名、RVA/文件偏移、字符串或 Xref；动态结论绑定 hook 点、参数、返回值和时间戳。
- 在未修改样本与实验副本上分别复现，保存 Frida 日志、dump 哈希和重放脚本到 `exports/android/`。
- Patch/重打包必须记录原始字节、修改字节、签名方式和安装启动结果，不能以“构建成功”代替行为验证。
