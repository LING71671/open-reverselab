# 透视/ESP 渲染技术

## 场景

在竞技 FPS/TPS 游戏中获得视觉优势——透过障碍物看到敌人位置、血量、武器信息。核心在于劫持渲染管线，在绘制循环中注入自定义绘制逻辑或修改深度测试/着色器参数。

## 输入信号

- 游戏使用 DX11/DX12/OpenGL/Vulkan 渲染
- 反作弊扫描 Present hook、检测 overlay 窗口、校验 shader hash
- 需要在不被 BattlEye/EAC/FaceIt 检测的前提下实现 ESP

## D3D11 Hook — Present 劫持

### 稳定的 Present Hook

```cpp
#include <d3d11.h>
#include <dxgi.h>

typedef HRESULT(__stdcall* Present_t)(IDXGISwapChain*, UINT, UINT);
Present_t OriginalPresent = nullptr;

// 找到 Present 的虚函数表索引
// IDXGISwapChain vtable (DXGI 1.1-1.6):
// [0] QueryInterface
// [1] AddRef
// [2] Release
// [3] SetPrivateData
// [4] SetPrivateDataInterface
// [5] GetPrivateData
// [6] GetParent
// [7] GetDevice
// [8] Present       ← 需要 hook 的
// [9] GetBuffer
// [10] SetFullscreenState
// [11] GetFullscreenState
// [12] GetDesc
// [13] ResizeBuffers
// [14] ResizeTarget

HRESULT __stdcall HookedPresent(IDXGISwapChain* swapChain,
    UINT syncInterval, UINT flags) {
    
    // 首次调用时初始化渲染资源
    static bool initialized = false;
    if (!initialized) {
        initialized = InitRenderResources(swapChain);
    }
    
    // 在 Present 前执行 ESP 绘制
    if (g_esp_enabled) {
        RenderESP(swapChain);
    }
    
    return OriginalPresent(swapChain, syncInterval, flags);
}

bool InitRenderResources(IDXGISwapChain* swapChain) {
    ID3D11Device* device = nullptr;
    ID3D11DeviceContext* context = nullptr;
    
    HRESULT hr = swapChain->GetDevice(__uuidof(ID3D11Device),
        (void**)&device);
    if (FAILED(hr)) return false;
    
    device->GetImmediateContext(&context);
    
    // 创建字体、画笔、着色器等
    // ...
    return true;
}
```

### Present Hook 安装 (VMT 替换)

```cpp
// VMT 劫持: 复制原始虚函数表 → 替换 Present 条目
void InstallPresentHook() {
    // 创建 dummy DXGI swapchain 获取 vtable
    IDXGISwapChain* swapChain = CreateDummySwapChain();
    
    // 读取 vtable
    void** vtable = *(void***)swapChain;
    OriginalPresent = (Present_t)vtable[8];
    
    // 写入新 vtable (或直接在原始 vtable 页面修改)
    DWORD oldProtect;
    VirtualProtect(&vtable[8], sizeof(void*), PAGE_READWRITE, &oldProtect);
    vtable[8] = &HookedPresent;
    VirtualProtect(&vtable[8], sizeof(void*), oldProtect, &oldProtect);
    
    // 反检测: EAC 扫描 vtable 是否在 .rdata 段
    // 直接在 .rdata 页面写 (VirtualProtect → RWX) 可以绕过简单扫描
    // 但更高级的检测: 读取 swapchain 并比较函数指针的原始偏移
}
```

### DX12 Present Hook

```cpp
// DX12 IDXGISwapChain::Present 索引同 DX11
// 但 DX12 需要额外注意命令队列同步

HRESULT __stdcall HookedPresentDX12(IDXGISwapChain3* swapChain,
    UINT syncInterval, UINT flags) {
    
    // DX12: 需要等待 GPU 完成前一帧
    // 否则在绘制时可能出现命令列表冲突
    
    // 获取命令队列
    ID3D12Device* device = nullptr;
    swapChain->GetDevice(IID_PPV_ARGS(&device));
    
    // 执行 ESP 绘制 (需要自己的 command list)
    if (g_esp_enabled) {
        RenderESPDX12(device, swapChain);
    }
    
    return OriginalPresentDX12(swapChain, syncInterval, flags);
}
```

## World-to-Screen 矩阵

### 视投影矩阵定位

```cpp
// W2S 核心: 将 3D 世界坐标投影到 2D 屏幕坐标
// screen_xy = world_xyz * view_matrix * projection_matrix * viewport_matrix

struct Matrix4x4 {
    float m[16];  // row-major
    
    Vector3 Transform(const Vector3& v) const {
        float w = v.x * m[12] + v.y * m[13] + v.z * m[14] + m[15];
        if (w < 0.001f) return Vector3(0, 0, 0);
        
        float inv_w = 1.0f / w;
        float x = (v.x * m[0] + v.y * m[1] + v.z * m[2] + m[3]) * inv_w;
        float y = (v.x * m[4] + v.y * m[5] + v.z * m[6] + m[7]) * inv_w;
        
        // 屏幕坐标: [-1,1] → [0, screen]
        float screen_x = (1.0f + x) * screen_width * 0.5f;
        float screen_y = (1.0f - y) * screen_height * 0.5f;
        
        return Vector3(screen_x, screen_y, w);  // w 用于距离判断
    }
};

// Pattern scan 查找 view-projection 矩阵
// 常见特征: Unreal Engine 4/5
// "ViewProjectionMatrix" 在渲染器中通常是全局变量
// IDA/Ghidra pattern:
// F3 0F 11 ?? ?? ?? ?? ?? F3 0F 11 ?? ?? ?? ?? ?? F3 0F 11 ?? ?? ?? ?? ??
// 对应: movss [r64+off], xmm0 (连续 4 次 → 4x4 矩阵的一行)

// Unity (IL2CPP): 从 Camera.worldToCameraMatrix / projectionMatrix 读取
// 用 Frida 定位:
// var camera = Camera.get_main();
// var vp = camera.projectionMatrix * camera.worldToCameraMatrix;
```

### W2S 函数 Hook

```cpp
// 一些 FPS 游戏使用特定 W2S 函数:
// WorldToScreen(Matrix*, Vector3*, Vector2*, bool*)
// 直接 hook 该函数可获取所有可见/不可见对象的屏幕坐标

// 特征: WorldToScreen 通常紧邻:
// - 检查 z-buffer 的可视性测试
// - 距离裁剪计算
// - 屏幕边界裁剪

// Hook 后:
bool __fastcall HookedWorldToScreen(void* this_ptr, Matrix4x4* vp,
    Vector3* world, Vector2* screen, bool* on_screen) {
    
    bool result = OriginalWorldToScreen(this_ptr, vp, world, screen, on_screen);
    
    if (result && *on_screen) {
        // 记录所有投影位置到 ESP 缓存
        g_esp_cache.push_back({*world, *screen});
    }
    
    return result;
}
```

## DrawIndexed Object Filtering

```cpp
// 高级 ESP: Hook DrawIndexed → 按顶点/常量缓冲区过滤 → 修改 shader

typedef void(__stdcall* DrawIndexed_t)(ID3D11DeviceContext*,
    UINT, UINT, INT);
DrawIndexed_t OriginalDrawIndexed = nullptr;

void __stdcall HookedDrawIndexed(ID3D11DeviceContext* context,
    UINT indexCount, UINT startIndex, INT baseVertex) {
    
    // 获取当前输入装配状态
    ID3D11Buffer* vertexBuffer = nullptr;
    UINT stride = 0, offset = 0;
    context->IAGetVertexBuffers(0, 1, &vertexBuffer, &stride, &offset);
    
    // 分析 stride 识别对象类型
    // FPS 游戏常见 stride 值:
    // 32 字节: 简单顶点 (pos + normal + uv)
    // 48 字节: 骨骼动画顶点
    // 56 字节: 带切线顶点
    
    if (g_chams_enabled && IsPlayerModel(stride, indexCount)) {
        // 替换着色器为 Chams 着色器
        context->VSSetShader(g_chamsVertexShader, nullptr, 0);
        context->PSSetShader(g_chamsPixelShader, nullptr, 0);
        
        // 禁用深度测试 (使敌人穿墙可见)
        context->OMSetDepthStencilState(g_depthDisabledState, 0);
        
        OriginalDrawIndexed(context, indexCount, startIndex, baseVertex);
        
        // 恢复原始着色器
        context->VSSetShader(g_originalVS, nullptr, 0);
        context->PSSetShader(g_originalPS, nullptr, 0);
        context->OMSetDepthStencilState(g_originalDepthState, 0);
    } else {
        OriginalDrawIndexed(context, indexCount, startIndex, baseVertex);
    }
}
```

## Chams / Glow 实现

### 修改深度缓冲区

```cpp
// Chams: 使玩家模型在墙后显示不同颜色
// 技术: 绘制两次 — 第一次禁用深度写入使 z-fail → 显示颜色
//        第二次正常绘制

// 深度测试状态:
D3D11_DEPTH_STENCIL_DESC depthDisabledDesc = {};
depthDisabledDesc.DepthEnable = TRUE;
depthDisabledDesc.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ZERO;  // 不写入深度
depthDisabledDesc.DepthFunc = D3D11_COMPARISON_LESS;
depthDisabledDesc.StencilEnable = FALSE;

ID3D11DepthStencilState* g_depthNoWriteState = nullptr;
device->CreateDepthStencilState(&depthDisabledDesc, &g_depthNoWriteState);

// 完全禁用深度测试 (穿透效果):
depthDisabledDesc.DepthEnable = FALSE;
device->CreateDepthStencilState(&depthDisabledDesc, &g_depthNoWriteAllState);
```

### 修改 Shader 常量

```cpp
// Glow/Highlights: 修改特定对象的像素着色器常量
// 通过 Hook PSSetConstantBuffers 或 UpdateSubresource

void OverridePlayerColor(ID3D11DeviceContext* context) {
    // 玩家高亮颜色 (RGBA)
    float glowColor[4] = { 1.0f, 0.0f, 0.0f, 0.5f };  // 半透明红色
    
    // 查找并替换常量缓冲区中的颜色
    ID3D11Buffer* constantBuffers[D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT];
    context->PSGetConstantBuffers(0, 4, constantBuffers);
    
    for (int i = 0; i < 4; ++i) {
        if (constantBuffers[i]) {
            D3D11_BUFFER_DESC desc;
            constantBuffers[i]->GetDesc(&desc);
            
            // 读取当前常量, 尝试替换颜色相关偏移
            uint8_t* mappedData = MapBuffer(constantBuffers[i]);
            // 在 mappedData 中扫描类似的 float 模式...
            // (需要结合静态逆向确定颜色偏移)
        }
    }
}
```

## External Overlay 渲染

```cpp
// 外部覆盖窗口 (不注入游戏进程, 检测面小)

HWND CreateTransparentOverlay(int width, int height) {
    WNDCLASSEX wc = {};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = OverlayWndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = L"OverlayWindow";
    RegisterClassEx(&wc);
    
    HWND overlay = CreateWindowEx(
        WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED |
        WS_EX_TOOLWINDOW,  // 不在任务栏显示
        L"OverlayWindow",
        L"",
        WS_POPUP,
        0, 0, width, height,
        NULL, NULL, wc.hInstance, NULL
    );
    
    // 设置透明色
    SetLayeredWindowAttributes(overlay, RGB(0, 0, 0), 0, LWA_COLORKEY);
    
    // 启用鼠标穿透: SetWindowLong + WS_EX_TRANSPARENT
    // 也可以使用 SetLayeredWindowAttributes with LWA_ALPHA 做半透明
    
    return overlay;
}

// 在覆盖窗口上绘制 ESP:
void RenderOnOverlay(HWND overlay, const ESPData& data) {
    HDC hdc = GetDC(overlay);
    
    // 使用 GDI 或 Direct2D 绘制
    // 设置画笔颜色 (敌人红色, 队友蓝色)
    HPEN redPen = CreatePen(PS_SOLID, 2, RGB(255, 0, 0));
    SelectObject(hdc, redPen);
    
    for (const auto& entity : data.entities) {
        if (entity.is_visible) {
            // 绘制方框
            Rectangle(hdc,
                entity.box_left, entity.box_top,
                entity.box_right, entity.box_bottom
            );
            // 绘制文字
            TextOutA(hdc, entity.label_x, entity.label_y,
                entity.label.c_str(), entity.label.length());
        }
    }
    
    ReleaseDC(overlay, hdc);
}

// 更新覆盖窗口位置追踪游戏窗口:
void UpdateOverlayPosition(HWND overlay, HWND gameWindow) {
    RECT rect;
    GetClientRect(gameWindow, &rect);
    
    POINT upperLeft = { rect.left, rect.top };
    ClientToScreen(gameWindow, &upperLeft);
    
    SetWindowPos(overlay, HWND_TOPMOST,
        upperLeft.x, upperLeft.y,
        rect.right - rect.left,
        rect.bottom - rect.top,
        SWP_SHOWWINDOW);
}
```

## ImGui 集成模式

```cpp
// DX11 + ImGui ESP 绘制

// 在 Present hook 内:
HRESULT __stdcall HookedPresent(IDXGISwapChain* swapChain, ...) {
    if (!g_imgui_initialized) {
        ImGui::CreateContext();
        ImGui_ImplDX11_Init(device, context);
        g_imgui_initialized = true;
    }
    
    // 每帧更新
    ImGui_ImplDX11_NewFrame();
    ImGui::NewFrame();
    
    if (g_menu_open) {
        ImGui::Begin("ESP Menu");
        ImGui::Checkbox("Enable ESP", &g_esp_enabled);
        ImGui::ColorEdit3("Enemy Color", g_enemy_color);
        ImGui::SliderFloat("Distance", &g_max_distance, 100, 1000);
        ImGui::Checkbox("Box ESP", &g_box_esp);
        ImGui::Checkbox("Line ESP", &g_line_esp);
        ImGui::Checkbox("Health Bar", &g_health_bar);
        ImGui::End();
    }
    
    // ESP 绘制
    if (g_esp_enabled) {
        for (const auto& player : g_player_cache) {
            Vector2 screen = player.w2s_position;
            
            if (g_box_esp) {
                float box_h = player.height / player.distance * 500;
                float box_w = box_h * 0.6f;
                ImGui::GetBackgroundDrawList()->AddRect(
                    ImVec2(screen.x - box_w/2, screen.y - box_h),
                    ImVec2(screen.x + box_w/2, screen.y),
                    player.is_enemy ?
                        IM_COL32(255, 0, 0, 255) : IM_COL32(0, 255, 0, 255),
                    0.0f, 0, 2.0f
                );
            }
            
            if (g_health_bar) {
                // 绘制血量条
            }
            
            if (g_line_esp) {
                // 屏幕中线到玩家的线
            }
        }
    }
    
    ImGui::Render();
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    
    return OriginalPresent(swapChain, syncInterval, flags);
}
```

## 反作弊检测向量与绕过

```
1. VMT Hook 检测
   EAC/BE 扫描 IDXGISwapChain vtable 是否在可写页面
   绕过: 使用硬件断点或 PageGuard (在 .rdata 页直接写)

2. Present Hook 检测
   检查 Present 函数头前 5 字节是否为 JMP
   绕过: 使用硬件断点的单步 hook (mov eax, target; jmp eax)

3. Overlay 窗口检测
   枚举所有 WS_EX_LAYERED 窗口 → 检查透明度+尺寸
   绕过: 使用 SetWindowsHookEx 注入到游戏进程内绘制
         或: 在游戏窗口的子窗口区域内绘制 (隐藏窗口类名)

4. Shader hash 校验
   BattlEye 定期校验所有已加载 shader 的 hash
   绕过: 在哈希校验前恢复原始 shader

5. 驱动级扫描
   EAC/BE 内核驱动扫描用户态 handle 和线程
   绕过: 使用无窗口的 DXGI output duplication API

6. 帧缓冲检测
   某些反作弊周期性截取帧缓冲进行 AI 分析
   绕过: 只在特定帧渲染 ESP, 跳过检测帧
```

## 攻击链

```
确定渲染 API (DX11/DX12/Vulkan)
→ 创建假 swapchain 获取 vtable → Hook Present
→ 通过 W2S pattern scan 定位视投影矩阵
→ 实现对象分类 (玩家/物品/地图)
→ 实现 ESP 渲染 (box/line/health/weapon)
→ 实现 Chams/Glow (深度测试修改)
→ 反检测: 绕过 VMT 扫描 + overlay 检测
→ Bypass: 硬件断点 hook / driver-less 绘制
```

## MCP 工具映射

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 搜索渲染引擎相关函数 | `ghidra_summary_call_focus` | behavior="render" 或 "graphics" |
| 特征码定位 W2S/DrawIndexed | `search_pattern` | 视投影矩阵或 DrawIndexed 特征码 |
| 函数阅读与反编译 | `ghidra_summary_function_detail` | 含完整 decompile + callees |
| 基础信息查 | `kb_router` | 搜索 DX11 hook / W2S 相关知识 |
| 汇编验证 | `rizin_assemble_bytes` | 验证 JMP/VMT 替换指令 |
| 导入表扫描 | `rizin_imports` | 确认 d3d11/dxgi/vulkan-1 导入 |

## 证据与验证闭环

- 固定输入样本、SHA256、工具版本和全部参数，先保存未处理 baseline。
- 每个假设至少绑定一个可观察量：已知明密文对、协议字段、状态转移、时间分布、偏移或重放输出。
- 用独立脚本重放核心变换，并以断言、输出哈希或逐字段 diff 验证，不以“看起来合理”作为结论。
- 原始抓包/样本进入 `exports/general/`，派生文件与原件分离并记录转换链。
