# Frida (Windows Desktop)

跨平台动态插桩框架的 Windows 桌面端工具。

## 用途

- 对 Windows 进程进行运行时 hook/插桩
- 配合 `frida-server` 对远程/Android 目标插桩
- API tracer、内存读写、加密函数拦截
- 与 x64dbg 互补的动态分析手段

## 安装

```powershell
pip install frida-tools
```

或通过 `install_tools.ps1 -Windows` 自动安装。

验证：
```powershell
frida --version
```

## 相关目录

- Frida 脚本 → `scripts/windows/frida/`
- Android 端 frida-server → 通过 MCP `android_frida_ensure_server` 部署
- Android Frida 脚本 → `scripts/android/`

## 在 MCP 中使用

Windows PE 的 Frida hook 方案通过 `make_pe_crypto_unpack_plan`（参数 `include_frida=true`）自动生成。
