# APK Reverse 逆向工程知识库 — Android 逆向 20 篇

APK/DEX/SO 逆向技术库，共 **8 类、20 篇正文**。

## 入口

- [完整技术索引](techniques/README.md)
- Board：`boards/android/README.md`
- 模板：`templates/notes/android-apk-analysis.md`

## 分析链

```text
APK 哈希/Manifest → jadx/apktool 静态分析 → Java/Native 调用链
→ Frida 动态验证 → crypto/network/dex dump → Patch/重打包 → 安装验活
```

每发现加密、混淆、壳、native 或网络信号，立即以 `board=apk-reverse` 调用 `kb_router`。
