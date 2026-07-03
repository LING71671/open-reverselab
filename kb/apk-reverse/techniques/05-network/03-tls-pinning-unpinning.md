---
id: "apk-reverse/05-network/03-tls-pinning-unpinning"
title: "TLS Pinning 定位与 Unpinning"
title_en: "TLS Pinning Location and Unpinning"
summary: >
  APK 网络分析中的 TLS pinning 打点卡片，覆盖 OkHttp CertificatePinner、TrustManager、SSLSocketFactory、Conscrypt、Cronet 与 native OpenSSL/BoringSSL 校验证书路径。
summary_en: >
  TLS pinning field card for APK network analysis, covering OkHttp CertificatePinner, TrustManager, SSLSocketFactory, Conscrypt, Cronet, and native OpenSSL/BoringSSL certificate verification paths.
board: "apk-reverse"
category: "05-network"
signals:
  - "SSLHandshakeException"
  - "Certificate pinning failure"
  - "okhttp3.CertificatePinner"
  - "TrustManager"
  - "X509TrustManager"
  - "CronetEngine"
  - "SSL_get_verify_result"
mcp_tools:
  - "android_http_observation_recipe"
  - "android_crypto_unpack_recipe"
  - "android_frida_run_script"
  - "kb_router"
keywords:
  - "TLS pinning"
  - "certificate pinning"
  - "unpinning"
  - "OkHttp"
  - "TrustManager"
  - "Cronet"
  - "BoringSSL"
difficulty: "intermediate"
tags:
  - "apk"
  - "network"
  - "frida"
  - "tls"
  - "pinning"
language: "zh-CN"
last_updated: "2026-07-03"
related_articles:
  - "apk-reverse/05-network/01-game-protocol-hook"
  - "apk-reverse/05-network/02-license-verification-bypass"
---
# TLS Pinning 定位与 Unpinning

## 1. 入口信号

看到这些信号时，优先把网络链路转到 pinning 路径：

```text
logcat: javax.net.ssl.SSLPeerUnverifiedException: Certificate pinning failure
logcat: Trust anchor for certification path not found
jadx: okhttp3.CertificatePinner.check
jadx: X509TrustManager.checkServerTrusted
native: SSL_get_verify_result / X509_verify_cert / SSL_set_custom_verify
抓包: 代理 CA 已安装但 App 仍拒绝连接
```

第一轮目标不是“全局绕过”，而是确定校验落在哪一层：Java OkHttp、系统 TrustManager、Cronet，还是 native TLS。

## 2. 静态定位

```powershell
jadx -d exports/android/app-jadx samples/app.apk
rg -n "CertificatePinner|checkServerTrusted|TrustManager|SSLSocketFactory|HostnameVerifier|Cronet|pin" exports/android/app-jadx
apktool d samples/app.apk -o exports/android/app-apktool
rg -n "network_security_config|usesCleartextTraffic" exports/android/app-apktool
```

Native 层继续看 SO：

```powershell
llvm-readelf -Ws exports/android/app-apktool/lib/arm64-v8a/*.so | rg "SSL_|X509_|verify|pin"
strings exports/android/app-apktool/lib/arm64-v8a/*.so | rg -i "cert|pin|sha256|ssl|boringssl|cronet"
```

## 3. Java 层打点脚本

```javascript
Java.perform(function () {
  const CertificatePinner = Java.use("okhttp3.CertificatePinner");
  CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (host, peerCerts) {
    console.log("[pin] CertificatePinner.check host=" + host + " certs=" + peerCerts.size());
    return;
  };

  const TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
  TrustManagerImpl.verifyChain.implementation = function (chain, anchors, host, clientAuth, ocsp, sct) {
    console.log("[pin] TrustManagerImpl.verifyChain host=" + host + " chain=" + chain.size());
    return chain;
  };

  const HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
  console.log("[pin] HostnameVerifier interface loaded: " + HostnameVerifier);
});
```

成功标志：代理中能看到原始请求/响应；logcat 出现 host 与证书链长度；App 不再在握手阶段退出。

## 4. Native 层打点脚本

```javascript
const symbols = [
  "SSL_get_verify_result",
  "X509_verify_cert",
  "SSL_set_custom_verify"
];

for (const name of symbols) {
  const p = Module.findExportByName(null, name);
  if (!p) continue;
  Interceptor.attach(p, {
    onEnter(args) {
      this.name = name;
      console.log("[tls] enter " + name + " @ " + p);
    },
    onLeave(ret) {
      console.log("[tls] leave " + this.name + " ret=" + ret);
      if (this.name === "SSL_get_verify_result") ret.replace(0);
      if (this.name === "X509_verify_cert") ret.replace(1);
    }
  });
}
```

如果 App 使用 Cronet，优先 hook Java builder，再看 native：

```javascript
Java.perform(function () {
  const Builder = Java.use("org.chromium.net.CronetEngine$Builder");
  Builder.enablePublicKeyPinningBypassForLocalTrustAnchors.implementation = function (v) {
    console.log("[cronet] force local trust anchor bypass");
    return this.enablePublicKeyPinningBypassForLocalTrustAnchors(true);
  };
});
```

## 5. 路径分叉

| 入口 | 打点动作 | 下一跳 |
|---|---|---|
| OkHttp `CertificatePinner` | hook `check()` 返回 | 抓 HTTP API / license verify |
| 自定义 `TrustManager` | hook `checkServerTrusted()` | 提取请求签名参数 |
| `network_security_config` | 添加代理 CA 或改 smali | 重打包复验 |
| Cronet | hook Builder / native verify | HTTP/2/gRPC 流量解析 |
| Native OpenSSL | hook `SSL_get_verify_result` | Ghidra 定位调用者 |

## 6. 攻击链 / 工作流

```text
代理失败 / SSLHandshakeException
  → jadx/strings 定位 CertificatePinner / TrustManager / Cronet / native TLS
  → Frida Java 层 unpin；若无效转 native SSL_get_verify_result/X509_verify_cert
  → 代理看到 API 请求和响应
  → 提取 sign/token/nonce 字段
  → 跳到 JNI RegisterNatives、请求签名或 license verify 路径
```

## 7. Evidence

| 项 | 记录内容 |
|---|---|
| 包与版本 | package name、versionCode、签名证书 SHA256 |
| 静态信号 | 类名、方法签名、SO 名称、字符串 |
| 动态输出 | host、证书链长度、hook 命中次数、返回值替换 |
| 网络结果 | 代理中的 URL、method、状态码、响应摘要 |
| 下一跳 | API 参数逆向、license 绕过、协议还原或重打包 |

## 8. MCP 工具映射

| 步骤 | MCP 工具 | 用途 |
|---|---|---|
| 网络观察 | `android_http_observation_recipe` | 抓取 HTTP/HTTPS 行为和代理状态 |
| Hook 生成 | `android_crypto_unpack_recipe` | 生成 Java/native Frida 模板 |
| 脚本执行 | `android_frida_run_script` | spawn/attach 运行 unpinning 脚本 |
| 知识路由 | `kb_router` | 按 pinning、OkHttp、Cronet 信号查下一篇 |
