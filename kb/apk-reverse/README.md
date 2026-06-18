# APK 逆向知识库

APK/DEX 实战逆向 Lab。每个文件 = 可复制运行的 Frida/分析代码。

## 结构

```
techniques/ (8 分类)
├── 01-dex-java/       DEX/Java 反编译与静态分析
├── 02-native/         Native (so) 库分析
├── 03-manifest/       Manifest 与组件分析
├── 04-crypto/         加密与解密
├── 05-network/        网络通信分析
├── 06-dynamic/        Frida 动态插桩
├── 07-packer/         壳与混淆
└── 08-patch-repack/   Patch 与重打包
```

## 流程

```
APK → 解包(apktool) → 静态(jadx) → 动态(Frida) → Patch → 重打包签名 → 验证
```

## 工具映射

参照 `techniques/README.md` 底部工具映射表。

## 原则

- 伪代码直接跑
- 先静态后动态
- 一次一个 hook 点
- 30 min 无果换面
- 证据落盘
