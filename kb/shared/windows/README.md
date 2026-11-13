# Windows 逆向技术库

Windows PE/二进制逆向技术库。

## 入口

- [完整技术索引](techniques/README.md)
- Board：`boards/windows/README.md`
- 模板：`templates/notes/windows-pe-analysis.md`

## 分析链

```text
样本哈希/类型/保护 → 静态分析 → 动态验证 → 脱壳/配置恢复 → IOC → YARA/Sigma → Patch
```

## 目录

### 本地代码执行

- [`techniques/notepadpp-config-injection.md`](../../red/windows/techniques/notepadpp-config-injection.md) — Notepad++ config.xml 命令注入（CVE-2026-48778）
