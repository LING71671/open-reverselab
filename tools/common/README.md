# Common Tools

跨平台/跨领域工具。

## 工具列表

| 工具 | 用途 | 安装说明 |
|---|---|---|
| Ghidra | NSA 开源反编译框架 | 见下方 |
| Apache Maven | Java 构建工具（Ghidra 脚本开发需要） | 见下方 |

## Ghidra

- 官网：https://ghidra-sre.org/
- 下载 `ghidra_*_PUBLIC_*.zip`
- 解压到 `tools/common/ghidra_*/`

## Apache Maven

- 官网：https://maven.apache.org/download.cgi
- 下载 `apache-maven-*-bin.zip`
- 解压到 `tools/common/apache-maven-*/`

## Python 虚拟环境

在 `tools/common/venvs/` 下为不同项目创建独立 venv：

```bash
python -m venv tools/common/venvs/android-frida
```
