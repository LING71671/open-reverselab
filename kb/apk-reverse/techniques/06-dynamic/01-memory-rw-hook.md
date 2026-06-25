# 进程内存读写检测与 Hook

## 场景

目标应用使用了跨进程内存读取（process_vm_readv / ioctl driver），需要检测并 Hook 这些调用，或者在被调试进程侧监控自己的内存被谁读取。

## 输入信号

- `strace -f` 追踪到大量 `process_vm_readv` 调用
- `/proc/pid/maps` 被频繁打开读取
- 内核模块 `ioctl` 未知命令 (cmd ≥ 0x600)
- 有未知进程/线程读写你的游戏数据

## 三种内存读写路径

### 路径 1: syscall process_vm_readv/writev

```bash
# 检测工具: strace
strace -e trace=process_vm_readv,process_vm_writev -p $PID
# 输出: process_vm_readv(12345, [...], 1, [...], 1, 0) = 8
# 说明: 进程从 PID=12345 读取了 8 字节
```

```javascript
// Frida 拦截 syscall
var readv_addr = Module.findExportByName(null, "process_vm_readv")
Interceptor.attach(readv_addr, {
    onEnter: function(args) {
        var target_pid = args[0].toInt32()
        var remote = Memory.readPointer(args[3])  // remote iovec
        var addr = Memory.readPointer(remote)
        var len = Memory.readPointer(remote.add(Process.pointerSize))
        console.log(`[readv] pid=${target_pid} addr=${addr} len=${len}`)
    }
})
```

### 路径 2: /proc/pid/mem

```bash
# 检测: 谁在读 /proc/*/mem?
lsof | grep "/proc/.*/mem"
# 或 inotify:
inotifywait -m /proc/$PID/mem
```

```c
// strace 可见模式
openat(AT_FDCWD, "/proc/12345/mem", O_RDONLY) = 3
lseek(3, 0x7A12345678, SEEK_SET) = 0x7A12345678   // 可疑: 直接 seek 到大地址
read(3, buf, 8) = 8
close(3)
```

### 路径 3: ioctl 内核驱动 (最难检测)

```c
// 特征: socket + ioctl 组合, ioctl cmd 是自定义魔数
int fd = socket(AF_INET, SOCK_DGRAM, 0);
ioctl(fd, 601, &copy_mem_struct);  // 自定义 cmd=601
```

## 攻击链

```
捕获进程 → strace 追踪 → 确认读写路径类型 → Frida Hook 关键 API
→ 如果是 readv: dump 读取的地址和内容 → 逆推数据结构
→ 如果是 ioctl: 分析内核模块 → 提取驱动通信协议 → 复现读写逻辑
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| Frida Hook process_vm_readv/writev | `android_frida_run_script` | 运行 Frida Hook process_vm_readv/writev |
| 渲染 memory hook 模板 | `android_frida_render_template` | 渲染 memory hook 模板 |

## 证据与验证闭环

- 记录 APK/SO 的 SHA256、包名、版本、ABI、设备/Android/Frida 版本及原始样本路径。
- 静态结论必须绑定类名、方法签名、RVA/文件偏移、字符串或 Xref；动态结论绑定 hook 点、参数、返回值和时间戳。
- 在未修改样本与实验副本上分别复现，保存 Frida 日志、dump 哈希和重放脚本到 `exports/android/`。
- Patch/重打包必须记录原始字节、修改字节、签名方式和安装启动结果，不能以“构建成功”代替行为验证。
