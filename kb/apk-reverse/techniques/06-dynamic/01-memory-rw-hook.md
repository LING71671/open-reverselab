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
