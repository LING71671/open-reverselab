# 指针链遍历模式

## 场景

游戏/应用使用多级对象引用（Manager→Container→Entity→Field），需要从根指针逐步解引用到达目标数据。这种串联指针链在 Unity、Unreal 游戏中极为常见。

## 输入信号

- 已获取进程 PID 和模块基址
- 静态分析发现多级 `obj+offset` 访问模式
- 已知某层偏移值但缺少下游链路

## 两种内存读取路径

### 用户态 syscall（通用但受限）

```c
// process_vm_readv: Linux 标准跨进程读
ssize_t pvm_read(pid_t pid, uintptr_t addr, void *buf, size_t len) {
    struct iovec local[1] = {{buf, len}};
    struct iovec remote[1] = {{(void*)addr, len}};
    return syscall(__NR_process_vm_readv, pid, local, 1, remote, 1, 0);
}
// 注意: syscall 号因架构而异
// arm64: __NR_process_vm_readv = 270
// x86_64: __NR_process_vm_readv = 310
```

### 内核驱动（深度访问，绕过保护）

```c
// 通过 socket + ioctl 与内核模块通信
// 内核模块注册设备，实现 copy_from_user → ptrace 或直接页表读写
class c_driver {
    int fd; // socket 句柄 → ioctl 中继到内核
    enum { OP_READ_MEM=601, OP_WRITE_MEM=602, OP_MODULE_BASE=603 };

    bool read(uintptr_t addr, void *buf, size_t sz) {
        COPY_MEMORY cm = {pid, addr, buf, sz};
        return ioctl(fd, OP_READ_MEM, &cm) == 0;
    }
};
// 优势: 绕过 seccomp、SELinux 限制、anti-debug 检测
```

## 指针链递归封装

```c
// getZZ: 实战中的 64-bit 指针解引用宏
// 等效于 *(uintptr_t*)(*(uintptr_t*)(...))
uintptr_t getZZ(uintptr_t addr) {
    uintptr_t val;
    driver->read(addr, &val, sizeof(val));
    return val;
}

// 五级链式调用: 读取嵌套对象
long obj = getZZ(getZZ(getZZ(getZZ(base + 0x4BCB0) + 0xB0) + 0x50) + 0xA0);

// 数组遍历: 固定步长迭代
for (int i = 0; i < count; i++) {
    long entity = getZZ(arrayHead + (i * 0x20));  // 每个元素占 0x20
    int hp    = getDword(entity + 0x36C);           // 血量 4 字节
    int level = getDword(entity + 0x370);           // 等级
    char name[256];
    long namePtr = getZZ(getZZ(entity + 0x268) + 0x28) + 0x14;
    getUTF8(namePtr, name);                         // 读取 UTF-8 字符串
}
```

## 常见偏移规律

| 游戏引擎 | 对象基类偏移特征 | 常见步长 |
|----------|----------------|---------|
| Unity IL2CPP | 静态区指针 → Manager → List → Item | 0x8/0x10/0x20 |
| UE4 | AActor→RootComponent→RelativeLocation | 0x8 |
| Cocos2d | CCObject→m_pComponent→m_sPosition | 0x4 |

## 实战技巧

1. **偏移在 ±0x4 误差内**：对齐调整，int 在 4 字节边界，long 在 8 字节边界
2. **区分数组步长和结构体偏移**：数组用 `i*sizeof(entry)`，字段用固定偏移
3. **指针过空保护**：每次 getZZ 后判断 `if (!ptr) continue;`
4. **特征码替代硬偏移**：lib 版本更新时，用 Ghidra 重新确认特征

## 攻击链

```
确定进程 PID → 获取模块基址 → 找到根指针偏移
→ 逐级 getZZ 遍历 → 确认数组基址/步长
→ 遍历读取目标字段 → 数据落盘/渲染
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| Frida 获取模块基址遍历指针链 | `android_frida_run_script` | 运行 Frida 脚本获取模块基址、遍历指针链 |
| 查找偏移相关函数 | `ghidra_summary_functions` | 查找偏移相关函数 |

## 证据与验证闭环

- 记录 APK/SO 的 SHA256、包名、版本、ABI、设备/Android/Frida 版本及原始样本路径。
- 静态结论必须绑定类名、方法签名、RVA/文件偏移、字符串或 Xref；动态结论绑定 hook 点、参数、返回值和时间戳。
- 在未修改样本与实验副本上分别复现，保存 Frida 日志、dump 哈希和重放脚本到 `exports/android/`。
- Patch/重打包必须记录原始字节、修改字节、签名方式和安装启动结果，不能以“构建成功”代替行为验证。
