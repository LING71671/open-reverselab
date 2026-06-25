# Kernel Driver 注入：proc 节点读写

## 场景

应用使用了 Linux 内核驱动（`.ko`）通过 `/proc` 文件系统节点实现跨进程内存读写。这是 Android 平台最高权限的读写方式，能绕过 SELinux/seccomp 限制。

## 输入信号

- `lsmod` 或 `/proc/modules` 中出现未知模块名
- `/proc/` 下出现非标准节点名（如 `/proc/wanbai`, `/proc/CheckMe`）
- dmesg 中有 "Driver initialized" 或 "Byxxx" 签名
- 应用执行了 `insmod` 命令

## 驱动注入全流程

### 1. 自解压 Shell 注入脚本

```bash
# 核心技巧: shell script 尾部嵌入 .ko 二进制
#!/system/bin/sh
# ... 环境检查、root 检查 ...
# 关键: 从脚本自身提取 .ko
sed "1,/^#BY x Kitten x 离/d" "$0" > /data/tmpf
chmod u+x /data/tmpf
insmod /data/tmpf
if [ $? -eq 0 ]; then
    echo "驱动加载成功"
    rm /data/tmpf
    dmesg -C  # 清空内核日志防止检测
else
    echo "驱动加载失败, 5秒后重启"
    sleep 5; reboot
fi
exit 0
#BY x Kitten x 离
# ↓ 此处开始是 .ko 二进制数据, shell 不会执行 ↓
<ELF HEADER><.ko binary data>
```

### 2. 驱动 proc 节点创建

```c
// 内核模块核心: 创建 /proc 节点供用户态读写
static struct proc_dir_entry *proc_entry;

static ssize_t proc_read(struct file *file, char __user *buf,
                         size_t len, loff_t *offset) {
    // 接收用户态传来的 COPY_MEMORY 结构
    // → walk page tables → read physical memory → copy_to_user
    return len;
}

static ssize_t proc_write(struct file *file, const char __user *buf,
                          size_t len, loff_t *offset) {
    // 接收用户态传来的 COPY_MEMORY 结构
    // → walk page tables → write physical memory
    return len;
}

static struct file_operations proc_fops = {
    .owner = THIS_MODULE,
    .read  = proc_read,
    .write = proc_write,
};

static int __init driver_init(void) {
    proc_entry = proc_create("driver_name", 0666, NULL, &proc_fops);
    printk("/proc/driver_name created\n");
    return 0;
}
```

### 3. 用户态通过 /proc 节点调用

```c
// 用户态: 打开 proc 节点, 写入 read/write 请求
int fd = open("/proc/driver_name", O_RDWR);
struct copy_memory cm;
cm.pid = target_pid;
cm.addr = 0x7A12345678;
cm.buffer = output_buf;
cm.size = 8;
write(fd, &cm, sizeof(cm));   // 发送读请求
read(fd, &cm, sizeof(cm));    // 读取结果
// output_buf 现在包含目标进程地址 0x7A12345678 处的 8 字节
close(fd);
```

## 驱动隐藏技术

```c
// 1. 不注册到 sysfs (避免在 /sys/module 中可见)
// module_init 中不调用 module_param

// 2. 随机化 proc 节点名
// 使用随机字符串作为节点名: /proc/a7f3b2c1

// 3. 使用合法驱动名伪装
// 命名为 /proc/sched_debug 或 /proc/version 类似名

// 4. 定时清理 dmesg
system("dmesg -c > /dev/null");
```

## 多内核版本适配

```bash
# 实战中预备 21+ 个不同内核版本的 .ko
# 运行时检测 uname -r, 选择匹配的驱动
kernel=$(uname -r | cut -d. -f1,2)
case "$kernel" in
    4.9.*)  ko_file=driver_4.9.ko  ;;
    4.14.*) ko_file=driver_4.14.ko ;;
    4.19.*) ko_file=driver_4.19.ko ;;
    5.4.*)  ko_file=driver_5.4.ko  ;;
    5.10.*) ko_file=driver_5.10.ko ;;
    5.15.*) ko_file=driver_5.15.ko ;;
    6.1.*)  ko_file=driver_6.1.ko  ;;
    6.6.*)  ko_file=driver_6.6.ko  ;;
    *) exit 1 ;;
esac
insmod $ko_file
# 同一个源码, 不同内核版本分别编译 → 生成 21 个 .ko
```

## 攻击链

```
root 权限确认 → uname -r 检测内核版本 → 匹配对应 .ko → insmod 加载
→ /proc 节点创建 → 用户态 open 节点 → write 读请求 → read 取结果
→ 卸载前 dmesg -c 清日志 → rmmod 卸载
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| 确保 ADB 连接 | `android_adb_connect` | 确保 ADB 连接 |
| 确认设备 root 状态 | `android_device_info` | 确认设备 root 状态 |
| 推送 .ko 文件到设备 | `android_push_file` | 推送 .ko 文件到设备 |

## 证据与验证闭环

- 记录 APK/SO 的 SHA256、包名、版本、ABI、设备/Android/Frida 版本及原始样本路径。
- 静态结论必须绑定类名、方法签名、RVA/文件偏移、字符串或 Xref；动态结论绑定 hook 点、参数、返回值和时间戳。
- 在未修改样本与实验副本上分别复现，保存 Frida 日志、dump 哈希和重放脚本到 `exports/android/`。
- Patch/重打包必须记录原始字节、修改字节、签名方式和安装启动结果，不能以“构建成功”代替行为验证。
