# 虚拟地址 → 物理地址转换

## 场景

需要绕过 Linux 进程隔离，从内核级或驱动级直接读写目标进程的物理内存。通过 `/proc/pid/pagemap` 完成虚拟地址到页帧号（PFN）的转换。

## 输入信号

- 代码中有 `/proc/%d/pagemap` 路径拼接
- `lseek` + `read` 8 字节操作
- 位运算 `& (1<<63)` 检查页面存在位
- 变量名包含 `pfn`、`page_offset`、`v_pageIndex`

## 页表遍历原理

```
虚拟地址 (64-bit)
│
├── 页内偏移 (bits 0-11, 4KB 页) → page_offset
│
└── 虚拟页号 (VPN, bits 12+) → v_pageIndex
    │
    └→ /proc/pid/pagemap[v_pageIndex * 8]
       │
       └── 64-bit 页表项
           ├── bit 63: 页面存在位 (Page Present)
           ├── bits 0-54: 物理页帧号 (PFN)
           └── bits 55-62: 软件标志
```

## 实现代码

```c
// 虚拟地址 → 对应进程的物理地址
uint64_t virt_to_phys(pid_t pid, uint64_t vaddr) {
    int page_size = getpagesize();  // 通常是 4096
    
    // 1. 计算虚拟页号和页内偏移
    uint64_t v_page_index = vaddr / page_size;
    uint64_t page_offset  = vaddr % page_size;
    
    // 2. pagemap 中的偏移: 每个页表项 8 字节
    uint64_t pfn_item_offset = v_page_index * sizeof(uint64_t);
    
    // 3. 读取 pagemap
    char pagemap_path[64];
    snprintf(pagemap_path, sizeof(pagemap_path), "/proc/%d/pagemap", pid);
    int fd = open(pagemap_path, O_RDONLY);
    if (fd < 0) return 0;
    
    // 4. lseek 到对应页表项位置
    if (lseek(fd, pfn_item_offset, SEEK_SET) < 0) {
        close(fd); return 0;
    }
    
    // 5. 读取 8 字节页表项
    uint64_t pte = 0;
    if (read(fd, &pte, sizeof(uint64_t)) != sizeof(uint64_t)) {
        close(fd); return 0;
    }
    close(fd);
    
    // 6. 检查页面是否在物理内存中 (bit 63)
    if (!(pte & (1ULL << 63))) {
        // 页面被交换出去或在页缓存中
        return 0;
    }
    
    // 7. 物理页帧号 (PFN) 在 bits 0-54
    uint64_t pfn = pte & ((1ULL << 55) - 1);
    
    // 8. 物理地址 = PFN * page_size + page_offset
    uint64_t phys_addr = (pfn * page_size) + page_offset;
    
    return phys_addr;
}
```

## 实战: 批量读取进程内存

```c
// 利用物理地址实现跨进程免 attach 读取
typedef struct {
    pid_t pid;
    uintptr_t vaddr;
    void *buffer;
    size_t size;
} mem_request_t;

bool phys_read(mem_request_t *req) {
    // 对每个页面做 VA→PA 转换
    uint64_t vaddr_start = req->vaddr;
    uint64_t vaddr_end   = req->vaddr + req->size;
    
    size_t copied = 0;
    for (uint64_t va = vaddr_start; va < vaddr_end; ) {
        uint64_t pa = virt_to_phys(req->pid, va);
        if (!pa) {
            // 页面不存在, 跳过此页
            va = ((va / PAGE_SIZE) + 1) * PAGE_SIZE;
            continue;
        }
        
        // 本页剩余字节
        size_t page_remain = PAGE_SIZE - (va % PAGE_SIZE);
        size_t to_read = min(req->size - copied, page_remain);
        
        // 通过 /dev/mem 或内核驱动直接读物理地址
        // pwrite(fd_mem, req->buffer + copied, to_read, pa);
        
        va += to_read;
        copied += to_read;
    }
    return copied == req->size;
}
```

## 检测 pagemap 是否可用

```bash
# 需要 root 或 CAP_SYS_ADMIN
# 检查: /proc/pid/pagemap 是否可读
ls -la /proc/self/pagemap
# 权限位应为 -r-------- (仅 owner 可读)

# 内核配置要求:
cat /proc/config.gz | gunzip | grep CONFIG_PROC_PAGE_MONITOR
# 需要 CONFIG_PROC_PAGE_MONITOR=y
```

## 实战要点

1. **内核版本兼容**：不同内核的 PFN 位宽不同 (48-bit vs 55-bit)，先检查 `uname -r`
2. **KPTI/KASLR**：启用后物理地址布局随机化，但 VA→PA 映射关系不变
3. **大页 (HugePage)**：2MB/1GB 大页的 pagemap 条目编码不同，需额外处理
4. **效率优化**：缓存 PFN→物理地址映射，避免重复读取 pagemap 文件

## 攻击链

```
获取目标 PID → open /proc/pid/pagemap → 目标 VA → lseek 到页表项偏移
→ read 64bit PTE → 检查 bit63 (page present) → 提取 PFN
→ PFN * PAGE_SIZE + page_offset = 物理地址 → /dev/mem 或驱动直接读写
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| Frida 脚本辅助定位 | `android_frida_run_script` | 运行 Frida 脚本辅助定位 |

## 证据与验证闭环

- 记录 APK/SO 的 SHA256、包名、版本、ABI、设备/Android/Frida 版本及原始样本路径。
- 静态结论必须绑定类名、方法签名、RVA/文件偏移、字符串或 Xref；动态结论绑定 hook 点、参数、返回值和时间戳。
- 在未修改样本与实验副本上分别复现，保存 Frida 日志、dump 哈希和重放脚本到 `exports/android/`。
- Patch/重打包必须记录原始字节、修改字节、签名方式和安装启动结果，不能以“构建成功”代替行为验证。
