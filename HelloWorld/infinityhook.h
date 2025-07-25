#pragma once
#include <ntifs.h>
#include <ntddk.h>

// InfinityHook structures and definitions
typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE
{
    PULONG_PTR ServiceTableBase;
    PULONG ServiceCounterTableBase;
    ULONG_PTR NumberOfServices;
    PUCHAR ParamTableBase;
} SYSTEM_SERVICE_DESCRIPTOR_TABLE, *PSYSTEM_SERVICE_DESCRIPTOR_TABLE;

typedef struct _HOOK_CONTEXT
{
    PVOID OriginalFunction;
    PVOID HookFunction;
    ULONG SsdtIndex;
} HOOK_CONTEXT, *PHOOK_CONTEXT;

// System call numbers (Windows 10)
#define SYSCALL_NTOPENPROCESS           0x26
#define SYSCALL_NTREADVIRTUALMEMORY     0x3F
#define SYSCALL_NTWRITEVIRTUALMEMORY    0x3A
#define SYSCALL_NTQUERYVIRTUALMEMORY    0x35
#define SYSCALL_NTPROTECTVIRTUALMEMORY  0x32
#define SYSCALL_NTALLOCATEVIRTUALMEMORY 0x18
#define SYSCALL_NTFREEVIRTUALMEMORY     0x1E
#define SYSCALL_NTCREATETHREADEX        0xC1
#define SYSCALL_NTTERMINATEPROCESS      0x2C
#define SYSCALL_NTQUERYINFORMATIONPROCESS 0x19
#define SYSCALL_NTSETINFORMATIONPROCESS 0x1C
#define SYSCALL_NTOPENTHREAD            0xFE
#define SYSCALL_NTTERMINATETHREAD       0x83
#define SYSCALL_NTSUSPENDTHREAD         0x188
#define SYSCALL_NTRESUMETHREAD          0x52
#define SYSCALL_NTCREATEFILE            0x55
#define SYSCALL_NTOPENFILE              0x33
#define SYSCALL_NTREADFILE              0x06
#define SYSCALL_NTWRITEFILE             0x08
#define SYSCALL_NTDEVICEIOCONTROLFILE   0x07
#define SYSCALL_NTLOADDRIVER            0x106
#define SYSCALL_NTUNLOADDRIVER          0x185

// Function prototypes
NTSTATUS InitializeInfinityHook();
NTSTATUS UninitializeInfinityHook();
NTSTATUS HookSyscall(ULONG SyscallNumber, PVOID HookFunction, PVOID* OriginalFunction);
NTSTATUS UnhookSyscall(ULONG SyscallNumber);
PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDT();
VOID DelayedHookInstallThread(PVOID Context);
PVOID CreateHookInNPXEPool(PVOID OriginalHookFunction, PVOID OriginalSyscall);
PVOID CreateAbsoluteJumpStub(PVOID TargetFunction);
NTSTATUS InstallSSDTHook(ULONG SyscallIndex, PVOID HookFunction);
NTSTATUS InstallAMDCompatibleSSDTHook();

// Helper functions
BOOLEAN IsEACProcess(PEPROCESS Process);
BOOLEAN IsEACThread(PETHREAD Thread);
VOID LogToDbgView(PCSTR Format, ...);

// 0xbekoo helper functions
BOOLEAN ChangePreviousMode(int Mode);
PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTViaKeAddSystemServiceTable();

// File logging functions
NTSTATUS InitializeFileLogging();
VOID UninitializeFileLogging();
NTSTATUS LogToFile(PCSTR Message);

// Original function pointers
extern PVOID g_OriginalNtOpenProcess;
extern PVOID g_OriginalNtReadVirtualMemory;
extern PVOID g_OriginalNtWriteVirtualMemory;
extern PVOID g_OriginalNtQueryVirtualMemory;
extern PVOID g_OriginalNtProtectVirtualMemory;
extern PVOID g_OriginalNtAllocateVirtualMemory;
extern PVOID g_OriginalNtFreeVirtualMemory;
extern PVOID g_OriginalNtCreateThreadEx;
extern PVOID g_OriginalNtTerminateProcess;
extern PVOID g_OriginalNtQueryInformationProcess;
extern PVOID g_OriginalNtSetInformationProcess;
extern PVOID g_OriginalNtOpenThread;
extern PVOID g_OriginalNtTerminateThread;
extern PVOID g_OriginalNtSuspendThread;
extern PVOID g_OriginalNtResumeThread;
extern PVOID g_OriginalNtCreateFile;
extern PVOID g_OriginalNtOpenFile;
extern PVOID g_OriginalNtReadFile;
extern PVOID g_OriginalNtWriteFile;
extern PVOID g_OriginalNtDeviceIoControlFile;
extern PVOID g_OriginalNtLoadDriver;
extern PVOID g_OriginalNtUnloadDriver;