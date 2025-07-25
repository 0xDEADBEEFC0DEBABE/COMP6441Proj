#include "hooks.h"
#include <ntstrsafe.h>

// Function pointer types for original functions
typedef NTSTATUS(NTAPI* pfnNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(NTAPI* pfnNtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* pfnNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* pfnNtQueryVirtualMemory)(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* pfnNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pfnNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* pfnNtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS(NTAPI* pfnNtTerminateProcess)(HANDLE, NTSTATUS);
typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pfnNtSetInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* pfnNtOpenThread)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(NTAPI* pfnNtTerminateThread)(HANDLE, NTSTATUS);
typedef NTSTATUS(NTAPI* pfnNtSuspendThread)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* pfnNtResumeThread)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* pfnNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* pfnNtOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
typedef NTSTATUS(NTAPI* pfnNtReadFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS(NTAPI* pfnNtWriteFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS(NTAPI* pfnNtDeviceIoControlFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* pfnNtLoadDriver)(PUNICODE_STRING);
typedef NTSTATUS(NTAPI* pfnNtUnloadDriver)(PUNICODE_STRING);

// 通用安全检查函数
BOOLEAN IsOriginalFunctionValid(PVOID OriginalFunction)
{
    if (!OriginalFunction)
        return FALSE;
        
    ULONG_PTR addr = (ULONG_PTR)OriginalFunction;
    
    // 检查是否在内核地址空间范围内
    if (addr < 0xFFFFF80000000000ULL)
        return FALSE;
        
    // 检查内存是否有效（安全检查）
    __try
    {
        if (!MmIsAddressValid(OriginalFunction))
            return FALSE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
    
    return TRUE;
}

// Get process name from EPROCESS structure directly
PUCHAR GetProcessImageFileNameSafe(PEPROCESS Process)
{
    if (!Process)
        return NULL;
        
    // Try different offsets for different Windows versions
    ULONG offsets[] = { 0x5A8, 0x450, 0x438, 0x46C }; // Win10, Win8, Win7, etc.
    
    for (ULONG i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++)
    {
        __try 
        {
            PUCHAR processName = (PUCHAR)((ULONG_PTR)Process + offsets[i]);
            
            // Validate the string - check if it looks like a valid process name
            if (processName[0] >= 'A' && processName[0] <= 'z')
            {
                BOOLEAN validName = TRUE;
                for (ULONG j = 0; j < 15 && processName[j]; j++)
                {
                    if (processName[j] < 0x20 || processName[j] > 0x7E)
                    {
                        if (processName[j] != 0) // Null terminator is OK
                        {
                            validName = FALSE;
                            break;
                        }
                    }
                }
                
                if (validName)
                    return processName;
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            continue; // Try next offset
        }
    }
    
    return NULL;
}

// Helper function to get process name - IRQL safe version
VOID GetProcessName(HANDLE ProcessHandle, PCHAR Buffer, SIZE_T BufferSize)
{
    // Initialize buffer
    RtlStringCchCopyA(Buffer, BufferSize, "<unknown>");
    
    // Only do complex operations at low IRQL
    if (KeGetCurrentIrql() > APC_LEVEL)
    {
        RtlStringCchCopyA(Buffer, BufferSize, "<high_irql>");
        return;
    }
    
    PEPROCESS Process;
    NTSTATUS status = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, KernelMode, (PVOID*)&Process, NULL);
    if (NT_SUCCESS(status))
    {
        // Get process name from EPROCESS structure directly (safer)
        PUCHAR processName = GetProcessImageFileNameSafe(Process);
        if (processName)
        {
            // Validate the string before copying
            BOOLEAN validString = TRUE;
            for (ULONG i = 0; i < 15 && processName[i]; i++)
            {
                if (processName[i] < 0x20 || processName[i] > 0x7E)
                {
                    validString = FALSE;
                    break;
                }
            }
            
            if (validString)
            {
                RtlStringCchCopyA(Buffer, BufferSize, (PCSTR)processName);
            }
            else
            {
                RtlStringCchCopyA(Buffer, BufferSize, "<invalid>");
            }
        }
        ObDereferenceObject(Process);
    }
}

// 0xbekoo-style hook with self-cleanup mechanism
NTSTATUS NTAPI HookedNtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId)
{
    LogToDbgView("HookedNtOpenProcess: 0xbekoo-style hook called\n");
    
    __try
    {
        // 0xbekoo方法：这是简化版本，完整实现会包含stub回溯逻辑
        
        // 记录EAC活动
        if (IsEACProcess(PsGetCurrentProcess()))
        {
            LogToDbgView("NtOpenProcess: EAC attempting to open process (PID: %lu) with access 0x%08X\n",
                ClientId ? HandleToULong(ClientId->UniqueProcess) : 0,
                DesiredAccess);
        }
        
        // 0xbekoo方法：设置PreviousMode为KernelMode绕过安全检查
        BOOLEAN previousStatus = ChangePreviousMode(0);  // 0 = KernelMode
        if (!previousStatus)
        {
            LogToDbgView("HookedNtOpenProcess: Failed to set PreviousMode to KernelMode\n");
        }
        
        // 安全检查：确保原始函数指针有效
        if (!IsOriginalFunctionValid(g_OriginalNtOpenProcess))
        {
            LogToDbgView("HookedNtOpenProcess: Invalid original function pointer\n");
            return STATUS_ACCESS_DENIED;
        }
        
        // 调用原始函数
        NTSTATUS status = ((pfnNtOpenProcess)g_OriginalNtOpenProcess)(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
        
        if (IsEACProcess(PsGetCurrentProcess()) && NT_SUCCESS(status) && ProcessHandle && *ProcessHandle)
        {
            CHAR targetProcessName[256] = { 0 };
            GetProcessName(*ProcessHandle, targetProcessName, sizeof(targetProcessName));
            LogToDbgView("NtOpenProcess: EAC successfully opened process %s - Status: 0x%08X\n",
                targetProcessName, status);
        }
        
        // 注意：在0xbekoo的完整实现中，这里会：
        // 1. 恢复原始SSDT条目
        // 2. 释放stub内存
        // 3. 但我们保持hook活跃以持续监控EAC行为
        
        return status;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("HookedNtOpenProcess: Exception in 0xbekoo-style hook: 0x%08X\n", GetExceptionCode());
        
        // 如果hook函数出错，尝试调用原始函数
        if (IsOriginalFunctionValid(g_OriginalNtOpenProcess))
        {
            return ((pfnNtOpenProcess)g_OriginalNtOpenProcess)(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
        }
        
        return STATUS_ACCESS_DENIED;
    }
}

NTSTATUS NTAPI HookedNtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesRead)
{
    // 安全检查：确保原始函数指针有效
    if (!IsOriginalFunctionValid(g_OriginalNtReadVirtualMemory))
    {
        LogToDbgView("HookedNtReadVirtualMemory: Invalid original function pointer, returning ACCESS_DENIED\n");
        return STATUS_ACCESS_DENIED;
    }
    
    if (IsEACProcess(PsGetCurrentProcess()))
    {
        CHAR targetProcessName[256] = { 0 };
        GetProcessName(ProcessHandle, targetProcessName, sizeof(targetProcessName));
        
        LogToDbgView("NtReadVirtualMemory: EAC reading %zu bytes from %s at address %p\n",
            BufferSize, targetProcessName, BaseAddress);
    }
    
    return ((pfnNtReadVirtualMemory)g_OriginalNtReadVirtualMemory)(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
}

NTSTATUS NTAPI HookedNtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten)
{
    if (IsEACProcess(PsGetCurrentProcess()))
    {
        CHAR targetProcessName[256] = { 0 };
        GetProcessName(ProcessHandle, targetProcessName, sizeof(targetProcessName));
        
        LogToDbgView("NtWriteVirtualMemory: EAC writing %zu bytes to %s at address %p\n",
            BufferSize, targetProcessName, BaseAddress);
    }
    
    return ((pfnNtWriteVirtualMemory)g_OriginalNtWriteVirtualMemory)(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
}

NTSTATUS NTAPI HookedNtQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength)
{
    if (IsEACProcess(PsGetCurrentProcess()))
    {
        CHAR targetProcessName[256] = { 0 };
        GetProcessName(ProcessHandle, targetProcessName, sizeof(targetProcessName));
        
        LogToDbgView("NtQueryVirtualMemory: EAC querying memory info (class %d) for %s at address %p\n",
            MemoryInformationClass, targetProcessName, BaseAddress);
    }
    
    return ((pfnNtQueryVirtualMemory)g_OriginalNtQueryVirtualMemory)(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
}

NTSTATUS NTAPI HookedNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtection,
    PULONG OldProtection)
{
    if (IsEACProcess(PsGetCurrentProcess()))
    {
        CHAR targetProcessName[256] = { 0 };
        GetProcessName(ProcessHandle, targetProcessName, sizeof(targetProcessName));
        
        LogToDbgView("NtProtectVirtualMemory: EAC changing protection for %s at address %p, size %zu, new protection 0x%08X\n",
            targetProcessName, BaseAddress ? *BaseAddress : NULL, RegionSize ? *RegionSize : 0, NewProtection);
    }
    
    return ((pfnNtProtectVirtualMemory)g_OriginalNtProtectVirtualMemory)(ProcessHandle, BaseAddress, RegionSize, NewProtection, OldProtection);
}

NTSTATUS NTAPI HookedNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    if (IsEACProcess(PsGetCurrentProcess()))
    {
        CHAR targetProcessName[256] = { 0 };
        GetProcessName(ProcessHandle, targetProcessName, sizeof(targetProcessName));
        
        LogToDbgView("NtAllocateVirtualMemory: EAC allocating memory in %s, size %zu, type 0x%08X, protection 0x%08X\n",
            targetProcessName, RegionSize ? *RegionSize : 0, AllocationType, Protect);
    }
    
    return ((pfnNtAllocateVirtualMemory)g_OriginalNtAllocateVirtualMemory)(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS NTAPI HookedNtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType)
{
    if (IsEACProcess(PsGetCurrentProcess()))
    {
        CHAR targetProcessName[256] = { 0 };
        GetProcessName(ProcessHandle, targetProcessName, sizeof(targetProcessName));
        
        LogToDbgView("NtFreeVirtualMemory: EAC freeing memory in %s at address %p, size %zu, type 0x%08X\n",
            targetProcessName, BaseAddress ? *BaseAddress : NULL, RegionSize ? *RegionSize : 0, FreeType);
    }
    
    return ((pfnNtFreeVirtualMemory)g_OriginalNtFreeVirtualMemory)(ProcessHandle, BaseAddress, RegionSize, FreeType);
}

NTSTATUS NTAPI HookedNtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList)
{
    if (IsEACProcess(PsGetCurrentProcess()))
    {
        CHAR targetProcessName[256] = { 0 };
        GetProcessName(ProcessHandle, targetProcessName, sizeof(targetProcessName));
        
        LogToDbgView("NtCreateThreadEx: EAC creating thread in %s, start routine %p, flags 0x%08X\n",
            targetProcessName, StartRoutine, CreateFlags);
    }
    
    return ((pfnNtCreateThreadEx)g_OriginalNtCreateThreadEx)(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS NTAPI HookedNtTerminateProcess(
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus)
{
    if (IsEACProcess(PsGetCurrentProcess()))
    {
        CHAR targetProcessName[256] = { 0 };
        GetProcessName(ProcessHandle, targetProcessName, sizeof(targetProcessName));
        
        LogToDbgView("NtTerminateProcess: EAC terminating process %s with status 0x%08X\n",
            targetProcessName, ExitStatus);
    }
    
    return ((pfnNtTerminateProcess)g_OriginalNtTerminateProcess)(ProcessHandle, ExitStatus);
}

NTSTATUS NTAPI HookedNtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength)
{
    if (IsEACProcess(PsGetCurrentProcess()))
    {
        CHAR targetProcessName[256] = { 0 };
        GetProcessName(ProcessHandle, targetProcessName, sizeof(targetProcessName));
        
        LogToDbgView("NtQueryInformationProcess: EAC querying info class %d for process %s\n",
            ProcessInformationClass, targetProcessName);
    }
    
    return ((pfnNtQueryInformationProcess)g_OriginalNtQueryInformationProcess)(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

NTSTATUS NTAPI HookedNtSetInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength)
{
    if (IsEACProcess(PsGetCurrentProcess()))
    {
        CHAR targetProcessName[256] = { 0 };
        GetProcessName(ProcessHandle, targetProcessName, sizeof(targetProcessName));
        
        LogToDbgView("NtSetInformationProcess: EAC setting info class %d for process %s\n",
            ProcessInformationClass, targetProcessName);
    }
    
    return ((pfnNtSetInformationProcess)g_OriginalNtSetInformationProcess)(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
}

NTSTATUS NTAPI HookedNtOpenThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId)
{
    if (IsEACProcess(PsGetCurrentProcess()))
    {
        LogToDbgView("NtOpenThread: EAC opening thread %lu with access 0x%08X\n",
            ClientId ? HandleToULong(ClientId->UniqueThread) : 0, DesiredAccess);
    }
    
    return ((pfnNtOpenThread)g_OriginalNtOpenThread)(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS NTAPI HookedNtTerminateThread(
    HANDLE ThreadHandle,
    NTSTATUS ExitStatus)
{
    if (IsEACProcess(PsGetCurrentProcess()))
    {
        LogToDbgView("NtTerminateThread: EAC terminating thread with status 0x%08X\n", ExitStatus);
    }
    
    return ((pfnNtTerminateThread)g_OriginalNtTerminateThread)(ThreadHandle, ExitStatus);
}

NTSTATUS NTAPI HookedNtSuspendThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount)
{
    if (IsEACProcess(PsGetCurrentProcess()))
    {
        LogToDbgView("NtSuspendThread: EAC suspending thread\n");
    }
    
    return ((pfnNtSuspendThread)g_OriginalNtSuspendThread)(ThreadHandle, PreviousSuspendCount);
}

NTSTATUS NTAPI HookedNtResumeThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount)
{
    if (IsEACProcess(PsGetCurrentProcess()))
    {
        LogToDbgView("NtResumeThread: EAC resuming thread\n");
    }
    
    return ((pfnNtResumeThread)g_OriginalNtResumeThread)(ThreadHandle, PreviousSuspendCount);
}

NTSTATUS NTAPI HookedNtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength)
{
    if (IsEACProcess(PsGetCurrentProcess()))
    {
        if (ObjectAttributes && ObjectAttributes->ObjectName)
        {
            LogToDbgView("NtCreateFile: EAC creating/opening file %wZ with access 0x%08X\n",
                ObjectAttributes->ObjectName, DesiredAccess);
        }
    }
    
    return ((pfnNtCreateFile)g_OriginalNtCreateFile)(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

NTSTATUS NTAPI HookedNtOpenFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions)
{
    if (IsEACProcess(PsGetCurrentProcess()))
    {
        if (ObjectAttributes && ObjectAttributes->ObjectName)
        {
            LogToDbgView("NtOpenFile: EAC opening file %wZ with access 0x%08X\n",
                ObjectAttributes->ObjectName, DesiredAccess);
        }
    }
    
    return ((pfnNtOpenFile)g_OriginalNtOpenFile)(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

NTSTATUS NTAPI HookedNtReadFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key)
{
    if (IsEACProcess(PsGetCurrentProcess()))
    {
        LogToDbgView("NtReadFile: EAC reading %lu bytes from file\n", Length);
    }
    
    return ((pfnNtReadFile)g_OriginalNtReadFile)(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

NTSTATUS NTAPI HookedNtWriteFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key)
{
    if (IsEACProcess(PsGetCurrentProcess()))
    {
        LogToDbgView("NtWriteFile: EAC writing %lu bytes to file\n", Length);
    }
    
    return ((pfnNtWriteFile)g_OriginalNtWriteFile)(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

NTSTATUS NTAPI HookedNtDeviceIoControlFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength)
{
    if (IsEACProcess(PsGetCurrentProcess()))
    {
        LogToDbgView("NtDeviceIoControlFile: EAC calling IOCTL 0x%08X, input size %lu, output size %lu\n",
            IoControlCode, InputBufferLength, OutputBufferLength);
    }
    
    return ((pfnNtDeviceIoControlFile)g_OriginalNtDeviceIoControlFile)(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
}

NTSTATUS NTAPI HookedNtLoadDriver(
    PUNICODE_STRING DriverServiceName)
{
    if (IsEACProcess(PsGetCurrentProcess()))
    {
        LogToDbgView("NtLoadDriver: EAC loading driver %wZ\n", DriverServiceName);
    }
    
    return ((pfnNtLoadDriver)g_OriginalNtLoadDriver)(DriverServiceName);
}

NTSTATUS NTAPI HookedNtUnloadDriver(
    PUNICODE_STRING DriverServiceName)
{
    if (IsEACProcess(PsGetCurrentProcess()))
    {
        LogToDbgView("NtUnloadDriver: EAC unloading driver %wZ\n", DriverServiceName);
    }
    
    return ((pfnNtUnloadDriver)g_OriginalNtUnloadDriver)(DriverServiceName);
}

// Initialize all hooks
NTSTATUS InitializeHooks()
{
    NTSTATUS status;
    ULONG successCount = 0;
    ULONG failureCount = 0;
    
    LogToDbgView("========== Hook Installation ==========\n");
    
    // Hook process-related functions
    LogToDbgView("Installing process-related hooks...\n");
    
    status = HookSyscall(SYSCALL_NTOPENPROCESS, (PVOID)HookedNtOpenProcess, &g_OriginalNtOpenProcess);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtOpenProcess hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtOpenProcess hook FAILED: 0x%08X\n", status);
    }
    
    status = HookSyscall(SYSCALL_NTREADVIRTUALMEMORY, (PVOID)HookedNtReadVirtualMemory, &g_OriginalNtReadVirtualMemory);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtReadVirtualMemory hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtReadVirtualMemory hook FAILED: 0x%08X\n", status);
    }
    
    status = HookSyscall(SYSCALL_NTWRITEVIRTUALMEMORY, (PVOID)HookedNtWriteVirtualMemory, &g_OriginalNtWriteVirtualMemory);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtWriteVirtualMemory hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtWriteVirtualMemory hook FAILED: 0x%08X\n", status);
    }
    
    status = HookSyscall(SYSCALL_NTQUERYVIRTUALMEMORY, (PVOID)HookedNtQueryVirtualMemory, &g_OriginalNtQueryVirtualMemory);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtQueryVirtualMemory hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtQueryVirtualMemory hook FAILED: 0x%08X\n", status);
    }
    
    status = HookSyscall(SYSCALL_NTPROTECTVIRTUALMEMORY, (PVOID)HookedNtProtectVirtualMemory, &g_OriginalNtProtectVirtualMemory);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtProtectVirtualMemory hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtProtectVirtualMemory hook FAILED: 0x%08X\n", status);
    }
    
    status = HookSyscall(SYSCALL_NTALLOCATEVIRTUALMEMORY, (PVOID)HookedNtAllocateVirtualMemory, &g_OriginalNtAllocateVirtualMemory);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtAllocateVirtualMemory hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtAllocateVirtualMemory hook FAILED: 0x%08X\n", status);
    }
    
    status = HookSyscall(SYSCALL_NTFREEVIRTUALMEMORY, (PVOID)HookedNtFreeVirtualMemory, &g_OriginalNtFreeVirtualMemory);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtFreeVirtualMemory hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtFreeVirtualMemory hook FAILED: 0x%08X\n", status);
    }
    
    status = HookSyscall(SYSCALL_NTCREATETHREADEX, (PVOID)HookedNtCreateThreadEx, &g_OriginalNtCreateThreadEx);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtCreateThreadEx hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtCreateThreadEx hook FAILED: 0x%08X\n", status);
    }
    
    status = HookSyscall(SYSCALL_NTTERMINATEPROCESS, (PVOID)HookedNtTerminateProcess, &g_OriginalNtTerminateProcess);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtTerminateProcess hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtTerminateProcess hook FAILED: 0x%08X\n", status);
    }
    
    status = HookSyscall(SYSCALL_NTQUERYINFORMATIONPROCESS, (PVOID)HookedNtQueryInformationProcess, &g_OriginalNtQueryInformationProcess);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtQueryInformationProcess hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtQueryInformationProcess hook FAILED: 0x%08X\n", status);
    }
    
    status = HookSyscall(SYSCALL_NTSETINFORMATIONPROCESS, (PVOID)HookedNtSetInformationProcess, &g_OriginalNtSetInformationProcess);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtSetInformationProcess hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtSetInformationProcess hook FAILED: 0x%08X\n", status);
    }
    
    // Hook thread-related functions
    LogToDbgView("Installing thread-related hooks...\n");
    
    status = HookSyscall(SYSCALL_NTOPENTHREAD, (PVOID)HookedNtOpenThread, &g_OriginalNtOpenThread);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtOpenThread hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtOpenThread hook FAILED: 0x%08X\n", status);
    }
    
    status = HookSyscall(SYSCALL_NTTERMINATETHREAD, (PVOID)HookedNtTerminateThread, &g_OriginalNtTerminateThread);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtTerminateThread hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtTerminateThread hook FAILED: 0x%08X\n", status);
    }
    
    status = HookSyscall(SYSCALL_NTSUSPENDTHREAD, (PVOID)HookedNtSuspendThread, &g_OriginalNtSuspendThread);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtSuspendThread hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtSuspendThread hook FAILED: 0x%08X\n", status);
    }
    
    status = HookSyscall(SYSCALL_NTRESUMETHREAD, (PVOID)HookedNtResumeThread, &g_OriginalNtResumeThread);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtResumeThread hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtResumeThread hook FAILED: 0x%08X\n", status);
    }
    
    // Hook file-related functions
    LogToDbgView("Installing file-related hooks...\n");
    
    status = HookSyscall(SYSCALL_NTCREATEFILE, (PVOID)HookedNtCreateFile, &g_OriginalNtCreateFile);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtCreateFile hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtCreateFile hook FAILED: 0x%08X\n", status);
    }
    
    status = HookSyscall(SYSCALL_NTOPENFILE, (PVOID)HookedNtOpenFile, &g_OriginalNtOpenFile);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtOpenFile hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtOpenFile hook FAILED: 0x%08X\n", status);
    }
    
    status = HookSyscall(SYSCALL_NTREADFILE, (PVOID)HookedNtReadFile, &g_OriginalNtReadFile);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtReadFile hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtReadFile hook FAILED: 0x%08X\n", status);
    }
    
    status = HookSyscall(SYSCALL_NTWRITEFILE, (PVOID)HookedNtWriteFile, &g_OriginalNtWriteFile);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtWriteFile hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtWriteFile hook FAILED: 0x%08X\n", status);
    }
    
    status = HookSyscall(SYSCALL_NTDEVICEIOCONTROLFILE, (PVOID)HookedNtDeviceIoControlFile, &g_OriginalNtDeviceIoControlFile);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtDeviceIoControlFile hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtDeviceIoControlFile hook FAILED: 0x%08X\n", status);
    }
    
    // Hook driver-related functions
    LogToDbgView("Installing driver-related hooks...\n");
    
    status = HookSyscall(SYSCALL_NTLOADDRIVER, (PVOID)HookedNtLoadDriver, &g_OriginalNtLoadDriver);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtLoadDriver hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtLoadDriver hook FAILED: 0x%08X\n", status);
    }
    
    status = HookSyscall(SYSCALL_NTUNLOADDRIVER, (PVOID)HookedNtUnloadDriver, &g_OriginalNtUnloadDriver);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtUnloadDriver hook installed successfully\n");
    } else {
        failureCount++;
        LogToDbgView("  ✗ NtUnloadDriver hook FAILED: 0x%08X\n", status);
    }
    
    LogToDbgView("========== Hook Installation Summary ==========\n");
    LogToDbgView("Successful hooks: %lu\n", successCount);
    LogToDbgView("Failed hooks: %lu\n", failureCount);
    LogToDbgView("Total hooks attempted: %lu\n", successCount + failureCount);
    
    if (successCount > 0) {
        LogToDbgView("Driver will monitor EAC activity with %lu active hooks\n", successCount);
        return STATUS_SUCCESS;
    } else {
        LogToDbgView("CRITICAL: No hooks were installed successfully!\n");
        return STATUS_UNSUCCESSFUL;
    }
}

// Uninitialize all hooks
NTSTATUS UninitializeHooks()
{
    return UninitializeInfinityHook();
}