#include "infinityhook.h"
#include "hooks.h"
#include <intrin.h>
#include <stdarg.h>
#include <ntstrsafe.h>

// 0xbekoo-style SSDT hooking implementation
// In kdmapper environment, KeServiceDescriptorTable not available, rely on dynamic discovery

// 0xbekoo风格的PreviousMode修改函数（基于汇编代码）
BOOLEAN ChangePreviousMode(int Mode)
{
    // PreviousMode: 0 = KernelMode, 1 = UserMode
    if (Mode != 0 && Mode != 1)
        return FALSE;
        
    __try
    {
        // 从GS段寄存器获取KPCR，然后获取当前线程
        // mov rdx, qword ptr gs:[188h]  ; Get current thread from KPCR
        PETHREAD currentThread = (PETHREAD)__readgsqword(0x188);
        
        if (!MmIsAddressValid(currentThread))
            return FALSE;
            
        // 0xbekoo's offset: PreviousMode at offset 0x232 in ETHREAD
        // mov byte ptr [rdx+232h], cl
        PUCHAR threadPtr = (PUCHAR)currentThread;
        UCHAR* previousMode = (UCHAR*)(threadPtr + 0x232);
        
        // 验证地址有效性
        if (!MmIsAddressValid(previousMode))
            return FALSE;
            
        *previousMode = (UCHAR)Mode;
        
        LogToDbgView("ChangePreviousMode: Set PreviousMode to %s\n", 
            Mode == 0 ? "KernelMode" : "UserMode");
        
        return TRUE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {  
        LogToDbgView("ChangePreviousMode: Exception: 0x%08X\n", GetExceptionCode());
        return FALSE;
    }
}

// Structure definitions for module enumeration
#pragma warning(push)
#pragma warning(disable: 4201) // nonstandard extension used: nameless struct/union
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
#pragma warning(pop)

// External kernel variables
extern "C" NTKERNELAPI PLIST_ENTRY PsLoadedModuleList;
extern "C" NTKERNELAPI PUCHAR PsGetProcessImageFileName(PEPROCESS Process);

// Global variables  
PVOID g_OriginalNtOpenProcess = NULL;
PVOID g_OriginalNtReadVirtualMemory = NULL;
PVOID g_OriginalNtWriteVirtualMemory = NULL;
PVOID g_OriginalNtQueryVirtualMemory = NULL;
PVOID g_OriginalNtProtectVirtualMemory = NULL;
PVOID g_OriginalNtAllocateVirtualMemory = NULL;
PVOID g_OriginalNtFreeVirtualMemory = NULL;
PVOID g_OriginalNtCreateThreadEx = NULL;
PVOID g_OriginalNtTerminateProcess = NULL;
PVOID g_OriginalNtQueryInformationProcess = NULL;
PVOID g_OriginalNtSetInformationProcess = NULL;
PVOID g_OriginalNtOpenThread = NULL;
PVOID g_OriginalNtTerminateThread = NULL;
PVOID g_OriginalNtSuspendThread = NULL;
PVOID g_OriginalNtResumeThread = NULL;
PVOID g_OriginalNtCreateFile = NULL;
PVOID g_OriginalNtOpenFile = NULL;
PVOID g_OriginalNtReadFile = NULL;
PVOID g_OriginalNtWriteFile = NULL;
PVOID g_OriginalNtDeviceIoControlFile = NULL;
PVOID g_OriginalNtLoadDriver = NULL;
PVOID g_OriginalNtUnloadDriver = NULL;

PSYSTEM_SERVICE_DESCRIPTOR_TABLE g_SSDT = NULL;
BOOLEAN g_HooksInitialized = FALSE;
BOOLEAN g_SSDTHooksEnabled = TRUE;
BOOLEAN g_SSDTValidated = FALSE;

// Cache validation results
BOOLEAN g_SyscallValidation[700] = { FALSE };

// Track executable pool allocations for cleanup
#define MAX_HOOK_POOLS 32
PVOID g_HookPools[MAX_HOOK_POOLS] = { NULL };
ULONG g_HookPoolCount = 0;

// Track code caves used for hooks
#define MAX_CODE_CAVES 32
PVOID g_CodeCaves[MAX_CODE_CAVES] = { NULL };
ULONG g_CodeCaveCount = 0;

// File logging variables
HANDLE g_LogFileHandle = NULL;
PFILE_OBJECT g_LogFileObject = NULL;
BOOLEAN g_FileLoggingEnabled = TRUE;
WCHAR g_LogFileName[260] = { 0 };

// Queue for deferred file logging
#define MAX_LOG_QUEUE_SIZE 1000
typedef struct _LOG_ENTRY {
    CHAR Message[512];
    BOOLEAN InUse;
} LOG_ENTRY, *PLOG_ENTRY;

LOG_ENTRY g_LogQueue[MAX_LOG_QUEUE_SIZE] = { 0 };
volatile LONG g_LogQueueHead = 0;
volatile LONG g_LogQueueTail = 0;
KSPIN_LOCK g_LogQueueLock;
BOOLEAN g_LogQueueInitialized = FALSE;

// Work item for deferred log flushing
WORK_QUEUE_ITEM g_LogWorkItem;
volatile BOOLEAN g_LogWorkItemQueued = FALSE;

// Forward declarations
PVOID FindCodeCaveNearKernel(SIZE_T requiredSize);
KIRQL DisableWriteProtection();
VOID EnableWriteProtection(KIRQL irql);
VOID LogFlushDpcCallback(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
VOID FlushLogQueueWorkItem(PVOID Context);

// Logging function implementations
VOID LogToDbgView(PCSTR Format, ...)
{
    CHAR buffer[512];
    va_list args;
    
    va_start(args, Format);
    
    if (NT_SUCCESS(RtlStringCchVPrintfA(buffer, sizeof(buffer), Format, args)))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[EAC-MONITOR] %s", buffer);
        
        // Always try file logging if enabled
        if (g_FileLoggingEnabled && g_LogFileHandle)
        {
            __try
            {
                LARGE_INTEGER systemTime, localTime;
                TIME_FIELDS timeFields;
                
                KeQuerySystemTime(&systemTime);
                ExSystemTimeToLocalTime(&systemTime, &localTime);
                RtlTimeToTimeFields(&localTime, &timeFields);
                
                CHAR timestampedBuffer[600];
                RtlStringCchPrintfA(timestampedBuffer, sizeof(timestampedBuffer), 
                    "[%02d:%02d:%02d] %s",
                    timeFields.Hour, timeFields.Minute, timeFields.Second,
                    buffer);
                
                LogToFile(timestampedBuffer);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                // If file logging fails, just continue with DbgPrint
            }
        }
    }
    
    va_end(args);
}

NTSTATUS InitializeFileLogging()
{
    g_FileLoggingEnabled = TRUE;
    
    KeInitializeSpinLock(&g_LogQueueLock);
    g_LogQueueHead = 0;
    g_LogQueueTail = 0;
    g_LogWorkItemQueued = FALSE;
    RtlZeroMemory(g_LogQueue, sizeof(g_LogQueue));
    g_LogQueueInitialized = TRUE;
        
    LARGE_INTEGER systemTime;
    TIME_FIELDS timeFields;
    KeQuerySystemTime(&systemTime);
    RtlTimeToTimeFields(&systemTime, &timeFields);
    
    RtlStringCchPrintfW(g_LogFileName, sizeof(g_LogFileName) / sizeof(WCHAR),
        L"\\??\\C:\\eac_monitor_%02d%02d%02d.log",
        timeFields.Hour, timeFields.Minute, timeFields.Second);
    
    UNICODE_STRING fileName;
    RtlInitUnicodeString(&fileName, g_LogFileName);
    
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &fileName, 
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status = ZwCreateFile(&g_LogFileHandle,
        GENERIC_WRITE | SYNCHRONIZE | FILE_APPEND_DATA,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0);
    
    if (NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[EAC-MONITOR] File logging initialized: %wZ\n", &fileName);
        
        CHAR initMsg[] = "EAC Monitor Driver Started\r\n";
        IO_STATUS_BLOCK writeStatus;
        ZwWriteFile(g_LogFileHandle, NULL, NULL, NULL, &writeStatus,
            initMsg, sizeof(initMsg) - 1, NULL, NULL);
    }
    else
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[EAC-MONITOR] Failed to initialize file logging: 0x%08X\n", status);
        g_FileLoggingEnabled = FALSE;
    }
    
    return status;
}

// DPC callback to schedule work item
VOID LogFlushDpcCallback(
    PKDPC Dpc,
    PVOID DeferredContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    
    // Use work item instead of creating thread at DISPATCH_LEVEL
    if (!g_LogWorkItemQueued)
    {
        g_LogWorkItemQueued = TRUE;
        ExInitializeWorkItem(&g_LogWorkItem, FlushLogQueueWorkItem, NULL);
        ExQueueWorkItem(&g_LogWorkItem, DelayedWorkQueue);
    }
}

// Work item callback to flush log queue at PASSIVE_LEVEL
VOID FlushLogQueueWorkItem(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    
    // Debug output to track work item execution
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
               "[EAC-MONITOR] WorkItem executing, queue head=%d, tail=%d\n", 
               g_LogQueueHead, g_LogQueueTail);
    
    if (!g_LogFileHandle || !g_LogQueueInitialized)
    {
        g_LogWorkItemQueued = FALSE;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
                   "[EAC-MONITOR] WorkItem exit: file handle or queue not ready\n");
        return;
    }
    
    // Process up to 50 queued log entries per work item execution
    INT processedCount = 0;
    while (g_LogQueueHead != g_LogQueueTail && processedCount < 50)
    {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_LogQueueLock, &oldIrql);
        
        LONG currentTail = g_LogQueueTail;
        if (currentTail != g_LogQueueHead && g_LogQueue[currentTail].InUse)
        {
            // Copy message to local buffer
            CHAR localBuffer[512];
            RtlCopyMemory(localBuffer, g_LogQueue[currentTail].Message, sizeof(localBuffer));
            
            // Mark entry as free
            g_LogQueue[currentTail].InUse = FALSE;
            g_LogQueueTail = (currentTail + 1) % MAX_LOG_QUEUE_SIZE;
            
            KeReleaseSpinLock(&g_LogQueueLock, oldIrql);
            
            // Write to file at PASSIVE_LEVEL
            __try
            {
                IO_STATUS_BLOCK ioStatus;
                SIZE_T messageLen = strlen(localBuffer);
                
                if (messageLen > 0)
                {
                    NTSTATUS writeStatus = ZwWriteFile(g_LogFileHandle, NULL, NULL, NULL, &ioStatus,
                                                      localBuffer, (ULONG)messageLen, NULL, NULL);
                    
                    if (!NT_SUCCESS(writeStatus))
                    {
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
                                   "[EAC-MONITOR] File write failed: 0x%08X\n", writeStatus);
                    }
                    
                    // Add newline
                    CHAR newline[] = "\r\n";
                    ZwWriteFile(g_LogFileHandle, NULL, NULL, NULL, &ioStatus,
                               newline, sizeof(newline) - 1, NULL, NULL);
                    
                    // Force flush to disk
                    ZwFlushBuffersFile(g_LogFileHandle, &ioStatus);
                }
                
                processedCount++;
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
                           "[EAC-MONITOR] Exception in file write: 0x%08X\n", GetExceptionCode());
                processedCount++;
            }
        }
        else
        {
            KeReleaseSpinLock(&g_LogQueueLock, oldIrql);
            break;
        }
    }
    
    // Always reset work item flag first
    g_LogWorkItemQueued = FALSE;
    
    // If there are still messages, schedule another work item
    if (g_LogQueueHead != g_LogQueueTail)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
                   "[EAC-MONITOR] Rescheduling work item, processed=%d\n", processedCount);
        
        if (InterlockedCompareExchange((LONG*)&g_LogWorkItemQueued, TRUE, FALSE) == FALSE)
        {
            ExInitializeWorkItem(&g_LogWorkItem, FlushLogQueueWorkItem, NULL);
            ExQueueWorkItem(&g_LogWorkItem, DelayedWorkQueue);
        }
    }
    else
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
                   "[EAC-MONITOR] WorkItem finished, processed=%d messages\n", processedCount);
    }
}

// Log to file (queue-based for any IRQL)
NTSTATUS LogToFile(PCSTR Message)
{
    if (!g_FileLoggingEnabled || !g_LogFileHandle || !Message || !g_LogQueueInitialized)
        return STATUS_SUCCESS;
        
    // Quick IRQL check - if we're at PASSIVE_LEVEL, write directly
    if (KeGetCurrentIrql() == PASSIVE_LEVEL)
    {
        __try
        {
            IO_STATUS_BLOCK ioStatus;
            SIZE_T messageLen = strlen(Message);
            
            if (messageLen > 0)
            {
                ZwWriteFile(g_LogFileHandle, NULL, NULL, NULL, &ioStatus,
                           (PVOID)Message, (ULONG)messageLen, NULL, NULL);
                
                // Add newline
                CHAR newline[] = "\r\n";
                ZwWriteFile(g_LogFileHandle, NULL, NULL, NULL, &ioStatus,
                           newline, sizeof(newline) - 1, NULL, NULL);
            }
            return STATUS_SUCCESS;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            // Fall through to queued approach
        }
    }
    
    // For higher IRQL, use queue
    __try
    {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_LogQueueLock, &oldIrql);
        
        // Find next free slot
        LONG nextHead = (g_LogQueueHead + 1) % MAX_LOG_QUEUE_SIZE;
        if (nextHead != g_LogQueueTail) // Queue not full
        {
            // Add to queue with minimal operations in spinlock
            SIZE_T messageLen = strlen(Message);
            SIZE_T copyLen = min(messageLen, sizeof(g_LogQueue[g_LogQueueHead].Message) - 1);
            
            RtlCopyMemory(g_LogQueue[g_LogQueueHead].Message, Message, copyLen);
            g_LogQueue[g_LogQueueHead].Message[copyLen] = '\0';
            g_LogQueue[g_LogQueueHead].InUse = TRUE;
            g_LogQueueHead = nextHead;
            
            BOOLEAN shouldSchedule = !g_LogWorkItemQueued;
            
            KeReleaseSpinLock(&g_LogQueueLock, oldIrql);
            
            // Schedule work item if needed (outside spinlock)
            if (shouldSchedule)
            {
                if (InterlockedCompareExchange((LONG*)&g_LogWorkItemQueued, TRUE, FALSE) == FALSE)
                {
                    ExInitializeWorkItem(&g_LogWorkItem, FlushLogQueueWorkItem, NULL);
                    ExQueueWorkItem(&g_LogWorkItem, DelayedWorkQueue);
                }
            }
        }
        else
        {
            KeReleaseSpinLock(&g_LogQueueLock, oldIrql);
            // Queue full, drop message
        }
        
        return STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return GetExceptionCode();
    }
}

// Uninitialize file logging
VOID UninitializeFileLogging()
{
    if (g_LogFileHandle)
    {
        ZwClose(g_LogFileHandle);
        g_LogFileHandle = NULL;
    }
    
    if (g_LogFileObject)
    {
        ObDereferenceObject(g_LogFileObject);
        g_LogFileObject = NULL;
    }
    
    g_FileLoggingEnabled = FALSE;
}

// Check if process is EAC
BOOLEAN IsEACProcess(PEPROCESS Process)
{
    // Simple implementation - check process name
    PUCHAR processName = PsGetProcessImageFileName(Process);
    if (processName)
    {
        if (_stricmp((const char*)processName, "EasyAntiCheat.exe") == 0 ||
            _stricmp((const char*)processName, "EasyAntiCheat_EOS.exe") == 0)
        {
            return TRUE;
        }
    }
    return FALSE;
}

// Find code cave in kernel modules
PVOID FindCodeCaveNearKernel(SIZE_T requiredSize)
{
    PLIST_ENTRY moduleList = PsLoadedModuleList;
    if (!moduleList || !MmIsAddressValid(moduleList))
        return NULL;
        
    PLIST_ENTRY currentEntry = moduleList->Flink;
    ULONG moduleCount = 0;
    
    // Get SSDT base for distance calculation
    ULONG_PTR ssdtBase = g_SSDT ? (ULONG_PTR)g_SSDT->ServiceTableBase : 0;
    if (!ssdtBase)
        return NULL;
    
    while (currentEntry != moduleList && moduleCount < 50)
    {
        __try
        {
            PLDR_DATA_TABLE_ENTRY moduleEntry = CONTAINING_RECORD(currentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            
            if (MmIsAddressValid(moduleEntry) && moduleEntry->DllBase && moduleEntry->SizeOfImage > 0x1000)
            {
                ULONG_PTR moduleBase = (ULONG_PTR)moduleEntry->DllBase;
                ULONG_PTR moduleEnd = moduleBase + moduleEntry->SizeOfImage;
                
                // Only check kernel space modules
                if (moduleBase >= 0xFFFFF80000000000ULL && moduleBase <= 0xFFFFFFFFFFF00000ULL)
                {
                    // Scan last few pages of module for code caves
                    ULONG_PTR scanStart = moduleEnd - 0x4000; // Last 16KB
                    if (scanStart < moduleBase) scanStart = moduleBase;
                    
                    for (ULONG_PTR addr = scanStart; addr < moduleEnd - requiredSize; addr++)
                    {
                        __try
                        {
                            // Check if within ±2GB of SSDT
                            LONG_PTR offset = (LONG_PTR)(addr - ssdtBase);
                            if (offset > 0x7FFFFFFF || offset < (LONG)(0x80000000U))
                                continue;
                                
                            // Check for continuous 0xCC (INT3) or 0x90 (NOP)
                            PUCHAR ptr = (PUCHAR)addr;
                            BOOLEAN isCave = TRUE;
                            
                            for (SIZE_T i = 0; i < requiredSize; i++)
                            {
                                if (ptr[i] != 0xCC && ptr[i] != 0x90 && ptr[i] != 0x00)
                                {
                                    isCave = FALSE;
                                    break;
                                }
                            }
                            
                            if (isCave)
                            {
                                // Verify writability
                                UCHAR testByte = ptr[0];
                                ptr[0] = 0x90;
                                if (ptr[0] == 0x90)
                                {
                                    ptr[0] = testByte; // Restore
                                    LogToDbgView("FindCodeCaveNearKernel: Found cave at %p in module %wZ\n", 
                                        (PVOID)addr, &moduleEntry->BaseDllName);
                                    return (PVOID)addr;
                                }
                            }
                        }
                        __except(EXCEPTION_EXECUTE_HANDLER)
                        {
                            // Continue scanning
                        }
                    }
                }
            }
            
            currentEntry = currentEntry->Flink;
            moduleCount++;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            break;
        }
    }
    
    return NULL;
}

// Disable write protection
KIRQL DisableWriteProtection()
{
    KIRQL irql = KeRaiseIrqlToDpcLevel();
    ULONG_PTR cr0 = __readcr0();
    cr0 &= ~0x10000; // Clear WP bit
    __writecr0(cr0);
    _disable();
    return irql;
}

// Enable write protection
VOID EnableWriteProtection(KIRQL irql)
{
    ULONG_PTR cr0 = __readcr0();
    cr0 |= 0x10000; // Set WP bit
    __writecr0(cr0);
    _enable();
    KeLowerIrql(irql);
}

// Get SSDT via KeAddSystemServiceTable (0xbekoo method) - Simplified
PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTViaKeAddSystemServiceTable()
{
    LogToDbgView("GetSSDTViaKeAddSystemServiceTable: Using simplified method\n");
    
    __try
    {
        // Simplified fallback: use MSR method for now
        ULONG_PTR kiSystemCall64 = __readmsr(0xC0000082);
        LogToDbgView("KiSystemCall64 found via MSR: 0x%p\n", (PVOID)kiSystemCall64);
        
        if (!MmIsAddressValid((PVOID)kiSystemCall64))
        {
            LogToDbgView("KiSystemCall64 address invalid\n");
            return NULL;
        }
        
        // Enhanced SSDT search pattern
        LogToDbgView("Searching for SSDT pattern near KiSystemCall64...\n");
        
        for (LONG offset = 0; offset < 0x1000000; offset += 8)
        {
            __try
            {
                PULONG_PTR scanAddr = (PULONG_PTR)(kiSystemCall64 + offset);
                
                if (!MmIsAddressValid(scanAddr))
                    continue;
                    
                ULONG_PTR value = *scanAddr;
                
                // Look for potential SSDT pointer in kernel space
                if ((value & 0xFFFFF00000000000ULL) == 0xFFFFF00000000000ULL)
                {
                    PSYSTEM_SERVICE_DESCRIPTOR_TABLE potentialSSDT = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)value;
                    
                    if (MmIsAddressValid(potentialSSDT) && 
                        MmIsAddressValid(potentialSSDT->ServiceTableBase) &&
                        potentialSSDT->NumberOfServices > 100 && 
                        potentialSSDT->NumberOfServices < 1000)
                    {
                        LogToDbgView("✓ Valid SSDT found at offset 0x%08X: %p\n", offset, potentialSSDT);
                        LogToDbgView("  ServiceTableBase: %p\n", potentialSSDT->ServiceTableBase);
                        LogToDbgView("  NumberOfServices: %lu\n", potentialSSDT->NumberOfServices);
                        return potentialSSDT;
                    }
                }
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                continue;
            }
        }
        
        LogToDbgView("SSDT search completed, no valid SSDT found\n");
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("GetSSDTViaKeAddSystemServiceTable: Exception: 0x%08X\n", GetExceptionCode());
    }
    
    return NULL;
}

// Initialize InfinityHook (0xbekoo method)
NTSTATUS InitializeInfinityHook()
{
    if (g_HooksInitialized)
        return STATUS_SUCCESS;
        
    LogToDbgView("Initializing InfinityHook (0xbekoo method)...\n");
    
    // Find SSDT using enhanced search method
    g_SSDT = GetSSDTViaKeAddSystemServiceTable();
    if (!g_SSDT)
    {
        LogToDbgView("Enhanced SSDT search failed\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    LogToDbgView("SSDT found at: %p\n", g_SSDT);
    LogToDbgView("ServiceTableBase: %p\n", g_SSDT->ServiceTableBase);
    LogToDbgView("NumberOfServices: %lu\n", g_SSDT->NumberOfServices);
    
    g_HooksInitialized = TRUE;
    g_SSDTValidated = TRUE;
    
    return STATUS_SUCCESS;
}

// Hook代码模板大小
#define HOOK_CODE_SIZE 0x100  // 256字节足够简单Hook逻辑

// 检查VT-x支持（为EPT Hook做准备）
BOOLEAN CheckVTxSupport()
{
    LogToDbgView("CheckVTxSupport: Checking Intel VT-x support...\n");
    
    // 检查CPUID.1:ECX[5] (VMX bit)
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    
    BOOLEAN vmxSupported = (cpuInfo[2] & (1 << 5)) != 0;
    LogToDbgView("CheckVTxSupport: VMX support: %s\n", vmxSupported ? "YES" : "NO");
    
    if (!vmxSupported)
    {
        LogToDbgView("CheckVTxSupport: ✗ VT-x not supported, EPT Hook not possible\n");
        return FALSE;
    }
    
    // 检查EPT支持
    // 这需要更复杂的MSR读取，暂时假设支持
    LogToDbgView("CheckVTxSupport: ✓ VT-x supported, EPT Hook potentially available\n");
    LogToDbgView("CheckVTxSupport: ℹ Consider implementing EPT Hook for stealthier monitoring\n");
    
    return TRUE;
}

// KDMapper-compatible SSDT Hook installer (0xbekoo style)
NTSTATUS InstallAMDCompatibleSSDTHook()
{
    LogToDbgView("InstallAMDCompatibleSSDTHook: Starting kdmapper-compatible SSDT hooks...\n");
    
    if (!g_SSDT || !g_SSDT->ServiceTableBase)
    {
        LogToDbgView("InstallAMDCompatibleSSDTHook: SSDT not available\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    LogToDbgView("InstallAMDCompatibleSSDTHook: Installing key syscall hooks...\n");
    
    NTSTATUS status;
    ULONG successCount = 0;
    
    // 1. NtOpenProcess (syscall 0x26) 
    status = HookSyscall(SYSCALL_NTOPENPROCESS, HookedNtOpenProcess, &g_OriginalNtOpenProcess);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtOpenProcess hooked\n");
    } else {
        LogToDbgView("  ✗ NtOpenProcess failed: 0x%08X\n", status);
    }
    
    // 2. NtReadVirtualMemory (syscall 0x3F)
    status = HookSyscall(SYSCALL_NTREADVIRTUALMEMORY, HookedNtReadVirtualMemory, &g_OriginalNtReadVirtualMemory);  
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtReadVirtualMemory hooked\n");
    } else {
        LogToDbgView("  ✗ NtReadVirtualMemory failed: 0x%08X\n", status);
    }
    
    // 3. NtWriteVirtualMemory (syscall 0x3A)
    status = HookSyscall(SYSCALL_NTWRITEVIRTUALMEMORY, HookedNtWriteVirtualMemory, &g_OriginalNtWriteVirtualMemory);
    if (NT_SUCCESS(status)) {
        successCount++;
        LogToDbgView("  ✓ NtWriteVirtualMemory hooked\n");
    } else {
        LogToDbgView("  ✗ NtWriteVirtualMemory failed: 0x%08X\n", status);
    }
    
    LogToDbgView("InstallAMDCompatibleSSDTHook: %lu hooks installed successfully\n", successCount);
    
    return (successCount > 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

// Hook安装线程（用于延迟安装）
VOID DelayedHookInstallThread(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    
    LogToDbgView("DelayedHookInstallThread: Thread started successfully!\n");
    
    // 安装AMD兼容的SSDT Hook
    InstallAMDCompatibleSSDTHook();
    
    LogToDbgView("DelayedHookInstallThread: Thread completed\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// 创建绝对跳转Stub（安全版本，逐步测试）
PVOID CreateAbsoluteJumpStub(PVOID TargetFunction)
{
    LogToDbgView("CreateAbsoluteJumpStub: Starting stub creation for target %p\n", TargetFunction);
    
    // 分配NPXE池用于绝对跳转stub
    PVOID stubMem = NULL;
    
    __try
    {
        LogToDbgView("CreateAbsoluteJumpStub: Attempting memory allocation...\n");
        
        #ifdef POOL_FLAG_NON_PAGED_EXECUTE
            stubMem = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, 16, 'bStM');
        #else
            #pragma warning(push)
            #pragma warning(disable: 4996)
            stubMem = ExAllocatePoolWithTag(NonPagedPoolExecute, 16, 'bStM');
            #pragma warning(pop)
        #endif
        
        if (!stubMem)
        {
            LogToDbgView("CreateAbsoluteJumpStub: Failed to allocate NPXE memory\n");
            return NULL;
        }
        
        LogToDbgView("CreateAbsoluteJumpStub: Memory allocated at %p\n", stubMem);
        
        // 测试内存写入
        LogToDbgView("CreateAbsoluteJumpStub: Testing memory write access...\n");
        PUCHAR stub = (PUCHAR)stubMem;
        
        // 先只写入第一个字节测试
        stub[0] = 0x48;  // REX.W prefix
        LogToDbgView("CreateAbsoluteJumpStub: First byte written successfully\n");
        
        // 构造完整指令
        stub[1] = 0xB8;  // MOV RAX, imm64
        *(PULONG_PTR)(stub + 2) = (ULONG_PTR)TargetFunction;  // imm64 = target address
        stub[10] = 0xFF; // JMP RAX
        stub[11] = 0xE0; // ModR/M byte for "jmp rax"
        
        LogToDbgView("CreateAbsoluteJumpStub: Instruction bytes written successfully\n");
        
        // 填充剩余字节为NOP（简化版本）
        stub[12] = 0x90; stub[13] = 0x90; stub[14] = 0x90; stub[15] = 0x90;
        
        LogToDbgView("CreateAbsoluteJumpStub: NOP padding completed\n");
        
        // 跳过KeFlushInstructionCache调用（可能是崩溃点）
        LogToDbgView("CreateAbsoluteJumpStub: Skipping instruction cache flush for safety\n");
        
        // 跟踪分配的内存
        if (g_HookPoolCount < MAX_HOOK_POOLS)
        {
            g_HookPools[g_HookPoolCount++] = stubMem;
        }
        
        LogToDbgView("CreateAbsoluteJumpStub: ✓ Stub creation completed at %p -> %p\n", stubMem, TargetFunction);
        return stubMem;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("CreateAbsoluteJumpStub: ✗ Exception during stub creation: 0x%08X\n", GetExceptionCode());
        
        if (stubMem)
        {
            __try
            {
                ExFreePoolWithTag(stubMem, 'bStM');
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        
        return NULL;
    }
}

// 安装SSDT Hook（修改SSDT表项）
NTSTATUS InstallSSDTHook(ULONG SyscallIndex, PVOID HookFunction)
{
    if (!g_SSDT || !g_SSDT->ServiceTableBase || SyscallIndex >= g_SSDT->NumberOfServices)
    {
        return STATUS_INVALID_PARAMETER;
    }
    
    __try
    {
        // 禁用写保护
        KIRQL irql = DisableWriteProtection();
        
        // 获取原始SSDT表项编码
        ULONG originalEntry = (ULONG)g_SSDT->ServiceTableBase[SyscallIndex];
        ULONG argumentCount = originalEntry & 0xF;  // 低4位是参数计数
        
        // 计算新的Hook函数相对于SSDT base的偏移
        ULONG_PTR ssdtBase = (ULONG_PTR)g_SSDT->ServiceTableBase;
        LONG_PTR offset = (LONG_PTR)((ULONG_PTR)HookFunction - ssdtBase);
        
        // 编码新的SSDT表项：(offset << 4) | argumentCount
        ULONG newEntry = ((ULONG)(offset << 4)) | argumentCount;
        
        // 修改SSDT表项
        g_SSDT->ServiceTableBase[SyscallIndex] = newEntry;
        
        // 恢复写保护
        EnableWriteProtection(irql);
        
        LogToDbgView("InstallSSDTHook: Syscall %lu: 0x%08X -> 0x%08X (offset: 0x%llX)\n", 
            SyscallIndex, originalEntry, newEntry, offset);
        
        return STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("InstallSSDTHook: Exception during hook installation: 0x%08X\n", GetExceptionCode());
        return STATUS_UNSUCCESSFUL;
    }
}

// 创建在NPXE池中运行的Hook代码（简化版本）
PVOID CreateHookInNPXEPool(PVOID OriginalHookFunction, PVOID OriginalSyscall)
{
    UNREFERENCED_PARAMETER(OriginalHookFunction);
    
    // 1. 分配非分页可执行池
    PVOID poolBase = NULL;
    #ifdef POOL_FLAG_NON_PAGED_EXECUTE
        poolBase = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, HOOK_CODE_SIZE, 'kHxM');
    #else
        #pragma warning(push)
        #pragma warning(disable: 4996)
        poolBase = ExAllocatePoolWithTag(NonPagedPoolExecute, HOOK_CODE_SIZE, 'kHxM');
        #pragma warning(pop)
    #endif
    
    if (!poolBase) {
        LogToDbgView("CreateHookInNPXEPool: Failed to allocate NPXE pool\n");
        return NULL;
    }
    
    LogToDbgView("CreateHookInNPXEPool: Allocated NPXE pool at %p\n", poolBase);
    
    // 2. 创建最简单的跳转桩：直接跳转到原始函数
    // 这样避免复杂的机器码导致的PAGE_FAULT
    PUCHAR code = (PUCHAR)poolBase;
    
    // 简单的跳转指令：movabs rax, addr; jmp rax
    code[0] = 0x48;  // REX.W
    code[1] = 0xB8;  // MOV RAX, imm64
    *(PULONG_PTR)(code + 2) = (ULONG_PTR)OriginalSyscall;
    code[10] = 0xFF; // JMP RAX
    code[11] = 0xE0;
    
    // 添加一些NOP指令填充剩余空间
    for (int i = 12; i < HOOK_CODE_SIZE; i++)
    {
        code[i] = 0x90; // NOP
    }
    
    // 3. 使用简单的内存屏障
    _ReadWriteBarrier();
    
    // 4. 跟踪分配的内存
    if (g_HookPoolCount < MAX_HOOK_POOLS)
    {
        g_HookPools[g_HookPoolCount++] = poolBase;
    }
    
    LogToDbgView("CreateHookInNPXEPool: Simple hook stub created, jumping to original at %p\n", OriginalSyscall);
    return poolBase;
}

// 0xbekoo-style SSDT Hook implementation for kdmapper
NTSTATUS HookSyscall(ULONG SyscallNumber, PVOID HookFunction, PVOID* OriginalFunction)
{
    LogToDbgView("HookSyscall: 0xbekoo-style hook for syscall %lu\n", SyscallNumber);
    
    // Try static KeServiceDescriptorTable first, fallback to dynamic discovery
    PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt = NULL;
    
    // kdmapper环境：只使用动态发现的SSDT
    ssdt = g_SSDT;
    LogToDbgView("HookSyscall: Using dynamically discovered SSDT at %p (kdmapper mode)\n", ssdt);
    
    if (!ssdt || !ssdt->ServiceTableBase || SyscallNumber >= ssdt->NumberOfServices)
    {
        LogToDbgView("HookSyscall: Invalid SSDT parameters\n");
        return STATUS_INVALID_PARAMETER;
    }
    
    __try
    {
        // 获取原始SSDT条目
        ULONG originalEntry = (ULONG)ssdt->ServiceTableBase[SyscallNumber];
        
        LogToDbgView("HookSyscall: Original SSDT[%lu] entry: 0x%08X\n", SyscallNumber, originalEntry);
        
        // 0xbekoo方法：正确的SSDT解码
        // Offset = SSDT + 4 * SSN (从SSDT条目中获取偏移)
        // RoutineAddress = SSDT + (Offset >> 4) (右移4位获取实际偏移)
        
        LogToDbgView("HookSyscall: Raw SSDT entry value: 0x%08X\n", originalEntry);
        
        // 0xbekoo的解码方法：直接右移4位获取偏移
        ULONG offset = originalEntry;  // 原始条目值
        ULONG_PTR originalAddress = (ULONG_PTR)ssdt->ServiceTableBase + (offset >> 4);
        
        // 验证解码结果
        LogToDbgView("HookSyscall: Decoding verification:\n");
        LogToDbgView("  Raw entry: 0x%08X\n", offset);
        LogToDbgView("  Shifted offset: 0x%08X\n", (offset >> 4));
        LogToDbgView("  SSDT base: %p\n", ssdt->ServiceTableBase);
        LogToDbgView("  Calculated address: %p\n", (PVOID)originalAddress);
        
        LogToDbgView("HookSyscall: 0xbekoo decode - SSDT: %p + (0x%08X >> 4) = %p\n", 
            ssdt->ServiceTableBase, offset, (PVOID)originalAddress);
        
        if (!MmIsAddressValid((PVOID)originalAddress))
        {
            LogToDbgView("HookSyscall: Invalid original function address %p\n", (PVOID)originalAddress);
            return STATUS_INVALID_ADDRESS;
        }
        
        *OriginalFunction = (PVOID)originalAddress;
        
        LogToDbgView("HookSyscall: Syscall %lu: %p -> Hook %p\n", 
            SyscallNumber, *OriginalFunction, HookFunction);
        
        // 智能内存分配策略：寻找28位范围内的内存
        PVOID stubAddress = NULL;
        ULONG stubSize = 32;
        ULONG_PTR ssdtBase = (ULONG_PTR)ssdt->ServiceTableBase;
        
        LogToDbgView("HookSyscall: SSDT base: %p, searching for memory within ±128MB range\n", (PVOID)ssdtBase);
        
        // 策略1：尝试在SSDT附近分配小块内存
        for (int attempt = 0; attempt < 50; attempt++)
        {
            ULONG allocSize = stubSize + (attempt * 16);  // 逐渐增加大小
            
#ifdef POOL_FLAG_NON_PAGED_EXECUTE
            stubAddress = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, allocSize, 'tSHk');
#else
            #pragma warning(push)
            #pragma warning(disable: 4996)
            stubAddress = ExAllocatePoolWithTag(NonPagedPoolExecute, allocSize, 'tSHk');
            #pragma warning(pop)
#endif
            
            if (!stubAddress)
                continue;
                
            ULONG_PTR stubAddr = (ULONG_PTR)stubAddress;
            LONG_PTR stubOffset = (LONG_PTR)(stubAddr - ssdtBase);
            
            LogToDbgView("HookSyscall: Attempt %d - Allocated %p, offset: 0x%llX\n", 
                attempt + 1, stubAddress, stubOffset);
            
            // 检查是否在28位有符号范围内 (-134,217,728 到 +134,217,727)
            if (stubOffset <= 0x7FFFFFF && stubOffset >= -0x8000000)
            {
                LogToDbgView("HookSyscall: ✓ Found suitable stub at %p (offset: 0x%llX)\n", 
                    stubAddress, stubOffset);
                break;
            }
            
            // 记录为什么这个地址不合适
            if (stubOffset > 0x7FFFFFF)
                LogToDbgView("HookSyscall: Address too high (0x%llX > 0x7FFFFFF)\n", stubOffset);
            else
                LogToDbgView("HookSyscall: Address too low (0x%llX < -0x8000000)\n", stubOffset);
            
            ExFreePoolWithTag(stubAddress, 'tSHk');
            stubAddress = NULL;
        }
        
        // 策略2：如果常规分配失败，尝试使用内核模块中的代码洞
        if (!stubAddress)
        {
            LogToDbgView("HookSyscall: Regular allocation failed, trying code cave method\n");
            stubAddress = FindCodeCaveNearKernel(stubSize);
            
            if (stubAddress)
            {
                LONG_PTR stubOffset = (LONG_PTR)((ULONG_PTR)stubAddress - ssdtBase);
                LogToDbgView("HookSyscall: Found code cave at %p (offset: 0x%llX)\n", 
                    stubAddress, stubOffset);
            }
        }
        
        if (!stubAddress)
        {
            LogToDbgView("HookSyscall: ✗ All allocation strategies failed\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        // 构造0xbekoo-style stub代码
        PUCHAR code = (PUCHAR)stubAddress;
        
        // 保存原始SSDT条目（用于清理）
        *(PULONG)(code + 0) = originalEntry;  // 前4字节存储原始条目
        *(PULONG)(code + 4) = SyscallNumber;  // 接下来4字节存储syscall号
        
        // Hook代码从offset 8开始
        // mov rax, HookFunction
        code[8] = 0x48; code[9] = 0xB8;
        *(PULONG_PTR)(code + 10) = (ULONG_PTR)HookFunction;
        
        // jmp rax
        code[18] = 0xFF; code[19] = 0xE0;
        
        // 填充剩余字节
        for (ULONG i = 20; i < stubSize; i++)
            code[i] = 0xCC;  // int3
            
        // 刷新指令缓存
        typedef VOID (*pfnKeFlushInstructionCache)(BOOLEAN AllProcessors);
        UNICODE_STRING funcName;
        RtlInitUnicodeString(&funcName, L"KeFlushInstructionCache");
        
        pfnKeFlushInstructionCache KeFlushInstructionCachePtr = 
            (pfnKeFlushInstructionCache)MmGetSystemRoutineAddress(&funcName);
        
        if (KeFlushInstructionCachePtr)
        {
            KeFlushInstructionCachePtr(TRUE);
        }
        
        // 计算新的SSDT条目
        ULONG argumentCount = originalEntry & 0xF;
        LONG_PTR newOffset = (LONG_PTR)((ULONG_PTR)(code + 8) - (ULONG_PTR)ssdt->ServiceTableBase);
        ULONG newEntry = ((ULONG)(newOffset << 4)) | argumentCount;
        
        // 0xbekoo方法：禁用写保护并替换SSDT条目
        ULONG_PTR cr0 = __readcr0();
        __writecr0(cr0 & ~0x10000);  // 清除WP位
        
        ssdt->ServiceTableBase[SyscallNumber] = newEntry;
        
        __writecr0(cr0);  // 恢复写保护
        
        // 跟踪分配的内存
        if (g_HookPoolCount < MAX_HOOK_POOLS)
        {
            g_HookPools[g_HookPoolCount++] = stubAddress;
        }
        
        LogToDbgView("HookSyscall: ✓ 0xbekoo-style hook installed (0x%08X -> 0x%08X)\n", 
            originalEntry, newEntry);
        
        return STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("HookSyscall: ✗ Exception: 0x%08X\n", GetExceptionCode());
        return STATUS_UNSUCCESSFUL;
    }
}

// Uninitialize InfinityHook
NTSTATUS UninitializeInfinityHook()
{
    if (!g_HooksInitialized)
        return STATUS_SUCCESS;
        
    LogToDbgView("Uninitializing InfinityHook...\n");
    
    g_HooksInitialized = FALSE;
    g_SSDT = NULL;
    g_SSDTValidated = FALSE;
    
    // Free pool allocations
    for (ULONG i = 0; i < g_HookPoolCount; i++)
    {
        if (g_HookPools[i])
        {
            ExFreePoolWithTag(g_HookPools[i], 'tSHk');
            g_HookPools[i] = NULL;
        }
    }
    g_HookPoolCount = 0;
    
    // Restore code caves
    for (ULONG i = 0; i < g_CodeCaveCount; i++)
    {
        if (g_CodeCaves[i])
        {
            __try
            {
                RtlFillMemory(g_CodeCaves[i], 16, 0xCC);
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {}
            g_CodeCaves[i] = NULL;
        }
    }
    g_CodeCaveCount = 0;
    
    LogToDbgView("InfinityHook uninitialized\n");
    return STATUS_SUCCESS;
}