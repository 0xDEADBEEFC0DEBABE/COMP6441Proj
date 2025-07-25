#include "infinityhook.h"
#include "advanced_ssdt.h"
#include <intrin.h>
#include <stdarg.h>
#include <ntstrsafe.h>

// Required type definitions
typedef struct _IMAGE_DOS_HEADER {
    USHORT e_magic;
    USHORT e_cblp;
    USHORT e_cp;
    USHORT e_crlc;
    USHORT e_cparhdr;
    USHORT e_minalloc;
    USHORT e_maxalloc;
    USHORT e_ss;
    USHORT e_sp;
    USHORT e_csum;
    USHORT e_ip;
    USHORT e_cs;
    USHORT e_lfarlc;
    USHORT e_ovno;
    USHORT e_res[4];
    USHORT e_oemid;
    USHORT e_oeminfo;
    USHORT e_res2[10];
    LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_NT_HEADERS64 {
    ULONG Signature;
    // Simplified for compilation
    UCHAR Reserved[248];
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

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

// File logging variables
HANDLE g_LogFileHandle = NULL;
PFILE_OBJECT g_LogFileObject = NULL;

// Find ntoskrnl.exe base address - safer version
PVOID GetNtoskrnlBaseSafe()
{
    // Try to get a known ntoskrnl function first
    __try
    {
        PVOID knownFunction = (PVOID)DbgPrintEx;
        if (knownFunction)
        {
            // Walk backward to find PE header
            ULONG_PTR addr = (ULONG_PTR)knownFunction & ~0xFFF; // Align to page
            
            for (ULONG i = 0; i < 0x10000; i++, addr -= 0x1000) // Search up to 256MB back
            {
                __try 
                {
                    if (MmIsAddressValid((PVOID)addr))
                    {
                        if (*(PUSHORT)addr == 0x5A4D) // MZ header
                        {
                            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)addr;
                            if (dosHeader->e_lfanew > 0 && dosHeader->e_lfanew < 0x1000)
                            {
                                PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(addr + dosHeader->e_lfanew);
                                if (MmIsAddressValid(ntHeaders) && ntHeaders->Signature == 0x00004550) // PE signature
                                {
                                    LogToDbgView("Found ntoskrnl base at: %p\n", (PVOID)addr);
                                    return (PVOID)addr;
                                }
                            }
                        }
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    continue;
                }
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("Exception in GetNtoskrnlBase\n");
    }
    
    LogToDbgView("Could not find ntoskrnl base\n");
    return NULL;
}

// Advanced SSDT discovery - multiple methods to bypass KASLR
PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDT()
{
    if (g_SSDT)  
    {
        LogToDbgView("SSDT already cached at: %p\n", g_SSDT);
        return g_SSDT;
    }

    LogToDbgView("Starting advanced SSDT discovery...\n");

    // Use advanced multi-method SSDT finder
    g_SSDT = FindSSDTAdvanced();
    
    if (g_SSDT)
    {
        LogToDbgView("✓ SSDT successfully found at: %p\n", g_SSDT);
        LogToDbgView("ServiceTableBase: %p, NumberOfServices: %lu\n", 
            g_SSDT->ServiceTableBase, g_SSDT->NumberOfServices);
        return g_SSDT;
    }
    
    LogToDbgView("✗ All advanced SSDT discovery methods failed\n");
    LogToDbgView("This is likely due to:\n");
    LogToDbgView("- KASLR randomization\n");
    LogToDbgView("- Kernel structure changes\n"); 
    LogToDbgView("- Anti-analysis countermeasures\n");
    LogToDbgView("- Memory protection changes\n");
    
    return NULL;
}

// Disable write protection
KIRQL DisableWriteProtectionSafe()
{
    KIRQL irql = KeRaiseIrqlToDpcLevel();
    ULONG_PTR cr0 = __readcr0();
    cr0 &= ~0x10000; // Clear WP bit
    __writecr0(cr0);
    _disable();
    return irql;
}

// Enable write protection
VOID EnableWriteProtectionSafe(KIRQL irql)
{
    ULONG_PTR cr0 = __readcr0();
    cr0 |= 0x10000; // Set WP bit
    __writecr0(cr0);
    _enable();
    KeLowerIrql(irql);
}

// Hook a system call
NTSTATUS HookSyscall(ULONG SyscallNumber, PVOID HookFunction, PVOID* OriginalFunction)
{
    if (!g_SSDT || !g_SSDT->ServiceTableBase)
    {
        LogToDbgView("HookSyscall: SSDT not available\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    if (SyscallNumber >= g_SSDT->NumberOfServices)
    {
        LogToDbgView("HookSyscall: Invalid syscall number %lu\n", SyscallNumber);
        return STATUS_INVALID_PARAMETER;
    }
    
    __try
    {
        // Get original function address (decode for Windows 10+)
        ULONG_PTR serviceEntry = g_SSDT->ServiceTableBase[SyscallNumber];
        ULONG_PTR originalAddress;
        
        // Windows 10+ uses encoded entries
        if (serviceEntry & 0xF0000000)
        {
            // Decode the address
            originalAddress = (ULONG_PTR)g_SSDT->ServiceTableBase + (serviceEntry >> 4);
        }
        else
        {
            // Direct address (older Windows)
            originalAddress = serviceEntry;
        }
        
        if (!MmIsAddressValid((PVOID)originalAddress))
        {
            LogToDbgView("HookSyscall: Invalid original function address: %p\n", (PVOID)originalAddress);
            return STATUS_UNSUCCESSFUL;
        }
        
        *OriginalFunction = (PVOID)originalAddress;
        
        // Calculate new encoded entry
        ULONG_PTR newEntry;
        if (serviceEntry & 0xF0000000)
        {
            // Encode the new address
            newEntry = ((ULONG_PTR)HookFunction - (ULONG_PTR)g_SSDT->ServiceTableBase) << 4;
        }
        else
        {
            newEntry = (ULONG_PTR)HookFunction;
        }
        
        // Install hook with write protection disabled
        KIRQL oldIrql = DisableWriteProtectionSafe();
        g_SSDT->ServiceTableBase[SyscallNumber] = newEntry;
        EnableWriteProtectionSafe(oldIrql);
        
        LogToDbgView("HookSyscall: Hooked syscall %lu: %p -> %p\n", 
            SyscallNumber, (PVOID)originalAddress, HookFunction);
        
        return STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("HookSyscall: Exception hooking syscall %lu\n", SyscallNumber);
        return STATUS_UNSUCCESSFUL;
    }
}

// Unhook a system call
NTSTATUS UnhookSyscall(ULONG SyscallNumber)
{
    // Implementation for unhooking if needed
    return STATUS_SUCCESS;
}

// Check if process is EAC-related - IRQL safe version
BOOLEAN IsEACProcess(PEPROCESS Process)
{
    if (!Process)
        return FALSE;
        
    // Only do complex operations at low IRQL
    if (KeGetCurrentIrql() > APC_LEVEL)
        return FALSE;
    
    __try
    {
        // Use direct EPROCESS offset access instead of PsGetProcessImageFileName
        PUCHAR processName = NULL;
        
        // Try different offsets for different Windows versions
        ULONG offsets[] = { 0x5A8, 0x450, 0x438, 0x46C }; // Win10, Win8, Win7, etc.
        
        for (ULONG i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++)
        {
            __try 
            {
                processName = (PUCHAR)((ULONG_PTR)Process + offsets[i]);
                
                // Basic validation
                if (processName[0] >= 'A' && processName[0] <= 'z')
                {
                    break;
                }
                processName = NULL;
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                processName = NULL;
                continue;
            }
        }
        
        if (!processName)
            return FALSE;
            
        // Check for EAC-related process names
        if (strstr((PCSTR)processName, "EasyAntiCheat") ||
            strstr((PCSTR)processName, "EAC") ||
            strstr((PCSTR)processName, "eac_") ||
            strstr((PCSTR)processName, "BEService") ||
            strstr((PCSTR)processName, "BattlEye"))
        {
            return TRUE;
        }
        
        return FALSE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

// Check if thread belongs to EAC
BOOLEAN IsEACThread(PETHREAD Thread)
{
    if (!Thread)
        return FALSE;
        
    PEPROCESS process = PsGetThreadProcess(Thread);
    return IsEACProcess(process);
}

// Log to DbgView
VOID LogToDbgView(PCSTR Format, ...)
{
    // Only log at safe IRQL levels
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        return;
        
    __try
    {
        CHAR buffer[512];
        va_list args;
        va_start(args, Format);
        
        // Use safe string functions
        NTSTATUS status = RtlStringCbVPrintfA(buffer, sizeof(buffer), Format, args);
        va_end(args);
        
        if (NT_SUCCESS(status))
        {
            // Add prefix
            CHAR finalBuffer[512];
            RtlStringCbPrintfA(finalBuffer, sizeof(finalBuffer), "[EAC-MONITOR] %s", buffer);
            
            // Output to debugger
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "%s", finalBuffer);
            
            // Also log to file if available
            LogToFile(finalBuffer);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
            "[EAC-MONITOR] Exception in LogToDbgView\n");
    }
}

// Initialize InfinityHook
NTSTATUS InitializeInfinityHook()
{
    LogToDbgView("Initializing advanced InfinityHook...\n");
    
    if (g_HooksInitialized)
    {
        LogToDbgView("InfinityHook already initialized\n");
        return STATUS_SUCCESS;
    }
    
    // Find SSDT using advanced methods
    PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt = GetSSDT();
    if (!ssdt)
    {
        LogToDbgView("Failed to find SSDT with advanced methods\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    LogToDbgView("Advanced InfinityHook initialized successfully\n");
    LogToDbgView("SSDT: %p, ServiceTable: %p, Services: %lu\n",
        ssdt, ssdt->ServiceTableBase, ssdt->NumberOfServices);
    
    g_HooksInitialized = TRUE;
    return STATUS_SUCCESS;
}

// Uninitialize InfinityHook
NTSTATUS UninitializeInfinityHook()
{
    if (!g_HooksInitialized)
        return STATUS_SUCCESS;
        
    LogToDbgView("Uninitializing InfinityHook...\n");
    
    // Unhook all syscalls if needed
    g_HooksInitialized = FALSE;
    g_SSDT = NULL;
    
    LogToDbgView("InfinityHook uninitialized\n");
    return STATUS_SUCCESS;
}

// Initialize file logging
NTSTATUS InitializeFileLogging()
{
    UNICODE_STRING fileName;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    
    RtlInitUnicodeString(&fileName, L"\\??\\C:\\eac_monitor.log");
    InitializeObjectAttributes(&objAttr, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    
    NTSTATUS status = ZwCreateFile(
        &g_LogFileHandle,
        GENERIC_WRITE,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    
    if (NT_SUCCESS(status))
    {
        status = ObReferenceObjectByHandle(g_LogFileHandle, 0, NULL, KernelMode, (PVOID*)&g_LogFileObject, NULL);
        if (!NT_SUCCESS(status))
        {
            ZwClose(g_LogFileHandle);
            g_LogFileHandle = NULL;
        }
    }
    
    return status;
}

// Uninitialize file logging
VOID UninitializeFileLogging()
{
    if (g_LogFileObject)
    {
        ObDereferenceObject(g_LogFileObject);
        g_LogFileObject = NULL;
    }
    
    if (g_LogFileHandle)
    {
        ZwClose(g_LogFileHandle);
        g_LogFileHandle = NULL;
    }
}

// Log message to file
NTSTATUS LogToFile(PCSTR Message)
{
    if (!g_LogFileHandle || KeGetCurrentIrql() > PASSIVE_LEVEL)
        return STATUS_UNSUCCESSFUL;
        
    __try
    {
        IO_STATUS_BLOCK ioStatus;
        SIZE_T messageLen = strlen(Message);
        
        return ZwWriteFile(g_LogFileHandle, NULL, NULL, NULL, &ioStatus, (PVOID)Message, (ULONG)messageLen, NULL, NULL);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return STATUS_UNSUCCESSFUL;
    }
}