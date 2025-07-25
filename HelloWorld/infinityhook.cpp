#include "infinityhook.h"
#include "advanced_ssdt.h"
#include <intrin.h>
#include <stdarg.h>
#include <ntstrsafe.h>

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
PVOID GetNtoskrnlBase()
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
                if (!MmIsAddressValid((PVOID)addr))
                    continue;
                    
                if (*(PUSHORT)addr == 0x5A4D) // MZ header
                {
                    ULONG peOffset = *(PULONG)(addr + 0x3C);
                    if (peOffset < 0x1000 && MmIsAddressValid((PVOID)(addr + peOffset)))
                    {
                        if (*(PULONG)(addr + peOffset) == 0x00004550) // PE signature
                        {
                            LogToDbgView("Found ntoskrnl base at: %p (from function %p)\n", (PVOID)addr, knownFunction);
                            return (PVOID)addr;
                        }
                    }
                }
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("Exception while searching for ntoskrnl base\n");
    }
    
    // Fallback: try common base addresses with better validation
    ULONG_PTR possibleBases[] = {
        0xFFFFF80000000000ULL,
        0xFFFFF80001000000ULL,
        0xFFFFF80002000000ULL,
        0xFFFFF80003000000ULL,
        0xFFFFF80004000000ULL
    };
    
    for (ULONG i = 0; i < sizeof(possibleBases) / sizeof(possibleBases[0]); i++)
    {
        __try
        {
            ULONG_PTR base = possibleBases[i];
            
            if (!MmIsAddressValid((PVOID)base))
                continue;
                
            // Check for MZ header
            if (*(PUSHORT)base == 0x5A4D)
            {
                // Check PE header
                ULONG peOffset = *(PULONG)(base + 0x3C);
                if (peOffset < 0x1000 && MmIsAddressValid((PVOID)(base + peOffset)))
                {
                    ULONG_PTR peHeader = base + peOffset;
                    if (*(PULONG)peHeader == 0x00004550) // PE signature
                    {
                        LogToDbgView("Found ntoskrnl base at: %p\n", (PVOID)base);
                        return (PVOID)base;
                    }
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            continue;
        }
    }
    
    return NULL;
}

// Advanced SSDT discovery - multiple methods to bypass KASLR
PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDT()
{
    if (g_SSDT)
    {
        LogToDbgView("SSDT already found at: %p\n", g_SSDT);
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
    
    // Only use hardcoded offsets - NO memory scanning to avoid crashes
    ULONG_PTR possibleSSDT[] = {
        // User's system specific offset: FFFFF807464018C0 - FFFFF80745600000 = 0xE018C0
        (ULONG_PTR)ntoskrnlBase + 0xE018C0,  // User's exact offset from WinDbg
        
        // Backup: absolute address (in case KASLR changed)
        0xFFFFF807464018C0,  // User's WinDbg result (absolute)
        
        // Then try other common offsets
        (ULONG_PTR)ntoskrnlBase + 0x3F9040,  // Win10 21H2 19044 primary
        (ULONG_PTR)ntoskrnlBase + 0x3F8040,  // Win10 21H1
        (ULONG_PTR)ntoskrnlBase + 0x3F7040,  // Variant
        (ULONG_PTR)ntoskrnlBase + 0x3F6040,  // Variant
        (ULONG_PTR)ntoskrnlBase + 0x3F5040,  // Variant
        (ULONG_PTR)ntoskrnlBase + 0x3FA040,  // Variant
        (ULONG_PTR)ntoskrnlBase + 0x3FB040,  // Variant
        (ULONG_PTR)ntoskrnlBase + 0x3FC040,  // Variant
        (ULONG_PTR)ntoskrnlBase + 0x3FD040,  // Variant
        (ULONG_PTR)ntoskrnlBase + 0x3FE040,  // Variant
        (ULONG_PTR)ntoskrnlBase + 0x3FF040,  // Variant
        
        // Different alignment
        (ULONG_PTR)ntoskrnlBase + 0x3F8C40,  // Win10 21H2 variant
        (ULONG_PTR)ntoskrnlBase + 0x3F9C40,  // Win10 21H2 variant
        (ULONG_PTR)ntoskrnlBase + 0x3F6300,  // Win10 2004
        (ULONG_PTR)ntoskrnlBase + 0x3F5D40,  // Win10 1909
        (ULONG_PTR)ntoskrnlBase + 0x3F5C40,  // Other versions
        
        // More common offsets for different builds
        (ULONG_PTR)ntoskrnlBase + 0x400000,  // 4MB
        (ULONG_PTR)ntoskrnlBase + 0x3E0000,  // 3.875MB
        (ULONG_PTR)ntoskrnlBase + 0x3D0000,  // 3.8125MB
        (ULONG_PTR)ntoskrnlBase + 0x3C0000,  // 3.75MB
        (ULONG_PTR)ntoskrnlBase + 0x3B0000,  // 3.6875MB
        (ULONG_PTR)ntoskrnlBase + 0x3A0000,  // 3.625MB
    };
    
    for (ULONG i = 0; i < sizeof(possibleSSDT) / sizeof(possibleSSDT[0]); i++)
    {
        __try
        {
            PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)possibleSSDT[i];
            
            LogToDbgView("Trying hardcoded offset %lu: %p\n", i, ssdt);
            
            // Very careful validation
            if (!MmIsAddressValid(ssdt))
                continue;
                
            if (!MmIsAddressValid((PVOID)((ULONG_PTR)ssdt + sizeof(SYSTEM_SERVICE_DESCRIPTOR_TABLE) - 1)))
                continue;
                
            if (!ssdt->ServiceTableBase)
                continue;
                
            if (!MmIsAddressValid(ssdt->ServiceTableBase))
                continue;
            
            if (ssdt->NumberOfServices < 300 || ssdt->NumberOfServices > 700)
                continue;
            
            // Check if we can access first syscall
            if (!MmIsAddressValid((PVOID)ssdt->ServiceTableBase[0]))
                continue;
                
            // Check if first syscall looks reasonable (in kernel space)
            if (ssdt->ServiceTableBase[0] < 0xFFFF800000000000ULL)
                continue;
            
            LogToDbgView("Method 2 SUCCESS: Valid SSDT found at hardcoded location: %p\n", ssdt);
            LogToDbgView("ServiceTableBase: %p, NumberOfServices: %lu\n", 
                ssdt->ServiceTableBase, ssdt->NumberOfServices);
            g_SSDT = ssdt;
            return g_SSDT;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            LogToDbgView("Exception at offset %lu, continuing...\n", i);
            continue;
        }
    }

    // Method 3: Extended search with more offsets based on your system
    LogToDbgView("Method 3: Extended search for your specific system...\n");
    LogToDbgView("Your ntoskrnl base: %p\n", ntoskrnlBase);
    
    // Calculate more specific offsets for your system
    // Your base is FFFFF805751FC000, so let's try offsets around common ranges
    ULONG_PTR extendedSSDT[] = {
        // Try offsets in 4KB increments around the expected range
        (ULONG_PTR)ntoskrnlBase + 0x3F0000,
        (ULONG_PTR)ntoskrnlBase + 0x3F1000,
        (ULONG_PTR)ntoskrnlBase + 0x3F2000,
        (ULONG_PTR)ntoskrnlBase + 0x3F3000,
        (ULONG_PTR)ntoskrnlBase + 0x3F4000,
        (ULONG_PTR)ntoskrnlBase + 0x3F5000,
        (ULONG_PTR)ntoskrnlBase + 0x3F6000,
        (ULONG_PTR)ntoskrnlBase + 0x3F7000,
        (ULONG_PTR)ntoskrnlBase + 0x3F8000,
        (ULONG_PTR)ntoskrnlBase + 0x3F9000,
        (ULONG_PTR)ntoskrnlBase + 0x3FA000,
        (ULONG_PTR)ntoskrnlBase + 0x3FB000,
        (ULONG_PTR)ntoskrnlBase + 0x3FC000,
        (ULONG_PTR)ntoskrnlBase + 0x3FD000,
        (ULONG_PTR)ntoskrnlBase + 0x3FE000,
        (ULONG_PTR)ntoskrnlBase + 0x3FF000,
        (ULONG_PTR)ntoskrnlBase + 0x400000,
        (ULONG_PTR)ntoskrnlBase + 0x401000,
        (ULONG_PTR)ntoskrnlBase + 0x402000,
        (ULONG_PTR)ntoskrnlBase + 0x403000,
        (ULONG_PTR)ntoskrnlBase + 0x404000,
        (ULONG_PTR)ntoskrnlBase + 0x405000,
        
        // Try some other common ranges
        (ULONG_PTR)ntoskrnlBase + 0x380000,
        (ULONG_PTR)ntoskrnlBase + 0x390000,
        (ULONG_PTR)ntoskrnlBase + 0x3A0000,
        (ULONG_PTR)ntoskrnlBase + 0x3B0000,
        (ULONG_PTR)ntoskrnlBase + 0x3C0000,
        (ULONG_PTR)ntoskrnlBase + 0x3D0000,
        (ULONG_PTR)ntoskrnlBase + 0x3E0000,
        
        // Different alignments
        (ULONG_PTR)ntoskrnlBase + 0x3F5800,
        (ULONG_PTR)ntoskrnlBase + 0x3F5A00,
        (ULONG_PTR)ntoskrnlBase + 0x3F5C00,
        (ULONG_PTR)ntoskrnlBase + 0x3F5E00,
        (ULONG_PTR)ntoskrnlBase + 0x3F6200,
        (ULONG_PTR)ntoskrnlBase + 0x3F6400,
        (ULONG_PTR)ntoskrnlBase + 0x3F6600,
        (ULONG_PTR)ntoskrnlBase + 0x3F6800,
        (ULONG_PTR)ntoskrnlBase + 0x3F6A00,
        (ULONG_PTR)ntoskrnlBase + 0x3F6C00,
        (ULONG_PTR)ntoskrnlBase + 0x3F6E00,
        (ULONG_PTR)ntoskrnlBase + 0x3F7200,
    };
    
    for (ULONG i = 0; i < sizeof(extendedSSDT) / sizeof(extendedSSDT[0]); i++)
    {
        __try
        {
            PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)extendedSSDT[i];
            
            LogToDbgView("Trying extended offset %lu: %p\n", i, ssdt);
            
            // Very minimal validation to avoid crashes
            if (!MmIsAddressValid(ssdt))
                continue;
                
            if (!ssdt->ServiceTableBase)
                continue;
                
            // Check if ServiceTableBase looks like a kernel pointer
            if ((ULONG_PTR)ssdt->ServiceTableBase < 0xFFFF000000000000ULL)
                continue;
                
            if (!MmIsAddressValid(ssdt->ServiceTableBase))
                continue;
            
            // Check NumberOfServices is in a reasonable range
            if (ssdt->NumberOfServices < 200 || ssdt->NumberOfServices > 800)
                continue;
            
            // Very basic validation of first syscall
            if (!MmIsAddressValid((PVOID)ssdt->ServiceTableBase[0]))
                continue;
                
            LogToDbgView("Method 3 SUCCESS: Valid SSDT found at: %p\n", ssdt);
            LogToDbgView("ServiceTableBase: %p, NumberOfServices: %lu\n", 
                ssdt->ServiceTableBase, ssdt->NumberOfServices);
            LogToDbgView("Offset from ntoskrnl base: 0x%X\n", (ULONG)((ULONG_PTR)ssdt - (ULONG_PTR)ntoskrnlBase));
            g_SSDT = ssdt;
            return g_SSDT;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            continue;
        }
    }

    LogToDbgView("================== MANUAL SSDT FINDING GUIDE ==================\n");
    LogToDbgView("All automatic methods failed. To find SSDT manually:\n");
    LogToDbgView("1. Use WinDbg kernel debugging:\n");
    LogToDbgView("   kd> dt nt!KeServiceDescriptorTable\n");
    LogToDbgView("   kd> ? KeServiceDescriptorTable\n");
    LogToDbgView("2. Your ntoskrnl base is: %p\n", ntoskrnlBase);
    LogToDbgView("3. Calculate offset: SSDT_Address - %p\n", ntoskrnlBase);
    LogToDbgView("4. Add the offset to the hardcoded list in the code\n");
    LogToDbgView("============================================================\n");
    
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

// Hook a system call
NTSTATUS HookSyscall(ULONG SyscallNumber, PVOID HookFunction, PVOID* OriginalFunction)
{
    LogToDbgView("Attempting to hook syscall 0x%02X\n", SyscallNumber);
    
    if (!HookFunction || !OriginalFunction)
    {
        LogToDbgView("ERROR: Invalid parameters - HookFunction: %p, OriginalFunction: %p\n", 
            HookFunction, OriginalFunction);
        return STATUS_INVALID_PARAMETER;
    }

    PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt = GetSSDT();
    if (!ssdt)
    {
        LogToDbgView("ERROR: SSDT not found, cannot install hook\n");
        return STATUS_UNSUCCESSFUL;
    }

    if (SyscallNumber >= ssdt->NumberOfServices)
    {
        LogToDbgView("ERROR: Syscall number 0x%02X exceeds service count %lu\n", 
            SyscallNumber, ssdt->NumberOfServices);
        return STATUS_INVALID_PARAMETER;
    }

    __try
    {
        // Validate addresses
        if (!MmIsAddressValid(&ssdt->ServiceTableBase[SyscallNumber]))
        {
            LogToDbgView("ERROR: ServiceTableBase[0x%02X] address not valid\n", SyscallNumber);
            return STATUS_INVALID_ADDRESS;
        }

        KIRQL irql = DisableWriteProtection();
        
        *OriginalFunction = (PVOID)ssdt->ServiceTableBase[SyscallNumber];
        LogToDbgView("Original function at ServiceTableBase[0x%02X]: %p\n", 
            SyscallNumber, *OriginalFunction);
        
        // Validate original function pointer
        if (!MmIsAddressValid(*OriginalFunction))
        {
            LogToDbgView("ERROR: Original function pointer %p is not valid\n", *OriginalFunction);
            EnableWriteProtection(irql);
            return STATUS_INVALID_ADDRESS;
        }
        
        ssdt->ServiceTableBase[SyscallNumber] = (ULONG_PTR)HookFunction;
        LogToDbgView("Hook installed: ServiceTableBase[0x%02X] = %p (was %p)\n", 
            SyscallNumber, HookFunction, *OriginalFunction);
        
        EnableWriteProtection(irql);

        return STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("ERROR: Exception occurred while hooking syscall 0x%02X\n", SyscallNumber);
        return STATUS_ACCESS_VIOLATION;
    }
}

// Unhook a system call
NTSTATUS UnhookSyscall(ULONG SyscallNumber)
{
    PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt = GetSSDT();
    if (!ssdt)
        return STATUS_UNSUCCESSFUL;

    if (SyscallNumber >= ssdt->NumberOfServices)
        return STATUS_INVALID_PARAMETER;

    PVOID* originalPtr = NULL;
    
    // Find the corresponding original function pointer
    switch (SyscallNumber)
    {
    case SYSCALL_NTOPENPROCESS:
        originalPtr = &g_OriginalNtOpenProcess;
        break;
    case SYSCALL_NTREADVIRTUALMEMORY:
        originalPtr = &g_OriginalNtReadVirtualMemory;
        break;
    case SYSCALL_NTWRITEVIRTUALMEMORY:
        originalPtr = &g_OriginalNtWriteVirtualMemory;
        break;
    case SYSCALL_NTQUERYVIRTUALMEMORY:
        originalPtr = &g_OriginalNtQueryVirtualMemory;
        break;
    case SYSCALL_NTPROTECTVIRTUALMEMORY:
        originalPtr = &g_OriginalNtProtectVirtualMemory;
        break;
    case SYSCALL_NTALLOCATEVIRTUALMEMORY:
        originalPtr = &g_OriginalNtAllocateVirtualMemory;
        break;
    case SYSCALL_NTFREEVIRTUALMEMORY:
        originalPtr = &g_OriginalNtFreeVirtualMemory;
        break;
    case SYSCALL_NTCREATETHREADEX:
        originalPtr = &g_OriginalNtCreateThreadEx;
        break;
    case SYSCALL_NTTERMINATEPROCESS:
        originalPtr = &g_OriginalNtTerminateProcess;
        break;
    case SYSCALL_NTQUERYINFORMATIONPROCESS:
        originalPtr = &g_OriginalNtQueryInformationProcess;
        break;
    case SYSCALL_NTSETINFORMATIONPROCESS:
        originalPtr = &g_OriginalNtSetInformationProcess;
        break;
    case SYSCALL_NTOPENTHREAD:
        originalPtr = &g_OriginalNtOpenThread;
        break;
    case SYSCALL_NTTERMINATETHREAD:
        originalPtr = &g_OriginalNtTerminateThread;
        break;
    case SYSCALL_NTSUSPENDTHREAD:
        originalPtr = &g_OriginalNtSuspendThread;
        break;
    case SYSCALL_NTRESUMETHREAD:
        originalPtr = &g_OriginalNtResumeThread;
        break;
    case SYSCALL_NTCREATEFILE:
        originalPtr = &g_OriginalNtCreateFile;
        break;
    case SYSCALL_NTOPENFILE:
        originalPtr = &g_OriginalNtOpenFile;
        break;
    case SYSCALL_NTREADFILE:
        originalPtr = &g_OriginalNtReadFile;
        break;
    case SYSCALL_NTWRITEFILE:
        originalPtr = &g_OriginalNtWriteFile;
        break;
    case SYSCALL_NTDEVICEIOCONTROLFILE:
        originalPtr = &g_OriginalNtDeviceIoControlFile;
        break;
    case SYSCALL_NTLOADDRIVER:
        originalPtr = &g_OriginalNtLoadDriver;
        break;
    case SYSCALL_NTUNLOADDRIVER:
        originalPtr = &g_OriginalNtUnloadDriver;
        break;
    }

    if (!originalPtr || !*originalPtr)
        return STATUS_UNSUCCESSFUL;

    __try
    {
        if (!MmIsAddressValid(*originalPtr))
            return STATUS_INVALID_ADDRESS;

        KIRQL irql = DisableWriteProtection();
        ssdt->ServiceTableBase[SyscallNumber] = (ULONG_PTR)*originalPtr;
        EnableWriteProtection(irql);

        return STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return STATUS_ACCESS_VIOLATION;
    }
}

// Get process name from EPROCESS structure directly
PUCHAR GetProcessImageFileName(PEPROCESS Process)
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

// Check if process is EAC-related - IRQL safe version
BOOLEAN IsEACProcess(PEPROCESS Process)
{
    if (!Process)
        return FALSE;

    // Get process name using direct memory access (IRQL safe)
    PUCHAR processName = GetProcessImageFileName(Process);
    if (!processName)
        return FALSE;
    
    // Convert to lowercase for comparison (simple ASCII conversion)
    CHAR lowerName[16] = {0}; // Process names are max 15 chars + null
    for (ULONG i = 0; i < 15 && processName[i]; i++)
    {
        // Basic validation to avoid reading garbage
        if (processName[i] < 0x20 || processName[i] > 0x7E)
            break;
            
        if (processName[i] >= 'A' && processName[i] <= 'Z')
            lowerName[i] = processName[i] + 32; // Convert to lowercase
        else
            lowerName[i] = processName[i];
    }
    
    // Check for EAC-related process names (case insensitive)
    BOOLEAN isEAC = FALSE;
    if (strstr(lowerName, "eac") ||
        strstr(lowerName, "anticheat") ||
        strstr(lowerName, "beservice") ||
        strstr(lowerName, "battleye"))
    {
        isEAC = TRUE;
        
        // Log when we detect an EAC process for the first time (only at low IRQL)
        if (KeGetCurrentIrql() <= APC_LEVEL)
        {
            static PEPROCESS lastEACProcess = NULL;
            if (Process != lastEACProcess)
            {
                lastEACProcess = Process;
                LogToDbgView("DETECTED EAC Process: %s (Process: %p)\n", lowerName, Process);
            }
        }
    }
    
    return isEAC;
}

// Check if thread belongs to EAC
BOOLEAN IsEACThread(PETHREAD Thread)
{
    if (!Thread)
        return FALSE;

    PEPROCESS process = IoThreadToProcess(Thread);
    return IsEACProcess(process);
}

// Log to DbgView
VOID LogToDbgView(PCSTR Format, ...)
{
    // Check IRQL level - only do complex operations at PASSIVE_LEVEL
    KIRQL currentIrql = KeGetCurrentIrql();
    
    va_list args;
    va_start(args, Format);
    
    CHAR message[512];
    RtlStringCchVPrintfA(message, sizeof(message), Format, args);
    
    if (currentIrql <= APC_LEVEL)
    {
        // Safe to do timestamp and file operations
        LARGE_INTEGER systemTime;
        TIME_FIELDS timeFields;
        KeQuerySystemTime(&systemTime);
        RtlTimeToTimeFields(&systemTime, &timeFields);
        
        CHAR timestampedMessage[1024];
        RtlStringCchPrintfA(timestampedMessage, sizeof(timestampedMessage), 
            "[%02d:%02d:%02d.%03d] [EAC-MONITOR] %s",
            timeFields.Hour, timeFields.Minute, timeFields.Second, 
            timeFields.Milliseconds, message);
        
        // Output to DbgView
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "%s", timestampedMessage);
        
        // Also log to file only at PASSIVE_LEVEL
        if (currentIrql == PASSIVE_LEVEL)
        {
            LogToFile(timestampedMessage);
        }
    }
    else
    {
        // High IRQL - just do basic DbgPrint without timestamp
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[EAC-MONITOR] [IRQL=%d] %s", currentIrql, message);
    }
    
    va_end(args);
}

// Initialize InfinityHook
NTSTATUS InitializeInfinityHook()
{
    if (g_HooksInitialized)
    {
        LogToDbgView("InfinityHook already initialized\n");
        return STATUS_SUCCESS;
    }

    LogToDbgView("========== InfinityHook Initialization ==========\n");
    
    PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt = GetSSDT();
    if (!ssdt)
    {
        LogToDbgView("CRITICAL ERROR: Failed to find SSDT\n");
        return STATUS_UNSUCCESSFUL;
    }

    LogToDbgView("========== SSDT Information ==========\n");
    LogToDbgView("SSDT found at: %p\n", ssdt);
    LogToDbgView("ServiceTableBase: %p\n", ssdt->ServiceTableBase);
    LogToDbgView("ServiceCounterTableBase: %p\n", ssdt->ServiceCounterTableBase);  
    LogToDbgView("NumberOfServices: %lu\n", ssdt->NumberOfServices);
    LogToDbgView("ParamTableBase: %p\n", ssdt->ParamTableBase);
    
    // Validate some known syscalls
    LogToDbgView("========== Syscall Validation ==========\n");
    if (SYSCALL_NTOPENPROCESS < ssdt->NumberOfServices)
        LogToDbgView("NtOpenProcess (0x%02X): %p\n", SYSCALL_NTOPENPROCESS, 
            (PVOID)ssdt->ServiceTableBase[SYSCALL_NTOPENPROCESS]);
    if (SYSCALL_NTREADVIRTUALMEMORY < ssdt->NumberOfServices)
        LogToDbgView("NtReadVirtualMemory (0x%02X): %p\n", SYSCALL_NTREADVIRTUALMEMORY,
            (PVOID)ssdt->ServiceTableBase[SYSCALL_NTREADVIRTUALMEMORY]);
    if (SYSCALL_NTWRITEVIRTUALMEMORY < ssdt->NumberOfServices)
        LogToDbgView("NtWriteVirtualMemory (0x%02X): %p\n", SYSCALL_NTWRITEVIRTUALMEMORY,
            (PVOID)ssdt->ServiceTableBase[SYSCALL_NTWRITEVIRTUALMEMORY]);

    g_HooksInitialized = TRUE;
    LogToDbgView("InfinityHook initialization completed successfully\n");
    return STATUS_SUCCESS;
}

// Uninitialize InfinityHook
NTSTATUS UninitializeInfinityHook()
{
    if (!g_HooksInitialized)
        return STATUS_SUCCESS;

    // Unhook all hooked functions
    UnhookSyscall(SYSCALL_NTOPENPROCESS);
    UnhookSyscall(SYSCALL_NTREADVIRTUALMEMORY);
    UnhookSyscall(SYSCALL_NTWRITEVIRTUALMEMORY);
    UnhookSyscall(SYSCALL_NTQUERYVIRTUALMEMORY);
    UnhookSyscall(SYSCALL_NTPROTECTVIRTUALMEMORY);
    UnhookSyscall(SYSCALL_NTALLOCATEVIRTUALMEMORY);
    UnhookSyscall(SYSCALL_NTFREEVIRTUALMEMORY);
    UnhookSyscall(SYSCALL_NTCREATETHREADEX);
    UnhookSyscall(SYSCALL_NTTERMINATEPROCESS);
    UnhookSyscall(SYSCALL_NTQUERYINFORMATIONPROCESS);
    UnhookSyscall(SYSCALL_NTSETINFORMATIONPROCESS);
    UnhookSyscall(SYSCALL_NTOPENTHREAD);
    UnhookSyscall(SYSCALL_NTTERMINATETHREAD);
    UnhookSyscall(SYSCALL_NTSUSPENDTHREAD);
    UnhookSyscall(SYSCALL_NTRESUMETHREAD);
    UnhookSyscall(SYSCALL_NTCREATEFILE);
    UnhookSyscall(SYSCALL_NTOPENFILE);
    UnhookSyscall(SYSCALL_NTREADFILE);
    UnhookSyscall(SYSCALL_NTWRITEFILE);
    UnhookSyscall(SYSCALL_NTDEVICEIOCONTROLFILE);
    UnhookSyscall(SYSCALL_NTLOADDRIVER);
    UnhookSyscall(SYSCALL_NTUNLOADDRIVER);

    g_HooksInitialized = FALSE;
    return STATUS_SUCCESS;
}

// Initialize file logging
NTSTATUS InitializeFileLogging()
{
    NTSTATUS status;
    UNICODE_STRING logFilePath;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatusBlock;
    
    
    // Set log file path
    RtlInitUnicodeString(&logFilePath, L"\\??\\C:\\eac_monitor.log");
    
    InitializeObjectAttributes(&objAttr, &logFilePath, 
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 
        NULL, NULL);
    
    // Create or open the log file
    status = ZwCreateFile(&g_LogFileHandle,
        FILE_APPEND_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0);
    
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
            "[EAC-MONITOR] Failed to create log file: 0x%08X\n", status);
        return status;
    }
    
    // Get file object
    status = ObReferenceObjectByHandle(g_LogFileHandle,
        FILE_APPEND_DATA,
        *IoFileObjectType,
        KernelMode,
        (PVOID*)&g_LogFileObject,
        NULL);
    
    if (!NT_SUCCESS(status))
    {
        ZwClose(g_LogFileHandle);
        g_LogFileHandle = NULL;
        return status;
    }
    
    // Write header
    CHAR header[] = "\r\n========================================\r\n"
                    "EAC Monitor Driver Log Started\r\n"
                    "========================================\r\n";
    LogToFile(header);
    
    return STATUS_SUCCESS;
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
    // Only log to file at PASSIVE_LEVEL
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_SUCCESS; // Don't fail, just skip file logging
        
    if (!g_LogFileHandle || !g_LogFileObject)
        return STATUS_INVALID_HANDLE;
    
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    SIZE_T messageLen = strlen(Message);
    
    // Add newline if not present
    CHAR buffer[1024];
    if (messageLen > 0 && Message[messageLen - 1] != '\n')
    {
        RtlStringCchPrintfA(buffer, sizeof(buffer), "%s\r\n", Message);
        messageLen = strlen(buffer);
    }
    else
    {
        RtlStringCchCopyA(buffer, sizeof(buffer), Message);
    }
    
    // Use mutex instead of spinlock for file operations
    __try
    {
        // Write to file at PASSIVE_LEVEL
        LARGE_INTEGER offset = { 0 };
        offset.HighPart = -1;
        offset.LowPart = FILE_WRITE_TO_END_OF_FILE;
        
        status = ZwWriteFile(g_LogFileHandle,
            NULL,
            NULL,
            NULL,
            &ioStatusBlock,
            buffer,
            (ULONG)messageLen,
            &offset,
            NULL);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        status = STATUS_UNSUCCESSFUL;
    }
    
    return status;
}