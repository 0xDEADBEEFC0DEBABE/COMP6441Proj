#include "advanced_ssdt.h"
#include "infinityhook.h"
#include <ntstrsafe.h>

// Required structure definitions
typedef struct _IDTR
{
    USHORT limit;
    ULONG_PTR base;
} IDTR;

typedef struct _IDT_ENTRY64
{
    USHORT OffsetLow;
    USHORT Selector;
    UCHAR InterruptStackTable : 3;
    UCHAR Reserved0 : 5;
    UCHAR Type : 4;
    UCHAR Reserved1 : 1;
    UCHAR DescriptorPrivilegeLevel : 2;
    UCHAR Present : 1;
    USHORT OffsetMiddle;
    ULONG OffsetHigh;
    ULONG Reserved2;
} IDT_ENTRY64, *PIDT_ENTRY64;

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
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// SSDT patterns for different Windows versions
SSDT_PATTERN g_SSDTPatterns[] = {
    // Windows 10/11 patterns
    {
        (PUCHAR)"\x4C\x8D\x15\x00\x00\x00\x00\x4C\x8D\x1D\x00\x00\x00\x00\x49\x83\xF8",
        (PUCHAR)"xxx????xxx????xxx",
        3,
        "Win10/11 KiSystemServiceStart pattern"
    },
    {
        (PUCHAR)"\x4C\x8D\x15\x00\x00\x00\x00\x4C\x8D\x1D\x00\x00\x00\x00\x41\xFF\xE3",
        (PUCHAR)"xxx????xxx????xxx",
        3,
        "Win10 alternative pattern"
    },
    {
        (PUCHAR)"\x48\x8D\x05\x00\x00\x00\x00\x48\x89\x44\x24\x00\x48\x8D\x05",
        (PUCHAR)"xxx????xxxx?xxx",
        3,
        "Legacy SSDT reference pattern"
    }
};

ULONG g_SSDTPatternCount = sizeof(g_SSDTPatterns) / sizeof(SSDT_PATTERN);

// Method 1: MSR-based approach (IA32_LSTAR contains KiSystemCall64)
struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE* GetSSDTViaMSR()
{
    __try 
    {
        LogToDbgView("Attempting SSDT discovery via MSR (IA32_LSTAR)...\n");
        
        // Read IA32_LSTAR MSR (0xC0000082) which contains KiSystemCall64 address
        ULONG_PTR kiSystemCall64 = __readmsr(0xC0000082);
        
        if (!kiSystemCall64 || !IsAddressInKernelSpace(kiSystemCall64))
        {
            LogToDbgView("Invalid KiSystemCall64 address from MSR: 0x%p\n", (PVOID)kiSystemCall64);
            return NULL;
        }

        LogToDbgView("KiSystemCall64 found via MSR: 0x%p\n", (PVOID)kiSystemCall64);

        // Search for SSDT reference in KiSystemCall64 function
        // Look for the lea instruction that loads SSDT address
        PUCHAR searchBase = (PUCHAR)kiSystemCall64;
        SIZE_T searchSize = 0x1000; // Search within 4KB

        for (ULONG i = 0; i < g_SSDTPatternCount; i++)
        {
            PVOID found = PatternScanKernel((ULONG_PTR)searchBase, searchSize, 
                                          g_SSDTPatterns[i].Pattern, g_SSDTPatterns[i].Mask);
            if (found)
            {
                // Extract relative offset and calculate absolute address
                LONG relativeOffset = *(PLONG)((PUCHAR)found + g_SSDTPatterns[i].Offset);
                ULONG_PTR ssdtAddress = (ULONG_PTR)found + g_SSDTPatterns[i].Offset + 4 + relativeOffset;
                
                struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE* ssdt = (struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE*)ssdtAddress;
                
                if (ValidateSSDTPointer(ssdt))
                {
                    LogToDbgView("SSDT found via MSR method using %s: 0x%p\n", 
                               g_SSDTPatterns[i].Description, ssdt);
                    return ssdt;
                }
            }
        }
        
        LogToDbgView("SSDT pattern not found in KiSystemCall64\n");
        return NULL;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("Exception in GetSSDTViaMSR: 0x%08X\n", GetExceptionCode());
        return NULL;
    }
}

// Method 2: IDT-based approach
PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTViaIDT()
{
    __try
    {
        LogToDbgView("Attempting SSDT discovery via IDT...\n");
        
        IDTR idtr;
        __sidt(&idtr);
        
        if (!idtr.base || idtr.limit < 0x1000)
        {
            LogToDbgView("Invalid IDT detected\n");
            return NULL;
        }
        
        LogToDbgView("IDT base: 0x%p, limit: 0x%04X\n", (PVOID)idtr.base, idtr.limit);
        
        // Get system call interrupt handler (usually interrupt 0x2E or 0x80)
        PIDT_ENTRY64 idtEntry = (PIDT_ENTRY64)idtr.base;
        
        // Check interrupt 0x2E (legacy system call)
        if (idtEntry[0x2E].Present)
        {
            ULONG_PTR handlerAddress = ((ULONG_PTR)idtEntry[0x2E].OffsetHigh << 32) |
                                     ((ULONG_PTR)idtEntry[0x2E].OffsetMiddle << 16) |
                                     idtEntry[0x2E].OffsetLow;
            
            LogToDbgView("System call handler (0x2E): 0x%p\n", (PVOID)handlerAddress);
            
            // Get kernel base from handler address
            ULONG_PTR kernelBase = handlerAddress & ~0xFFFFF; // Align to 1MB boundary
            while (kernelBase >= 0xFFFFF80000000000ULL)
            {
                if (*(PUSHORT)kernelBase == 0x5A4D) // MZ header
                {
                    LogToDbgView("Potential kernel base found via IDT: 0x%p\n", (PVOID)kernelBase);
                    
                    // Try known offsets from this base
                    ULONG_PTR possibleOffsets[] = { 0xE018C0, 0xC018C0, 0xD018C0, 0xF018C0 };
                    
                    for (ULONG i = 0; i < sizeof(possibleOffsets) / sizeof(possibleOffsets[0]); i++)
                    {
                        PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt = 
                            (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)(kernelBase + possibleOffsets[i]);
                        
                        if (ValidateSSDTPointer(ssdt))
                        {
                            LogToDbgView("SSDT found via IDT method: 0x%p\n", ssdt);
                            return ssdt;
                        }
                    }
                }
                kernelBase -= 0x100000; // Move back by 1MB
            }
        }
        
        LogToDbgView("SSDT not found via IDT method\n");
        return NULL;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("Exception in GetSSDTViaIDT: 0x%08X\n", GetExceptionCode());
        return NULL;
    }
}

// Method 3: Module list traversal
PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTViaModuleList()
{
    __try
    {
        LogToDbgView("Attempting SSDT discovery via module list...\n");
        
        // Get ntoskrnl base via PsLoadedModuleList
        ULONG_PTR kernelBase = GetKernelBaseViaModuleList();
        if (!kernelBase)
        {
            LogToDbgView("Failed to get kernel base via module list\n");
            return NULL;
        }
        
        LogToDbgView("Kernel base found via module list: 0x%p\n", (PVOID)kernelBase);
        
        // Try common SSDT offsets
        ULONG_PTR commonOffsets[] = { 
            0xE018C0, 0xC018C0, 0xD018C0, 0xF018C0,  // Win10
            0xE01AC0, 0xC01AC0, 0xD01AC0, 0xF01AC0,  // Win10 variants
            0xE01700, 0xC01700, 0xD01700, 0xF01700   // Other versions
        };
        
        for (ULONG i = 0; i < sizeof(commonOffsets) / sizeof(commonOffsets[0]); i++)
        {
            PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt = 
                (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)(kernelBase + commonOffsets[i]);
            
            if (ValidateSSDTPointer(ssdt))
            {
                LogToDbgView("SSDT found via module list method at offset 0x%08X: 0x%p\n", 
                           commonOffsets[i], ssdt);
                return ssdt;
            }
        }
        
        LogToDbgView("SSDT not found via module list method\n");
        return NULL;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("Exception in GetSSDTViaModuleList: 0x%08X\n", GetExceptionCode());
        return NULL;
    }
}

// Method 4: Export table parsing (if available)
PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTViaExports()
{
    __try
    {
        LogToDbgView("Attempting SSDT discovery via exports...\n");
        
        // Try to get KeServiceDescriptorTable export
        PVOID ssdtExport = GetKernelExport("KeServiceDescriptorTable");
        if (ssdtExport)
        {
            PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)ssdtExport;
            if (ValidateSSDTPointer(ssdt))
            {
                LogToDbgView("SSDT found via exports: 0x%p\n", ssdt);
                return ssdt;
            }
        }
        
        LogToDbgView("SSDT export not found\n");
        return NULL;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("Exception in GetSSDTViaExports: 0x%08X\n", GetExceptionCode());
        return NULL;
    }
}

// Method 5: Intelligent pattern scanning
PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTViaPatternScan()
{
    __try
    {
        LogToDbgView("Attempting SSDT discovery via pattern scanning...\n");
        
        ULONG_PTR kernelBase = GetNtoskrnlBase();
        if (!kernelBase)
        {
            LogToDbgView("Failed to get kernel base for pattern scanning\n");
            return NULL;
        }
        
        // Scan in text section (usually first 2MB)
        SIZE_T scanSize = 0x200000;
        
        for (ULONG i = 0; i < g_SSDTPatternCount; i++)
        {
            LogToDbgView("Trying pattern %u: %s\n", i, g_SSDTPatterns[i].Description);
            
            PVOID found = PatternScanKernel(kernelBase, scanSize, 
                                          g_SSDTPatterns[i].Pattern, g_SSDTPatterns[i].Mask);
            if (found)
            {
                LogToDbgView("Pattern found at: 0x%p\n", found);
                
                // Extract SSDT address from pattern
                LONG relativeOffset = *(PLONG)((PUCHAR)found + g_SSDTPatterns[i].Offset);
                ULONG_PTR ssdtAddress = (ULONG_PTR)found + g_SSDTPatterns[i].Offset + 4 + relativeOffset;
                
                struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE* ssdt = (struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE*)ssdtAddress;
                
                if (ValidateSSDTPointer(ssdt))
                {
                    LogToDbgView("SSDT found via pattern scan: 0x%p\n", ssdt);
                    return ssdt;
                }
                else
                {
                    LogToDbgView("Invalid SSDT pointer from pattern: 0x%p\n", ssdt);
                }
            }
        }
        
        LogToDbgView("No valid SSDT found via pattern scanning\n");
        return NULL;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("Exception in GetSSDTViaPatternScan: 0x%08X\n", GetExceptionCode());
        return NULL;
    }
}

// Multi-method SSDT finder - tries all methods
PSYSTEM_SERVICE_DESCRIPTOR_TABLE FindSSDTAdvanced()
{
    LogToDbgView("========== Advanced SSDT Discovery ==========\n");
    
    PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt = NULL;
    
    // Method 1: MSR-based (most reliable for modern Windows)
    ssdt = GetSSDTViaMSR();
    if (ssdt) 
    {
        LogToDbgView("✓ SSDT found via MSR method\n");
        return ssdt;
    }
    
    // Method 2: Export table (if available)
    ssdt = GetSSDTViaExports();
    if (ssdt)
    {
        LogToDbgView("✓ SSDT found via exports method\n");
        return ssdt;
    }
    
    // Method 3: Module list traversal
    ssdt = GetSSDTViaModuleList();
    if (ssdt)
    {
        LogToDbgView("✓ SSDT found via module list method\n");
        return ssdt;
    }
    
    // Method 4: IDT-based
    ssdt = GetSSDTViaIDT();
    if (ssdt)
    {
        LogToDbgView("✓ SSDT found via IDT method\n");
        return ssdt;
    }
    
    // Method 5: Pattern scanning (last resort)
    ssdt = GetSSDTViaPatternScan();
    if (ssdt)
    {
        LogToDbgView("✓ SSDT found via pattern scanning\n");
        return ssdt;
    }
    
    LogToDbgView("✗ All SSDT discovery methods failed\n");
    return NULL;
}

// Helper function implementations
BOOLEAN ValidateSSDTPointer(PSYSTEM_SERVICE_DESCRIPTOR_TABLE Ssdt)
{
    if (!Ssdt || !IsAddressInKernelSpace((ULONG_PTR)Ssdt))
        return FALSE;
        
    __try
    {
        // Check if ServiceTableBase is valid
        if (!Ssdt->ServiceTableBase || !IsAddressInKernelSpace((ULONG_PTR)Ssdt->ServiceTableBase))
            return FALSE;
            
        // Check if NumberOfServices is reasonable (typically 300-500)
        if (Ssdt->NumberOfServices == 0 || Ssdt->NumberOfServices > 1000)
            return FALSE;
            
        // Validate a few service table entries
        for (ULONG i = 0; i < min(10, Ssdt->NumberOfServices); i++)
        {
            ULONG_PTR serviceAddress = Ssdt->ServiceTableBase[i];
            if (!IsValidSSDTEntry(serviceAddress))
                return FALSE;
        }
        
        return TRUE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

BOOLEAN IsAddressInKernelSpace(ULONG_PTR Address)
{
    return (Address >= 0xFFFF800000000000ULL);
}

BOOLEAN IsValidSSDTEntry(ULONG_PTR Address)
{
    // For Windows 10+, SSDT entries are encoded
    if (Address == 0)
        return FALSE;
        
    // Basic kernel address range check
    return IsAddressInKernelSpace(Address);
}

ULONG_PTR GetKernelBaseViaModuleList()
{
    __try
    {
        // Get PsLoadedModuleList
        PLIST_ENTRY moduleList = (PLIST_ENTRY)GetKernelExport("PsLoadedModuleList");
        if (!moduleList)
            return 0;
            
        // First entry should be ntoskrnl
        PLDR_DATA_TABLE_ENTRY firstModule = CONTAINING_RECORD(moduleList->Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        
        if (firstModule && firstModule->DllBase)
        {
            LogToDbgView("Kernel module found: %wZ at 0x%p\n", &firstModule->BaseDllName, firstModule->DllBase);
            return (ULONG_PTR)firstModule->DllBase;
        }
        
        return 0;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
}

ULONG_PTR GetNtoskrnlBase()
{
    // Try multiple methods to get kernel base
    ULONG_PTR base;
    
    base = GetKernelBaseViaModuleList();
    if (base) return base;
    
    base = GetKernelBaseViaIDT();
    if (base) return base;
    
    base = GetKernelBaseViaMSR();
    if (base) return base;
    
    return 0;
}

ULONG_PTR GetKernelBaseViaMSR()
{
    __try
    {
        ULONG_PTR kiSystemCall64 = __readmsr(0xC0000082);
        if (kiSystemCall64)
        {
            // Align to potential module boundary
            ULONG_PTR base = kiSystemCall64 & ~0xFFFFF;
            while (base >= 0xFFFFF80000000000ULL)
            {
                if (*(PUSHORT)base == 0x5A4D) // MZ header
                {
                    return base;
                }
                base -= 0x100000;
            }
        }
        return 0;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
}

ULONG_PTR GetKernelBaseViaIDT()
{
    __try
    {
        IDTR idtr;
        __sidt(&idtr);
        
        if (idtr.base)
        {
            PIDT_ENTRY64 idtEntry = (PIDT_ENTRY64)idtr.base;
            if (idtEntry[0x2E].Present)
            {
                ULONG_PTR handlerAddress = ((ULONG_PTR)idtEntry[0x2E].OffsetHigh << 32) |
                                         ((ULONG_PTR)idtEntry[0x2E].OffsetMiddle << 16) |
                                         idtEntry[0x2E].OffsetLow;
                
                ULONG_PTR base = handlerAddress & ~0xFFFFF;
                while (base >= 0xFFFFF80000000000ULL)
                {
                    if (*(PUSHORT)base == 0x5A4D)
                    {
                        return base;
                    }
                    base -= 0x100000;
                }
            }
        }
        return 0;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
}

PVOID PatternScanKernel(ULONG_PTR BaseAddress, SIZE_T Size, PUCHAR Pattern, PUCHAR Mask)
{
    __try
    {
        SIZE_T patternLength = strlen((PCSTR)Mask);
        
        for (SIZE_T i = 0; i <= Size - patternLength; i++)
        {
            BOOLEAN found = TRUE;
            for (SIZE_T j = 0; j < patternLength; j++)
            {
                if (Mask[j] == 'x' && ((PUCHAR)(BaseAddress + i))[j] != Pattern[j])
                {
                    found = FALSE;
                    break;
                }
            }
            
            if (found)
            {
                return (PVOID)(BaseAddress + i);
            }
        }
        
        return NULL;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return NULL;
    }
}

PVOID GetKernelExport(PCSTR ExportName)
{
    // This is a simplified implementation
    // In KDMapper context, standard APIs might not be available
    UNREFERENCED_PARAMETER(ExportName);
    return NULL;
}

