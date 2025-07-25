#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>

// Forward declaration
struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE;
typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE* PSSDT_TABLE;

// Advanced SSDT discovery methods
typedef struct _ADVANCED_SSDT_METHODS
{
    PSSDT_TABLE (*GetSSDTViaMSR)(void);
    PSSDT_TABLE (*GetSSDTViaIDT)(void);
    PSSDT_TABLE (*GetSSDTViaKiSystemCall)(void);
    PSSDT_TABLE (*GetSSDTViaModuleList)(void);
    PSSDT_TABLE (*GetSSDTViaPatternScan)(void);
    PSSDT_TABLE (*GetSSDTViaExports)(void);
} ADVANCED_SSDT_METHODS, *PADVANCED_SSDT_METHODS;

// Method 1: MSR-based kernel base detection
struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE* GetSSDTViaMSR();
ULONG_PTR GetKernelBaseViaMSR();

// Method 2: IDT-based SSDT discovery  
struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE* GetSSDTViaIDT();
ULONG_PTR GetKernelBaseViaIDT();

// Method 3: KiSystemCall64 function analysis
struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE* GetSSDTViaKiSystemCall();
PVOID FindKiSystemCall64();

// Method 4: Module list traversal
struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE* GetSSDTViaModuleList();
ULONG_PTR GetKernelBaseViaModuleList();

// Method 5: Intelligent pattern scanning
struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE* GetSSDTViaPatternScan();
PVOID PatternScanKernel(ULONG_PTR BaseAddress, SIZE_T Size, PUCHAR Pattern, PUCHAR Mask);

// Method 6: Export table parsing
struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE* GetSSDTViaExports();
PVOID GetKernelExport(PCSTR ExportName);

// Helper functions
BOOLEAN ValidateSSDTPointer(struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE* Ssdt);
ULONG_PTR GetNtoskrnlBaseAdvanced();
BOOLEAN IsAddressInKernelSpace(ULONG_PTR Address);
BOOLEAN IsValidSSDTEntry(ULONG_PTR Address);

// Stealth utilities
VOID DisableWriteProtectionAdvanced();
VOID EnableWriteProtectionAdvanced();
BOOLEAN IsDebuggerPresent();
BOOLEAN IsVirtualMachine();

// Multi-method SSDT finder
struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE* FindSSDTAdvanced();

// Pattern definitions for different Windows versions
typedef struct _SSDT_PATTERN
{
    PUCHAR Pattern;
    PUCHAR Mask;
    ULONG Offset;
    PCSTR Description;
} SSDT_PATTERN, *PSSDT_PATTERN;

extern SSDT_PATTERN g_SSDTPatterns[];
extern ULONG g_SSDTPatternCount;