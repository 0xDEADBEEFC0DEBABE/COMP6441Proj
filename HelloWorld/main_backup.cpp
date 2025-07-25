#include <ntifs.h>
#include <ntddk.h>
#include "infinityhook.h"
// Remove hooks.h for now - test if this causes BSOD

// Forward declare only what we need
extern PVOID g_OriginalNtOpenProcess;
NTSTATUS NTAPI HookedNtOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);

PDRIVER_OBJECT g_DriverObject = NULL;

// Driver unload routine
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
        "[EAC-MONITOR] Driver unloading...\n");
}

// The code below is executed when the driver is loaded or unloaded.
NTSTATUS CustomDriverEntry(
    _In_ PDRIVER_OBJECT  kdmapperParam1,
    _In_ PUNICODE_STRING kdmapperParam2
)
{
    UNREFERENCED_PARAMETER(kdmapperParam2);
    
    // Test with infinityhook.h included
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
        "[EAC-MONITOR] TEST 1: Entry point reached with infinityhook.h\n");
    
    g_DriverObject = kdmapperParam1;
    
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
        "[EAC-MONITOR] TEST 2: Driver object assignment done\n");
    
    // Test InitializeFileLogging function
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
        "[EAC-MONITOR] TEST 3: About to test InitializeFileLogging\n");
    
    __try
    {
        NTSTATUS status = InitializeFileLogging();
        if (NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
                "[EAC-MONITOR] TEST 4: InitializeFileLogging SUCCESS\n");
        }
        else
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
                "[EAC-MONITOR] TEST 4: InitializeFileLogging FAILED: 0x%08X\n", status);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
            "[EAC-MONITOR] TEST 4: InitializeFileLogging EXCEPTION: 0x%08X\n", GetExceptionCode());
    }
    
    // Test LogToDbgView with file logging enabled
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
        "[EAC-MONITOR] TEST 5: About to test LogToDbgView with file logging\n");
    
    __try
    {
        LogToDbgView("TEST: LogToDbgView with file logging enabled\n");
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
            "[EAC-MONITOR] TEST 6: LogToDbgView with file logging SUCCESS\n");
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
            "[EAC-MONITOR] TEST 6: LogToDbgView with file logging EXCEPTION: 0x%08X\n", GetExceptionCode());
    }
    
    // Test SSDT initialization
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
        "[EAC-MONITOR] TEST 8: About to test SSDT initialization\n");
    LogToDbgView("TEST 8: Testing SSDT initialization...\n");
    
    __try
    {
        NTSTATUS status = InitializeInfinityHook();
        if (NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
                "[EAC-MONITOR] TEST 9: SSDT initialization SUCCESS\n");
            LogToDbgView("TEST 9: SSDT initialization SUCCESS\n");
        }
        else
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
                "[EAC-MONITOR] TEST 9: SSDT initialization FAILED: 0x%08X\n", status);
            LogToDbgView("TEST 9: SSDT initialization FAILED: 0x%08X\n", status);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
            "[EAC-MONITOR] TEST 9: SSDT initialization EXCEPTION: 0x%08X\n", GetExceptionCode());
        LogToDbgView("TEST 9: SSDT initialization EXCEPTION: 0x%08X\n", GetExceptionCode());
    }
    
    // Test single hook installation
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
        "[EAC-MONITOR] TEST 11: About to test single hook installation\n");
    LogToDbgView("TEST 11: Testing single hook installation...\n");
    
    __try
    {
        NTSTATUS status = HookSyscall(SYSCALL_NTOPENPROCESS, (PVOID)HookedNtOpenProcess, &g_OriginalNtOpenProcess);
        if (NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
                "[EAC-MONITOR] TEST 12: Single hook SUCCESS\n");
            LogToDbgView("TEST 12: NtOpenProcess hook installed successfully\n");
        }
        else
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
                "[EAC-MONITOR] TEST 12: Single hook FAILED: 0x%08X\n", status);
            LogToDbgView("TEST 12: NtOpenProcess hook FAILED: 0x%08X\n", status);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
            "[EAC-MONITOR] TEST 12: Single hook EXCEPTION: 0x%08X\n", GetExceptionCode());
        LogToDbgView("TEST 12: Single hook EXCEPTION: 0x%08X\n", GetExceptionCode());
    }
    
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
        "[EAC-MONITOR] TEST 13: About to return SUCCESS\n");
    LogToDbgView("TEST 13: All tests complete - driver ready for EAC monitoring\n");
    
    return STATUS_SUCCESS;
}