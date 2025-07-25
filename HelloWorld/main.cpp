#include <ntifs.h>
#include <ntddk.h>
#include "infinityhook.h"
#include "callbacks.h"

// Global driver object
PDRIVER_OBJECT g_DriverObject = NULL;

// Driver unload routine
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    
    LogToDbgView("Driver unloading...\n");
    
    // Uninitialize callbacks only (SSDT hooks removed)
    UninitializeCallbacks();
    
    LogToDbgView("Driver unloaded successfully\n");
    
    // Uninitialize file logging
    UninitializeFileLogging();
}

// The code below is executed when the driver is loaded or unloaded.
NTSTATUS CustomDriverEntry(
    _In_ PDRIVER_OBJECT  kdmapperParam1,
    _In_ PUNICODE_STRING kdmapperParam2
)
{
    UNREFERENCED_PARAMETER(kdmapperParam2);
    
    g_DriverObject = kdmapperParam1;
    
    // Set unload routine (even though kdmapper doesn't use it normally)
    if (kdmapperParam1)
    {
        kdmapperParam1->DriverUnload = DriverUnload;
    }
    
    // Initialize file logging first (MUST have file output)
    NTSTATUS status = InitializeFileLogging();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
            "[EAC-MONITOR] Failed to initialize file logging: 0x%08X\n", status);
        // Continue anyway, but file logging is required so we'll keep trying
    }
    
    LogToDbgView("EAC Monitor Driver loading...\n");
    LogToDbgView("File logging enabled - logs will be saved to C:\\\n");
    
    BOOLEAN hasAnyMonitoring = FALSE;
    
    // Try kernel callbacks first (safer than SSDT)
    LogToDbgView("========== Method 1: Kernel Callbacks ==========\n");
    LogToDbgView("DriverObject (kdmapperParam1): %p\n", kdmapperParam1);
    LogToDbgView("g_DriverObject: %p\n", g_DriverObject);
    __try
    {
        // Pass the driver object to InitializeCallbacks for ValidSection bypass
        status = InitializeCallbacks(kdmapperParam1);
        if (NT_SUCCESS(status))
        {
            LogToDbgView("✓ Kernel callbacks initialized successfully\n");
            hasAnyMonitoring = TRUE;
        }
        else
        {
            LogToDbgView("✗ Kernel callbacks failed: 0x%08X\n", status);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("✗ Kernel callbacks caused exception: 0x%08X\n", GetExceptionCode());
    }
    
    // SSDT hooks removed as requested - using only kernel callbacks
    
    // Final status
    if (hasAnyMonitoring)
    {
        LogToDbgView("[SUCCESS] EAC Monitor Driver loaded successfully\n");
        LogToDbgView("All monitoring methods active - EAC activity will be logged\n");
    }
    else
    {
        LogToDbgView("[WARNING] EAC Monitor Driver loaded with limited functionality\n");
        LogToDbgView("Basic logging is still active\n");
    }
    
    return STATUS_SUCCESS;
}