#include <ntifs.h>
#include <ntddk.h>

// Add only the basic SSDT structure definition
typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE
{
    PULONG_PTR ServiceTableBase;
    PULONG ServiceCounterTableBase;
    ULONG_PTR NumberOfServices;
    PUCHAR ParamTableBase;
} SYSTEM_SERVICE_DESCRIPTOR_TABLE, *PSYSTEM_SERVICE_DESCRIPTOR_TABLE;

// Add only essential global variables (no external declarations yet)
PSYSTEM_SERVICE_DESCRIPTOR_TABLE g_SSDT = NULL;
BOOLEAN g_FileLoggingEnabled = FALSE;
PDRIVER_OBJECT g_TestDriverObject = NULL;

VOID TestDriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
        "[TEST] Driver unloading...\n");
}

NTSTATUS CustomDriverEntry(
    _In_ PDRIVER_OBJECT  kdmapperParam1,
    _In_ PUNICODE_STRING kdmapperParam2
)
{
    UNREFERENCED_PARAMETER(kdmapperParam2);
    
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
        "[TEST] Step 1: Entry with SSDT structure definition\n");
    
    g_TestDriverObject = kdmapperParam1;
    g_FileLoggingEnabled = FALSE;
    g_SSDT = NULL;
    
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
        "[TEST] Step 2: Global variables initialized\n");
    
    if (kdmapperParam1)
    {
        kdmapperParam1->DriverUnload = TestDriverUnload;
    }
    
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
        "[TEST] Step 3: Driver ready with basic SSDT support\n");
    
    return STATUS_SUCCESS;
}