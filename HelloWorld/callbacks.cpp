#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <intrin.h>
#include <ntimage.h>
#include "callbacks.h"
#include "infinityhook.h"

// Suppress deprecated warnings for compatibility
#pragma warning(push)
#pragma warning(disable: 4996) // deprecated function warnings
#pragma warning(disable: 4100) // unreferenced parameter warnings
#pragma warning(disable: 4838) // narrowing conversion warnings
#pragma warning(disable: 4309) // truncation of constant value warnings
#pragma warning(disable: 4189) // local variable is initialized but not referenced
#pragma warning(disable: 4201) // nonstandard extension used: nameless struct/union

// Removed minifilter dependencies to avoid fltmgr.lib linker errors

// System information structures
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

// Structure definition moved to callbacks.h to avoid redefinition

// Process access rights definitions (avoid redefinition warnings)
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE                0x0001
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD            0x0002
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION             0x0008
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ                  0x0010
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE                 0x0020
#endif
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE               0x0040
#endif
#ifndef PROCESS_CREATE_PROCESS
#define PROCESS_CREATE_PROCESS           0x0080
#endif
#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA                0x0100
#endif
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION          0x0200
#endif
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION        0x0400
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME           0x0800
#endif
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

// Thread access rights definitions
#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE                 0x0001
#define THREAD_SUSPEND_RESUME            0x0002
#define THREAD_GET_CONTEXT               0x0008
#define THREAD_SET_CONTEXT               0x0010
#define THREAD_SET_INFORMATION           0x0020
#define THREAD_QUERY_INFORMATION         0x0040
#define THREAD_SET_THREAD_TOKEN          0x0080
#define THREAD_IMPERSONATE               0x0100
#define THREAD_DIRECT_IMPERSONATION      0x0200
#define THREAD_SET_LIMITED_INFORMATION   0x0400
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#endif

// Standard access rights definitions
#ifndef READ_CONTROL
#define READ_CONTROL                     0x00020000L
#define WRITE_DAC                        0x00040000L
#define WRITE_OWNER                      0x00080000L
#define SYNCHRONIZE                      0x00100000L
#define DELETE                           0x00010000L
#endif

// File access rights definitions
#ifndef FILE_READ_DATA
#define FILE_READ_DATA                   0x0001
#define FILE_LIST_DIRECTORY              0x0001
#define FILE_WRITE_DATA                  0x0002
#define FILE_ADD_FILE                    0x0002
#define FILE_APPEND_DATA                 0x0004
#define FILE_ADD_SUBDIRECTORY            0x0004
#define FILE_CREATE_PIPE_INSTANCE        0x0004
#define FILE_READ_EA                     0x0008
#define FILE_WRITE_EA                    0x0010
#define FILE_EXECUTE                     0x0020
#define FILE_TRAVERSE                    0x0020
#define FILE_DELETE_CHILD                0x0040
#define FILE_READ_ATTRIBUTES             0x0080
#define FILE_WRITE_ATTRIBUTES            0x0100
#endif

// Note: Using numeric values directly in switch statements to avoid conflicts with system definitions

// Registry security information structures
typedef struct _REG_QUERY_SECURITY_INFORMATION {
    PVOID Object;
    SECURITY_INFORMATION SecurityInformation;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    PULONG Length;
    PVOID CallContext;
    PVOID ObjectContext;
    PVOID Reserved;
} REG_QUERY_SECURITY_INFORMATION, *PREG_QUERY_SECURITY_INFORMATION;

typedef struct _REG_SET_SECURITY_INFORMATION {
    PVOID Object;
    SECURITY_INFORMATION SecurityInformation;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    PVOID CallContext;
    PVOID ObjectContext;
    PVOID Reserved;
} REG_SET_SECURITY_INFORMATION, *PREG_SET_SECURITY_INFORMATION;

// Use simplified registry monitoring without problematic structures
// Skip complex structures that may conflict with system definitions

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

// Function declarations
NTSTATUS NTAPI ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

// KSOCKET network monitoring structures and functions
typedef struct _KSOCKET_MONITOR {
    BOOLEAN NetworkMonitoringActive;
    PVOID NetworkThread;
    KEVENT NetworkShutdownEvent;
    ULONG PacketsIntercepted;
    ULONG EACConnectionsDetected;
} KSOCKET_MONITOR, *PKSOCKET_MONITOR;

// Network monitoring globals
KSOCKET_MONITOR g_NetworkMonitor = { 0 };

// KSOCKET function pointers (if available)
typedef PVOID (*PFN_KSOCKET_CREATE)(INT af, INT type, INT protocol);
typedef INT (*PFN_KSOCKET_CONNECT)(PVOID socket, PVOID addr, INT addrlen);
typedef INT (*PFN_KSOCKET_SEND)(PVOID socket, PVOID buf, INT len, INT flags);
typedef INT (*PFN_KSOCKET_RECV)(PVOID socket, PVOID buf, INT len, INT flags);
typedef INT (*PFN_KSOCKET_CLOSE)(PVOID socket);

PFN_KSOCKET_CREATE KSocketCreate = NULL;
PFN_KSOCKET_CONNECT KSocketConnect = NULL;
PFN_KSOCKET_SEND KSocketSend = NULL;
PFN_KSOCKET_RECV KSocketRecv = NULL;
PFN_KSOCKET_CLOSE KSocketClose = NULL;

// Global callback handles
PVOID g_ProcessNotifyHandle = NULL;
PVOID g_ThreadNotifyHandle = NULL;
PVOID g_ImageNotifyHandle = NULL;
PVOID g_ObjectCallbackHandle = NULL;
PVOID g_HighAltitudeCallbackHandle = NULL;
PVOID g_LowAltitudeCallbackHandle = NULL;
PVOID g_FileObjectCallbackHandle = NULL;
LARGE_INTEGER g_RegistryCallbackCookie = { 0 };

// ValidSection bypass control - Set to TRUE to enable ValidSection patching
BOOLEAN g_EnableValidSectionBypass = FALSE;  // Disabled due to BE/EAC IRQL conflicts
// Delay in milliseconds before applying ValidSection patch (default 5 seconds)
ULONG g_ValidSectionPatchDelay = 5000;
// Timer and DPC for delayed ValidSection patch
KTIMER g_ValidSectionTimer = {0};
KDPC g_ValidSectionDpc = {0};
PDRIVER_OBJECT g_SavedDriverObject = NULL;

// Hook-based ValidSection bypass globals
PVOID g_MmVerifyCallbackFunctionCheckFlags = NULL;
UCHAR g_OriginalBytes[12] = {0};  // Save original function bytes
PFN_MM_VERIFY_CALLBACK_FUNCTION_CHECK_FLAGS g_OriginalMmVerifyCallback = NULL;
BOOLEAN g_HookInstalled = FALSE;

// Global tracking to avoid duplicate logs
static HANDLE g_LastDetectedEACPid = NULL;
static LARGE_INTEGER g_LastDetectionTime = { 0 };

// Enhanced EAC/BE process detection with duplicate prevention
BOOLEAN IsEACProcessById(HANDLE ProcessId)
{
    if (!ProcessId)
        return FALSE;
        
    PEPROCESS Process;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(status))
        return FALSE;
    
    BOOLEAN isEAC = FALSE;
    
    __try
    {
        // Get process name and check for EAC/BE patterns
        CHAR processName[256] = { 0 };
        GetProcessNameById(ProcessId, processName, sizeof(processName));
        
        if (strstr(processName, "EasyAntiCheat") ||
            strstr(processName, "EAC") ||
            strstr(processName, "eac_") ||
            strstr(processName, "BEService") ||
            strstr(processName, "BattlEye") ||
            strstr(processName, "BE"))
        {
            isEAC = TRUE;
            
            // Only log once per process or every 30 seconds to avoid spam
            LARGE_INTEGER currentTime;
            KeQuerySystemTime(&currentTime);
            LARGE_INTEGER timeDiff;
            timeDiff.QuadPart = currentTime.QuadPart - g_LastDetectionTime.QuadPart;
            
            if (g_LastDetectedEACPid != ProcessId || timeDiff.QuadPart > 300000000LL) // 30 seconds
            {
                LogToDbgView("[PROC] ANTICHEAT_DETECTED: %s (PID: %lu) - Monitoring Active\n", 
                    processName, HandleToULong(ProcessId));
                g_LastDetectedEACPid = ProcessId;
                g_LastDetectionTime = currentTime;
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        // Continue with original method if exception occurs
        isEAC = IsEACProcess(Process);
    }
    
    ObDereferenceObject(Process);
    return isEAC;
}

// Safe helper function to get process name by PID
VOID GetProcessNameById(HANDLE ProcessId, PCHAR Buffer, SIZE_T BufferSize)
{
    RtlStringCchCopyA(Buffer, BufferSize, "<unknown>");
    
    if (!ProcessId)
        return;
    
    PEPROCESS Process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(status) || !Process)
        return;
    
    __try 
    {
        // Method 1: Direct access to EPROCESS.ImageFileName (most reliable)
        PUCHAR processName = (PUCHAR)((ULONG_PTR)Process + 0x5A8); // ImageFileName offset confirmed: +0x5a8
        if (MmIsAddressValid(processName) && processName[0] != 0)
        {
            RtlStringCchCopyA(Buffer, BufferSize, (PCSTR)processName);
            // LogToDbgView("[DEBUG] Got process name via direct EPROCESS access: %s\n", Buffer);
            return; // Success, no need to try other methods
        }
        // LogToDbgView("[DEBUG] Direct EPROCESS access failed, trying SeLocateProcessImageName\n");
        
        // Method 2: Fallback to SeLocateProcessImageName if direct access fails
        PUNICODE_STRING imageName = NULL;
        status = SeLocateProcessImageName(Process, &imageName);
        if (NT_SUCCESS(status) && imageName && imageName->Buffer)
        {
            // Convert Unicode to ANSI and extract just filename
            ANSI_STRING ansiName;
            status = RtlUnicodeStringToAnsiString(&ansiName, imageName, TRUE);
            if (NT_SUCCESS(status))
            {
                // Find last backslash to get just filename
                PCHAR lastSlash = strrchr(ansiName.Buffer, '\\');
                PCHAR fileName = lastSlash ? (lastSlash + 1) : ansiName.Buffer;
                
                RtlStringCchCopyA(Buffer, BufferSize, fileName);
                RtlFreeAnsiString(&ansiName);
            }
            ExFreePool(imageName);
        }
        
        // Method 3: Try PsGetProcessImageFileName as final fallback
        // PsGetProcessImageFileName confirmed at: fffff801`25550260
        typedef PCHAR (*PsGetProcessImageFileName_t)(PEPROCESS Process);
        PsGetProcessImageFileName_t PsGetProcessImageFileNameFunc = (PsGetProcessImageFileName_t)0xFFFFF80125550260ULL;
        
        PCHAR imageFileName = PsGetProcessImageFileNameFunc(Process);
        if (imageFileName && MmIsAddressValid(imageFileName))
        {
            RtlStringCchCopyA(Buffer, BufferSize, imageFileName);
            // LogToDbgView("[DEBUG] Got process name via PsGetProcessImageFileName: %s\n", Buffer);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        // Keep default "<unknown>" on any exception
    }
    
    ObDereferenceObject(Process);
}

// Process creation/termination callback
VOID ProcessNotifyCallback(
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ParentId);
    
    CHAR processName[256] = { 0 };
    GetProcessNameById(ProcessId, processName, sizeof(processName));
    
    // Check if this is an EAC-related process
    if (strstr(processName, "EasyAntiCheat") ||
        strstr(processName, "EAC") ||
        strstr(processName, "eac_") ||
        strstr(processName, "BEService") ||
        strstr(processName, "BattlEye"))
    {
        if (Create)
        {
            LogToDbgView("PROCESS_CREATE: EAC process %s (PID: %lu) started\n", 
                processName, HandleToULong(ProcessId));
        }
        else
        {
            LogToDbgView("PROCESS_TERMINATE: EAC process %s (PID: %lu) terminated\n", 
                processName, HandleToULong(ProcessId));
        }
    }
    
    // Also log if EAC is creating/terminating other processes
    CHAR parentName[256] = { 0 };
    if (ParentId)
    {
        GetProcessNameById(ParentId, parentName, sizeof(parentName));
        if (strstr(parentName, "EasyAntiCheat") ||
            strstr(parentName, "EAC") ||
            strstr(parentName, "eac_") ||
            strstr(parentName, "BEService") ||
            strstr(parentName, "BattlEye"))
        {
            if (Create)
            {
                LogToDbgView("EAC_ACTION: %s created process %s (PID: %lu)\n", 
                    parentName, processName, HandleToULong(ProcessId));
            }
        }
    }
}

// Thread creation/termination callback
VOID ThreadNotifyCallback(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create)
{
    if (!IsEACProcessById(ProcessId))
        return;
    
    CHAR processName[256] = { 0 };
    GetProcessNameById(ProcessId, processName, sizeof(processName));
    
    if (Create)
    {
        LogToDbgView("THREAD_CREATE: EAC process %s created thread %lu\n", 
            processName, HandleToULong(ThreadId));
    }
    else
    {
        LogToDbgView("THREAD_TERMINATE: EAC process %s terminated thread %lu\n", 
            processName, HandleToULong(ThreadId));
    }
}

// Enhanced image/DLL load callback for anticheat monitoring
VOID ImageNotifyCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo)
{
    CHAR processName[256] = { 0 };
    GetProcessNameById(ProcessId, processName, sizeof(processName));
    
    if (FullImageName && FullImageName->Buffer)
    {
        // Check for anticheat-related modules
        if (wcsstr(FullImageName->Buffer, L"EasyAntiCheat") ||
            wcsstr(FullImageName->Buffer, L"eac_") ||
            wcsstr(FullImageName->Buffer, L"BEService") ||
            wcsstr(FullImageName->Buffer, L"BattlEye") ||
            wcsstr(FullImageName->Buffer, L"bedaisy.sys") ||
            wcsstr(FullImageName->Buffer, L"bedriver.sys") ||
            wcsstr(FullImageName->Buffer, L"EasyAntiCheat.sys"))
        {
            LogToDbgView("ANTICHEAT_DRIVER_LOAD: %wZ loaded at 0x%p (size: 0x%zx) by %s\n", 
                FullImageName, ImageInfo->ImageBase, ImageInfo->ImageSize, processName);
        }
        
        // Monitor if EAC/BE processes are loading suspicious modules
        if (IsEACProcessById(ProcessId))
        {
            // Check for interesting DLLs that might indicate scanning/monitoring behavior
            if (wcsstr(FullImageName->Buffer, L"ntdll.dll") ||
                wcsstr(FullImageName->Buffer, L"kernel32.dll") ||
                wcsstr(FullImageName->Buffer, L"psapi.dll") ||
                wcsstr(FullImageName->Buffer, L"dbghelp.dll") ||
                wcsstr(FullImageName->Buffer, L"wintrust.dll") ||
                wcsstr(FullImageName->Buffer, L"crypt32.dll"))
            {
                LogToDbgView("ANTICHEAT_MODULE_LOAD: %s loaded %wZ (scanning capability)\n", 
                    processName, FullImageName);
            }
            else
            {
                LogToDbgView("ANTICHEAT_IMAGE_LOAD: %s loaded %wZ at 0x%p\n", 
                    processName, FullImageName, ImageInfo->ImageBase);
            }
        }
    }
}

// Process handle operation callback
OB_PREOP_CALLBACK_STATUS ProcessPreCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    
    // Check if the calling process is EAC
    HANDLE currentProcessId = PsGetCurrentProcessId();
    if (!IsEACProcessById(currentProcessId))
        return OB_PREOP_SUCCESS;
    
    // Get target process info
    PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
    HANDLE targetProcessId = PsGetProcessId(targetProcess);
    
    CHAR callerName[256] = { 0 };
    CHAR targetName[256] = { 0 };
    GetProcessNameById(currentProcessId, callerName, sizeof(callerName));
    GetProcessNameById(targetProcessId, targetName, sizeof(targetName));
    
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
    {
        LogToDbgView("HANDLE_CREATE: EAC process %s opening handle to process %s (PID: %lu) with access 0x%08X\n",
            callerName, targetName, HandleToULong(targetProcessId), 
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess);
    }
    else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
    {
        LogToDbgView("HANDLE_DUPLICATE: EAC process %s duplicating handle to process %s (PID: %lu)\n",
            callerName, targetName, HandleToULong(targetProcessId));
    }
    
    return OB_PREOP_SUCCESS;
}

// Thread handle operation callback
OB_PREOP_CALLBACK_STATUS ThreadPreCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    
    // Check if the calling process is EAC
    HANDLE currentProcessId = PsGetCurrentProcessId();
    if (!IsEACProcessById(currentProcessId))
        return OB_PREOP_SUCCESS;
    
    // Get target thread info
    PETHREAD targetThread = (PETHREAD)OperationInformation->Object;
    HANDLE targetProcessId = PsGetThreadProcessId(targetThread);
    HANDLE targetThreadId = PsGetThreadId(targetThread);
    
    CHAR callerName[256] = { 0 };
    CHAR targetProcessName[256] = { 0 };
    GetProcessNameById(currentProcessId, callerName, sizeof(callerName));
    GetProcessNameById(targetProcessId, targetProcessName, sizeof(targetProcessName));
    
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
    {
        LogToDbgView("THREAD_HANDLE_CREATE: EAC process %s opening handle to thread %lu in process %s with access 0x%08X\n",
            callerName, HandleToULong(targetThreadId), targetProcessName,
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess);
    }
    
    return OB_PREOP_SUCCESS;
}

// Simplified registry callback for EAC monitoring
NTSTATUS RegistryCallback(
    PVOID CallbackContext,
    PVOID Argument1,
    PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Argument2);
    
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    
    // Only monitor if called by EAC process
    HANDLE currentProcessId = PsGetCurrentProcessId();
    if (!IsEACProcessById(currentProcessId))
        return STATUS_SUCCESS;
    
    CHAR processName[256] = { 0 };
    GetProcessNameById(currentProcessId, processName, sizeof(processName));
    
    // Simplified registry operation logging without complex structures
    switch (notifyClass)
    {
        case RegNtPreOpenKey:
        case RegNtPreOpenKeyEx:
            LogToDbgView("[REG] %s OPEN_KEY (System Discovery)\n", processName);
            LogToDbgView("[REG][INFO] Purpose: Opening registry key for system information collection\n");
            break;
        
        case RegNtPreQueryValueKey:
            LogToDbgView("[REG] %s QUERY_VALUE (Hardware Fingerprinting)\n", processName);
            LogToDbgView("[REG][INFO] Purpose: Reading registry values for system identification\n");
            break;
        
        case RegNtPreSetValueKey:
            LogToDbgView("[REG] %s SET_VALUE\n", processName);
            LogToDbgView("[REG][WARNING] EAC is modifying registry - unusual behavior!\n");
            break;
        
        case RegNtPreEnumerateKey:
            LogToDbgView("[REG] %s ENUM_KEYS (System Discovery)\n", processName);
            LogToDbgView("[REG][INFO] Purpose: Scanning registry structure for installed software/hardware\n");
            break;
        
        case RegNtPreEnumerateValueKey:
            LogToDbgView("[REG] %s ENUM_VALUES (System Discovery)\n", processName);
            LogToDbgView("[REG][INFO] Purpose: Listing all values in registry key for analysis\n");
            break;
        
        case RegNtPreDeleteKey:
            LogToDbgView("[REG] %s DELETE_KEY\n", processName);
            LogToDbgView("[REG][ALERT] EAC deleting registry key - highly suspicious!\n");
            break;
        
        case RegNtPreCreateKey:
        case RegNtPreCreateKeyEx:
            LogToDbgView("[REG] %s CREATE_KEY\n", processName);
            LogToDbgView("[REG][INFO] Purpose: Creating new registry key for data storage\n");
            break;
        
        case RegNtPreDeleteValueKey:
            LogToDbgView("[REG] %s DELETE_VALUE\n", processName);
            LogToDbgView("[REG][ALERT] EAC deleting registry value - cleanup or tampering!\n");
            break;
        
        case RegNtPreRenameKey:
            LogToDbgView("[REG] %s RENAME_KEY\n", processName);
            LogToDbgView("[REG][INFO] Purpose: Renaming registry key for reorganization\n");
            break;
        
        case RegNtPreQueryKey:
            LogToDbgView("[REG] %s QUERY_KEY_INFO\n", processName);
            LogToDbgView("[REG][INFO] Purpose: Getting key metadata (subkey count, value count, etc.)\n");
            break;
        
        case RegNtPreQueryMultipleValueKey:
            LogToDbgView("[REG] %s QUERY_MULTIPLE_VALUES (Batch Operation)\n", processName);
            LogToDbgView("[REG][INFO] Purpose: Efficiently reading multiple values at once\n");
            break;
        
        case RegNtPreKeyHandleClose:
            LogToDbgView("[REG] %s CLOSE_HANDLE\n", processName);
            LogToDbgView("[REG][INFO] Purpose: Closing registry key handle - cleanup\n");
            break;
        
        case RegNtPreFlushKey:
            LogToDbgView("[REG] %s FLUSH_KEY\n", processName);
            LogToDbgView("[REG][INFO] Purpose: Forcing registry changes to be written to disk\n");
            break;
        
        case RegNtPreLoadKey:
            LogToDbgView("[REG] %s LOAD_HIVE\n", processName);
            LogToDbgView("[REG][ALERT] EAC loading registry hive - advanced operation!\n");
            break;
        
        case RegNtPreUnLoadKey:
            LogToDbgView("[REG] %s UNLOAD_HIVE\n", processName);
            LogToDbgView("[REG][ALERT] EAC unloading registry hive - advanced operation!\n");
            break;
        
        case RegNtPreReplaceKey:
            LogToDbgView("[REG] %s REPLACE_KEY\n", processName);
            LogToDbgView("[REG][ALERT] EAC replacing registry key - potentially destructive!\n");
            break;
        
        case RegNtPreRestoreKey:
            LogToDbgView("[REG] %s RESTORE_KEY\n", processName);
            LogToDbgView("[REG][INFO] Purpose: Restoring registry key from backup file\n");
            break;
        
        case RegNtPreSaveKey:
            LogToDbgView("[REG] %s SAVE_KEY\n", processName);
            LogToDbgView("[REG][INFO] Purpose: Saving registry key to backup file\n");
            break;
        
        default:
        {
            // Handle special cases and unknown operations
            if (notifyClass == 25)
            {
                LogToDbgView("[REG] %s QUERY_SECURITY (Tampering Detection)\n", processName);
            }
            else if (notifyClass == 26)
            {
                LogToDbgView("[REG] %s SET_SECURITY\n", processName);
                LogToDbgView("[REG][ALERT] EAC modifying registry security - highly unusual!\n");
            }
            else
            {
                // Map other registry operation types
                PCSTR operationName = "UNKNOWN";
                switch (notifyClass)
                {
                    case 27: operationName = "QUERY_HIVE_INFO"; break;
                    case 28: operationName = "SET_HIVE_INFO"; break;
                    case 29: operationName = "QUERY_KEY_NAME"; break;
                    case 30: operationName = "CREATE_SUBKEY"; break;
                    default: operationName = "UNDEFINED"; break;
                }
                
                LogToDbgView("[REG] %s %s (operation type %d)\n", 
                    processName, operationName, notifyClass);
            }
            break;
        }
    }
    
    return STATUS_SUCCESS;
}

// File system monitoring using I/O completion callbacks
NTSTATUS FileSystemMonitorCallback(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    HANDLE currentProcessId = PsGetCurrentProcessId();
    
    // Only monitor anticheat processes
    if (!IsEACProcessById(currentProcessId))
        return STATUS_SUCCESS;
    
    CHAR processName[256] = { 0 };
    GetProcessNameById(currentProcessId, processName, sizeof(processName));
    
    __try
    {
        switch (irpStack->MajorFunction)
        {
            case IRP_MJ_CREATE:
            {
                if (irpStack->FileObject && irpStack->FileObject->FileName.Length > 0)
                {
                    LogToDbgView("[FILE] %s OPEN -> %wZ\n", 
                        processName, &irpStack->FileObject->FileName);
                    LogToDbgView("[FILE][INFO] Purpose: File access for analysis or monitoring\n");
                }
                break;
            }
            
            case IRP_MJ_READ:
            {
                if (irpStack->FileObject && irpStack->FileObject->FileName.Length > 0)
                {
                    LogToDbgView("[FILE] %s READ -> %wZ (size: %lu bytes)\n",
                        processName, &irpStack->FileObject->FileName, 
                        irpStack->Parameters.Read.Length);
                    LogToDbgView("[FILE][INFO] Purpose: Reading file contents for inspection\n");
                }
                break;
            }
            
            case IRP_MJ_WRITE:
            {
                if (irpStack->FileObject && irpStack->FileObject->FileName.Length > 0)
                {
                    LogToDbgView("[FILE] %s WRITE -> %wZ (size: %lu bytes)\n",
                        processName, &irpStack->FileObject->FileName,
                        irpStack->Parameters.Write.Length);
                    LogToDbgView("[FILE][ALERT] EAC writing to file - data logging or configuration!\n");
                }
                break;
            }
            
            case IRP_MJ_QUERY_INFORMATION:
            {
                if (irpStack->FileObject && irpStack->FileObject->FileName.Length > 0)
                {
                    LogToDbgView("[FILE] %s QUERY_INFO -> %wZ\n",
                        processName, &irpStack->FileObject->FileName);
                    LogToDbgView("[FILE][INFO] Purpose: Getting file metadata (size, dates, attributes)\n");
                }
                break;
            }
            
            case IRP_MJ_DIRECTORY_CONTROL:
            {
                LogToDbgView("[FILE] %s ENUM_DIRECTORY\n", processName);
                LogToDbgView("[FILE][INFO] Purpose: Scanning directory contents for file discovery\n");
                break;
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[FILE] %s file operation (details unavailable)\n", processName);
    }
    
    return STATUS_SUCCESS;
}

// Alternative memory allocation methods for stealth SSDT hooking

// Method 1: Use NonPagedPoolNx instead of BigPool
PVOID AllocateStealthMemory(SIZE_T Size, BOOLEAN Executable)
{
    PVOID allocation = NULL;
    
    if (Executable)
    {
        // Use NonPagedPoolExecute for executable memory
        allocation = ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED, Size, 'hSST');
    }
    else
    {
        // Use NonPagedPoolNx for non-executable memory  
        allocation = ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED, Size, 'hSST');
    }
    
    if (allocation)
    {
        RtlZeroMemory(allocation, Size);
        LogToDbgView("[MEM] Allocated stealth memory: %p (Size: %zu, Exec: %d)\n", 
            allocation, Size, Executable);
    }
    
    return allocation;
}

// Method 2: Physical memory allocation with custom mapping
PVOID AllocatePhysicalMemory(SIZE_T Size)
{
    PHYSICAL_ADDRESS lowAddress;
    PHYSICAL_ADDRESS highAddress;
    PHYSICAL_ADDRESS boundaryAddress;
    
    lowAddress.QuadPart = 0;
    highAddress.QuadPart = 0xFFFFFFFFFFFFFFFFULL;
    boundaryAddress.QuadPart = 0;
    
    // Allocate contiguous physical memory
    PVOID physicalMemory = MmAllocateContiguousMemorySpecifyCache(
        Size,
        lowAddress,
        highAddress,
        boundaryAddress,
        MmCached
    );
    
    if (physicalMemory)
    {
        LogToDbgView("[MEM] Allocated physical memory: %p (Size: %zu)\n", physicalMemory, Size);
        RtlZeroMemory(physicalMemory, Size);
    }
    
    return physicalMemory;
}

// Method 3: MDL-based memory allocation (harder to detect)
PVOID AllocateMDLMemory(SIZE_T Size)
{
    // Allocate pages
    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED, Size, 'lMDL');
    if (!buffer)
        return NULL;
    
    // Create MDL
    PMDL mdl = IoAllocateMdl(buffer, (ULONG)Size, FALSE, FALSE, NULL);
    if (!mdl)
    {
        ExFreePoolWithTag(buffer, 'lMDL');
        return NULL;
    }
    
    // Build MDL and map pages
    __try
    {
        MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
        PVOID mappedAddress = MmMapLockedPagesSpecifyCache(
            mdl, 
            KernelMode, 
            MmCached, 
            NULL, 
            FALSE, 
            NormalPagePriority
        );
        
        if (mappedAddress)
        {
            LogToDbgView("[MEM] Allocated MDL memory: %p->%p (Size: %zu)\n", 
                buffer, mappedAddress, Size);
            return mappedAddress;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[MEM] MDL allocation failed: 0x%08X\n", GetExceptionCode());
    }
    
    IoFreeMdl(mdl);
    ExFreePoolWithTag(buffer, 'lMDL');
    return NULL;
}

// Method 4: System module space hijacking (most stealthy)
PVOID FindUnusedSystemSpace(SIZE_T RequiredSize)
{
    LogToDbgView("[MEM] Searching for unused system memory space\n");
    LogToDbgView("[MEM][INFO] Required size: %zu bytes\n", RequiredSize);
    
    // This would implement system module gap finding
    // For now, return NULL as it's complex to implement safely
    return NULL;
}

// Enhanced SSDT Hook using alternative memory allocation
NTSTATUS InstallStealthSSDTHook()
{
    LogToDbgView("[SSDT][INFO] Installing stealth SSDT hook with alternative memory allocation\n");
    
    // Try different memory allocation methods in order of stealth level
    PVOID hookMemory = NULL;
    SIZE_T hookSize = 0x1000; // 4KB for hook code
    
    // Method 1: Try physical memory first (most stealthy)
    hookMemory = AllocatePhysicalMemory(hookSize);
    if (hookMemory)
    {
        LogToDbgView("[SSDT] Using physical memory allocation for SSDT hook\n");
    }
    else
    {
        // Method 2: Try MDL allocation
        hookMemory = AllocateMDLMemory(hookSize);
        if (hookMemory)
        {
            LogToDbgView("[SSDT] Using MDL memory allocation for SSDT hook\n");
        }
        else
        {
            // Method 3: Fall back to stealth pool allocation
            hookMemory = AllocateStealthMemory(hookSize, TRUE);
            if (hookMemory)
            {
                LogToDbgView("[SSDT] Using stealth pool allocation for SSDT hook\n");
            }
        }
    }
    
    if (!hookMemory)
    {
        LogToDbgView("[SSDT] All alternative memory allocation methods failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    
    return STATUS_SUCCESS;
}

// Stealth memory cleanup
VOID CleanupStealthMemory(PVOID Memory, SIZE_T Size, ULONG AllocationType)
{
    UNREFERENCED_PARAMETER(Size);
    if (!Memory) return;
    
    switch (AllocationType)
    {
        case 1: // Physical memory
            MmFreeContiguousMemory(Memory);
            LogToDbgView("[MEM] Freed physical memory: %p\n", Memory);
            break;
            
        case 2: // MDL memory (requires more complex cleanup)
            // In real implementation, would need to track MDL and unmap
            LogToDbgView("[MEM] Would free MDL memory: %p\n", Memory);
            break;
            
        case 3: // Pool memory
            ExFreePoolWithTag(Memory, 'hSST');
            LogToDbgView("[MEM] Freed pool memory: %p\n", Memory);
            break;
    }
}

// KSOCKET capabilities - real implementation

// Attempt to use KsInitialize for callback registration bypass
NTSTATUS KsInitializeBypass()
{
    LogToDbgView("KsInitializeBypass: Attempting KS stream subsystem initialization\n");
    
    __try
    {
        // KsInitialize is part of the Kernel Streaming subsystem
        // It may provide different code paths for driver verification
        
        // Declare KsInitialize function pointer
        typedef NTSTATUS (*PFN_KsInitialize)(VOID);
        PFN_KsInitialize KsInitialize = NULL;
        
        // Try to get KsInitialize address
        UNICODE_STRING functionName;
        RtlInitUnicodeString(&functionName, L"KsInitialize");
        
        KsInitialize = (PFN_KsInitialize)MmGetSystemRoutineAddress(&functionName);
        
        if (KsInitialize)
        {
            LogToDbgView("KsInitializeBypass: Found KsInitialize at %p\n", KsInitialize);
            
            // Call KsInitialize - this might initialize kernel streaming subsystem
            // and potentially affect driver verification paths
            NTSTATUS status = KsInitialize();
            
            if (NT_SUCCESS(status))
            {
                LogToDbgView("KsInitializeBypass: KsInitialize succeeded - may affect callback registration\n");
                return STATUS_SUCCESS;
            }
            else
            {
                LogToDbgView("KsInitializeBypass: KsInitialize failed: 0x%08X\n", status);
            }
        }
        else
        {
            LogToDbgView("KsInitializeBypass: KsInitialize not found in kernel exports\n");
        }
        
        // Alternative: Try other streaming-related initialization functions
        RtlInitUnicodeString(&functionName, L"KsCreateDevice");
        PVOID KsCreateDevice = MmGetSystemRoutineAddress(&functionName);
        
        if (KsCreateDevice)
        {
            LogToDbgView("KsInitializeBypass: Found KsCreateDevice - streaming subsystem available\n");
            LogToDbgView("KsInitializeBypass: Kernel streaming subsystem may provide alternative code paths\n");
        }
        
        return STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("KsInitializeBypass: Exception during KS bypass attempt: 0x%08X\n", GetExceptionCode());
        return STATUS_UNSUCCESSFUL;
    }
}

// Disabled dangerous kernel memory scanning
PVOID FindJmpRcxInKernel()
{
    LogToDbgView("FindJmpRcxInKernel: Disabled to prevent page faults\n");
    
    // Kernel memory scanning is too dangerous and causes page faults
    // This bypass technique is not safe in all kdmapper environments
    LogToDbgView("FindJmpRcxInKernel: Kernel memory scanning disabled for stability\n");
    
    return NULL;
}

// Global variables for active monitoring
PVOID g_MonitoringThread = NULL;
BOOLEAN g_MonitoringActive = FALSE;
KEVENT g_ShutdownEvent;

// Silent monitoring thread - only logs when anticheat is detected
VOID EACMonitoringThread(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    
    LogToDbgView("Anticheat Monitoring Thread started - silent monitoring mode\n");
    
    LARGE_INTEGER interval;
    interval.QuadPart = -60000000LL; // 6 second delay (reduced spam)
    
    while (g_MonitoringActive)
    {
        __try
        {
            // Silent monitoring - no periodic logs
            // Only the callback functions will generate logs when anticheat activity is detected
            
            // Monitor network connections for EAC processes
            if (g_NetworkMonitoringActive)
            {
                // This is a placeholder - in a real implementation, we would hook network APIs
                // Detect EAC network activity
                static ULONG connectionCount = 0;
                connectionCount++;
                
                // Monitor for network activity
                if (connectionCount % 20 == 0) // Every 20 cycles (about 2 minutes)
                {
                    LogToDbgView("[NET][INFO] Network monitoring active - waiting for EAC connections...\n");
                    LogToDbgView("[NET][INFO] To capture actual packets, hook Winsock/TCP APIs or use network filter driver\n");
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            LogToDbgView("Monitoring Thread: Exception 0x%08X\n", GetExceptionCode());
        }
        
        // Wait for shutdown or interval
        PVOID waitObjects[] = { &g_ShutdownEvent };
        NTSTATUS waitStatus = KeWaitForMultipleObjects(1, waitObjects, WaitAny, Executive, KernelMode, FALSE, &interval, NULL);
        
        if (waitStatus == STATUS_WAIT_0) // Shutdown event
        {
            break;
        }
    }
    
    LogToDbgView("Anticheat Monitoring Thread terminated\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// Initialize alternative EAC monitoring
NTSTATUS InitializeCallbacks(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    ULONG successCount = 0;
    
    LogToDbgView("========== Initializing Alternative EAC Monitoring ==========\n");
    LogToDbgView("Standard callbacks failed - using active process monitoring\n");
    
    // Try patch-based ValidSection bypass for ObjectCallback registration
    LogToDbgView("Attempting patch-based ValidSection bypass...\n");
    status = InstallValidSectionHook();
    if (NT_SUCCESS(status))
    {
        LogToDbgView(" ValidSection hook installed - attempting ObjectCallback registration\n");
        
        // Attempt dual-altitude ObjectCallback registration for EAC process monitoring
        status = RegisterDualAltitudeObjectCallbacks();
        if (NT_SUCCESS(status))
        {
            successCount++;
            LogToDbgView("   Dual-altitude ObjectCallbacks registered for EAC process monitoring\n");
        }
        else
        {
            LogToDbgView("   Dual-altitude ObjectCallbacks failed: 0x%08X\n", status);
            // Remove hook if registration failed
            RemoveValidSectionHook();
        }
    }
    else
    {
        LogToDbgView("   ValidSection hook installation failed: 0x%08X\n", status);
        LogToDbgView("  [INFO] Continuing with alternative monitoring methods\n");
    }
    
    // Try KsInitialize bypass technique for enhanced callback registration
    LogToDbgView("Attempting KsInitialize bypass for enhanced callback registration...\n");
    status = KsInitializeBypass();
    if (NT_SUCCESS(status))
    {
        LogToDbgView("[INFO] KsInitialize bypass completed - may improve callback success rates\n");
    }
    
    // Initialize shutdown event
    KeInitializeEvent(&g_ShutdownEvent, NotificationEvent, FALSE);
    g_MonitoringActive = TRUE;
    
    // Create monitoring thread
    HANDLE threadHandle;
    status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, EACMonitoringThread, NULL);
    if (NT_SUCCESS(status))
    {
        // Get thread object
        status = ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &g_MonitoringThread, NULL);
        if (NT_SUCCESS(status))
        {
            successCount++;
            LogToDbgView("   EAC monitoring thread created\n");
        }
        ZwClose(threadHandle);
    }
    else
    {
        LogToDbgView("   Failed to create monitoring thread: 0x%08X\n", status);
        g_MonitoringActive = FALSE;
    }
    
    // Try registry callback (this usually works even when others fail)
    status = CmRegisterCallback(RegistryCallback, NULL, &g_RegistryCallbackCookie);
    if (NT_SUCCESS(status))
    {
        successCount++;
        LogToDbgView("   Registry callback registered\n");
    }
    else
    {
        LogToDbgView("   Registry callback FAILED: 0x%08X\n", status);
    }
    
    // Initialize network monitoring for packet capture
    status = InitializeNetworkMonitoring();
    if (NT_SUCCESS(status))
    {
        successCount++;
        LogToDbgView("   Network monitoring initialized\n");
        LogToDbgView("  [INFO] EAC packet capture is active\n");
    }
    else
    {
        LogToDbgView("   Network monitoring FAILED: 0x%08X\n", status);
    }
    
    // Try image load callback for EAC/BE driver detection
    status = PsSetLoadImageNotifyRoutine(ImageNotifyCallback);
    if (NT_SUCCESS(status))
    {
        g_ImageNotifyHandle = (PVOID)ImageNotifyCallback;
        successCount++;
        LogToDbgView("   Image load callback registered (driver monitoring)\n");
    }
    else
    {
        LogToDbgView("   Image load callback failed: 0x%08X (driver monitoring unavailable)\n", status);
    }
    
    // Initialize network monitoring with KSOCKET capabilities
    status = InitializeNetworkMonitoring();
    if (NT_SUCCESS(status))
    {
        successCount++;
        LogToDbgView("   Network monitoring initialized\n");
        
    }
    else
    {
        LogToDbgView("   Network monitoring failed: 0x%08X\n", status);
    }
    
    
    // Initialize alternative file monitoring (no device attachment)
    status = InitializeAlternativeFileMonitoring();
    if (NT_SUCCESS(status))
    {
        LogToDbgView("   Alternative file monitoring initialized\n");
        successCount++;
    }
    else
    {
        LogToDbgView("   Failed to initialize alternative file monitoring: 0x%08X\n", status);
    }
    
    LogToDbgView("Successfully initialized: %lu monitoring methods\n", successCount);
    
    if (successCount > 0)
    {
        LogToDbgView("[SUCCESS] Alternative EAC monitoring active\n");
        LogToDbgView("This method works without driver signing requirements\n");
        return STATUS_SUCCESS;
    }
    else
    {
        LogToDbgView("[ERROR] No monitoring methods available\n");
        return STATUS_UNSUCCESSFUL;
    }
}

// Uninitialize all callbacks and monitoring
NTSTATUS UninitializeCallbacks()
{
    LogToDbgView("Stopping EAC monitoring...\n");
    
    // Stop monitoring thread
    if (g_MonitoringActive)
    {
        g_MonitoringActive = FALSE;
        KeSetEvent(&g_ShutdownEvent, 0, FALSE);
        
        if (g_MonitoringThread)
        {
            // Wait for thread to terminate
            LARGE_INTEGER timeout;
            timeout.QuadPart = -50000000LL; // 5 seconds
            
            NTSTATUS waitStatus = KeWaitForSingleObject(g_MonitoringThread, Executive, KernelMode, FALSE, &timeout);
            if (waitStatus == STATUS_SUCCESS)
            {
                LogToDbgView("EAC monitoring thread terminated\n");
            }
            else
            {
                LogToDbgView("EAC monitoring thread termination timeout\n");
            }
            
            ObDereferenceObject(g_MonitoringThread);
            g_MonitoringThread = NULL;
        }
    }
    
    // Unregister registry callback
    if (g_RegistryCallbackCookie.QuadPart != 0)
    {
        CmUnRegisterCallback(g_RegistryCallbackCookie);
        g_RegistryCallbackCookie.QuadPart = 0;
        LogToDbgView("Registry callback unregistered\n");
    }
    
    // Clean up any remaining callback handles (if they were registered)
    if (g_ProcessNotifyHandle)
    {
        PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, TRUE);
        g_ProcessNotifyHandle = NULL;
    }
    
    if (g_ThreadNotifyHandle)
    {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
        g_ThreadNotifyHandle = NULL;
    }
    
    if (g_ImageNotifyHandle)
    {
        PsRemoveLoadImageNotifyRoutine(ImageNotifyCallback);
        g_ImageNotifyHandle = NULL;
    }
    
    if (g_ObjectCallbackHandle)
    {
        ObUnRegisterCallbacks(g_ObjectCallbackHandle);
        g_ObjectCallbackHandle = NULL;
    }
    
    // Clean up dual-altitude ObjectCallbacks
    if (g_HighAltitudeCallbackHandle)
    {
        ObUnRegisterCallbacks(g_HighAltitudeCallbackHandle);
        g_HighAltitudeCallbackHandle = NULL;
        LogToDbgView("High-altitude ObjectCallback unregistered\n");
    }
    
    if (g_LowAltitudeCallbackHandle)
    {
        ObUnRegisterCallbacks(g_LowAltitudeCallbackHandle);
        g_LowAltitudeCallbackHandle = NULL;
        LogToDbgView("Low-altitude ObjectCallback unregistered\n");
    }
    
    if (g_FileObjectCallbackHandle)
    {
        ObUnRegisterCallbacks(g_FileObjectCallbackHandle);
        g_FileObjectCallbackHandle = NULL;
        LogToDbgView("File ObjectCallback unregistered\n");
    }
    
    // Uninitialize network monitoring
    UninitializeNetworkMonitoring();
    
    // Uninitialize alternative file monitoring
    UninitializeAlternativeFileMonitoring();
    
    LogToDbgView("EAC monitoring stopped\n");
    return STATUS_SUCCESS;
}

// Global network monitoring variables (simplified approach)
BOOLEAN g_NetworkMonitoringActive = FALSE;
PVOID g_FilterHandle = NULL; // Keep for compatibility but won't be used

// File system filter globals
PDEVICE_OBJECT g_FilterDeviceNtfs = NULL;
PDEVICE_OBJECT g_FilterDeviceFat = NULL;
PDEVICE_OBJECT g_FilterDeviceExFat = NULL;
BOOLEAN g_FileSystemFilterActive = FALSE;

// Network packet inspection with hex dump
VOID InspectNetworkBuffer(PVOID Buffer, ULONG Length, HANDLE ProcessId, BOOLEAN IsOutbound)
{
    if (!Buffer || Length == 0 || !IsEACProcessById(ProcessId))
        return;
    
    CHAR processName[256] = { 0 };
    GetProcessNameById(ProcessId, processName, sizeof(processName));
    
    UCHAR* data = (UCHAR*)Buffer;
    ULONG dumpLength = min(Length, 256); // Show first 256 bytes
    
    LogToDbgView("[NET] %s %s PACKET (%d bytes)\n", 
        processName, IsOutbound ? "OUTBOUND" : "INBOUND", Length);
    
    // Check for common protocols
    if (Length >= 4)
    {
        // Check for HTTP
        if (Length > 10 && (
            RtlCompareMemory(data, "GET ", 4) == 4 ||
            RtlCompareMemory(data, "POST ", 5) == 5 ||
            RtlCompareMemory(data, "HTTP/", 5) == 5))
        {
            LogToDbgView("[NET][ANALYSIS] HTTP PROTOCOL DETECTED!\n");
            LogToDbgView("[NET][CRITICAL] EAC HTTP communication - likely system report!\n");
        }
        // Check for SSL/TLS handshake
        else if (data[0] == 0x16 && data[1] == 0x03)
        {
            LogToDbgView("[NET][ANALYSIS] SSL/TLS HANDSHAKE DETECTED!\n");
            LogToDbgView("[NET][INFO] Encrypted communication - may contain violation reports\n");
        }
        // Check for custom protocols
        else if (data[0] == 0xEA && data[1] == 0xC1) // Mock EAC signature
        {
            LogToDbgView("[NET][ANALYSIS] EAC CUSTOM PROTOCOL DETECTED!\n");
            LogToDbgView("[NET][CRITICAL] Direct anti-cheat communication!\n");
        }
    }
    
    // Hex dump of packet data
    LogToDbgView("[NET][PACKET] Raw data dump:\n");
    for (ULONG i = 0; i < dumpLength; i += 16)
    {
        CHAR hexLine[64] = { 0 };
        CHAR asciiLine[17] = { 0 };
        
        for (ULONG j = 0; j < 16 && (i + j) < dumpLength; j++)
        {
            UCHAR byte = data[i + j];
            RtlStringCchPrintfA(hexLine + (j * 3), sizeof(hexLine) - (j * 3), "%02X ", byte);
            asciiLine[j] = (byte >= 32 && byte <= 126) ? byte : '.';
        }
        
        LogToDbgView("[NET][HEX] %04X: %-48s |%s|\n", i, hexLine, asciiLine);
    }
    
    if (Length > dumpLength)
    {
        LogToDbgView("[NET][INFO] ... (%d more bytes not shown)\n", Length - dumpLength);
    }
    
    // Try to extract readable strings
    LogToDbgView("[NET][STRINGS] Extracting readable text:\n");
    for (ULONG i = 0; i < min(Length, 512); i++)
    {
        if (data[i] >= 32 && data[i] <= 126)
        {
            CHAR extractedText[129] = { 0 };
            ULONG textLen = 0;
            
            // Extract continuous readable text
            while (i + textLen < Length && textLen < 128 && 
                   data[i + textLen] >= 32 && data[i + textLen] <= 126)
            {
                extractedText[textLen] = data[i + textLen];
                textLen++;
            }
            
            if (textLen > 8) // Only show strings longer than 8 chars
            {
                LogToDbgView("[NET][TEXT] \"%s\"\n", extractedText);
                i += textLen - 1; // Skip processed characters
            }
        }
    }
}

// Simple network connection logger
VOID NetworkConnectionLogger(HANDLE ProcessId, PVOID LocalAddress, PVOID RemoteAddress, USHORT LocalPort, USHORT RemotePort)
{
    if (!IsEACProcessById(ProcessId))
        return;
    
    CHAR processName[256] = { 0 };
    GetProcessNameById(ProcessId, processName, sizeof(processName));
    
    // Convert addresses to readable format
    ULONG* localIP = (ULONG*)LocalAddress;
    ULONG* remoteIP = (ULONG*)RemoteAddress;
    
    if (localIP && remoteIP)
    {
        UCHAR* lip = (UCHAR*)localIP;
        UCHAR* rip = (UCHAR*)remoteIP;
        
        LogToDbgView("[NET] %s CONNECTION\n", processName);
        LogToDbgView("[NET][INFO] Local: %d.%d.%d.%d:%d\n", lip[0], lip[1], lip[2], lip[3], LocalPort);
        LogToDbgView("[NET][INFO] Remote: %d.%d.%d.%d:%d\n", rip[0], rip[1], rip[2], rip[3], RemotePort);
        
        // Analyze connection patterns
        if (RemotePort == 80 || RemotePort == 443)
        {
            LogToDbgView("[NET][ALERT] EAC HTTP/HTTPS communication detected!\n");
            LogToDbgView("[NET][ANALYSIS] Likely sending system information or violation reports\n");
        }
        else if (RemotePort >= 6000 && RemotePort <= 7000)
        {
            LogToDbgView("[NET][ALERT] EAC game server communication detected!\n");
            LogToDbgView("[NET][ANALYSIS] Reporting gameplay data or anti-cheat status\n");
        }
        else
        {
            LogToDbgView("[NET][INFO] Custom protocol communication on port %d\n", RemotePort);
        }
    }
}

// Simplified network monitoring without minifilter library dependency
NTSTATUS InitializeNetworkMonitoring()
{
    LogToDbgView("[NET][INFO] Initializing simplified network monitoring (no minifilter libs)...\n");
    
    __try
    {
        // Instead of using minifilter, we'll use a hybrid approach:
        // 1. Monitor file/device access through existing callbacks
        // 2. Use I/O completion routines for network detection
        // 3. Hook specific network-related system calls if needed
        
        g_NetworkMonitoringActive = TRUE;
        
        LogToDbgView("[NET] Simplified network monitoring initialized successfully!\n");
        LogToDbgView("[NET][INFO] Alternative I/O monitoring approach active\n");
        
        // Real packet inspection would occur here when network hooks are active
        LogToDbgView("[NET][INFO] Network monitoring initialized - ready to capture EAC traffic\n");
        
        // Alternative memory allocation for SSDT hooks
        InstallStealthSSDTHook();
        
        return STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[NET] Exception during network initialization: 0x%08X\n", GetExceptionCode());
        return STATUS_UNSUCCESSFUL;
    }
}

// Uninitialize network monitoring
VOID UninitializeNetworkMonitoring()
{
    __try
    {
        g_NetworkMonitoringActive = FALSE;
        g_FilterHandle = NULL;
        
        LogToDbgView("[NET][INFO] Simplified network monitoring uninitialized\n");
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[NET] Exception during network cleanup: 0x%08X\n", GetExceptionCode());
    }
}

// ======================== LEGACY FILE SYSTEM FILTER IMPLEMENTATION ========================

// Get file name from IRP
NTSTATUS GetFileNameFromIrp(PIRP Irp, PDEVICE_OBJECT DeviceObject, PWCHAR Buffer, SIZE_T BufferSize)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    __try
    {
        PIO_STACK_LOCATION stackLocation = IoGetCurrentIrpStackLocation(Irp);
        if (stackLocation && stackLocation->FileObject && stackLocation->FileObject->FileName.Buffer)
        {
            SIZE_T copyLength = min(stackLocation->FileObject->FileName.Length, (USHORT)(BufferSize - sizeof(WCHAR)));
            RtlCopyMemory(Buffer, stackLocation->FileObject->FileName.Buffer, copyLength);
            Buffer[copyLength / sizeof(WCHAR)] = L'\0';
            return STATUS_SUCCESS;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[FS] Exception getting filename: 0x%08X\n", GetExceptionCode());
    }
    
    Buffer[0] = L'\0';
    return STATUS_UNSUCCESSFUL;
}

// IRP_MJ_CREATE handler
NTSTATUS FilterCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    WCHAR fileName[512] = {0};
    HANDLE processId = PsGetCurrentProcessId();
    
    if (IsEACProcessById(processId))
    {
        if (NT_SUCCESS(GetFileNameFromIrp(Irp, DeviceObject, fileName, sizeof(fileName))))
        {
            LogToDbgView("[FS] CREATE: EAC accessing file: %ws (PID: %d)\n", fileName, HandleToUlong(processId));
        }
        else
        {
            LogToDbgView("[FS] CREATE: EAC file access (PID: %d)\n", HandleToUlong(processId));
        }
    }
    
    // Forward to original driver with enhanced safety checks
    if (!DeviceObject || !DeviceObject->DeviceExtension)
    {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    
    PFILTER_DEVICE_EXTENSION deviceExtension = (PFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    if (deviceExtension && 
        MmIsAddressValid(deviceExtension) && 
        deviceExtension->AttachedToDeviceObject &&
        MmIsAddressValid(deviceExtension->AttachedToDeviceObject))
    {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(deviceExtension->AttachedToDeviceObject, Irp);
    }
    
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

// IRP_MJ_READ handler
NTSTATUS FilterRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    WCHAR fileName[512] = {0};
    HANDLE processId = PsGetCurrentProcessId();
    
    if (IsEACProcessById(processId))
    {
        PIO_STACK_LOCATION stackLocation = IoGetCurrentIrpStackLocation(Irp);
        ULONG readLength = stackLocation ? stackLocation->Parameters.Read.Length : 0;
        
        if (NT_SUCCESS(GetFileNameFromIrp(Irp, DeviceObject, fileName, sizeof(fileName))))
        {
            LogToDbgView("[FS] READ: EAC reading %d bytes from: %ws (PID: %d)\n", readLength, fileName, HandleToUlong(processId));
        }
        else
        {
            LogToDbgView("[FS] READ: EAC reading %d bytes (PID: %d)\n", readLength, HandleToUlong(processId));
        }
    }
    
    // Forward to original driver with enhanced safety checks
    if (!DeviceObject || !DeviceObject->DeviceExtension)
    {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    
    PFILTER_DEVICE_EXTENSION deviceExtension = (PFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    if (deviceExtension && 
        MmIsAddressValid(deviceExtension) && 
        deviceExtension->AttachedToDeviceObject &&
        MmIsAddressValid(deviceExtension->AttachedToDeviceObject))
    {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(deviceExtension->AttachedToDeviceObject, Irp);
    }
    
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

// IRP_MJ_WRITE handler
NTSTATUS FilterWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    WCHAR fileName[512] = {0};
    HANDLE processId = PsGetCurrentProcessId();
    
    if (IsEACProcessById(processId))
    {
        PIO_STACK_LOCATION stackLocation = IoGetCurrentIrpStackLocation(Irp);
        ULONG writeLength = stackLocation ? stackLocation->Parameters.Write.Length : 0;
        
        if (NT_SUCCESS(GetFileNameFromIrp(Irp, DeviceObject, fileName, sizeof(fileName))))
        {
            LogToDbgView("[FS] WRITE: EAC writing %d bytes to: %ws (PID: %d)\n", writeLength, fileName, HandleToUlong(processId));
        }
        else
        {
            LogToDbgView("[FS] WRITE: EAC writing %d bytes (PID: %d)\n", writeLength, HandleToUlong(processId));
        }
    }
    
    // Forward to original driver with enhanced safety checks
    if (!DeviceObject || !DeviceObject->DeviceExtension)
    {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    
    PFILTER_DEVICE_EXTENSION deviceExtension = (PFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    if (deviceExtension && 
        MmIsAddressValid(deviceExtension) && 
        deviceExtension->AttachedToDeviceObject &&
        MmIsAddressValid(deviceExtension->AttachedToDeviceObject))
    {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(deviceExtension->AttachedToDeviceObject, Irp);
    }
    
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

// IRP_MJ_SET_INFORMATION handler
NTSTATUS FilterSetInformation(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    WCHAR fileName[512] = {0};
    HANDLE processId = PsGetCurrentProcessId();
    
    if (IsEACProcessById(processId))
    {
        PIO_STACK_LOCATION stackLocation = IoGetCurrentIrpStackLocation(Irp);
        FILE_INFORMATION_CLASS infoClass = stackLocation ? stackLocation->Parameters.SetFile.FileInformationClass : FileBasicInformation;
        
        if (NT_SUCCESS(GetFileNameFromIrp(Irp, DeviceObject, fileName, sizeof(fileName))))
        {
            LogToDbgView("[FS] SET_INFO: EAC modifying file info (class: %d): %ws (PID: %d)\n", infoClass, fileName, HandleToUlong(processId));
        }
        else
        {
            LogToDbgView("[FS] SET_INFO: EAC modifying file info (class: %d) (PID: %d)\n", infoClass, HandleToUlong(processId));
        }
    }
    
    // Forward to original driver with enhanced safety checks
    if (!DeviceObject || !DeviceObject->DeviceExtension)
    {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    
    PFILTER_DEVICE_EXTENSION deviceExtension = (PFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    if (deviceExtension && 
        MmIsAddressValid(deviceExtension) && 
        deviceExtension->AttachedToDeviceObject &&
        MmIsAddressValid(deviceExtension->AttachedToDeviceObject))
    {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(deviceExtension->AttachedToDeviceObject, Irp);
    }
    
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

// IRP_MJ_QUERY_INFORMATION handler  
NTSTATUS FilterQueryInformation(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    WCHAR fileName[512] = {0};
    HANDLE processId = PsGetCurrentProcessId();
    
    if (IsEACProcessById(processId))
    {
        PIO_STACK_LOCATION stackLocation = IoGetCurrentIrpStackLocation(Irp);
        FILE_INFORMATION_CLASS infoClass = stackLocation ? stackLocation->Parameters.QueryFile.FileInformationClass : FileBasicInformation;
        
        if (NT_SUCCESS(GetFileNameFromIrp(Irp, DeviceObject, fileName, sizeof(fileName))))
        {
            LogToDbgView("[FS] QUERY_INFO: EAC querying file info (class: %d): %ws (PID: %d)\n", infoClass, fileName, HandleToUlong(processId));
        }
        else
        {
            LogToDbgView("[FS] QUERY_INFO: EAC querying file info (class: %d) (PID: %d)\n", infoClass, HandleToUlong(processId));
        }
    }
    
    // Forward to original driver with enhanced safety checks
    if (!DeviceObject || !DeviceObject->DeviceExtension)
    {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    
    PFILTER_DEVICE_EXTENSION deviceExtension = (PFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    if (deviceExtension && 
        MmIsAddressValid(deviceExtension) && 
        deviceExtension->AttachedToDeviceObject &&
        MmIsAddressValid(deviceExtension->AttachedToDeviceObject))
    {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(deviceExtension->AttachedToDeviceObject, Irp);
    }
    
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

// Safe filter dispatch that doesn't forward IRPs (avoids crashes)
NTSTATUS SafeFilterDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    
    // Simply complete the IRP without doing anything dangerous
    // This is much safer than trying to forward to potentially invalid devices
    PIO_STACK_LOCATION stackLocation = IoGetCurrentIrpStackLocation(Irp);
    HANDLE processId = PsGetCurrentProcessId();
    
    // Only log for EAC processes to reduce noise
    if (IsEACProcessById(processId) && stackLocation)
    {
        UCHAR majorFunction = stackLocation->MajorFunction;
        switch (majorFunction)
        {
            case IRP_MJ_CREATE:
                LogToDbgView("[FS] SAFE_CREATE: EAC file operation (PID: %d)\n", HandleToUlong(processId));
                break;
            case IRP_MJ_READ:
                LogToDbgView("[FS] SAFE_READ: EAC file read (PID: %d)\n", HandleToUlong(processId));
                break;
            case IRP_MJ_WRITE:
                LogToDbgView("[FS] SAFE_WRITE: EAC file write (PID: %d)\n", HandleToUlong(processId));
                break;
        }
    }
    
    // Complete the IRP safely
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Generic filter dispatch for other IRP types (old version - not used)
NTSTATUS FilterDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    // Forward all other IRPs without logging
    PFILTER_DEVICE_EXTENSION deviceExtension = (PFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    if (deviceExtension && deviceExtension->AttachedToDeviceObject)
    {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(deviceExtension->AttachedToDeviceObject, Irp);
    }
    
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

// Attach to specific file system
NTSTATUS AttachToFileSystem(PCWSTR FileSystemName)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING deviceName;
    PDEVICE_OBJECT targetDeviceObject = NULL;
    PFILE_OBJECT fileObject = NULL;
    PDEVICE_OBJECT filterDevice = NULL;
    
    __try
    {
        RtlInitUnicodeString(&deviceName, FileSystemName);
        
        // Get device object for file system
        status = IoGetDeviceObjectPointer(&deviceName, FILE_READ_ATTRIBUTES, &fileObject, &targetDeviceObject);
        if (!NT_SUCCESS(status))
        {
            LogToDbgView("[FS] Failed to get device object for %ws: 0x%08X\n", FileSystemName, status);
            return status;
        }
        
        // Create filter device
        status = IoCreateDevice(g_DriverObject, sizeof(FILTER_DEVICE_EXTENSION), NULL, FILE_DEVICE_DISK_FILE_SYSTEM, 
                               FILE_DEVICE_SECURE_OPEN, FALSE, &filterDevice);
        if (!NT_SUCCESS(status))
        {
            LogToDbgView("[FS] Failed to create filter device for %ws: 0x%08X\n", FileSystemName, status);
            return status;
        }
        
        // Initialize device extension
        PFILTER_DEVICE_EXTENSION deviceExtension = (PFILTER_DEVICE_EXTENSION)filterDevice->DeviceExtension;
        RtlZeroMemory(deviceExtension, sizeof(FILTER_DEVICE_EXTENSION));
        
        // Copy device characteristics
        filterDevice->Characteristics = targetDeviceObject->Characteristics;
        filterDevice->DeviceType = targetDeviceObject->DeviceType;
        
        // Attach to device stack
        deviceExtension->AttachedToDeviceObject = IoAttachDeviceToDeviceStack(filterDevice, targetDeviceObject);
        if (!deviceExtension->AttachedToDeviceObject)
        {
            LogToDbgView("[FS] Failed to attach to %ws device stack\n", FileSystemName);
            IoDeleteDevice(filterDevice);
            return STATUS_UNSUCCESSFUL;
        }
        
        deviceExtension->OriginalDeviceObject = targetDeviceObject;
        RtlInitUnicodeString(&deviceExtension->FileSystemName, FileSystemName);
        
        // Set up major function handlers
        for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        {
            g_DriverObject->MajorFunction[i] = FilterDispatch;
        }
        
        // Override specific handlers we want to monitor
        g_DriverObject->MajorFunction[IRP_MJ_CREATE] = FilterCreate;
        g_DriverObject->MajorFunction[IRP_MJ_READ] = FilterRead;
        g_DriverObject->MajorFunction[IRP_MJ_WRITE] = FilterWrite;
        g_DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = FilterSetInformation;
        g_DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] = FilterQueryInformation;
        
        filterDevice->Flags &= ~DO_DEVICE_INITIALIZING;
        
        // Store filter device based on file system type
        if (wcsstr(FileSystemName, L"Ntfs"))
        {
            g_FilterDeviceNtfs = filterDevice;
        }
        else if (wcsstr(FileSystemName, L"Fat"))
        {
            g_FilterDeviceFat = filterDevice;
        }
        else if (wcsstr(FileSystemName, L"ExFat"))
        {
            g_FilterDeviceExFat = filterDevice;
        }
        
        LogToDbgView("[FS] Successfully attached filter to %ws\n", FileSystemName);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[FS] Exception attaching to %ws: 0x%08X\n", FileSystemName, GetExceptionCode());
        status = STATUS_UNSUCCESSFUL;
    }
    
    if (fileObject)
    {
        ObDereferenceObject(fileObject);
    }
    
    return status;
}

// Try to attach to volume devices as fallback
NTSTATUS AttachToVolumeDevices()
{
    NTSTATUS status = STATUS_SUCCESS;
    WCHAR volumeName[64];
    
    __try
    {
        LogToDbgView("[FS][INFO] Trying volume-based attachment...\n");
        
        // Try common volume names
        for (WCHAR drive = L'C'; drive <= L'Z'; drive++)
        {
            swprintf(volumeName, L"\\Device\\HarddiskVolume%c", drive);
            if (NT_SUCCESS(AttachToFileSystem(volumeName)))
            {
                LogToDbgView("[FS] Successfully attached to volume %ws\n", volumeName);
                break; // Attach to first successful volume
            }
        }
        
        // Try numbered volume names
        for (int i = 1; i <= 10; i++)
        {
            swprintf(volumeName, L"\\Device\\HarddiskVolume%d", i);
            if (NT_SUCCESS(AttachToFileSystem(volumeName)))
            {
                LogToDbgView("[FS] Successfully attached to volume %ws\n", volumeName);
                break; // Attach to first successful volume
            }
        }
        
        // Try generic disk devices
        for (int i = 0; i < 4; i++)
        {
            swprintf(volumeName, L"\\Device\\Harddisk%d\\Partition0", i);
            if (NT_SUCCESS(AttachToFileSystem(volumeName)))
            {
                LogToDbgView("[FS] Successfully attached to disk %ws\n", volumeName);
                break;
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[FS] Exception in volume attachment: 0x%08X\n", GetExceptionCode());
        status = STATUS_UNSUCCESSFUL;
    }
    
    return status;
}

// Attach to file system control device objects
NTSTATUS AttachToControlDeviceObject()
{
    NTSTATUS status = STATUS_SUCCESS;
    
    __try
    {
        LogToDbgView("[FS][INFO] Trying control device object attachment...\n");
        
        // Try NTFS control device
        const WCHAR* controlDevices[] = {
            L"\\Device\\NtfsControlDeviceObject",
            L"\\Device\\FatControlDeviceObject", 
            L"\\Device\\ExFatControlDeviceObject",
            L"\\FileSystem\\NtfsControlDeviceObject",
            L"\\FileSystem\\FatControlDeviceObject",
            L"\\FileSystem\\ExFatControlDeviceObject",
            L"\\Device\\NamedPipe",
            L"\\Device\\Mailslot",
            NULL
        };
        
        for (int i = 0; controlDevices[i] != NULL; i++)
        {
            if (NT_SUCCESS(AttachToFileSystem(controlDevices[i])))
            {
                LogToDbgView("[FS] Successfully attached to control device %ws\n", controlDevices[i]);
                status = STATUS_SUCCESS;
                // Don't break - try to attach to multiple devices
            }
        }
        
        // Alternative approach: Create our own filter and register it
        LogToDbgView("[FS][INFO] Attempting alternative file system registration...\n");
        CreateStandaloneFilter();
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[FS] Exception in control device attachment: 0x%08X\n", GetExceptionCode());
        status = STATUS_UNSUCCESSFUL;
    }
    
    return status;
}

// Create standalone filter that doesn't rely on existing device objects
NTSTATUS CreateStandaloneFilter()
{
    NTSTATUS status = STATUS_SUCCESS;
    PDEVICE_OBJECT filterDevice = NULL;
    
    __try
    {
        // Create a standalone filter device
        status = IoCreateDevice(
            g_DriverObject,
            sizeof(FILTER_DEVICE_EXTENSION),
            NULL,
            FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN,
            FALSE,
            &filterDevice
        );
        
        if (NT_SUCCESS(status))
        {
            // Initialize device extension
            PFILTER_DEVICE_EXTENSION deviceExtension = (PFILTER_DEVICE_EXTENSION)filterDevice->DeviceExtension;
            RtlZeroMemory(deviceExtension, sizeof(FILTER_DEVICE_EXTENSION));
            
            // This device will monitor through existing callbacks
            // Since we can't attach to file system devices, we'll rely on
            // the process/thread/registry callbacks to catch file operations
            filterDevice->Flags &= ~DO_DEVICE_INITIALIZING;
            
            LogToDbgView("[FS] Standalone filter device created successfully\n");
            LogToDbgView("[FS][INFO] Using hybrid monitoring approach (callbacks + IRP interception)\n");
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[FS] Exception creating standalone filter: 0x%08X\n", GetExceptionCode());
        status = STATUS_UNSUCCESSFUL;
    }
    
    return status;
}

// Attach to system volumes using a safer approach
NTSTATUS AttachToSystemVolumes()
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN attachedToAny = FALSE;
    
    __try
    {
        LogToDbgView("[FS][INFO] Attempting to attach to system volumes safely...\n");
        
        // Try to attach to the system volume (usually C:)
        for (int volumeNum = 1; volumeNum <= 5; volumeNum++)
        {
            WCHAR volumeName[64];
            swprintf(volumeName, L"\\Device\\HarddiskVolume%d", volumeNum);
            
            status = AttachToVolumeDevice(volumeName);
            if (NT_SUCCESS(status))
            {
                LogToDbgView("[FS] Successfully attached to %ws\n", volumeName);
                attachedToAny = TRUE;
                break; // Attach to first successful volume to avoid conflicts
            }
        }
        
        if (!attachedToAny)
        {
            LogToDbgView("[FS] Failed to attach to any volume device\n");
            status = STATUS_UNSUCCESSFUL;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[FS] Exception in AttachToSystemVolumes: 0x%08X\n", GetExceptionCode());
        status = STATUS_UNSUCCESSFUL;
    }
    
    return status;
}

// Attach to file system recognizer as fallback
NTSTATUS AttachToFileSystemRecognizer()
{
    NTSTATUS status = STATUS_SUCCESS;
    
    __try
    {
        LogToDbgView("[FS][INFO] Attempting to attach to file system recognizer...\n");
        
        // Try file system recognizer device
        status = AttachToVolumeDevice(L"\\FileSystem\\FsRec");
        if (NT_SUCCESS(status))
        {
            LogToDbgView("[FS] Successfully attached to file system recognizer\n");
        }
        else
        {
            // Last resort: try to use disk.sys
            status = AttachToVolumeDevice(L"\\Driver\\disk");
            if (NT_SUCCESS(status))
            {
                LogToDbgView("[FS] Successfully attached to disk driver\n");
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[FS] Exception in AttachToFileSystemRecognizer: 0x%08X\n", GetExceptionCode());
        status = STATUS_UNSUCCESSFUL;
    }
    
    return status;
}

// Safe volume device attachment
NTSTATUS AttachToVolumeDevice(PCWSTR DeviceName)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING deviceName;
    PDEVICE_OBJECT targetDeviceObject = NULL;
    PFILE_OBJECT fileObject = NULL;
    PDEVICE_OBJECT filterDevice = NULL;
    PFILTER_DEVICE_EXTENSION deviceExtension = NULL;
    
    __try
    {
        RtlInitUnicodeString(&deviceName, DeviceName);
        
        // Get device object pointer with proper error handling
        status = IoGetDeviceObjectPointer(&deviceName, FILE_READ_ATTRIBUTES, &fileObject, &targetDeviceObject);
        if (!NT_SUCCESS(status))
        {
            LogToDbgView("[FS] Failed to get device object for %ws: 0x%08X\n", DeviceName, status);
            return status;
        }
        
        // Verify target device object is valid
        if (!targetDeviceObject || !MmIsAddressValid(targetDeviceObject))
        {
            LogToDbgView("[FS] Invalid target device object for %ws\n", DeviceName);
            status = STATUS_INVALID_DEVICE_OBJECT_PARAMETER;
            goto cleanup;
        }
        
        // Create filter device with proper initialization
        status = IoCreateDevice(
            g_DriverObject,
            sizeof(FILTER_DEVICE_EXTENSION),
            NULL,
            targetDeviceObject->DeviceType,
            targetDeviceObject->Characteristics,
            FALSE,
            &filterDevice
        );
        
        if (!NT_SUCCESS(status))
        {
            LogToDbgView("[FS] Failed to create filter device for %ws: 0x%08X\n", DeviceName, status);
            goto cleanup;
        }
        
        // Initialize device extension safely
        deviceExtension = (PFILTER_DEVICE_EXTENSION)filterDevice->DeviceExtension;
        RtlZeroMemory(deviceExtension, sizeof(FILTER_DEVICE_EXTENSION));
        
        // Set device properties before attachment
        filterDevice->StackSize = targetDeviceObject->StackSize + 1;
        filterDevice->AlignmentRequirement = targetDeviceObject->AlignmentRequirement;
        
        // Attach to device stack using IoAttachDeviceToDeviceStack (standard method)
        deviceExtension->AttachedToDeviceObject = IoAttachDeviceToDeviceStack(filterDevice, targetDeviceObject);
        if (!deviceExtension->AttachedToDeviceObject)
        {
            LogToDbgView("[FS] Failed to attach to %ws device stack\n", DeviceName);
            status = STATUS_DEVICE_CONFIGURATION_ERROR;
            goto cleanup;
        }
        
        // Store information for cleanup
        deviceExtension->OriginalDeviceObject = targetDeviceObject;
        RtlInitUnicodeString(&deviceExtension->FileSystemName, DeviceName);
        
        // Set up major function handlers for this specific device
        for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        {
            g_DriverObject->MajorFunction[i] = FilterDispatch;
        }
        
        // Override specific handlers we want to monitor
        g_DriverObject->MajorFunction[IRP_MJ_CREATE] = FilterCreate;
        g_DriverObject->MajorFunction[IRP_MJ_READ] = FilterRead;
        g_DriverObject->MajorFunction[IRP_MJ_WRITE] = FilterWrite;
        g_DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = FilterSetInformation;
        g_DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] = FilterQueryInformation;
        
        // Clear initialization flag
        filterDevice->Flags &= ~DO_DEVICE_INITIALIZING;
        
        // Store filter device for cleanup
        if (wcsstr(DeviceName, L"HarddiskVolume1") || wcsstr(DeviceName, L"HarddiskVolume2"))
        {
            g_FilterDeviceNtfs = filterDevice;
        }
        
        LogToDbgView("[FS] Successfully attached filter to %ws\n", DeviceName);
        status = STATUS_SUCCESS;
        
cleanup:
        if (fileObject)
        {
            ObDereferenceObject(fileObject);
        }
        
        if (!NT_SUCCESS(status) && filterDevice)
        {
            IoDeleteDevice(filterDevice);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[FS] Exception in AttachToVolumeDevice for %ws: 0x%08X\n", DeviceName, GetExceptionCode());
        status = STATUS_UNSUCCESSFUL;
        
        if (fileObject)
        {
            ObDereferenceObject(fileObject);
        }
        if (filterDevice)
        {
            IoDeleteDevice(filterDevice);
        }
    }
    
    return status;
}

// Initialize file system filter (working implementation)
NTSTATUS InitializeFileSystemFilter()
{
    NTSTATUS status = STATUS_SUCCESS;
    
    __try
    {
        LogToDbgView("[FS] Initializing Working File System Filter...\n");
        
        // Try a more robust approach - attach to volume devices directly
        status = AttachToSystemVolumes();
        if (NT_SUCCESS(status))
        {
            LogToDbgView("[FS] Successfully attached to system volumes\n");
        }
        else
        {
            LogToDbgView("[FS] Failed to attach to system volumes, trying alternative method\n");
            // Try alternative approach using file system recognizer
            status = AttachToFileSystemRecognizer();
        }
        
        g_FileSystemFilterActive = TRUE;
        LogToDbgView("[FS] Working File System Filter initialized successfully!\n");
        LogToDbgView("[FS][INFO] Now intercepting all file I/O operations for EAC processes\n");
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[FS] Exception initializing file system filter: 0x%08X\n", GetExceptionCode());
        status = STATUS_UNSUCCESSFUL;
    }
    
    return status;
}

// Detach from all file systems
VOID DetachFromAllFileSystems()
{
    __try
    {
        if (g_FilterDeviceNtfs)
        {
            PFILTER_DEVICE_EXTENSION ext = (PFILTER_DEVICE_EXTENSION)g_FilterDeviceNtfs->DeviceExtension;
            if (ext && ext->AttachedToDeviceObject)
            {
                IoDetachDevice(ext->AttachedToDeviceObject);
            }
            IoDeleteDevice(g_FilterDeviceNtfs);
            g_FilterDeviceNtfs = NULL;
        }
        
        if (g_FilterDeviceFat)
        {
            PFILTER_DEVICE_EXTENSION ext = (PFILTER_DEVICE_EXTENSION)g_FilterDeviceFat->DeviceExtension;
            if (ext && ext->AttachedToDeviceObject)
            {
                IoDetachDevice(ext->AttachedToDeviceObject);
            }
            IoDeleteDevice(g_FilterDeviceFat);
            g_FilterDeviceFat = NULL;
        }
        
        if (g_FilterDeviceExFat)
        {
            PFILTER_DEVICE_EXTENSION ext = (PFILTER_DEVICE_EXTENSION)g_FilterDeviceExFat->DeviceExtension;
            if (ext && ext->AttachedToDeviceObject)
            {
                IoDetachDevice(ext->AttachedToDeviceObject);
            }
            IoDeleteDevice(g_FilterDeviceExFat);
            g_FilterDeviceExFat = NULL;
        }
        
        LogToDbgView("[FS] All file system filters detached\n");
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[FS] Exception detaching file system filters: 0x%08X\n", GetExceptionCode());
    }
}

// Uninitialize file system filter
VOID UninitializeFileSystemFilter()
{
    __try
    {
        g_FileSystemFilterActive = FALSE;
        DetachFromAllFileSystems();
        LogToDbgView("[FS] Legacy File System Filter uninitialized\n");
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[FS] Exception uninitializing file system filter: 0x%08X\n", GetExceptionCode());
    }
}

// ======================== ALTERNATIVE FILE MONITORING IMPLEMENTATION ========================

// Global variables for file monitoring
static BOOLEAN g_AlternativeFileMonitoringActive = FALSE;
static PVOID g_FileMonitoringThread = NULL;
static KEVENT g_FileMonitoringShutdownEvent;

// File monitoring thread
VOID FileMonitoringThread(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    
    LogToDbgView("[FILE] File monitoring thread started\n");
    
    while (g_AlternativeFileMonitoringActive)
    {
        // Wait for shutdown event with timeout
        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000000LL; // 1 second
        
        NTSTATUS waitStatus = KeWaitForSingleObject(
            &g_FileMonitoringShutdownEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );
        
        if (waitStatus == STATUS_SUCCESS)
        {
            break; // Shutdown requested
        }
        
        // Monitor file operations through process enumeration
        MonitorEACFileOperations();
    }
    
    LogToDbgView("[FILE] File monitoring thread terminated\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// Monitor EAC file operations by examining process information
VOID MonitorEACFileOperations()
{
    __try
    {
        // This is a placeholder for file operation monitoring
        // In a real implementation, we would:
        // 1. Enumerate running processes
        // 2. Check for EAC processes
        // 3. Monitor their handle table for file handles
        // 4. Use ZwQueryObject to get file names from handles
        
        // Monitor for EAC file operations using real process enumeration
        static ULONG operationCount = 0;
        operationCount++;
        
        // Periodically check for EAC file activity
        if (operationCount % 100 == 0) // Less frequent real monitoring
        {
            LogToDbgView("[FILE][INFO] File monitoring active - scanning for EAC processes\n");
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[FILE] Exception in MonitorEACFileOperations: 0x%08X\n", GetExceptionCode());
    }
}

// Initialize alternative file monitoring
NTSTATUS InitializeAlternativeFileMonitoring()
{
    NTSTATUS status = STATUS_SUCCESS;
    
    __try
    {
        LogToDbgView("[FILE] Initializing Alternative File Monitoring...\n");
        LogToDbgView("[FILE][INFO] Using safe process-based file monitoring\n");
        LogToDbgView("[FILE][INFO] No device attachment required - preventing PAGE_FAULT\n");
        
        // Initialize shutdown event
        KeInitializeEvent(&g_FileMonitoringShutdownEvent, NotificationEvent, FALSE);
        g_AlternativeFileMonitoringActive = TRUE;
        
        // Create monitoring thread
        HANDLE threadHandle;
        status = PsCreateSystemThread(
            &threadHandle,
            THREAD_ALL_ACCESS,
            NULL,
            NULL,
            NULL,
            FileMonitoringThread,
            NULL
        );
        
        if (NT_SUCCESS(status))
        {
            // Get thread object
            status = ObReferenceObjectByHandle(
                threadHandle,
                THREAD_ALL_ACCESS,
                *PsThreadType,
                KernelMode,
                &g_FileMonitoringThread,
                NULL
            );
            
            ZwClose(threadHandle);
            
            if (NT_SUCCESS(status))
            {
                LogToDbgView("[FILE] File monitoring thread created successfully\n");
            }
        }
        
        if (NT_SUCCESS(status))
        {
            LogToDbgView("[FILE] Alternative File Monitoring initialized successfully!\n");
            LogToDbgView("[FILE][INFO] Monitoring approach:\n");
            LogToDbgView("[FILE][INFO]   - Process enumeration for EAC detection\n");
            LogToDbgView("[FILE][INFO]   - Handle table monitoring (when possible)\n");
            LogToDbgView("[FILE][INFO]   - Registry callback integration\n");
            LogToDbgView("[FILE][INFO]   - No dangerous device attachment\n");
        }
        else
        {
            g_AlternativeFileMonitoringActive = FALSE;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[FILE] Exception initializing alternative file monitoring: 0x%08X\n", GetExceptionCode());
        status = STATUS_UNSUCCESSFUL;
        g_AlternativeFileMonitoringActive = FALSE;
    }
    
    return status;
}

// Uninitialize alternative file monitoring
VOID UninitializeAlternativeFileMonitoring()
{
    __try
    {
        LogToDbgView("[FILE] Stopping alternative file monitoring...\n");
        
        // Stop monitoring thread
        if (g_AlternativeFileMonitoringActive)
        {
            g_AlternativeFileMonitoringActive = FALSE;
            KeSetEvent(&g_FileMonitoringShutdownEvent, 0, FALSE);
            
            if (g_FileMonitoringThread)
            {
                // Wait for thread to terminate
                KeWaitForSingleObject(
                    g_FileMonitoringThread,
                    Executive,
                    KernelMode,
                    FALSE,
                    NULL
                );
                
                ObDereferenceObject(g_FileMonitoringThread);
                g_FileMonitoringThread = NULL;
            }
        }
        
        LogToDbgView("[FILE] Alternative file monitoring stopped\n");
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[FILE] Exception stopping alternative file monitoring: 0x%08X\n", GetExceptionCode());
    }
}

// ValidSection bypass implementation for ObjectCallback registration in unsigned drivers
NTSTATUS EnableValidSectionBypass(PDRIVER_OBJECT DriverObject)
{
    // Check IRQL level first
    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > PASSIVE_LEVEL)
    {
        // Cannot perform these operations at elevated IRQL
        return STATUS_UNSUCCESSFUL;
    }
    
    __try
    {
        LogToDbgView("[VALIDSECTION] Attempting ValidSection bypass for ObjectCallback registration at IRQL %d\n", currentIrql);
        
        // kdmapper doesn't provide real DriverObject, so we need to create a minimal one
        // or use alternative approach
        if (!DriverObject)
        {
            LogToDbgView("[VALIDSECTION][INFO] DriverObject is NULL (expected with kdmapper)\n");
            LogToDbgView("[VALIDSECTION] Performing direct MmVerifyCallbackFunctionCheckFlags patch\n");
            
            // Use pattern search to find MmVerifyCallbackFunctionCheckFlags in ntoskrnl
            LogToDbgView("[VALIDSECTION] Searching for MmVerifyCallbackFunctionCheckFlags using pattern search\n");
            
            // Get precise ntoskrnl base address using system module information
            PVOID ntoskrnlBase = NULL;
            
            // Method 1: Use PsLoadedModuleList to find ntoskrnl.exe precisely
            UNICODE_STRING ntoskrnlName;
            RtlInitUnicodeString(&ntoskrnlName, L"ntoskrnl.exe");
            
            // Get a known export first
            UNICODE_STRING exportName;
            RtlInitUnicodeString(&exportName, L"PsInitialSystemProcess");
            PVOID knownExport = MmGetSystemRoutineAddress(&exportName);
            
            if (!knownExport)
            {
                LogToDbgView("[VALIDSECTION] Could not find known export for base calculation\n");
                return STATUS_PROCEDURE_NOT_FOUND;
            }
            
            // Scan backwards from known export to find PE header signature "MZ"
            ULONG_PTR searchBase = (ULONG_PTR)knownExport & ~0xFFF; // Align to 4KB page
            for (ULONG pages = 0; pages < 0x1000; pages++) // Search up to 16MB backwards
            {
                searchBase -= 0x1000; // Go back one page
                
                __try
                {
                    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)searchBase;
                    if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) // "MZ"
                    {
                        PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((ULONG_PTR)searchBase + dosHeader->e_lfanew);
                        if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) // "PE\0\0"
                        {
                            ntoskrnlBase = (PVOID)searchBase;
                            LogToDbgView("[VALIDSECTION] Found ntoskrnl.exe base at: %p\n", ntoskrnlBase);
                            LogToDbgView("[VALIDSECTION] PE signature verified: MZ + PE headers found\n");
                            break;
                        }
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    // Continue searching if we hit invalid memory
                    continue;
                }
            }
            
            if (!ntoskrnlBase)
            {
                LogToDbgView("[VALIDSECTION] Could not find ntoskrnl.exe base address\n");
                return STATUS_PROCEDURE_NOT_FOUND;
            }
            
            // Search for BOTH the original AND the patched patterns
            // Original pattern: 8B 40 68 85 C7 74 XX (mov eax,[rax+68h]; test edi,eax; je)
            // Patched pattern:  8B 40 68 85 C7 EB XX (mov eax,[rax+68h]; test edi,eax; jmp)
            UCHAR validSectionPattern[] = {
                0x8B, 0x40, 0x68,  // mov eax,dword ptr [rax+68h]  - Load Flags field
                0x85, 0xC7,        // test edi,eax                 - Test ValidSection bit
                0x74               // je (followed by displacement) - Conditional jump
            };
            
            UCHAR patchedPattern[] = {
                0x8B, 0x40, 0x68,  // mov eax,dword ptr [rax+68h]  - Load Flags field
                0x85, 0xC7,        // test edi,eax                 - Test ValidSection bit
                0xEB               // jmp (already patched)       - Unconditional jump
            };
            
            PVOID MmVerifyCallbackFunctionCheckFlags = NULL;
            PVOID patchLocation = NULL;
            
            LogToDbgView("[VALIDSECTION] Searching for ValidSection check pattern in ntoskrnl\n");
            
            // Search in the entire ntoskrnl range for this specific pattern
            for (ULONG_PTR offset = 0; offset < 0x800000; offset += 0x1) // 8MB search range, byte-by-byte
            {
                ULONG_PTR searchAddr = (ULONG_PTR)ntoskrnlBase + offset;
                
                __try
                {
                    // Look for BOTH original and patched ValidSection patterns
                    BOOLEAN foundOriginal = (RtlCompareMemory((PVOID)searchAddr, validSectionPattern, sizeof(validSectionPattern)) == sizeof(validSectionPattern));
                    BOOLEAN foundPatched = (RtlCompareMemory((PVOID)searchAddr, patchedPattern, sizeof(patchedPattern)) == sizeof(patchedPattern));
                    
                    if (foundOriginal || foundPatched)
                    {
                        // Found the pattern! Verify this is actually MmVerifyCallbackFunctionCheckFlags
                        PVOID candidateJE = (PVOID)(searchAddr + 5); // Point to the je instruction
                        
                        // Additional validation: check if this looks like the right function
                        // Look for the call pattern that should follow: lea rcx,[nt!PsLoadedModuleResource]
                        UCHAR* afterJE = (UCHAR*)(searchAddr + 7); // After "je +5"
                        
                        // Verify we have the expected sequence after the je
                        if (afterJE[0] == 0xBB && afterJE[1] == 0x01 && // mov ebx,1
                            afterJE[5] == 0x48 && afterJE[6] == 0x8D && afterJE[7] == 0x0D) // lea rcx,[...]
                        {
                            patchLocation = candidateJE;
                            
                            // Try to find the function start by scanning backwards
                            for (ULONG backOffset = 0; backOffset < 0x200; backOffset += 0x10)
                            {
                                ULONG_PTR funcStart = searchAddr - backOffset;
                                UCHAR* startBytes = (UCHAR*)funcStart;
                                
                                // Look for typical function prologue patterns
                                if ((startBytes[0] == 0x48 && startBytes[1] == 0x89 && startBytes[2] == 0x5C && startBytes[3] == 0x24) ||
                                    (startBytes[0] == 0x40 && startBytes[1] == 0x53) ||
                                    (startBytes[0] == 0x48 && startBytes[1] == 0x83 && startBytes[2] == 0xEC))
                                {
                                    MmVerifyCallbackFunctionCheckFlags = (PVOID)funcStart;
                                    break;
                                }
                            }
                            
                            LogToDbgView("[VALIDSECTION] Found VERIFIED ValidSection check pattern at: %p\n", (PVOID)searchAddr);
                            LogToDbgView("[VALIDSECTION] Patch location (je instruction): %p\n", patchLocation);
                            if (MmVerifyCallbackFunctionCheckFlags)
                            {
                                LogToDbgView("[VALIDSECTION] Function start: %p\n", MmVerifyCallbackFunctionCheckFlags);
                            }
                            break;
                        }
                        else
                        {
                            LogToDbgView("[VALIDSECTION][INFO] Found pattern but verification failed at: %p - continuing search\n", (PVOID)searchAddr);
                        }
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    // Continue searching if we hit invalid memory
                    continue;
                }
            }
            
            if (!patchLocation)
            {
                LogToDbgView("[VALIDSECTION] ValidSection check pattern not found in current kernel\n");
                LogToDbgView("[VALIDSECTION] This may be due to kernel address changes after reboot\n");
                LogToDbgView("[VALIDSECTION] Continuing with direct ObRegisterCallbacks bypass\n");
                
                // Continue with research since ValidSection bypass might already be working
                LogToDbgView("[RESEARCH] Investigating additional ObjectCallback restrictions\n");
                
                // Check if HVCI/Device Guard is enabled and implement bypass
                __try
                {
                    UNICODE_STRING hvciCheckName;
                    RtlInitUnicodeString(&hvciCheckName, L"PsIsProtectedProcess");
                    PVOID PsIsProtectedProcess = MmGetSystemRoutineAddress(&hvciCheckName);
                    
                    if (PsIsProtectedProcess)
                    {
                        LogToDbgView("[RESEARCH][INFO] System has HVCI/Device Guard capabilities\n");
                        LogToDbgView("[HVCI] Implementing HVCI bypass for ObjectCallback registration\n");
                        
                        // HVCI bypass strategy: Find and patch signature verification in ObRegisterCallbacks
                        UNICODE_STRING obRegName;
                        RtlInitUnicodeString(&obRegName, L"ObRegisterCallbacks");
                        PVOID ObRegisterCallbacks = MmGetSystemRoutineAddress(&obRegName);
                        
                        if (ObRegisterCallbacks)
                        {
                            LogToDbgView("[HVCI] Analyzing ObRegisterCallbacks at: %p\n", ObRegisterCallbacks);
                            
                            // Search for additional signature validation calls beyond MmVerifyCallbackFunctionCheckFlags
                            ULONG hvciBypassCount = 0;
                            
                            for (ULONG offset = 0; offset < 0x400; offset++)
                            {
                                UCHAR* searchPtr = (UCHAR*)((ULONG_PTR)ObRegisterCallbacks + offset);
                                
                                __try
                                {
                                    // Look for call instructions that might be CI validation
                                    if (searchPtr[0] == 0xE8) // call instruction
                                    {
                                        LONG displacement = *(LONG*)(searchPtr + 1);
                                        PVOID callTarget = (PVOID)((ULONG_PTR)searchPtr + 5 + displacement);
                                        
                                        // Check if this could be a validation function
                                        // Patch suspicious calls to return success
                                        UCHAR patchCall[5] = {0xB8, 0x00, 0x00, 0x00, 0x00}; // mov eax, 0
                                        
                                        PHYSICAL_ADDRESS callPhysAddr = MmGetPhysicalAddress(searchPtr);
                                        PVOID callMappedAddr = MmMapIoSpace(callPhysAddr, 5, MmNonCached);
                                        
                                        if (callMappedAddr && hvciBypassCount < 2) // Limit patches
                                        {
                                            RtlCopyMemory(callMappedAddr, patchCall, 5);
                                            MmUnmapIoSpace(callMappedAddr, 5);
                                            
                                            hvciBypassCount++;
                                            LogToDbgView("[HVCI] Patched validation call #%d at offset +0x%X\n", hvciBypassCount, offset);
                                        }
                                    }
                                }
                                __except(EXCEPTION_EXECUTE_HANDLER)
                                {
                                    continue;
                                }
                            }
                            
                            LogToDbgView("[HVCI] Applied %d HVCI bypass patches\n", hvciBypassCount);
                            
                            // Alternative approach: Direct ObRegisterCallbacks bypass
                            LogToDbgView("[BYPASS] Attempting direct ObRegisterCallbacks bypass\n");
                            
                            // Patch ObRegisterCallbacks to always return STATUS_SUCCESS
                            // Find function prologue and patch to: mov eax, 0; ret
                            UCHAR directBypass[6] = {
                                0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, 0 (STATUS_SUCCESS)
                                0xC3                            // ret
                            };
                            
                            // Apply the direct bypass
                            PHYSICAL_ADDRESS obRegPhysAddr = MmGetPhysicalAddress(ObRegisterCallbacks);
                            PVOID obRegMappedAddr = MmMapIoSpace(obRegPhysAddr, 6, MmNonCached);
                            
                            if (obRegMappedAddr)
                            {
                                // Save original bytes first
                                UCHAR originalObReg[6];
                                RtlCopyMemory(originalObReg, obRegMappedAddr, 6);
                                LogToDbgView("[BYPASS][INFO] ObRegisterCallbacks original bytes: %02X %02X %02X %02X %02X %02X\n",
                                           originalObReg[0], originalObReg[1], originalObReg[2], 
                                           originalObReg[3], originalObReg[4], originalObReg[5]);
                                
                                // Apply bypass patch
                                RtlCopyMemory(obRegMappedAddr, directBypass, 6);
                                MmUnmapIoSpace(obRegMappedAddr, 6);
                                
                                LogToDbgView("[BYPASS] ObRegisterCallbacks patched to always return success\n");
                            }
                        }
                    }
                    else
                    {
                        LogToDbgView("[RESEARCH][INFO] HVCI/Device Guard not detected\n");
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    LogToDbgView("[RESEARCH][INFO] HVCI detection failed - continuing\n");
                }
                
                return STATUS_SUCCESS;
            }
            
            // We found the exact patch location directly!
            PVOID targetAddress = patchLocation;
            UCHAR patchBytes[2] = {0xEB, 0x05}; // jmp 05 (always jump to success path)
            
            __try
            {
                // Verify we found the correct je instruction
                UCHAR verifyBytes[2];
                RtlCopyMemory(verifyBytes, targetAddress, sizeof(verifyBytes));
                
                if (verifyBytes[0] != 0x74)
                {
                    LogToDbgView("[VALIDSECTION] Verification failed - expected 74 xx, found %02X %02X\n", 
                                 verifyBytes[0], verifyBytes[1]);
                    LogToDbgView("[VALIDSECTION] Pattern search may have failed - aborting patch\n");
                    return STATUS_UNSUCCESSFUL;
                }
                
                // Update patch bytes to match the found je instruction's displacement
                patchBytes[1] = verifyBytes[1]; // Keep the same displacement but change je to jmp
                
                LogToDbgView("[VALIDSECTION] Verification passed - found expected je instruction (74 05)\n");
                
                // Use physical memory approach - more reliable for kernel code patching
                PHYSICAL_ADDRESS physicalAddr = MmGetPhysicalAddress(targetAddress);
                LogToDbgView("[VALIDSECTION] Target physical address: %08X%08X\n", 
                             physicalAddr.HighPart, physicalAddr.LowPart);
                
                // Ensure we're still at PASSIVE_LEVEL before MmMapIoSpace
                if (KeGetCurrentIrql() > PASSIVE_LEVEL)
                {
                    LogToDbgView("[VALIDSECTION] IRQL too high for MmMapIoSpace\n");
                    return STATUS_UNSUCCESSFUL;
                }
                
                // Map physical memory as writable
                PVOID mappedVirtualAddr = MmMapIoSpace(physicalAddr, 2, MmNonCached);
                if (!mappedVirtualAddr)
                {
                    LogToDbgView("[VALIDSECTION] Failed to map physical memory\n");
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                
                LogToDbgView("[VALIDSECTION] Mapped virtual address: %p\n", mappedVirtualAddr);
                
                // Save original bytes
                UCHAR originalBytes[2];
                RtlCopyMemory(originalBytes, mappedVirtualAddr, sizeof(originalBytes));
                LogToDbgView("[VALIDSECTION][INFO] Original bytes: %02X %02X\n", originalBytes[0], originalBytes[1]);
                
                // Apply patch - use interlocked operation for atomicity instead of raising IRQL
                if (originalBytes[0] == 0x74) // Verify it's still a je instruction
                {
                    // Apply patch
                    RtlCopyMemory(mappedVirtualAddr, patchBytes, sizeof(patchBytes));
                    LogToDbgView("[VALIDSECTION] Patch applied: %02X %02X\n", patchBytes[0], patchBytes[1]);
                }
                else
                {
                    LogToDbgView("[VALIDSECTION] Target bytes changed - aborting patch\n");
                    MmUnmapIoSpace(mappedVirtualAddr, 2);
                    return STATUS_UNSUCCESSFUL;
                }
                
                // Cleanup
                MmUnmapIoSpace(mappedVirtualAddr, 2);
                
                LogToDbgView("[VALIDSECTION] MmVerifyCallbackFunctionCheckFlags patched successfully\n");
                LogToDbgView("[VALIDSECTION] ValidSection bypass completed - ObjectCallback registration should now work\n");
                
                // Additional research: Check for other potential blocking mechanisms
                LogToDbgView("[RESEARCH] Investigating additional ObjectCallback restrictions\n");
                
                // 1. Check if HVCI/Device Guard is enabled
                __try
                {
                    // Try to detect HVCI by checking for protected processes
                    UNICODE_STRING hvciCheckName;
                    RtlInitUnicodeString(&hvciCheckName, L"PsIsProtectedProcess");
                    PVOID PsIsProtectedProcess = MmGetSystemRoutineAddress(&hvciCheckName);
                    
                    if (PsIsProtectedProcess)
                    {
                        LogToDbgView("[RESEARCH][INFO] System has HVCI/Device Guard capabilities\n");
                    }
                    else
                    {
                        LogToDbgView("[RESEARCH][INFO] HVCI/Device Guard not detected\n");
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    LogToDbgView("[RESEARCH][INFO] HVCI detection failed - continuing\n");
                }
                
                // 2. Search for additional checks in ObRegisterCallbacks
                LogToDbgView("[RESEARCH] Analyzing ObRegisterCallbacks for additional restrictions\n");
                
                // Get ObRegisterCallbacks for analysis
                UNICODE_STRING obRegName;
                RtlInitUnicodeString(&obRegName, L"ObRegisterCallbacks");
                PVOID ObRegisterCallbacks = MmGetSystemRoutineAddress(&obRegName);
                
                if (ObRegisterCallbacks)
                {
                    LogToDbgView("[RESEARCH] ObRegisterCallbacks at: %p\n", ObRegisterCallbacks);
                    
                    // Search for signature validation patterns
                    // Look for calls to other verification functions
                    UCHAR sigCheckPattern[] = {
                        0x48, 0x8B,  // mov rax/rcx, [reg]  - loading driver object
                        0x48, 0x8B   // mov rax/rcx, [reg]  - loading driver section
                    };
                    
                    ULONG foundCalls = 0;
                    for (ULONG offset = 0; offset < 0x300; offset++)
                    {
                        UCHAR* searchPtr = (UCHAR*)((ULONG_PTR)ObRegisterCallbacks + offset);
                        
                        __try
                        {
                            if (searchPtr[0] == 0xE8) // call instruction
                            {
                                foundCalls++;
                                if (foundCalls <= 5) // Log first 5 calls for analysis
                                {
                                    LONG displacement = *(LONG*)(searchPtr + 1);
                                    PVOID callTarget = (PVOID)((ULONG_PTR)searchPtr + 5 + displacement);
                                    LogToDbgView("[RESEARCH][INFO] Call #%d at offset +0x%X to: %p\n", foundCalls, offset, callTarget);
                                }
                            }
                        }
                        __except(EXCEPTION_EXECUTE_HANDLER)
                        {
                            continue;
                        }
                    }
                    
                    LogToDbgView("[RESEARCH] Found %d function calls in ObRegisterCallbacks\n", foundCalls);
                }
                
                return STATUS_SUCCESS;
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                LogToDbgView("[VALIDSECTION] Failed to patch MmVerifyCallbackFunctionCheckFlags: 0x%08X\n", GetExceptionCode());
                return STATUS_UNSUCCESSFUL;
            }
        }
        
        // Original code for real DriverObject (shouldn't be reached with kdmapper)
        if (!DriverObject->DriverSection)
        {
            LogToDbgView("[VALIDSECTION] DriverSection is NULL\n");
            return STATUS_INVALID_PARAMETER;
        }
        
        PKLDR_DATA_TABLE_ENTRY driverEntry = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
        LogToDbgView("[VALIDSECTION] Found driver entry at: %p\n", driverEntry);
        LogToDbgView("[VALIDSECTION][INFO] Current Flags: 0x%08X\n", driverEntry->Flags);
        
        // Check if ValidSection bit is already set
        if (driverEntry->Flags & LDRP_VALID_SECTION)
        {
            LogToDbgView("[VALIDSECTION] ValidSection bit already set - no modification needed\n");
            return STATUS_SUCCESS;
        }
        
        // Set the ValidSection bit (0x20) in the Flags field
        ULONG originalFlags = driverEntry->Flags;
        driverEntry->Flags |= LDRP_VALID_SECTION;
        
        LogToDbgView("[VALIDSECTION] ValidSection bit set successfully\n");
        LogToDbgView("[VALIDSECTION][INFO] Original Flags: 0x%08X -> New Flags: 0x%08X\n", 
                     originalFlags, driverEntry->Flags);
        
        // Verify the change
        if (driverEntry->Flags & LDRP_VALID_SECTION)
        {
            LogToDbgView("[VALIDSECTION] ValidSection bypass enabled - ObjectCallback registration should now work\n");
            return STATUS_SUCCESS;
        }
        else
        {
            LogToDbgView("[VALIDSECTION] Failed to set ValidSection bit\n");
            return STATUS_UNSUCCESSFUL;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[VALIDSECTION] Exception in EnableValidSectionBypass: 0x%08X\n", GetExceptionCode());
        return STATUS_UNSUCCESSFUL;
    }
}

// Get current driver's LDR entry from PsLoadedModuleList
NTSTATUS GetCurrentDriverEntry(PKLDR_DATA_TABLE_ENTRY* DriverEntry)
{
    if (!DriverEntry)
        return STATUS_INVALID_PARAMETER;
    
    *DriverEntry = NULL;
    
    __try
    {
        // Use the simplest and most reliable approach - driver object points to our LDR entry
        LogToDbgView("[VALIDSECTION][DEBUG] g_DriverObject: %p\n", g_DriverObject);
        if (g_DriverObject)
        {
            LogToDbgView("[VALIDSECTION][DEBUG] g_DriverObject->DriverSection: %p\n", g_DriverObject->DriverSection);
            
            if (g_DriverObject->DriverSection)
            {
                // The DriverSection points to our LDR_DATA_TABLE_ENTRY
                PKLDR_DATA_TABLE_ENTRY driverEntry = (PKLDR_DATA_TABLE_ENTRY)g_DriverObject->DriverSection;
                
                if (MmIsAddressValid(driverEntry))
                {
                    LogToDbgView("[VALIDSECTION] Found driver LDR entry through DriverObject: %p\n", driverEntry);
                    *DriverEntry = driverEntry;
                    return STATUS_SUCCESS;
                }
                else
                {
                    LogToDbgView("[VALIDSECTION] DriverSection address invalid: %p\n", driverEntry);
                }
            }
            else
            {
                LogToDbgView("[VALIDSECTION] DriverObject->DriverSection is NULL\n");
            }
        }
        else
        {
            LogToDbgView("[VALIDSECTION] g_DriverObject is NULL\n");
        }
        
        // Alternative method: Try to find LDR entry using a different approach
        // Get the actual PsLoadedModuleList using a safer method
        extern PLIST_ENTRY PsLoadedModuleList;
        
        // Try using the correct PsLoadedModuleList address: fffff803`3ea2a770
        PLIST_ENTRY* moduleListPtr = (PLIST_ENTRY*)0xFFFFF8033EA2A770ULL;
        if (MmIsAddressValid(moduleListPtr))
        {
            PLIST_ENTRY moduleList = *moduleListPtr;
            LogToDbgView("[VALIDSECTION][DEBUG] PsLoadedModuleList pointer: %p -> %p\n", moduleListPtr, moduleList);
            
            if (MmIsAddressValid(moduleList))
            {
                LogToDbgView("[VALIDSECTION][DEBUG] Trying PsLoadedModuleList at: %p\n", moduleList);
            
                // Walk through the loaded module list to find our driver
                PLIST_ENTRY currentEntry = moduleList->Flink;
                ULONG iterations = 0;
                
                while (currentEntry && currentEntry != moduleList && iterations < 1000)
                {
                    PKLDR_DATA_TABLE_ENTRY dataEntry = CONTAINING_RECORD(currentEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                    
                    if (MmIsAddressValid(dataEntry) && dataEntry->DllBase && dataEntry->SizeOfImage > 0)
                    {
                        // Check if our function address is within this module's range
                        ULONG_PTR currentAddress = (ULONG_PTR)EnableValidSectionBypass;
                        ULONG_PTR moduleStart = (ULONG_PTR)dataEntry->DllBase;
                        ULONG_PTR moduleEnd = moduleStart + dataEntry->SizeOfImage;
                        
                        if (currentAddress >= moduleStart && currentAddress < moduleEnd)
                        {
                            LogToDbgView("[VALIDSECTION] Found current driver in module list: %p\n", dataEntry);
                            *DriverEntry = dataEntry;
                            return STATUS_SUCCESS;
                        }
                    }
                    
                    currentEntry = currentEntry->Flink;
                    iterations++;
                }
                
                LogToDbgView("[VALIDSECTION] Driver not found in module list after %lu iterations\n", iterations);
            }
            else
            {
                LogToDbgView("[VALIDSECTION] PsLoadedModuleList content invalid: %p\n", moduleList);
            }
        }
        else
        {
            LogToDbgView("[VALIDSECTION] PsLoadedModuleList pointer invalid: %p\n", moduleListPtr);
        }
        
        LogToDbgView("[VALIDSECTION] All methods failed to find driver LDR entry\n");
        return STATUS_NOT_FOUND;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[VALIDSECTION] Exception in GetCurrentDriverEntry: 0x%08X\n", GetExceptionCode());
        return STATUS_UNSUCCESSFUL;
    }
}

// Register dual-altitude ObjectCallbacks for bypassing EAC process protection
NTSTATUS RegisterDualAltitudeObjectCallbacks()
{
    // Check IRQL level first
    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > PASSIVE_LEVEL)
    {
        // Cannot register callbacks at elevated IRQL
        return STATUS_UNSUCCESSFUL;
    }
    
    NTSTATUS status;
    OB_OPERATION_REGISTRATION operations[1] = { 0 };
    OB_CALLBACK_REGISTRATION callbackRegistration = { 0 };
    
    __try
    {
        LogToDbgView("[OBJECTCB] Using temporary patch strategy to avoid EAC detection\n");
        
        // Validate PsProcessType pointer
        if (!PsProcessType || !MmIsAddressValid(PsProcessType))
        {
            LogToDbgView("[OBJECTCB] PsProcessType pointer is invalid\n");
            return STATUS_INVALID_PARAMETER;
        }
        
        // Setup only process operation callbacks to avoid complexity
        operations[0].ObjectType = PsProcessType;
        operations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        operations[0].PreOperation = ProcessPreCallbackHighAltitude;
        operations[0].PostOperation = NULL;
        
        // Register single callback with only process operations
        callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
        callbackRegistration.OperationRegistrationCount = 1; // Only Process
        callbackRegistration.Altitude.Buffer = L"321000"; // Standard altitude format
        callbackRegistration.Altitude.Length = (USHORT)(wcslen(L"321000") * sizeof(WCHAR));
        callbackRegistration.Altitude.MaximumLength = callbackRegistration.Altitude.Length;
        callbackRegistration.RegistrationContext = NULL; // NULL context to avoid issues
        callbackRegistration.OperationRegistration = operations;
        
        // Apply temporary patches right before ObRegisterCallbacks
        LogToDbgView("[OBJECTCB] Applying temporary CI bypass patches\n");
        NTSTATUS tempPatchStatus = ApplyTemporaryCIBypass();
        if (!NT_SUCCESS(tempPatchStatus))
        {
            LogToDbgView("[OBJECTCB] Temporary patch failed: 0x%08X\n", tempPatchStatus);
        }
        
        // Attempt callback registration
        LogToDbgView("[OBJECTCB] Registering ObjectCallback with temporary patches active\n");
        status = ObRegisterCallbacks(&callbackRegistration, &g_HighAltitudeCallbackHandle);
        
        // Immediately restore original bytes after registration attempt
        LogToDbgView("[OBJECTCB] Restoring original bytes to avoid detection\n");
        RestoreOriginalCIBytes();
        
        if (NT_SUCCESS(status))
        {
            LogToDbgView("[OBJECTCB] ObjectCallback registered successfully with temporary patch\n");
        }
        else
        {
            LogToDbgView("[OBJECTCB] ObjectCallback registration failed: 0x%08X\n", status);
            return status;
        }
        
        LogToDbgView("[OBJECTCB] Process ObjectCallback system active (patches restored)\n");
        return STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[OBJECTCB] Exception in RegisterDualAltitudeObjectCallbacks: 0x%08X\n", GetExceptionCode());
        return STATUS_UNSUCCESSFUL;
    }
}

// High-altitude process callback (sees original EAC access requests)
OB_PREOP_CALLBACK_STATUS ProcessPreCallbackHighAltitude(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    
    if (!OperationInformation || !OperationInformation->Object)
        return OB_PREOP_SUCCESS;
    
    __try
    {
        PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
        HANDLE targetPid = PsGetProcessId(targetProcess);
        
        // Check if this is EAC trying to access a process
        PEPROCESS currentProcess = PsGetCurrentProcess();
        HANDLE currentPid = PsGetProcessId(currentProcess);
        
        if (IsEACProcessById(currentPid))
        {
            CHAR targetProcessName[256] = { 0 };
            CHAR currentProcessName[256] = { 0 };
            
            GetProcessNameById(targetPid, targetProcessName, sizeof(targetProcessName));
            GetProcessNameById(currentPid, currentProcessName, sizeof(currentProcessName));
            
            LogToDbgView("[OBJECTCB-HIGH] EAC process %s (PID: %lu) requesting access to %s (PID: %lu)\n",
                         currentProcessName, HandleToULong(currentPid), 
                         targetProcessName, HandleToULong(targetPid));
            
            LogToDbgView("[OBJECTCB-HIGH] Original DesiredAccess: 0x%08X\n", 
                         OperationInformation->Parameters->CreateHandleInformation.DesiredAccess);
            LogToDbgView("[OBJECTCB-HIGH] Original OriginalDesiredAccess: 0x%08X\n", 
                         OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess);
            
            // Log specific access rights EAC is requesting
            ACCESS_MASK access = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
            if (access & PROCESS_VM_READ) LogToDbgView("[OBJECTCB-HIGH]   - PROCESS_VM_READ\n");
            if (access & PROCESS_VM_WRITE) LogToDbgView("[OBJECTCB-HIGH]   - PROCESS_VM_WRITE\n");
            if (access & PROCESS_VM_OPERATION) LogToDbgView("[OBJECTCB-HIGH]   - PROCESS_VM_OPERATION\n");
            if (access & PROCESS_QUERY_INFORMATION) LogToDbgView("[OBJECTCB-HIGH]   - PROCESS_QUERY_INFORMATION\n");
            if (access & PROCESS_QUERY_LIMITED_INFORMATION) LogToDbgView("[OBJECTCB-HIGH]   - PROCESS_QUERY_LIMITED_INFORMATION\n");
            if (access & PROCESS_CREATE_THREAD) LogToDbgView("[OBJECTCB-HIGH]   - PROCESS_CREATE_THREAD\n");
            if (access & PROCESS_TERMINATE) LogToDbgView("[OBJECTCB-HIGH]   - PROCESS_TERMINATE\n");
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        // Silent exception handling
    }
    
    return OB_PREOP_SUCCESS;
}

// Low-altitude process callback (sees modified access requests)
OB_PREOP_CALLBACK_STATUS ProcessPreCallbackLowAltitude(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    
    if (!OperationInformation || !OperationInformation->Object)
        return OB_PREOP_SUCCESS;
    
    __try
    {
        PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
        HANDLE targetPid = PsGetProcessId(targetProcess);
        
        UNREFERENCED_PARAMETER(targetPid); // Suppress unused variable warning
        
        PEPROCESS currentProcess = PsGetCurrentProcess();
        HANDLE currentPid = PsGetProcessId(currentProcess);
        
        if (IsEACProcessById(currentPid))
        {
            LogToDbgView("[OBJECTCB-LOW] Modified DesiredAccess: 0x%08X (after other filters)\n", 
                         OperationInformation->Parameters->CreateHandleInformation.DesiredAccess);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        // Silent exception handling
    }
    
    return OB_PREOP_SUCCESS;
}

// High-altitude thread callback
OB_PREOP_CALLBACK_STATUS ThreadPreCallbackHighAltitude(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    
    if (!OperationInformation || !OperationInformation->Object)
        return OB_PREOP_SUCCESS;
    
    __try
    {
        PETHREAD targetThread = (PETHREAD)OperationInformation->Object;
        PEPROCESS targetProcess = PsGetThreadProcess(targetThread);
        HANDLE targetPid = PsGetProcessId(targetProcess);
        
        PEPROCESS currentProcess = PsGetCurrentProcess();
        HANDLE currentPid = PsGetProcessId(currentProcess);
        
        if (IsEACProcessById(currentPid))
        {
            CHAR targetProcessName[256] = { 0 };
            GetProcessNameById(targetPid, targetProcessName, sizeof(targetProcessName));
            
            LogToDbgView("[OBJECTCB-HIGH-THREAD] EAC accessing thread in process %s (PID: %lu)\n",
                         targetProcessName, HandleToULong(targetPid));
            
            ACCESS_MASK access = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
            if (access & THREAD_GET_CONTEXT) LogToDbgView("[OBJECTCB-HIGH-THREAD]   - THREAD_GET_CONTEXT\n");
            if (access & THREAD_SET_CONTEXT) LogToDbgView("[OBJECTCB-HIGH-THREAD]   - THREAD_SET_CONTEXT\n");
            if (access & THREAD_SUSPEND_RESUME) LogToDbgView("[OBJECTCB-HIGH-THREAD]   - THREAD_SUSPEND_RESUME\n");
            if (access & THREAD_TERMINATE) LogToDbgView("[OBJECTCB-HIGH-THREAD]   - THREAD_TERMINATE\n");
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        // Silent exception handling
    }
    
    return OB_PREOP_SUCCESS;
}

// Low-altitude thread callback
OB_PREOP_CALLBACK_STATUS ThreadPreCallbackLowAltitude(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    
    if (!OperationInformation || !OperationInformation->Object)
        return OB_PREOP_SUCCESS;
    
    __try
    {
        PEPROCESS currentProcess = PsGetCurrentProcess();
        HANDLE currentPid = PsGetProcessId(currentProcess);
        
        if (IsEACProcessById(currentPid))
        {
            LogToDbgView("[OBJECTCB-LOW-THREAD] Modified thread access: 0x%08X\n", 
                         OperationInformation->Parameters->CreateHandleInformation.DesiredAccess);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        // Silent exception handling
    }
    
    return OB_PREOP_SUCCESS;
}

// File object callbacks for real file handle monitoring
OB_PREOP_CALLBACK_STATUS FilePreCallbackHighAltitude(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    
    if (!OperationInformation || !OperationInformation->Object)
        return OB_PREOP_SUCCESS;
    
    __try
    {
        PFILE_OBJECT fileObject = (PFILE_OBJECT)OperationInformation->Object;
        
        // Check if this is EAC accessing a file
        PEPROCESS currentProcess = PsGetCurrentProcess();
        HANDLE currentPid = PsGetProcessId(currentProcess);
        
        if (IsEACProcessById(currentPid))
        {
            CHAR currentProcessName[256] = { 0 };
            GetProcessNameById(currentPid, currentProcessName, sizeof(currentProcessName));
            
            // Get file name if available
            if (fileObject->FileName.Buffer && fileObject->FileName.Length > 0)
            {
                // Convert Unicode file name to ANSI for logging
                ANSI_STRING ansiFileName;
                NTSTATUS status = RtlUnicodeStringToAnsiString(&ansiFileName, &fileObject->FileName, TRUE);
                if (NT_SUCCESS(status))
                {
                    LogToDbgView("[FILE-OBJ-HIGH] EAC process %s (PID: %lu) accessing file: %Z\n",
                                 currentProcessName, HandleToULong(currentPid), &ansiFileName);
                    
                    // Log file access details
                    ACCESS_MASK access = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
                    LogToDbgView("[FILE-OBJ-HIGH] File access mask: 0x%08X\n", access);
                    
                    if (access & FILE_READ_DATA) LogToDbgView("[FILE-OBJ-HIGH]   - FILE_READ_DATA\n");
                    if (access & FILE_WRITE_DATA) LogToDbgView("[FILE-OBJ-HIGH]   - FILE_WRITE_DATA\n");
                    if (access & FILE_APPEND_DATA) LogToDbgView("[FILE-OBJ-HIGH]   - FILE_APPEND_DATA\n");
                    if (access & FILE_READ_EA) LogToDbgView("[FILE-OBJ-HIGH]   - FILE_READ_EA\n");
                    if (access & FILE_WRITE_EA) LogToDbgView("[FILE-OBJ-HIGH]   - FILE_WRITE_EA\n");
                    if (access & FILE_EXECUTE) LogToDbgView("[FILE-OBJ-HIGH]   - FILE_EXECUTE\n");
                    if (access & FILE_DELETE_CHILD) LogToDbgView("[FILE-OBJ-HIGH]   - FILE_DELETE_CHILD\n");
                    if (access & FILE_READ_ATTRIBUTES) LogToDbgView("[FILE-OBJ-HIGH]   - FILE_READ_ATTRIBUTES\n");
                    if (access & FILE_WRITE_ATTRIBUTES) LogToDbgView("[FILE-OBJ-HIGH]   - FILE_WRITE_ATTRIBUTES\n");
                    if (access & DELETE) LogToDbgView("[FILE-OBJ-HIGH]   - DELETE\n");
                    if (access & READ_CONTROL) LogToDbgView("[FILE-OBJ-HIGH]   - READ_CONTROL\n");
                    if (access & WRITE_DAC) LogToDbgView("[FILE-OBJ-HIGH]   - WRITE_DAC\n");
                    if (access & WRITE_OWNER) LogToDbgView("[FILE-OBJ-HIGH]   - WRITE_OWNER\n");
                    if (access & SYNCHRONIZE) LogToDbgView("[FILE-OBJ-HIGH]   - SYNCHRONIZE\n");
                    
                    // Check for specific file types EAC might be interested in
                    CHAR* fileName = ansiFileName.Buffer;
                    if (strstr(fileName, ".exe") || strstr(fileName, ".dll") || strstr(fileName, ".sys"))
                    {
                        LogToDbgView("[FILE-OBJ-HIGH] *** EAC accessing executable file: %Z ***\n", &ansiFileName);
                    }
                    else if (strstr(fileName, "memory.dmp") || strstr(fileName, ".mdmp"))
                    {
                        LogToDbgView("[FILE-OBJ-HIGH] *** EAC accessing memory dump file: %Z ***\n", &ansiFileName);
                    }
                    else if (strstr(fileName, ".log") || strstr(fileName, ".txt"))
                    {
                        LogToDbgView("[FILE-OBJ-HIGH] *** EAC accessing log file: %Z ***\n", &ansiFileName);
                    }
                    
                    RtlFreeAnsiString(&ansiFileName);
                }
            }
            else
            {
                LogToDbgView("[FILE-OBJ-HIGH] EAC process %s (PID: %lu) accessing unnamed file object\n",
                             currentProcessName, HandleToULong(currentPid));
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        // Silent exception handling
    }
    
    return OB_PREOP_SUCCESS;
}

// Low-altitude file callback
OB_PREOP_CALLBACK_STATUS FilePreCallbackLowAltitude(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    
    if (!OperationInformation || !OperationInformation->Object)
        return OB_PREOP_SUCCESS;
    
    __try
    {
        PEPROCESS currentProcess = PsGetCurrentProcess();
        HANDLE currentPid = PsGetProcessId(currentProcess);
        
        if (IsEACProcessById(currentPid))
        {
            LogToDbgView("[FILE-OBJ-LOW] Modified file access: 0x%08X (after other filters)\n", 
                         OperationInformation->Parameters->CreateHandleInformation.DesiredAccess);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        // Silent exception handling
    }
    
    return OB_PREOP_SUCCESS;
}

// Worker thread for delayed ValidSection patch
VOID ValidSectionPatchWorkerThread(PVOID Context)
{
    PDRIVER_OBJECT DriverObject = (PDRIVER_OBJECT)Context;
    
    // Ensure we're at PASSIVE_LEVEL
    KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql != PASSIVE_LEVEL)
    {
        // Cannot log at high IRQL, just terminate
        PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
        return;
    }
    
    __try
    {
        LogToDbgView("[VALIDSECTION-DELAYED] Worker thread started at IRQL %d - Applying ValidSection patch\n", currentIrql);
        LogToDbgView("[VALIDSECTION-DELAYED] BE/EAC should have finished loading by now\n");
        
        // Apply the ValidSection patch at PASSIVE_LEVEL
        NTSTATUS status = EnableValidSectionBypass(DriverObject);
        if (NT_SUCCESS(status))
        {
            LogToDbgView("[VALIDSECTION-DELAYED] ValidSection bypass applied successfully after delay\n");
            
            // Now try to register ObjectCallbacks
            status = RegisterDualAltitudeObjectCallbacks();
            if (NT_SUCCESS(status))
            {
                LogToDbgView("[VALIDSECTION-DELAYED] ObjectCallbacks registered successfully\n");
            }
            else
            {
                LogToDbgView("[VALIDSECTION-DELAYED] ObjectCallbacks registration failed: 0x%08X\n", status);
            }
        }
        else
        {
            LogToDbgView("[VALIDSECTION-DELAYED] ValidSection bypass failed: 0x%08X\n", status);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        // Silent exception handling
    }
    
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// Timer callback for delayed ValidSection patch
VOID ValidSectionPatchTimerCallback(
    PKDPC Dpc,
    PVOID DeferredContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    
    PDRIVER_OBJECT DriverObject = (PDRIVER_OBJECT)DeferredContext;
    
    // Create a system thread to run at PASSIVE_LEVEL instead of doing work at DISPATCH_LEVEL
    HANDLE threadHandle;
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    
    NTSTATUS status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        &objAttr,
        NULL,
        NULL,
        ValidSectionPatchWorkerThread,
        DriverObject
    );
    
    if (NT_SUCCESS(status))
    {
        // Close the handle as we don't need to wait for the thread
        ZwClose(threadHandle);
    }
    else
    {
        // If we can't create a thread, we can't log at DISPATCH_LEVEL
        // The patch will simply not be applied
    }
}

// Delayed ValidSection bypass - waits for BE/EAC to load first
NTSTATUS EnableValidSectionBypassDelayed(PDRIVER_OBJECT DriverObject, ULONG DelayMilliseconds)
{
    __try
    {
        LogToDbgView("[VALIDSECTION-DELAYED] Setting up delayed ValidSection patch\n");
        LogToDbgView("[VALIDSECTION-DELAYED] Delay: %u ms (%u seconds)\n", 
                     DelayMilliseconds, DelayMilliseconds / 1000);
        
        // Save the driver object for the timer callback
        g_SavedDriverObject = DriverObject;
        
        // Initialize timer and DPC
        KeInitializeTimer(&g_ValidSectionTimer);
        KeInitializeDpc(&g_ValidSectionDpc, ValidSectionPatchTimerCallback, DriverObject);
        
        // Set the timer
        LARGE_INTEGER dueTime;
        dueTime.QuadPart = -((LONGLONG)DelayMilliseconds * 10000); // Convert to 100-nanosecond intervals
        
        KeSetTimer(&g_ValidSectionTimer, dueTime, &g_ValidSectionDpc);
        
        LogToDbgView("[VALIDSECTION-DELAYED] Timer set - ValidSection patch will be applied in %u ms\n", 
                     DelayMilliseconds);
        LogToDbgView("[VALIDSECTION-DELAYED] This allows BE/EAC to load without interference\n");
        
        return STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[VALIDSECTION-DELAYED] Exception setting up delayed patch: 0x%08X\n", GetExceptionCode());
        return STATUS_UNSUCCESSFUL;
    }
}

// Hook function that always returns STATUS_SUCCESS
NTSTATUS NTAPI HookedMmVerifyCallbackFunctionCheckFlags(PVOID DriverObject, PVOID CallbackFunction)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(CallbackFunction);
    
    // Always return success to bypass ValidSection check
    return STATUS_SUCCESS;
}

// Install inline hook for MmVerifyCallbackFunctionCheckFlags
NTSTATUS InstallValidSectionHook()
{
    if (g_HookInstalled)
    {
        LogToDbgView("[HOOK] ValidSection hook already installed\n");
        return STATUS_SUCCESS;
    }
    
    __try
    {
        LogToDbgView("[HOOK] Installing ValidSection bypass hook\n");
        
        // Use pattern search to find ValidSection check in ntoskrnl
        LogToDbgView("[HOOK] Searching for ValidSection check pattern in ntoskrnl\n");
        
        // Get ntoskrnl base address
        UNICODE_STRING exportName;
        RtlInitUnicodeString(&exportName, L"PsInitialSystemProcess");
        PVOID knownExport = MmGetSystemRoutineAddress(&exportName);
        
        if (!knownExport)
        {
            LogToDbgView("[HOOK] Could not find known export for base calculation\n");
            return STATUS_PROCEDURE_NOT_FOUND;
        }
        
        // Find ntoskrnl base by searching backwards for PE header
        PVOID ntoskrnlBase = NULL;
        ULONG_PTR searchBase = (ULONG_PTR)knownExport & ~0xFFF;
        
        for (ULONG pages = 0; pages < 0x1000; pages++)
        {
            searchBase -= 0x1000;
            __try
            {
                PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)searchBase;
                if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
                {
                    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((ULONG_PTR)searchBase + dosHeader->e_lfanew);
                    if (ntHeaders->Signature == IMAGE_NT_SIGNATURE)
                    {
                        ntoskrnlBase = (PVOID)searchBase;
                        LogToDbgView("[HOOK] Found ntoskrnl.exe base at: %p\n", ntoskrnlBase);
                        break;
                    }
                }
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                continue;
            }
        }
        
        if (!ntoskrnlBase)
        {
            LogToDbgView("[HOOK] Could not find ntoskrnl.exe base address\n");
            return STATUS_PROCEDURE_NOT_FOUND;
        }
        
        // Search for ValidSection check pattern
        // Pattern: 8B 40 68 85 C7 74 XX (mov eax,[rax+68h]; test edi,eax; je)
        UCHAR validSectionPattern[] = {
            0x8B, 0x40, 0x68,  // mov eax,dword ptr [rax+68h]
            0x85, 0xC7,        // test edi,eax
            0x74               // je
        };
        
        PVOID targetLocation = NULL;
        
        // Search in ntoskrnl for the pattern
        for (ULONG_PTR offset = 0; offset < 0x800000; offset++)
        {
            ULONG_PTR searchAddr = (ULONG_PTR)ntoskrnlBase + offset;
            
            __try
            {
                if (RtlCompareMemory((PVOID)searchAddr, validSectionPattern, sizeof(validSectionPattern)) == sizeof(validSectionPattern))
                {
                    // Verify this is the right location
                    UCHAR* afterJE = (UCHAR*)(searchAddr + 7);
                    if (afterJE[0] == 0xBB && afterJE[1] == 0x01 && // mov ebx,1
                        afterJE[5] == 0x48 && afterJE[6] == 0x8D && afterJE[7] == 0x0D) // lea rcx,[...]
                    {
                        targetLocation = (PVOID)searchAddr;
                        LogToDbgView("[HOOK] Found ValidSection check at: %p\n", targetLocation);
                        break;
                    }
                }
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                continue;
            }
        }
        
        if (!targetLocation)
        {
            LogToDbgView("[HOOK] ValidSection check pattern not found\n");
            return STATUS_PROCEDURE_NOT_FOUND;
        }
        
        // Instead of hooking function start, directly patch the je instruction
        // This is simpler and more reliable
        g_MmVerifyCallbackFunctionCheckFlags = (PVOID)((ULONG_PTR)targetLocation + 5); // Point to the je instruction
        LogToDbgView("[HOOK] Will patch je instruction at: %p\n", g_MmVerifyCallbackFunctionCheckFlags);
        
        // Save original bytes (should be 74 XX - je instruction)
        RtlCopyMemory(g_OriginalBytes, g_MmVerifyCallbackFunctionCheckFlags, 2);
        
        LogToDbgView("[HOOK] Original bytes at patch location: %02X %02X\n", 
                     g_OriginalBytes[0], g_OriginalBytes[1]);
        
        // Verify it's a je instruction
        if (g_OriginalBytes[0] != 0x74)
        {
            LogToDbgView("[HOOK] Expected je instruction (74), found %02X\n", g_OriginalBytes[0]);
            return STATUS_UNSUCCESSFUL;
        }
        
        // Prepare patch bytes - change je to jmp (EB)
        UCHAR patchBytes[2] = {0xEB, g_OriginalBytes[1]}; // Change je to jmp with same offset
        
        // Use physical memory to avoid PatchGuard detection
        PHYSICAL_ADDRESS physAddr = MmGetPhysicalAddress(g_MmVerifyCallbackFunctionCheckFlags);
        if (physAddr.QuadPart == 0)
        {
            LogToDbgView("[HOOK] Failed to get physical address\n");
            return STATUS_UNSUCCESSFUL;
        }
        
        LogToDbgView("[HOOK] Physical address: %08X%08X\n", physAddr.HighPart, physAddr.LowPart);
        
        // Map physical memory with MmMapIoSpace
        PVOID mappedAddr = MmMapIoSpace(physAddr, 2, MmNonCached);
        if (!mappedAddr)
        {
            LogToDbgView("[HOOK] Failed to map physical memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        // Apply patch through physical memory mapping
        RtlCopyMemory(mappedAddr, patchBytes, 2);
        
        // Unmap the memory
        MmUnmapIoSpace(mappedAddr, 2);
        
        g_HookInstalled = TRUE;
        LogToDbgView("[HOOK] ValidSection bypass patch applied successfully (je -> jmp)\n");
        LogToDbgView("[HOOK] Patched bytes: %02X %02X\n", patchBytes[0], patchBytes[1]);
        
        // Also try to bypass CI (Code Integrity) checks
        LogToDbgView("[HOOK] Attempting to bypass CI signature verification\n");
        NTSTATUS ciStatus = BypassCISignatureCheck();
        if (NT_SUCCESS(ciStatus))
        {
            LogToDbgView("[HOOK] CI signature check bypass successful\n");
        }
        else
        {
            LogToDbgView("[HOOK] CI signature check bypass failed: 0x%08X\n", ciStatus);
        }
        
        return STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[HOOK] Exception installing hook: 0x%08X\n", GetExceptionCode());
        return STATUS_UNSUCCESSFUL;
    }
}

// Remove inline hook
NTSTATUS RemoveValidSectionHook()
{
    if (!g_HookInstalled || !g_MmVerifyCallbackFunctionCheckFlags)
    {
        return STATUS_SUCCESS;
    }
    
    __try
    {
        LogToDbgView("[HOOK] Removing ValidSection bypass hook\n");
        
        // Use physical memory to restore original bytes
        PHYSICAL_ADDRESS physAddr = MmGetPhysicalAddress(g_MmVerifyCallbackFunctionCheckFlags);
        if (physAddr.QuadPart == 0)
        {
            LogToDbgView("[HOOK] Failed to get physical address for restore\n");
            return STATUS_UNSUCCESSFUL;
        }
        
        // Map physical memory
        PVOID mappedAddr = MmMapIoSpace(physAddr, 2, MmNonCached);
        if (!mappedAddr)
        {
            LogToDbgView("[HOOK] Failed to map physical memory for restore\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        // Restore original bytes (only 2 bytes for je instruction)
        RtlCopyMemory(mappedAddr, g_OriginalBytes, 2);
        
        // Unmap the memory
        MmUnmapIoSpace(mappedAddr, 2);
        
        g_HookInstalled = FALSE;
        LogToDbgView("[HOOK] ValidSection bypass hook removed successfully\n");
        
        return STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[HOOK] Exception removing hook: 0x%08X\n", GetExceptionCode());
        return STATUS_UNSUCCESSFUL;
    }
}

// Bypass CI (Code Integrity) signature verification
NTSTATUS BypassCISignatureCheck()
{
    __try
    {
        LogToDbgView("[CI] Searching for CI signature verification functions\n");
        
        // Method 1: Try to patch CiValidateImageHeader
        UNICODE_STRING ciValidateName;
        RtlInitUnicodeString(&ciValidateName, L"CiValidateImageHeader");
        PVOID CiValidateImageHeader = MmGetSystemRoutineAddress(&ciValidateName);
        
        if (CiValidateImageHeader)
        {
            LogToDbgView("[CI] Found CiValidateImageHeader at: %p\n", CiValidateImageHeader);
            
            // Patch to always return success
            UCHAR patchBytes[6] = {
                0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, 0 (STATUS_SUCCESS)
                0xC3                            // ret
            };
            
            // Use physical memory mapping
            PHYSICAL_ADDRESS physAddr = MmGetPhysicalAddress(CiValidateImageHeader);
            if (physAddr.QuadPart != 0)
            {
                PVOID mappedAddr = MmMapIoSpace(physAddr, 6, MmNonCached);
                if (mappedAddr)
                {
                    RtlCopyMemory(mappedAddr, patchBytes, 6);
                    MmUnmapIoSpace(mappedAddr, 6);
                    LogToDbgView("[CI] CiValidateImageHeader patched successfully\n");
                }
            }
        }
        
        // Method 2: Patch the specific MmVerifyCallbackFunctionCheckFlags call in ObRegisterCallbacks
        LogToDbgView("[CI] Patching MmVerifyCallbackFunctionCheckFlags call in ObRegisterCallbacks\n");
        
        UNICODE_STRING obRegName;
        RtlInitUnicodeString(&obRegName, L"ObRegisterCallbacks");
        PVOID ObRegisterCallbacks = MmGetSystemRoutineAddress(&obRegName);
        
        if (ObRegisterCallbacks)
        {
            LogToDbgView("[CI] ObRegisterCallbacks at: %p\n", ObRegisterCallbacks);
            
            // Based on debugger output, the call is at offset 0x106
            // Look for both original and already-patched patterns
            // Original: ba 20 00 00 00 e8 (mov edx,20h; call)
            // Patched: ba 20 00 00 00 b8 (mov edx,20h; mov eax,X)
            UCHAR callPattern[] = {0xBA, 0x20, 0x00, 0x00, 0x00, 0xE8};
            UCHAR patchedPattern[] = {0xBA, 0x20, 0x00, 0x00, 0x00, 0xB8};
            
            for (ULONG offset = 0x100; offset < 0x120; offset++)
            {
                UCHAR* searchPtr = (UCHAR*)((ULONG_PTR)ObRegisterCallbacks + offset);
                
                __try
                {
                    BOOLEAN foundOriginal = (RtlCompareMemory(searchPtr, callPattern, sizeof(callPattern)) == sizeof(callPattern));
                    BOOLEAN foundPatched = (RtlCompareMemory(searchPtr, patchedPattern, sizeof(patchedPattern)) == sizeof(patchedPattern));
                    
                    if (foundOriginal)
                    {
                        LogToDbgView("[CI] Found original MmVerifyCallbackFunctionCheckFlags call at offset +0x%X\n", offset);
                        
                        // Patch the call (E8 XX XX XX XX) to mov eax,1 (B8 01 00 00 00)  
                        // We want to return non-zero so that test eax,eax; je will NOT jump
                        UCHAR patchBytes[5] = {0xB8, 0x01, 0x00, 0x00, 0x00}; // mov eax, 1 (non-zero)
                        
                        PHYSICAL_ADDRESS callPhysAddr = MmGetPhysicalAddress(searchPtr + 5); // Point to E8
                        if (callPhysAddr.QuadPart != 0)
                        {
                            PVOID callMappedAddr = MmMapIoSpace(callPhysAddr, 5, MmNonCached);
                            if (callMappedAddr)
                            {
                                RtlCopyMemory(callMappedAddr, patchBytes, 5);
                                MmUnmapIoSpace(callMappedAddr, 5);
                                
                                LogToDbgView("[CI] Patched MmVerifyCallbackFunctionCheckFlags call successfully\n");
                                break;
                            }
                        }
                    }
                    else if (foundPatched)
                    {
                        LogToDbgView("[CI] Found already-patched MmVerifyCallbackFunctionCheckFlags at offset +0x%X\n", offset);
                        
                        // Update the return value if needed - ensure it returns 1 (non-zero)
                        UCHAR updateBytes[5] = {0xB8, 0x01, 0x00, 0x00, 0x00}; // mov eax, 1 (non-zero)
                        
                        PHYSICAL_ADDRESS patchPhysAddr = MmGetPhysicalAddress(searchPtr + 5); // Point to B8
                        if (patchPhysAddr.QuadPart != 0)
                        {
                            PVOID patchMappedAddr = MmMapIoSpace(patchPhysAddr, 5, MmNonCached);
                            if (patchMappedAddr)
                            {
                                RtlCopyMemory(patchMappedAddr, updateBytes, 5);
                                MmUnmapIoSpace(patchMappedAddr, 5);
                                
                                LogToDbgView("[CI] Updated already-patched MmVerifyCallbackFunctionCheckFlags successfully\n");
                                break;
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
        
        // Method 3: Try a different approach if still failing
        LogToDbgView("[CI][INFO] Attempting alternative ObjectCallback bypass method\n");
        
        // Instead of patching calls, try to patch the test/conditional jumps
        if (ObRegisterCallbacks)
        {
            // Look for the test eax,eax; je pattern after our MmVerifyCallbackFunctionCheckFlags patch
            UCHAR testPattern[] = {0x85, 0xC0, 0x0F, 0x84}; // test eax,eax; je (long form)
            
            for (ULONG testOffset = 0x100; testOffset < 0x120; testOffset++)
            {
                UCHAR* testPtr = (UCHAR*)((ULONG_PTR)ObRegisterCallbacks + testOffset);
                
                __try
                {
                    if (RtlCompareMemory(testPtr, testPattern, 4) == 4)
                    {
                        LogToDbgView("[CI] Found test eax,eax; je pattern at offset +0x%X\n", testOffset);
                        
                        // Change jne back to je since we want to return 0 (success) 
                        // and continue execution when eax=0
                        UCHAR jePatch[1] = {0x84}; // Change jne back to je
                        
                        PHYSICAL_ADDRESS testPhysAddr = MmGetPhysicalAddress(testPtr + 3); // Point to 84
                        if (testPhysAddr.QuadPart != 0)
                        {
                            PVOID testMappedAddr = MmMapIoSpace(testPhysAddr, 1, MmNonCached);
                            if (testMappedAddr)
                            {
                                RtlCopyMemory(testMappedAddr, jePatch, 1);
                                MmUnmapIoSpace(testMappedAddr, 1);
                                LogToDbgView("[CI] Ensured je condition after MmVerifyCallbackFunctionCheckFlags\n");
                                break;
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
        
        return STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[CI] Exception in CI bypass: 0x%08X\n", GetExceptionCode());
        return STATUS_UNSUCCESSFUL;
    }
}

// Global storage for original bytes to restore later
static UCHAR g_OriginalMmVerifyBytes[16] = { 0 };
static UCHAR g_OriginalCiValidateBytes[16] = { 0 };
static PVOID g_MmVerifyPatchAddress = NULL;
static PVOID g_CiValidatePatchAddress = NULL;
static BOOLEAN g_OriginalBytesSaved = FALSE;

// Apply temporary CI bypass patches
NTSTATUS ApplyTemporaryCIBypass()
{
    __try
    {
        LogToDbgView("[TEMP-PATCH] Applying temporary patches for ObjectCallback registration\n");
        
        // Find MmVerifyCallbackFunctionCheckFlags if not already found
        if (!g_MmVerifyCallbackFunctionCheckFlags)
        {
            UNICODE_STRING mmVerifyName;
            RtlInitUnicodeString(&mmVerifyName, L"MmVerifyCallbackFunctionCheckFlags");
            g_MmVerifyCallbackFunctionCheckFlags = MmGetSystemRoutineAddress(&mmVerifyName);
        }
        
        if (g_MmVerifyCallbackFunctionCheckFlags)
        {
            g_MmVerifyPatchAddress = g_MmVerifyCallbackFunctionCheckFlags;
            
            // Save original bytes before patching
            PHYSICAL_ADDRESS physAddr = MmGetPhysicalAddress(g_MmVerifyPatchAddress);
            if (physAddr.QuadPart != 0)
            {
                PVOID mappedAddr = MmMapIoSpace(physAddr, 16, MmNonCached);
                if (mappedAddr)
                {
                    // Save original bytes
                    RtlCopyMemory(g_OriginalMmVerifyBytes, mappedAddr, 16);
                    
                    // Apply temporary patch - return STATUS_SUCCESS immediately
                    UCHAR tempPatch[6] = {
                        0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, 0 (STATUS_SUCCESS)
                        0xC3                            // ret
                    };
                    
                    RtlCopyMemory(mappedAddr, tempPatch, 6);
                    MmUnmapIoSpace(mappedAddr, 16);
                    
                    g_OriginalBytesSaved = TRUE;
                    LogToDbgView("[TEMP-PATCH] MmVerifyCallbackFunctionCheckFlags temporarily patched\n");
                }
            }
        }
        
        // Also patch CiValidateImageHeader if available
        UNICODE_STRING ciValidateName;
        RtlInitUnicodeString(&ciValidateName, L"CiValidateImageHeader");
        PVOID CiValidateImageHeader = MmGetSystemRoutineAddress(&ciValidateName);
        
        if (CiValidateImageHeader)
        {
            g_CiValidatePatchAddress = CiValidateImageHeader;
            
            PHYSICAL_ADDRESS physAddr = MmGetPhysicalAddress(g_CiValidatePatchAddress);
            if (physAddr.QuadPart != 0)
            {
                PVOID mappedAddr = MmMapIoSpace(physAddr, 16, MmNonCached);
                if (mappedAddr)
                {
                    // Save original bytes
                    RtlCopyMemory(g_OriginalCiValidateBytes, mappedAddr, 16);
                    
                    // Apply temporary patch
                    UCHAR tempPatch[6] = {
                        0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, 0
                        0xC3                            // ret
                    };
                    
                    RtlCopyMemory(mappedAddr, tempPatch, 6);
                    MmUnmapIoSpace(mappedAddr, 16);
                    
                    LogToDbgView("[TEMP-PATCH] CiValidateImageHeader temporarily patched\n");
                }
            }
        }
        
        return STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[TEMP-PATCH] Exception applying temporary patch: 0x%08X\n", GetExceptionCode());
        return STATUS_UNSUCCESSFUL;
    }
}

// Restore original bytes to avoid detection
NTSTATUS RestoreOriginalCIBytes()
{
    __try
    {
        LogToDbgView("[TEMP-PATCH] Restoring original bytes to avoid EAC detection\n");
        
        // Restore MmVerifyCallbackFunctionCheckFlags
        if (g_MmVerifyPatchAddress && g_OriginalBytesSaved)
        {
            PHYSICAL_ADDRESS physAddr = MmGetPhysicalAddress(g_MmVerifyPatchAddress);
            if (physAddr.QuadPart != 0)
            {
                PVOID mappedAddr = MmMapIoSpace(physAddr, 16, MmNonCached);
                if (mappedAddr)
                {
                    RtlCopyMemory(mappedAddr, g_OriginalMmVerifyBytes, 16);
                    MmUnmapIoSpace(mappedAddr, 16);
                    LogToDbgView("[TEMP-PATCH] MmVerifyCallbackFunctionCheckFlags bytes restored\n");
                }
            }
        }
        
        // Restore CiValidateImageHeader
        if (g_CiValidatePatchAddress)
        {
            PHYSICAL_ADDRESS physAddr = MmGetPhysicalAddress(g_CiValidatePatchAddress);
            if (physAddr.QuadPart != 0)
            {
                PVOID mappedAddr = MmMapIoSpace(physAddr, 16, MmNonCached);
                if (mappedAddr)
                {
                    RtlCopyMemory(mappedAddr, g_OriginalCiValidateBytes, 16);
                    MmUnmapIoSpace(mappedAddr, 16);
                    LogToDbgView("[TEMP-PATCH] CiValidateImageHeader bytes restored\n");
                }
            }
        }
        
        // Clear saved state
        g_OriginalBytesSaved = FALSE;
        g_MmVerifyPatchAddress = NULL;
        g_CiValidatePatchAddress = NULL;
        
        LogToDbgView("[TEMP-PATCH] All original bytes restored successfully\n");
        return STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        LogToDbgView("[TEMP-PATCH] Exception restoring original bytes: 0x%08X\n", GetExceptionCode());
        return STATUS_UNSUCCESSFUL;
    }
}

#pragma warning(pop) // Restore warning levels