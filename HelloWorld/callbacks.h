#pragma once
#include <ntifs.h>
#include <ntddk.h>
// Removed fltKernel.h to avoid minifilter dependencies

// Callback registration functions
NTSTATUS InitializeCallbacks(PDRIVER_OBJECT DriverObject);
NTSTATUS UninitializeCallbacks();

// Process creation callback
VOID ProcessNotifyCallback(
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create
);

// Thread creation callback  
VOID ThreadNotifyCallback(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create
);

// Image load callback
VOID ImageNotifyCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
);

// Process handle operation callback
OB_PREOP_CALLBACK_STATUS ProcessPreCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);

// Thread handle operation callback
OB_PREOP_CALLBACK_STATUS ThreadPreCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);

// Registry callback
NTSTATUS RegistryCallback(
    PVOID CallbackContext,
    PVOID Argument1,
    PVOID Argument2
);

// File system callbacks (removed - not needed for basic monitoring)

// Helper functions
BOOLEAN IsEACProcessById(HANDLE ProcessId);
VOID GetProcessNameById(HANDLE ProcessId, PCHAR Buffer, SIZE_T BufferSize);

// Minifilter network monitoring functions
NTSTATUS InitializeNetworkMonitoring();
VOID UninitializeNetworkMonitoring();
VOID NetworkConnectionLogger(HANDLE ProcessId, PVOID LocalAddress, PVOID RemoteAddress, USHORT LocalPort, USHORT RemotePort);

// Minifilter callbacks removed to avoid linker errors

// Network packet inspection
VOID InspectNetworkBuffer(PVOID Buffer, ULONG Length, HANDLE ProcessId, BOOLEAN IsOutbound);

// Legacy File System Filter functions
NTSTATUS InitializeFileSystemFilter();
VOID UninitializeFileSystemFilter();

// Alternative file monitoring (safer approach)
NTSTATUS InitializeAlternativeFileMonitoring();
VOID UninitializeAlternativeFileMonitoring();
VOID FileMonitoringThread(PVOID Context);
VOID MonitorEACFileOperations();
NTSTATUS FilterDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS SafeFilterDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS AttachToFileSystem(PCWSTR FileSystemName);
NTSTATUS AttachToVolumeDevices();
NTSTATUS AttachToControlDeviceObject();
NTSTATUS CreateStandaloneFilter();
NTSTATUS AttachToSystemVolumes();
NTSTATUS AttachToFileSystemRecognizer();
NTSTATUS AttachToVolumeDevice(PCWSTR DeviceName);
VOID DetachFromAllFileSystems();

// IRP Major Function handlers
NTSTATUS FilterCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS FilterRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS FilterWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS FilterSetInformation(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS FilterQueryInformation(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

// Device attachment tracking
typedef struct _FILTER_DEVICE_EXTENSION {
    PDEVICE_OBJECT AttachedToDeviceObject;
    PDEVICE_OBJECT OriginalDeviceObject; 
    UNICODE_STRING FileSystemName;
} FILTER_DEVICE_EXTENSION, *PFILTER_DEVICE_EXTENSION;

// Global callback handles
extern PVOID g_ProcessNotifyHandle;
extern PVOID g_ThreadNotifyHandle;
extern PVOID g_ImageNotifyHandle;
extern PVOID g_ObjectCallbackHandle;
extern LARGE_INTEGER g_RegistryCallbackCookie;
extern BOOLEAN g_NetworkMonitoringActive;
extern PVOID g_FilterHandle; // Simplified type to avoid FLT dependencies

// File system filter globals
extern PDEVICE_OBJECT g_FilterDeviceNtfs;
extern PDEVICE_OBJECT g_FilterDeviceFat;
extern PDEVICE_OBJECT g_FilterDeviceExFat;
extern BOOLEAN g_FileSystemFilterActive;

// Global driver object
extern PDRIVER_OBJECT g_DriverObject;

// KLDR_DATA_TABLE_ENTRY structure for ValidSection bypass
typedef struct _KLDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;        // +0x000
    LIST_ENTRY InMemoryOrderLinks;      // +0x010  
    LIST_ENTRY InInitializationOrderLinks; // +0x020
    PVOID DllBase;                      // +0x030
    PVOID EntryPoint;                   // +0x038
    UINT32 SizeOfImage;                 // +0x040
    UNICODE_STRING FullDllName;         // +0x048
    UNICODE_STRING BaseDllName;         // +0x058
    
    union                               // +0x068
    {
        UCHAR FlagGroup[4];
        UINT32 Flags;
        struct _flags
        {
            UINT32 PackagedBinary : 1;
            UINT32 MarkedForRemoval : 1;
            UINT32 ImageDll : 1;
            UINT32 LoadNotificationsSent : 1;
            UINT32 TelemetryEntryProcessed : 1;
            UINT32 ProcessStaticImport : 1;     // ValidSection bit (bit 5, value 0x20)
            UINT32 InLegacyLists : 1;
            UINT32 InIndexes : 1;
            UINT32 ShimDll : 1;
            UINT32 InExceptionTable : 1;
            UINT32 ReservedFlags1 : 22;
        };
    };
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

// ValidSection flag constant
#ifndef LDRP_VALID_SECTION
#define LDRP_VALID_SECTION 0x20
#endif

// ValidSection bypass functions
NTSTATUS EnableValidSectionBypass(PDRIVER_OBJECT DriverObject);
NTSTATUS GetCurrentDriverEntry(PKLDR_DATA_TABLE_ENTRY* pDriverEntry);
NTSTATUS RegisterDualAltitudeObjectCallbacks();
NTSTATUS EnableValidSectionBypassDelayed(PDRIVER_OBJECT DriverObject, ULONG DelayMilliseconds);
VOID ValidSectionPatchTimerCallback(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);

// Hook-based ValidSection bypass
typedef NTSTATUS(*PFN_MM_VERIFY_CALLBACK_FUNCTION_CHECK_FLAGS)(PVOID DriverObject, PVOID CallbackFunction);
NTSTATUS InstallValidSectionHook();
NTSTATUS RemoveValidSectionHook();
NTSTATUS NTAPI HookedMmVerifyCallbackFunctionCheckFlags(PVOID DriverObject, PVOID CallbackFunction);
NTSTATUS BypassCISignatureCheck();

// Temporary patch functions to avoid EAC detection
NTSTATUS ApplyTemporaryCIBypass();
NTSTATUS RestoreOriginalCIBytes();

// Dual-altitude ObjectCallback handlers
OB_PREOP_CALLBACK_STATUS ProcessPreCallbackHighAltitude(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);

OB_PREOP_CALLBACK_STATUS ProcessPreCallbackLowAltitude(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);

OB_PREOP_CALLBACK_STATUS ThreadPreCallbackHighAltitude(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);

OB_PREOP_CALLBACK_STATUS ThreadPreCallbackLowAltitude(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);

// File object callback handlers for real file monitoring
OB_PREOP_CALLBACK_STATUS FilePreCallbackHighAltitude(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);

OB_PREOP_CALLBACK_STATUS FilePreCallbackLowAltitude(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);

// Global callback handles for dual-altitude system
extern PVOID g_HighAltitudeCallbackHandle;
extern PVOID g_LowAltitudeCallbackHandle;
extern PVOID g_FileObjectCallbackHandle;