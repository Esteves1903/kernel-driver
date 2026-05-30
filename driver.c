/*
 * driver.c — MemMon kernel driver
 *
 * Provides IOCTL-based access to process memory for debugging
 * and system monitoring (comparable to Process Hacker / System Informer).
 *
 * Build: Visual Studio 2022 + WDK, x64 Release, target OS ≥ Win10.
 *
 * IMPORTANT — test on a VM first!  An error in kernel code will BSOD.
 * Load with:  sc create MemMon type= kernel binPath= C:\path\driver.sys
 *             sc start  MemMon
 * Unload:     sc stop   MemMon
 *             sc delete MemMon
 */

#include <ntifs.h>
#include <ntstrsafe.h>

/* ────────────────────────────────────────────────────────────────── */
/*  Shared constants (mirror common.h without pulling in Windows.h) */
/* ────────────────────────────────────────────────────────────────── */

#define MEMMON_DEVICE_NAME   L"\\Device\\MemMon"
#define MEMMON_SYMLINK_NAME  L"\\DosDevices\\MemMon"

#define MEMMON_DEVICE_TYPE   0x8000

#define IOCTL_MEMMON_READ_MEMORY   \
    CTL_CODE(MEMMON_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MEMMON_WRITE_MEMORY  \
    CTL_CODE(MEMMON_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_MEMMON_LIST_PROCS        \
    CTL_CODE(MEMMON_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MEMMON_LIST_MODULES      \
    CTL_CODE(MEMMON_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MEMMON_CROSSREF_DRIVERS  \
    CTL_CODE(MEMMON_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS)

#define MEMMON_MAX_RW_SIZE      (16 * 1024 * 1024)
#define MEMMON_MAX_PROC_COUNT   4096
#define MEMMON_PROC_NAME_LEN    64

/* ── Request / response structs (must match common.h layout) ──── */

typedef struct _MEMMON_READ_REQUEST {
    ULONG   ProcessId;
    ULONG64 Address;
    ULONG   Size;
} MEMMON_READ_REQUEST, *PMEMMON_READ_REQUEST;

typedef struct _MEMMON_READ_RESPONSE {
    LONG    Status;
    ULONG   BytesRead;
    UCHAR   Data[1];
} MEMMON_READ_RESPONSE, *PMEMMON_READ_RESPONSE;

typedef struct _MEMMON_WRITE_REQUEST {
    ULONG   ProcessId;
    ULONG64 Address;
    ULONG   Size;
    UCHAR   Data[1];
} MEMMON_WRITE_REQUEST, *PMEMMON_WRITE_REQUEST;

typedef struct _MEMMON_WRITE_RESPONSE {
    LONG    Status;
    ULONG   BytesWritten;
} MEMMON_WRITE_RESPONSE, *PMEMMON_WRITE_RESPONSE;

typedef struct _MEMMON_PROC_ENTRY {
    ULONG   ProcessId;
    WCHAR   Name[MEMMON_PROC_NAME_LEN];
} MEMMON_PROC_ENTRY, *PMEMMON_PROC_ENTRY;

typedef struct _MEMMON_PROC_LIST {
    ULONG             Count;
    MEMMON_PROC_ENTRY  Entries[1];
} MEMMON_PROC_LIST, *PMEMMON_PROC_LIST;

/* ── Detection: loaded module list ───────────────────────────────
 *
 * Returned by IOCTL_MEMMON_LIST_MODULES.
 * Mirrors the KLDR_DATA_TABLE_ENTRY fields useful for cross-referencing.
 */
#define MEMMON_MODULE_NAME_LEN  128

typedef struct _MEMMON_MODULE_ENTRY {
    ULONG_PTR BaseAddress;
    ULONG64   EntryPoint;
    ULONG     SizeOfImage;
    ULONG     _Pad;
    WCHAR     BaseName[64];
    WCHAR     FullPath[MEMMON_MODULE_NAME_LEN];
} MEMMON_MODULE_ENTRY, *PMEMMON_MODULE_ENTRY;

typedef struct _MEMMON_MODULE_LIST {
    ULONG             Count;
    MEMMON_MODULE_ENTRY Entries[1];
} MEMMON_MODULE_LIST, *PMEMMON_MODULE_LIST;

/* ── Detection: \Driver object cross-reference ────────────────────
 *
 * Returned by IOCTL_MEMMON_CROSSREF_DRIVERS.
 * Each entry corresponds to one object in the \Driver namespace.
 * InModuleList == 0 means the driver object's code address was NOT
 * found in any PsLoadedModuleList entry → DKOM candidate.
 */
typedef struct _MEMMON_ORPHAN_ENTRY {
    WCHAR     ObjectName[64];   /* name inside \Driver\               */
    ULONG_PTR DriverStart;      /* DriverObject->DriverStart          */
    ULONG     DriverSize;       /* DriverObject->DriverSize           */
    ULONG     InModuleList;     /* 1 = in list, 0 = anomaly           */
} MEMMON_ORPHAN_ENTRY, *PMEMMON_ORPHAN_ENTRY;

typedef struct _MEMMON_ORPHAN_LIST {
    ULONG Count;
    ULONG OrphanCount;          /* entries where InModuleList == 0    */
    MEMMON_ORPHAN_ENTRY Entries[1];
} MEMMON_ORPHAN_LIST, *PMEMMON_ORPHAN_LIST;

/* ── Shared memory packet ─────────────────────────────────────────
 *
 * Layout must exactly match the SHARED_PACKET struct in monitor.c.
 * Total size is one page (4 KB) — keeps the section simple.
 */
#define SHMEM_SECTION_NAME  L"\\BaseNamedObjects\\MemMonShared"
#define SHMEM_EVENT_NAME    L"\\BaseNamedObjects\\MemMonDataReady"
#define SHMEM_VIEW_BYTES    4096

typedef struct _SHARED_PACKET {
    volatile LONG Sequence;   /* writer increments; reader detects new data  */
    ULONG         DataSize;   /* valid bytes in Message[]                    */
    CHAR          Message[SHMEM_VIEW_BYTES - sizeof(LONG) - sizeof(ULONG)];
} SHARED_PACKET, *PSHARED_PACKET;
/* static check: sizeof(SHARED_PACKET) must equal SHMEM_VIEW_BYTES (4096) */

/* ────────────────────────────────────────────────────────────────── */
/*  Undocumented-but-stable imports we need from ntoskrnl           */
/* ────────────────────────────────────────────────────────────────── */

NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
    PEPROCESS       SourceProcess,
    PVOID           SourceAddress,
    PEPROCESS       TargetProcess,
    PVOID           TargetAddress,
    SIZE_T          BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T         ReturnSize
);

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
    HANDLE    ProcessId,
    PEPROCESS *Process
);

NTKERNELAPI PUCHAR PsGetProcessImageFileName(
    PEPROCESS Process
);

extern POBJECT_TYPE *MmSectionObjectType;

/*
 * Kernel loaded-module list entry.
 * Defined here because some WDK configurations don't expose KLDR_DATA_TABLE_ENTRY
 * through ntifs.h.  Layout verified on x64 Windows 10/11 via WinDbg dt output.
 */
#ifndef _KLDR_DATA_TABLE_ENTRY_DEFINED
#define _KLDR_DATA_TABLE_ENTRY_DEFINED
typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;    /* offset 0x00 — the list anchor        */
    PVOID          ExceptionTable;      /* offset 0x10                          */
    ULONG          ExceptionTableSize;  /* offset 0x18                          */
    ULONG          _Pad0;               /* offset 0x1C — compiler alignment pad */
    PVOID          GpValue;             /* offset 0x20                          */
    PVOID          NonPagedDebugInfo;   /* offset 0x28                          */
    PVOID          DllBase;             /* offset 0x30 — image base             */
    PVOID          EntryPoint;          /* offset 0x38                          */
    ULONG          SizeOfImage;         /* offset 0x40                          */
    ULONG          _Pad1;               /* offset 0x44 — compiler alignment pad */
    UNICODE_STRING FullDllName;         /* offset 0x48                          */
    UNICODE_STRING BaseDllName;         /* offset 0x58                          */
    ULONG          Flags;               /* offset 0x68                          */
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;
#endif

/*
 * Entry returned by ZwQueryDirectoryObject.
 * Also not always visible through ntifs.h depending on WDK version.
 */
#ifndef _OBJECT_DIRECTORY_INFORMATION_DEFINED
#define _OBJECT_DIRECTORY_INFORMATION_DEFINED
typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;
#endif

/* PsLoadedModuleList — exported from ntoskrnl; anchors the KLDR_DATA_TABLE_ENTRY ring */
extern LIST_ENTRY    PsLoadedModuleList;

/* IoDriverObjectType — needed to open \Driver\<name> objects by name */
extern POBJECT_TYPE *IoDriverObjectType;

NTKERNELAPI NTSTATUS ObReferenceObjectByName(
    PUNICODE_STRING  ObjectName,
    ULONG            Attributes,
    PACCESS_STATE    AccessState,
    ACCESS_MASK      DesiredAccess,
    POBJECT_TYPE     ObjectType,
    KPROCESSOR_MODE  AccessMode,
    PVOID            ParseContext,
    PVOID           *Object
);

/* ZwQuerySystemInformation for process enumeration */
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG           NextEntryOffset;
    ULONG           NumberOfThreads;
    LARGE_INTEGER   Reserved[3];
    LARGE_INTEGER   CreateTime;
    LARGE_INTEGER   UserTime;
    LARGE_INTEGER   KernelTime;
    UNICODE_STRING  ImageName;
    KPRIORITY       BasePriority;
    HANDLE          UniqueProcessId;
    /* remaining fields omitted — we only need the above */
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
);

#define SystemProcessInformation 5

/* ────────────────────────────────────────────────────────────────── */
/*  Forward declarations                                            */
/* ────────────────────────────────────────────────────────────────── */

DRIVER_INITIALIZE  DriverEntry;
DRIVER_UNLOAD      MemMonUnload;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH    MemMonCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH    MemMonDeviceControl;

static NTSTATUS HandleReadMemory  (PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS HandleWriteMemory (PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS HandleListProcs        (PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS HandleListModules      (PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS HandleCrossRefDrivers  (PIRP Irp, PIO_STACK_LOCATION IoStack);

static NTSTATUS SharedMemInit     (void);
static VOID     SharedMemCleanup  (void);
static VOID     SharedMemWrite    (const CHAR *msg, ULONG len);
static KSTART_ROUTINE WriterThread;

/* ────────────────────────────────────────────────────────────────── */
/*  Globals                                                         */
/* ────────────────────────────────────────────────────────────────── */

static PDEVICE_OBJECT g_DeviceObject    = NULL;

/* shared memory state */
static HANDLE    g_ShmSection     = NULL;
static PVOID     g_ShmKernelView  = NULL;   /* MmMapViewInSystemSpace result    */
static HANDLE    g_ShmEventHandle = NULL;
static PKEVENT   g_ShmEvent       = NULL;   /* for KeSetEvent at DISPATCH_LEVEL */
static HANDLE    g_WriterThread   = NULL;
static KEVENT    g_StopWriter;              /* NotificationEvent, signaled at unload */

/* ────────────────────────────────────────────────────────────────── */
/*  Helpers                                                         */
/* ────────────────────────────────────────────────────────────────── */

static NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS Status, ULONG_PTR Info)
{
    Irp->IoStatus.Status      = Status;
    Irp->IoStatus.Information = Info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

/*
 * Verify the calling process is running elevated (high-integrity token).
 * Rejects non-admin callers at the IOCTL boundary.
 */
static BOOLEAN CallerIsAdmin(void)
{
    PACCESS_TOKEN   token;
    BOOLEAN         isAdmin = FALSE;
    LUID            seLuid  = { 0 };

    /* A rough but effective check: see if the token has SeDebugPrivilege.
     * Only administrators (or processes running as SYSTEM) hold it.       */
    seLuid.LowPart = 20;  /* SE_DEBUG_PRIVILEGE */

    token = PsReferencePrimaryToken(PsGetCurrentProcess());
    if (token) {
        PRIVILEGE_SET privSet = {
            .PrivilegeCount = 1,
            .Control        = PRIVILEGE_SET_ALL_NECESSARY,
            .Privilege[0]   = { seLuid, SE_PRIVILEGE_ENABLED }
        };
        SECURITY_SUBJECT_CONTEXT subjectCtx = { 0 };
        subjectCtx.PrimaryToken = token;
        if (SePrivilegeCheck(&privSet, &subjectCtx, UserMode) == TRUE) {
            isAdmin = TRUE;
        }
        /* A simpler fallback: just check token elevation */
        PsDereferencePrimaryToken(token);
    }

    /* Fallback: allow if previous mode is KernelMode (SYSTEM callers). */
    if (!isAdmin && ExGetPreviousMode() == KernelMode)
        isAdmin = TRUE;

    return isAdmin;
}

/* ────────────────────────────────────────────────────────────────── */
/*  DriverEntry                                                     */
/* ────────────────────────────────────────────────────────────────── */

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS        status;
    UNICODE_STRING  deviceName, symlinkName;
    PDEVICE_OBJECT  deviceObject = NULL;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[MemMon] DriverEntry\n");

    /* Create device object */
    RtlInitUnicodeString(&deviceName, MEMMON_DEVICE_NAME);
    status = IoCreateDevice(
        DriverObject,
        0,                         /* no device extension */
        &deviceName,
        MEMMON_DEVICE_TYPE,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,                     /* not exclusive       */
        &deviceObject);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[MemMon] IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    /* Create symbolic link so user-mode can open \\.\MemMon */
    RtlInitUnicodeString(&symlinkName, MEMMON_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[MemMon] IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    /* Set up dispatch routines */
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = MemMonCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = MemMonCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MemMonDeviceControl;
    DriverObject->DriverUnload                         = MemMonUnload;

    /* Buffered I/O */
    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    g_DeviceObject = deviceObject;

    /* Start the shared-memory writer thread.  Failure is non-fatal —
       the IOCTL interface still works; shared memory just won't be active. */
    status = SharedMemInit();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[MemMon] SharedMemInit failed: 0x%08X\n", status);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[MemMon] Driver loaded successfully\n");
    return STATUS_SUCCESS;
}

/* ────────────────────────────────────────────────────────────────── */
/*  Unload                                                          */
/* ────────────────────────────────────────────────────────────────── */

VOID MemMonUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symlinkName;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[MemMon] Unloading\n");

    /* Stop the writer thread and tear down shared memory before
       the device is removed so no DPCs/threads reference freed objects. */
    SharedMemCleanup();

    RtlInitUnicodeString(&symlinkName, MEMMON_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);

    if (DriverObject->DeviceObject)
        IoDeleteDevice(DriverObject->DeviceObject);
}

/* ────────────────────────────────────────────────────────────────── */
/*  Create / Close — allow open and close without extra logic       */
/* ────────────────────────────────────────────────────────────────── */

NTSTATUS MemMonCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return CompleteIrp(Irp, STATUS_SUCCESS, 0);
}

/* ────────────────────────────────────────────────────────────────── */
/*  DeviceControl — IOCTL router                                    */
/* ────────────────────────────────────────────────────────────────── */

NTSTATUS MemMonDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status;

    if (!CallerIsAdmin())
        return CompleteIrp(Irp, STATUS_ACCESS_DENIED, 0);

    switch (ioStack->Parameters.DeviceIoControl.IoControlCode) {

    case IOCTL_MEMMON_READ_MEMORY:
        status = HandleReadMemory(Irp, ioStack);
        break;

    case IOCTL_MEMMON_WRITE_MEMORY:
        status = HandleWriteMemory(Irp, ioStack);
        break;

    case IOCTL_MEMMON_LIST_PROCS:
        status = HandleListProcs(Irp, ioStack);
        break;

    case IOCTL_MEMMON_LIST_MODULES:
        status = HandleListModules(Irp, ioStack);
        break;

    case IOCTL_MEMMON_CROSSREF_DRIVERS:
        status = HandleCrossRefDrivers(Irp, ioStack);
        break;

    default:
        status = CompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
        break;
    }

    return status;
}

/* ────────────────────────────────────────────────────────────────── */
/*  IOCTL: Read process memory                                      */
/* ────────────────────────────────────────────────────────────────── */

static NTSTATUS HandleReadMemory(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    NTSTATUS  status;
    ULONG     inLen  = IoStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG     outLen = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

    /* ── Validate input buffer ────────────────────────────────────── */
    if (inLen < sizeof(MEMMON_READ_REQUEST))
        return CompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, 0);

    PMEMMON_READ_REQUEST req = (PMEMMON_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer;

    /*
     * Snapshot request fields into locals NOW.
     *
     * METHOD_BUFFERED reuses SystemBuffer for both input and output, so
     * once we start writing the response the req fields at the same offsets
     * would be corrupted.  Reading them here, before any output is written,
     * prevents that overlap from mattering.
     */
    ULONG   pid        = req->ProcessId;
    ULONG64 targetAddr = req->Address;
    ULONG   copySize   = req->Size;

    if (copySize == 0 || copySize > MEMMON_MAX_RW_SIZE)
        return CompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0);

    if (targetAddr == 0)
        return CompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0);

    /* Reject reads into kernel address space */
    if (targetAddr >= 0xFFFF800000000000ULL)
        return CompleteIrp(Irp, STATUS_ACCESS_DENIED, 0);

    ULONG neededOut = FIELD_OFFSET(MEMMON_READ_RESPONSE, Data) + copySize;
    if (outLen < neededOut)
        return CompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, 0);

    /* ── Look up target process ───────────────────────────────────── */
    PEPROCESS targetProc = NULL;
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &targetProc);
    if (!NT_SUCCESS(status))
        return CompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0);

    /*
     * Save our own EPROCESS BEFORE attaching.  After KeStackAttachProcess,
     * PsGetCurrentProcess() returns targetProc (it reads ApcState.Process
     * which the attach redirects), so we must hold a pre-attach reference
     * to use as the MmCopyVirtualMemory destination.
     */
    PEPROCESS  driverProc = PsGetCurrentProcess();
    KAPC_STATE apcState;
    SIZE_T     bytesRead = 0;

    /* ── Attach → copy → detach ───────────────────────────────────── */
    KeStackAttachProcess(targetProc, &apcState);

    PMEMMON_READ_RESPONSE resp =
        (PMEMMON_READ_RESPONSE)Irp->AssociatedIrp.SystemBuffer;

    __try {
        status = MmCopyVirtualMemory(
            targetProc,                      /* source process         */
            (PVOID)(ULONG_PTR)targetAddr,    /* source virtual address */
            driverProc,                      /* destination process    */
            resp->Data,                      /* destination buffer     */
            (SIZE_T)copySize,
            KernelMode,
            &bytesRead);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status    = GetExceptionCode();
        bytesRead = 0;
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(targetProc);

    resp->Status    = (LONG)status;
    resp->BytesRead = (ULONG)bytesRead;

    ULONG written = FIELD_OFFSET(MEMMON_READ_RESPONSE, Data) + (ULONG)bytesRead;
    return CompleteIrp(Irp, STATUS_SUCCESS, written);
}

/* ────────────────────────────────────────────────────────────────── */
/*  IOCTL: Write process memory                                     */
/* ────────────────────────────────────────────────────────────────── */

static NTSTATUS HandleWriteMemory(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    NTSTATUS  status;
    ULONG     inLen  = IoStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG     outLen = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (inLen < (ULONG)FIELD_OFFSET(MEMMON_WRITE_REQUEST, Data))
        return CompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, 0);

    PMEMMON_WRITE_REQUEST req = (PMEMMON_WRITE_REQUEST)Irp->AssociatedIrp.SystemBuffer;

    if (req->Size == 0 || req->Size > MEMMON_MAX_RW_SIZE)
        return CompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0);

    if (req->Address == 0)
        return CompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0);

    /* Reject writes into kernel address space */
    if (req->Address >= 0xFFFF800000000000ULL)
        return CompleteIrp(Irp, STATUS_ACCESS_DENIED, 0);

    /* Make sure the caller actually sent enough data bytes */
    if (inLen < FIELD_OFFSET(MEMMON_WRITE_REQUEST, Data) + req->Size)
        return CompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, 0);

    if (outLen < sizeof(MEMMON_WRITE_RESPONSE))
        return CompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, 0);

    /* ── Look up target ───────────────────────────────────────────── */
    PEPROCESS targetProc = NULL;
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->ProcessId,
                                        &targetProc);
    if (!NT_SUCCESS(status))
        return CompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0);

    SIZE_T bytesWritten = 0;

    __try {
        status = MmCopyVirtualMemory(
            PsGetCurrentProcess(),              /* source = our buffer */
            req->Data,
            targetProc,                         /* target process      */
            (PVOID)(ULONG_PTR)req->Address,
            (SIZE_T)req->Size,
            KernelMode,
            &bytesWritten);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status       = GetExceptionCode();
        bytesWritten = 0;
    }

    ObDereferenceObject(targetProc);

    /* Reuse SystemBuffer for the response (METHOD_BUFFERED) */
    PMEMMON_WRITE_RESPONSE resp =
        (PMEMMON_WRITE_RESPONSE)Irp->AssociatedIrp.SystemBuffer;
    resp->Status       = (LONG)status;
    resp->BytesWritten = (ULONG)bytesWritten;

    return CompleteIrp(Irp, STATUS_SUCCESS, sizeof(MEMMON_WRITE_RESPONSE));
}

/* ────────────────────────────────────────────────────────────────── */
/*  IOCTL: List processes                                           */
/* ────────────────────────────────────────────────────────────────── */

static NTSTATUS HandleListProcs(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    NTSTATUS  status;
    ULONG     outLen = IoStack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID     sysInfo = NULL;
    ULONG     sysInfoLen = 0;

    /* ── Query system process information ─────────────────────────── */
    ULONG needed = 0;
    status = ZwQuerySystemInformation(SystemProcessInformation,
                                      NULL, 0, &needed);
    if (status != STATUS_INFO_LENGTH_MISMATCH && !NT_SUCCESS(status))
        return CompleteIrp(Irp, status, 0);

    sysInfoLen = needed + 4096;   /* pad for race with new processes */
    sysInfo = ExAllocatePool2(POOL_FLAG_NON_PAGED, sysInfoLen,
                              'MnoM');                 /* tag 'MonM' */
    if (!sysInfo)
        return CompleteIrp(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);

    status = ZwQuerySystemInformation(SystemProcessInformation,
                                      sysInfo, sysInfoLen, &needed);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(sysInfo, 'MnoM');
        return CompleteIrp(Irp, status, 0);
    }

    /* ── Walk the list and fill the output buffer ─────────────────── */
    PMEMMON_PROC_LIST outList =
        (PMEMMON_PROC_LIST)Irp->AssociatedIrp.SystemBuffer;

    /* How many entries can fit? */
    ULONG maxEntries = 0;
    if (outLen >= (ULONG)FIELD_OFFSET(MEMMON_PROC_LIST, Entries))
        maxEntries = (outLen - (ULONG)FIELD_OFFSET(MEMMON_PROC_LIST, Entries))
                     / sizeof(MEMMON_PROC_ENTRY);

    ULONG count = 0;
    PSYSTEM_PROCESS_INFORMATION entry = (PSYSTEM_PROCESS_INFORMATION)sysInfo;

    for (;;) {
        if (count >= maxEntries || count >= MEMMON_MAX_PROC_COUNT)
            break;

        outList->Entries[count].ProcessId =
            (ULONG)(ULONG_PTR)entry->UniqueProcessId;

        /* Copy image name (may be NULL for the Idle process) */
        RtlZeroMemory(outList->Entries[count].Name,
                       sizeof(outList->Entries[count].Name));

        if (entry->ImageName.Buffer && entry->ImageName.Length > 0) {
            USHORT copyLen = entry->ImageName.Length;
            if (copyLen > (MEMMON_PROC_NAME_LEN - 1) * sizeof(WCHAR))
                copyLen = (MEMMON_PROC_NAME_LEN - 1) * sizeof(WCHAR);

            __try {
                RtlCopyMemory(outList->Entries[count].Name,
                              entry->ImageName.Buffer,
                              copyLen);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                /* leave name as empty string */
            }
        } else {
            RtlStringCbCopyW(outList->Entries[count].Name,
                             sizeof(outList->Entries[count].Name),
                             L"[System Idle]");
        }

        count++;

        if (entry->NextEntryOffset == 0)
            break;
        entry = (PSYSTEM_PROCESS_INFORMATION)
                ((PUCHAR)entry + entry->NextEntryOffset);
    }

    outList->Count = count;

    ExFreePoolWithTag(sysInfo, 'MnoM');

    ULONG written = FIELD_OFFSET(MEMMON_PROC_LIST, Entries)
                    + count * sizeof(MEMMON_PROC_ENTRY);
    return CompleteIrp(Irp, STATUS_SUCCESS, written);
}

/* ────────────────────────────────────────────────────────────────── */
/*  Shared memory — section, event, writer thread                   */
/* ────────────────────────────────────────────────────────────────── */

/* ────────────────────────────────────────────────────────────────── */
/*  IOCTL: Walk PsLoadedModuleList and return every loaded module    */
/* ────────────────────────────────────────────────────────────────── */

static NTSTATUS HandleListModules(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    ULONG outLen = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

    ULONG maxEntries = 0;
    if (outLen >= FIELD_OFFSET(MEMMON_MODULE_LIST, Entries))
        maxEntries = (outLen - FIELD_OFFSET(MEMMON_MODULE_LIST, Entries))
                     / sizeof(MEMMON_MODULE_ENTRY);

    if (maxEntries == 0)
        return CompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, 0);

    PMEMMON_MODULE_LIST list =
        (PMEMMON_MODULE_LIST)Irp->AssociatedIrp.SystemBuffer;

    ULONG           count = 0;
    PLIST_ENTRY     head  = &PsLoadedModuleList;
    PLIST_ENTRY     cur   = head->Flink;

    /*
     * PsLoadedModuleList is normally guarded by PsLoadedModuleResource
     * (an ERESOURCE).  For a read-only snapshot in a demo driver we walk
     * without acquiring the lock.  A production tool should call
     * ExAcquireResourceSharedLite(PsLoadedModuleResource, TRUE) first.
     */
    while (cur != head && count < maxEntries) {
        PKLDR_DATA_TABLE_ENTRY ldte =
            CONTAINING_RECORD(cur, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        PMEMMON_MODULE_ENTRY e = &list->Entries[count];
        e->BaseAddress = (ULONG_PTR)ldte->DllBase;
        e->EntryPoint  = (ULONG64)(ULONG_PTR)ldte->EntryPoint;
        e->SizeOfImage = ldte->SizeOfImage;
        e->_Pad        = 0;

        RtlZeroMemory(e->BaseName, sizeof(e->BaseName));
        RtlZeroMemory(e->FullPath, sizeof(e->FullPath));

        __try {
            if (ldte->BaseDllName.Buffer && ldte->BaseDllName.Length) {
                USHORT bytes = min(ldte->BaseDllName.Length,
                                   (USHORT)((64 - 1) * sizeof(WCHAR)));
                RtlCopyMemory(e->BaseName, ldte->BaseDllName.Buffer, bytes);
            }
            if (ldte->FullDllName.Buffer && ldte->FullDllName.Length) {
                USHORT bytes = min(ldte->FullDllName.Length,
                                   (USHORT)((MEMMON_MODULE_NAME_LEN - 1) * sizeof(WCHAR)));
                RtlCopyMemory(e->FullPath, ldte->FullDllName.Buffer, bytes);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            /* name buffer was paged out or invalid — leave zeroed */
        }

        count++;
        cur = cur->Flink;
    }

    list->Count = count;

    ULONG written = FIELD_OFFSET(MEMMON_MODULE_LIST, Entries)
                    + count * sizeof(MEMMON_MODULE_ENTRY);
    return CompleteIrp(Irp, STATUS_SUCCESS, written);
}

/* ────────────────────────────────────────────────────────────────── */
/*  IOCTL: Cross-reference \Driver objects against PsLoadedModuleList */
/*                                                                    */
/*  For every object in the \Driver namespace the kernel keeps a      */
/*  DRIVER_OBJECT with a DriverStart field (the image base).  If that */
/*  address does not fall inside any KLDR_DATA_TABLE_ENTRY range, the  */
/*  module was unlinked from PsLoadedModuleList while still running — */
/*  the classic DKOM indicator.                                        */
/* ────────────────────────────────────────────────────────────────── */

static BOOLEAN AddressInModuleList(ULONG_PTR addr)
{
    PLIST_ENTRY head = &PsLoadedModuleList;
    PLIST_ENTRY cur  = head->Flink;
    while (cur != head) {
        PKLDR_DATA_TABLE_ENTRY ldte =
            CONTAINING_RECORD(cur, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        ULONG_PTR base = (ULONG_PTR)ldte->DllBase;
        if (addr >= base && addr < base + ldte->SizeOfImage)
            return TRUE;
        cur = cur->Flink;
    }
    return FALSE;
}

static NTSTATUS HandleCrossRefDrivers(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    NTSTATUS status;
    ULONG    outLen = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (outLen < FIELD_OFFSET(MEMMON_ORPHAN_LIST, Entries))
        return CompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, 0);

    ULONG maxEntries = (outLen - FIELD_OFFSET(MEMMON_ORPHAN_LIST, Entries))
                       / sizeof(MEMMON_ORPHAN_ENTRY);

    PMEMMON_ORPHAN_LIST result =
        (PMEMMON_ORPHAN_LIST)Irp->AssociatedIrp.SystemBuffer;
    result->Count       = 0;
    result->OrphanCount = 0;

    /* Open the \Driver object-manager directory */
    UNICODE_STRING    dirName;
    OBJECT_ATTRIBUTES oa;
    RtlInitUnicodeString(&dirName, L"\\Driver");
    InitializeObjectAttributes(&oa, &dirName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE dirHandle = NULL;
    status = ZwOpenDirectoryObject(&dirHandle,
                                   DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
                                   &oa);
    if (!NT_SUCCESS(status))
        return CompleteIrp(Irp, status, 0);

    /* Scratch buffer for ZwQueryDirectoryObject results */
    const ULONG dirBufSize = 65536;
    PVOID dirBuf = ExAllocatePool2(POOL_FLAG_PAGED, dirBufSize, 'fRMM');
    if (!dirBuf) {
        ZwClose(dirHandle);
        return CompleteIrp(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
    }

    ULONG   context = 0;
    BOOLEAN restart = TRUE;
    ULONG   count   = 0;

    for (;;) {
        ULONG retLen = 0;
        status = ZwQueryDirectoryObject(dirHandle, dirBuf, dirBufSize,
                                        FALSE,   /* return multiple entries */
                                        restart,
                                        &context,
                                        &retLen);
        restart = FALSE;

        if (status == STATUS_NO_MORE_ENTRIES) { status = STATUS_SUCCESS; break; }
        if (!NT_SUCCESS(status)) break;

        POBJECT_DIRECTORY_INFORMATION info =
            (POBJECT_DIRECTORY_INFORMATION)dirBuf;

        /* Each call fills the buffer with entries; a zero-length Name ends the list */
        for (; info->Name.Length > 0 && count < maxEntries; info++) {

            /* Build the full kernel path \Driver\<name> */
            WCHAR        pathBuf[256];
            UNICODE_STRING fullPath = { 0, sizeof(pathBuf), pathBuf };
            RtlAppendUnicodeToString(&fullPath, L"\\Driver\\");
            RtlAppendUnicodeStringToString(&fullPath, &info->Name);

            /* Obtain the actual DRIVER_OBJECT — bypasses any list manipulation */
            PDRIVER_OBJECT drvObj = NULL;
            NTSTATUS s = ObReferenceObjectByName(
                &fullPath,
                OBJ_CASE_INSENSITIVE,
                NULL,                   /* no access state */
                0,                      /* no specific access required */
                *IoDriverObjectType,
                KernelMode,
                NULL,
                (PVOID *)&drvObj);

            if (!NT_SUCCESS(s) || !drvObj)
                continue;

            PMEMMON_ORPHAN_ENTRY e = &result->Entries[count];

            /* Copy the short name (e.g. "MemMon", "Tcpip") */
            RtlZeroMemory(e->ObjectName, sizeof(e->ObjectName));
            USHORT bytes = min(info->Name.Length,
                               (USHORT)((64 - 1) * sizeof(WCHAR)));
            RtlCopyMemory(e->ObjectName, info->Name.Buffer, bytes);

            e->DriverStart = (ULONG_PTR)drvObj->DriverStart;
            e->DriverSize  = drvObj->DriverSize;

            /*
             * Cross-reference: does the driver's code base fall inside
             * any entry currently in PsLoadedModuleList?
             *
             * If NO — the driver is executing code that has been unlinked
             * from the official list (DKOM).  That is the anomaly.
             */
            e->InModuleList = AddressInModuleList(e->DriverStart) ? 1 : 0;

            if (e->InModuleList == 0)
                result->OrphanCount++;

            count++;
            ObDereferenceObject(drvObj);
        }
    }

    ExFreePoolWithTag(dirBuf, 'fRMM');
    ZwClose(dirHandle);

    result->Count = count;

    ULONG written = FIELD_OFFSET(MEMMON_ORPHAN_LIST, Entries)
                    + count * sizeof(MEMMON_ORPHAN_ENTRY);
    return CompleteIrp(Irp, NT_SUCCESS(status) ? STATUS_SUCCESS : status, written);
}

/* ────────────────────────────────────────────────────────────────── */
/*  Shared memory — section, event, writer thread                   */
/* ────────────────────────────────────────────────────────────────── */

/*
 * WriterThread runs at PASSIVE_LEVEL — safe for string formatting,
 * KeDelayExecutionThread, and anything that might page-fault.
 * It wakes every second and pushes a timestamped tick to user mode.
 */
static VOID WriterThread(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    LARGE_INTEGER interval;
    interval.QuadPart = -10000000LL;   /* -1 s in 100-ns units (relative) */

    ULONG tick = 0;

    /*
     * Wait on g_StopWriter with a 1-second timeout each iteration.
     *   STATUS_TIMEOUT  → timeout fired, write another tick and loop.
     *   STATUS_SUCCESS  → event was signaled (DriverUnload path), exit.
     */
    while (KeWaitForSingleObject(&g_StopWriter, Executive,
                                  KernelMode, FALSE, &interval) == STATUS_TIMEOUT)
    {
        LARGE_INTEGER now;
        KeQuerySystemTime(&now);

        TIME_FIELDS tf;
        RtlTimeToTimeFields(&now, &tf);

        CHAR buf[128];
        size_t len = 0;
        if (NT_SUCCESS(RtlStringCbPrintfA(buf, sizeof(buf),
                "[MemMon] tick=%-4lu  %04hd-%02hd-%02hd %02hd:%02hd:%02hd (UTC)",
                tick, tf.Year, tf.Month, tf.Day,
                tf.Hour, tf.Minute, tf.Second)))
        {
            RtlStringCbLengthA(buf, sizeof(buf), &len);
            SharedMemWrite(buf, (ULONG)len);
            tick++;
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

/*
 * SharedMemWrite — copy msg into the shared page and signal the event.
 * Safe from PASSIVE_LEVEL or DISPATCH_LEVEL (g_ShmKernelView is in
 * system space, always mapped; KeSetEvent works at DISPATCH_LEVEL).
 */
static VOID SharedMemWrite(const CHAR *msg, ULONG len)
{
    if (!g_ShmKernelView || !g_ShmEvent)
        return;

    PSHARED_PACKET pkt = (PSHARED_PACKET)g_ShmKernelView;

    if (len >= sizeof(pkt->Message))
        len = sizeof(pkt->Message) - 1;

    RtlCopyMemory(pkt->Message, msg, len);
    pkt->Message[len] = '\0';
    pkt->DataSize = len;

    /*
     * InterlockedIncrement issues a full memory fence (LOCK XADD on x64).
     * The fence guarantees Message/DataSize are globally visible BEFORE
     * the reader ever observes the new Sequence value.
     */
    InterlockedIncrement(&pkt->Sequence);

    /* Wake exactly one waiting user-mode thread (auto-reset event). */
    KeSetEvent(g_ShmEvent, IO_NO_INCREMENT, FALSE);
}

/*
 * SharedMemInit — create the named section and event, map a kernel-side
 * view in system space, then launch the writer thread.
 * Must be called at PASSIVE_LEVEL (from DriverEntry).
 */
static NTSTATUS SharedMemInit(void)
{
    NTSTATUS         status;
    UNICODE_STRING   name;
    OBJECT_ATTRIBUTES oa;
    LARGE_INTEGER    maxSize;
    PVOID            sectionObj = NULL;
    SIZE_T           viewSize   = SHMEM_VIEW_BYTES;

    /* ── Section ─────────────────────────────────────────────────── */
    RtlInitUnicodeString(&name, SHMEM_SECTION_NAME);
    InitializeObjectAttributes(&oa, &name,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
        NULL, NULL);

    maxSize.QuadPart = SHMEM_VIEW_BYTES;
    status = ZwCreateSection(&g_ShmSection,
                             SECTION_ALL_ACCESS,
                             &oa,
                             &maxSize,
                             PAGE_READWRITE,
                             SEC_COMMIT,   /* pagefile-backed, immediately committed */
                             NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[MemMon] ZwCreateSection failed: 0x%08X\n", status);
        return status;
    }

    /*
     * MmMapViewInSystemSpace needs the section OBJECT, not the handle.
     * It maps the view into the kernel's own system VA (0xFFFF... range),
     * which is accessible from any process context and at any IRQL —
     * unlike ZwMapViewOfSection into a process which gives a user-space VA.
     */
    status = ObReferenceObjectByHandle(g_ShmSection,
                                       SECTION_MAP_WRITE,
                                       *MmSectionObjectType,
                                       KernelMode,
                                       &sectionObj,
                                       NULL);
    if (!NT_SUCCESS(status)) goto fail_section;

    status = MmMapViewInSystemSpace(sectionObj, &g_ShmKernelView, &viewSize);
    ObDereferenceObject(sectionObj);   /* handle ref no longer needed */
    if (!NT_SUCCESS(status)) goto fail_section;

    RtlZeroMemory(g_ShmKernelView, SHMEM_VIEW_BYTES);

    /* ── Named auto-reset event ──────────────────────────────────── */
    RtlInitUnicodeString(&name, SHMEM_EVENT_NAME);
    InitializeObjectAttributes(&oa, &name,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
        NULL, NULL);

    status = ZwCreateEvent(&g_ShmEventHandle,
                           EVENT_ALL_ACCESS,
                           &oa,
                           SynchronizationEvent,   /* auto-reset: wakes one waiter */
                           FALSE);                  /* initially non-signaled       */
    if (!NT_SUCCESS(status)) goto fail_map;

    /*
     * Obtain a PKEVENT so KeSetEvent can be called from DISPATCH_LEVEL.
     * ZwSetEvent requires PASSIVE_LEVEL, making it unsafe from a DPC.
     */
    status = ObReferenceObjectByHandle(g_ShmEventHandle,
                                       EVENT_MODIFY_STATE,
                                       *ExEventObjectType,
                                       KernelMode,
                                       (PVOID *)&g_ShmEvent,
                                       NULL);
    if (!NT_SUCCESS(status)) goto fail_event;

    /* ── Writer thread ───────────────────────────────────────────── */
    KeInitializeEvent(&g_StopWriter, NotificationEvent, FALSE);

    status = PsCreateSystemThread(&g_WriterThread,
                                  THREAD_ALL_ACCESS,
                                  NULL, NULL, NULL,
                                  WriterThread, NULL);
    if (!NT_SUCCESS(status)) goto fail_event;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[MemMon] Shared memory ready — open Global\\MemMonShared\n");
    return STATUS_SUCCESS;

fail_event:
    if (g_ShmEvent) { ObDereferenceObject(g_ShmEvent); g_ShmEvent = NULL; }
    ZwClose(g_ShmEventHandle); g_ShmEventHandle = NULL;
fail_map:
    MmUnmapViewInSystemSpace(g_ShmKernelView); g_ShmKernelView = NULL;
fail_section:
    ZwClose(g_ShmSection); g_ShmSection = NULL;
    return status;
}

/*
 * SharedMemCleanup — signal the writer thread to stop, wait for it to
 * exit, then release every kernel object in reverse-creation order.
 * Must be called at PASSIVE_LEVEL (from DriverUnload) — we block here.
 */
static VOID SharedMemCleanup(void)
{
    if (g_WriterThread) {
        /* Tell WriterThread to exit on its next wake-up. */
        KeSetEvent(&g_StopWriter, IO_NO_INCREMENT, FALSE);

        /*
         * Wait for the thread object to become signaled (thread exited).
         * We must wait on the OBJECT, not the handle — the handle might
         * be closed before the thread fully exits.
         */
        PVOID threadObj = NULL;
        if (NT_SUCCESS(ObReferenceObjectByHandle(g_WriterThread,
                                                  SYNCHRONIZE,
                                                  NULL,        /* skip type check in kernel mode */
                                                  KernelMode,
                                                  &threadObj,
                                                  NULL)))
        {
            KeWaitForSingleObject(threadObj, Executive, KernelMode, FALSE, NULL);
            ObDereferenceObject(threadObj);
        }

        ZwClose(g_WriterThread);
        g_WriterThread = NULL;
    }

    if (g_ShmEvent)       { ObDereferenceObject(g_ShmEvent);    g_ShmEvent       = NULL; }
    if (g_ShmEventHandle) { ZwClose(g_ShmEventHandle);           g_ShmEventHandle = NULL; }
    if (g_ShmKernelView)  { MmUnmapViewInSystemSpace(g_ShmKernelView);
                             g_ShmKernelView = NULL; }
    if (g_ShmSection)     { ZwClose(g_ShmSection);               g_ShmSection     = NULL; }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[MemMon] Shared memory cleaned up\n");
}
