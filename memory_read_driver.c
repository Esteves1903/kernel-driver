#include <ntdef.h>
#include <ntifs.h>
#include <ntddkbd.h>
#include <wdf.h>

// IOCTL codes for communication
#define IOCTL_READ_PROCESS_MEMORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _READ_MEMORY_REQUEST {
    ULONG ProcessId;
    ULONGLONG Address;
    ULONG Size;
    UCHAR Data[4096];
} READ_MEMORY_REQUEST, *PREAD_MEMORY_REQUEST;

typedef struct _READ_MEMORY_RESPONSE {
    NTSTATUS Status;
    ULONG BytesRead;
    UCHAR Data[4096];
} READ_MEMORY_RESPONSE, *PREAD_MEMORY_RESPONSE;

NTSTATUS ReadProcessMemory(ULONG ProcessId, ULONGLONG Address, ULONG Size,
                           PVOID OutputBuffer, ULONG OutputBufferSize,
                           PULONG BytesReturned)
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS SourceProcess = NULL;
    KAPC_STATE ApcState = {0};
    READ_MEMORY_RESPONSE *Response = (READ_MEMORY_RESPONSE *)OutputBuffer;
    SIZE_T BytesToRead = 0;

    // Validate input
    if (!OutputBuffer || OutputBufferSize < sizeof(READ_MEMORY_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (Size > sizeof(Response->Data)) {
        Size = sizeof(Response->Data);
    }

    RtlZeroMemory(Response, OutputBufferSize);

    // Lookup the target process
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &SourceProcess);
    if (!NT_SUCCESS(status)) {
        Response->Status = status;
        Response->BytesRead = 0;
        *BytesReturned = sizeof(READ_MEMORY_RESPONSE);
        return STATUS_SUCCESS;
    }

    __try {
        // Attach to target process context
        KeStackAttachProcess(SourceProcess, &ApcState);

        // Copy memory from target process
        status = MmCopyVirtualMemory(
            SourceProcess,
            (PVOID)Address,
            PsGetCurrentProcess(),
            &Response->Data[0],
            Size,
            KernelMode,
            &BytesToRead
        );

        // Detach from process
        KeUnstackDetachProcess(&ApcState);

        Response->Status = status;
        Response->BytesRead = (ULONG)BytesToRead;
        *BytesReturned = sizeof(READ_MEMORY_RESPONSE);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KeUnstackDetachProcess(&ApcState);
        Response->Status = GetExceptionCode();
        Response->BytesRead = 0;
        *BytesReturned = sizeof(READ_MEMORY_RESPONSE);
        status = STATUS_SUCCESS;
    }

    // Release process reference
    ObDereferenceObject(SourceProcess);

    return status;
}

NTSTATUS DeviceIoControl_Dispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG BytesReturned = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_READ_PROCESS_MEMORY: {
            PREAD_MEMORY_REQUEST Request = (PREAD_MEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;
            ULONG InputLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
            ULONG OutputLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;

            if (InputLength < sizeof(READ_MEMORY_REQUEST)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            status = ReadProcessMemory(
                Request->ProcessId,
                Request->Address,
                Request->Size,
                Irp->AssociatedIrp.SystemBuffer,
                OutputLength,
                &BytesReturned
            );
            break;
        }

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = BytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}
