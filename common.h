#pragma once
/*
 * common.h — Shared definitions for MemMon kernel driver and user-mode client.
 *
 * IOCTL codes, request/response structures, and constants shared
 * between the kernel driver (.sys) and the console client (.exe).
 */

#include <Windows.h>
#include <winioctl.h>

/* ── Device naming ────────────────────────────────────────────────── */
#define MEMMON_DEVICE_NAME   L"\\Device\\MemMon"
#define MEMMON_SYMLINK_NAME  L"\\DosDevices\\MemMon"
#define MEMMON_USER_PATH     L"\\\\.\\MemMon"

/* ── IOCTL codes ──────────────────────────────────────────────────── */
#define MEMMON_DEVICE_TYPE   0x8000  /* custom device type */

#define IOCTL_MEMMON_READ_MEMORY   \
    CTL_CODE(MEMMON_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_MEMMON_WRITE_MEMORY  \
    CTL_CODE(MEMMON_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_MEMMON_LIST_PROCS    \
    CTL_CODE(MEMMON_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)

/* ── Limits ───────────────────────────────────────────────────────── */
#define MEMMON_MAX_READ_SIZE    (16 * 1024 * 1024)   /* 16 MiB per read   */
#define MEMMON_MAX_WRITE_SIZE   (16 * 1024 * 1024)   /* 16 MiB per write  */
#define MEMMON_MAX_PROC_COUNT   4096
#define MEMMON_PROC_NAME_LEN    64

/* ── Read memory ──────────────────────────────────────────────────── */
typedef struct _MEMMON_READ_REQUEST {
    ULONG   ProcessId;
    ULONG64 Address;
    ULONG   Size;
} MEMMON_READ_REQUEST, *PMEMMON_READ_REQUEST;

/*
 * Response layout (METHOD_BUFFERED — SystemBuffer reused for output):
 *   struct { NTSTATUS Status; ULONG BytesRead; UCHAR Data[BytesRead]; }
 */
typedef struct _MEMMON_READ_RESPONSE {
    LONG    Status;       /* NTSTATUS cast to LONG for user-mode  */
    ULONG   BytesRead;
    UCHAR   Data[1];      /* variable-length                      */
} MEMMON_READ_RESPONSE, *PMEMMON_READ_RESPONSE;

/* ── Write memory ─────────────────────────────────────────────────── */
/*
 * Input layout:
 *   struct { PID; Address; Size; Data[Size]; }
 */
typedef struct _MEMMON_WRITE_REQUEST {
    ULONG   ProcessId;
    ULONG64 Address;
    ULONG   Size;
    UCHAR   Data[1];      /* variable-length                      */
} MEMMON_WRITE_REQUEST, *PMEMMON_WRITE_REQUEST;

typedef struct _MEMMON_WRITE_RESPONSE {
    LONG    Status;
    ULONG   BytesWritten;
} MEMMON_WRITE_RESPONSE, *PMEMMON_WRITE_RESPONSE;

/* ── Process list ─────────────────────────────────────────────────── */
typedef struct _MEMMON_PROC_ENTRY {
    ULONG   ProcessId;
    WCHAR   Name[MEMMON_PROC_NAME_LEN];
} MEMMON_PROC_ENTRY, *PMEMMON_PROC_ENTRY;

typedef struct _MEMMON_PROC_LIST {
    ULONG             Count;
    MEMMON_PROC_ENTRY  Entries[1];   /* variable-length */
} MEMMON_PROC_LIST, *PMEMMON_PROC_LIST;
