/*
 * detect.c — rootkit detection tool for the MemMon driver.
 *
 * Calls two IOCTLs and cross-references the results:
 *   IOCTL_MEMMON_LIST_MODULES     — dumps PsLoadedModuleList
 *   IOCTL_MEMMON_CROSSREF_DRIVERS — checks every \Driver object against
 *                                   that list and flags orphans
 *
 * Build (x64 Native Tools Command Prompt):
 *   cl /W4 /O2 detect.c /link /subsystem:console
 *
 * Run as Administrator after loading the driver:
 *   detect.exe
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

/* ── IOCTL codes — must match driver.c exactly ───────────────────── */
#define MEMMON_DEVICE_TYPE   0x8000

#define IOCTL_MEMMON_LIST_MODULES     \
    CTL_CODE(MEMMON_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MEMMON_CROSSREF_DRIVERS \
    CTL_CODE(MEMMON_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS)

/* ── Shared structs — must match driver.c exactly ────────────────── */
#define MEMMON_MODULE_NAME_LEN 128

typedef struct {
    ULONG64 BaseAddress;
    ULONG64 EntryPoint;
    ULONG   SizeOfImage;
    ULONG   _Pad;
    WCHAR   BaseName[64];
    WCHAR   FullPath[MEMMON_MODULE_NAME_LEN];
} MEMMON_MODULE_ENTRY;

typedef struct {
    ULONG             Count;
    MEMMON_MODULE_ENTRY Entries[1];
} MEMMON_MODULE_LIST;

typedef struct {
    WCHAR   ObjectName[64];
    ULONG64 DriverStart;
    ULONG   DriverSize;
    ULONG   InModuleList;   /* 1 = present in PsLoadedModuleList, 0 = anomaly */
} MEMMON_ORPHAN_ENTRY;

typedef struct {
    ULONG Count;
    ULONG OrphanCount;
    MEMMON_ORPHAN_ENTRY Entries[1];
} MEMMON_ORPHAN_LIST;

/* ── Helpers ─────────────────────────────────────────────────────── */

static HANDLE OpenDriver(void)
{
    HANDLE h = CreateFileW(L"\\\\.\\MemMon",
                           GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL,
                           OPEN_EXISTING,
                           0,
                           NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr,
                "[!] Cannot open \\\\.\\MemMon (error %lu).\n"
                "    Is the driver loaded?  Run detect.exe as Administrator.\n",
                GetLastError());
    }
    return h;
}

static void *IoctlAlloc(HANDLE hDev, DWORD code,
                        DWORD bufSize, DWORD *pBytesOut)
{
    void *buf = malloc(bufSize);
    if (!buf) { fprintf(stderr, "[!] malloc failed\n"); return NULL; }

    DWORD returned = 0;
    if (!DeviceIoControl(hDev, code,
                         NULL, 0,
                         buf, bufSize,
                         &returned, NULL)) {
        fprintf(stderr, "[!] DeviceIoControl 0x%08lX failed (error %lu)\n",
                code, GetLastError());
        free(buf);
        return NULL;
    }
    if (pBytesOut) *pBytesOut = returned;
    return buf;
}

/* ── Section 1: PsLoadedModuleList dump ──────────────────────────── */

static void PrintModuleList(HANDLE hDev)
{
    DWORD bytes = 0;
    MEMMON_MODULE_LIST *list =
        (MEMMON_MODULE_LIST *)IoctlAlloc(hDev, IOCTL_MEMMON_LIST_MODULES,
                                         4 * 1024 * 1024, &bytes);
    if (!list) return;

    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  PsLoadedModuleList  (%lu modules)                           \n",
           list->Count);
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("  %-4s  %-18s  %-8s  %s\n",
           "No.", "Base", "Size", "Module");
    printf("  ----  ------------------  --------  ------\n");

    for (ULONG i = 0; i < list->Count; i++) {
        MEMMON_MODULE_ENTRY *e = &list->Entries[i];
        printf("  %3lu   0x%016llX  %7luK  %ls\n",
               i + 1,
               e->BaseAddress,
               e->SizeOfImage / 1024,
               e->BaseName);
    }
    printf("\n");
    free(list);
}

/* ── Section 2: \Driver cross-reference ──────────────────────────── */

static void PrintCrossRef(HANDLE hDev)
{
    DWORD bytes = 0;
    MEMMON_ORPHAN_LIST *xref =
        (MEMMON_ORPHAN_LIST *)IoctlAlloc(hDev, IOCTL_MEMMON_CROSSREF_DRIVERS,
                                          2 * 1024 * 1024, &bytes);
    if (!xref) return;

    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  \\Driver namespace vs PsLoadedModuleList  (%lu objects)      \n",
           xref->Count);
    if (xref->OrphanCount > 0)
        printf("║  *** %lu ANOMALY(IES) DETECTED ***                           \n",
               xref->OrphanCount);
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("  %-8s  %-18s  %-8s  %s\n",
           "Status", "DriverStart", "Size", "\\Driver\\<name>");
    printf("  --------  ------------------  --------  ------\n");

    for (ULONG i = 0; i < xref->Count; i++) {
        MEMMON_ORPHAN_ENTRY *e = &xref->Entries[i];

        /*
         * InModuleList == 0 means DriverObject->DriverStart does not fall
         * inside any currently-listed module range.  The driver is executing
         * but has been removed from PsLoadedModuleList — the DKOM signature.
         */
        const char *tag = e->InModuleList ? "  OK   " : "[ALERT]";

        printf("  %s   0x%016llX  %7luK  \\Driver\\%ls\n",
               tag,
               e->DriverStart,
               e->DriverSize / 1024,
               e->ObjectName);
    }

    printf("\n");

    if (xref->OrphanCount == 0) {
        printf("[OK] All %lu \\Driver objects are present in PsLoadedModuleList.\n"
               "     No DKOM-based module hiding detected.\n",
               xref->Count);
    } else {
        printf("[!!] %lu driver(s) flagged as anomalies.\n"
               "     These have code running in the kernel but are NOT in the\n"
               "     official loaded-module list — consistent with DKOM rootkit\n"
               "     activity (e.g. manual InLoadOrderLinks unlinking).\n",
               xref->OrphanCount);
    }

    printf("\n");
    free(xref);
}

/* ── main ────────────────────────────────────────────────────────── */

int main(void)
{
    printf("\nMemMon Detection Tool\n");
    printf("=====================\n\n");

    HANDLE hDev = OpenDriver();
    if (hDev == INVALID_HANDLE_VALUE)
        return 1;

    PrintModuleList(hDev);
    PrintCrossRef(hDev);

    CloseHandle(hDev);
    return 0;
}
