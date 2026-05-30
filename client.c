/*
 * client.c — MemMon user-mode console client
 *
 * Communicates with the MemMon kernel driver via DeviceIoControl.
 * Must be run as Administrator (the driver requires SeDebugPrivilege).
 *
 * Build: cl /W4 /O2 client.c /Fe:memmon.exe
 *        (or add to a VS2022 console-app project)
 *
 * Usage:
 *   memmon.exe list
 *   memmon.exe read  <pid> <hex-address> [size]
 *   memmon.exe write <pid> <hex-address> <hex-bytes>
 */

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Pull in the shared header */
#include "common.h"

/* ────────────────────────────────────────────────────────────────── */
/*  Driver handle helpers                                           */
/* ────────────────────────────────────────────────────────────────── */

static HANDLE OpenDriver(void)
{
    HANDLE hDev = CreateFileW(
        MEMMON_USER_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);

    if (hDev == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND)
            fprintf(stderr,
                "[!] Driver not loaded. "
                "Load with: sc start MemMon\n");
        else if (err == ERROR_ACCESS_DENIED)
            fprintf(stderr,
                "[!] Access denied. Run this tool as Administrator.\n");
        else
            fprintf(stderr,
                "[!] CreateFile failed, error %lu\n", err);
    }
    return hDev;
}

/* ────────────────────────────────────────────────────────────────── */
/*  Hex-dump helper                                                 */
/* ────────────────────────────────────────────────────────────────── */

static void HexDump(ULONG64 baseAddr, const UCHAR *data, ULONG len)
{
    const ULONG bytesPerLine = 16;

    for (ULONG off = 0; off < len; off += bytesPerLine) {
        /* Address column */
        printf("  %016llX  ", (unsigned long long)(baseAddr + off));

        /* Hex bytes */
        for (ULONG j = 0; j < bytesPerLine; j++) {
            if (j == 8) putchar(' ');
            if (off + j < len)
                printf("%02X ", data[off + j]);
            else
                printf("   ");
        }

        /* ASCII column */
        printf(" |");
        for (ULONG j = 0; j < bytesPerLine && (off + j) < len; j++) {
            UCHAR c = data[off + j];
            putchar((c >= 0x20 && c <= 0x7E) ? c : '.');
        }
        printf("|\n");
    }
}

/* ────────────────────────────────────────────────────────────────── */
/*  Command: list                                                   */
/* ────────────────────────────────────────────────────────────────── */

static int CmdListProcesses(HANDLE hDev)
{
    /* Allocate a generous output buffer */
    ULONG outSize = FIELD_OFFSET(MEMMON_PROC_LIST, Entries)
                    + MEMMON_MAX_PROC_COUNT * sizeof(MEMMON_PROC_ENTRY);

    PMEMMON_PROC_LIST list = (PMEMMON_PROC_LIST)malloc(outSize);
    if (!list) {
        fprintf(stderr, "[!] Out of memory\n");
        return 1;
    }
    ZeroMemory(list, outSize);

    DWORD returned = 0;
    BOOL ok = DeviceIoControl(hDev,
                              IOCTL_MEMMON_LIST_PROCS,
                              NULL, 0,          /* no input  */
                              list, outSize,
                              &returned, NULL);
    if (!ok) {
        fprintf(stderr, "[!] DeviceIoControl failed, error %lu\n",
                GetLastError());
        free(list);
        return 1;
    }

    printf("\n  %-8s  %s\n", "PID", "Process Name");
    printf("  %-8s  %s\n", "--------", "--------------------");

    for (ULONG i = 0; i < list->Count; i++) {
        printf("  %-8lu  %ls\n",
               list->Entries[i].ProcessId,
               list->Entries[i].Name);
    }
    printf("\n  Total: %lu processes\n\n", list->Count);

    free(list);
    return 0;
}

/* ────────────────────────────────────────────────────────────────── */
/*  Command: read                                                   */
/* ────────────────────────────────────────────────────────────────── */

static int CmdReadMemory(HANDLE hDev, ULONG pid, ULONG64 addr, ULONG size)
{
    if (size == 0 || size > MEMMON_MAX_READ_SIZE) {
        fprintf(stderr, "[!] Invalid size (1 .. %u)\n", MEMMON_MAX_READ_SIZE);
        return 1;
    }

    MEMMON_READ_REQUEST req = { .ProcessId = pid,
                                .Address   = addr,
                                .Size      = size };

    ULONG outSize = FIELD_OFFSET(MEMMON_READ_RESPONSE, Data) + size;
    PMEMMON_READ_RESPONSE resp = (PMEMMON_READ_RESPONSE)malloc(outSize);
    if (!resp) {
        fprintf(stderr, "[!] Out of memory\n");
        return 1;
    }
    ZeroMemory(resp, outSize);

    DWORD returned = 0;
    BOOL ok = DeviceIoControl(hDev,
                              IOCTL_MEMMON_READ_MEMORY,
                              &req, sizeof(req),
                              resp, outSize,
                              &returned, NULL);
    if (!ok) {
        fprintf(stderr, "[!] DeviceIoControl failed, error %lu\n",
                GetLastError());
        free(resp);
        return 1;
    }

    if (resp->Status != 0) {  /* NTSTATUS */
        fprintf(stderr,
                "[!] Kernel read returned NTSTATUS 0x%08X "
                "(read %lu of %lu bytes)\n",
                (unsigned)resp->Status, resp->BytesRead, size);
        if (resp->BytesRead == 0) {
            free(resp);
            return 1;
        }
        /* Partial read — still dump what we got */
    }

    printf("\n  PID %lu | 0x%llX | %lu bytes\n\n",
           pid, (unsigned long long)addr, resp->BytesRead);

    HexDump(addr, resp->Data, resp->BytesRead);
    putchar('\n');

    free(resp);
    return 0;
}

/* ────────────────────────────────────────────────────────────────── */
/*  Command: write                                                  */
/* ────────────────────────────────────────────────────────────────── */

/*
 * Parse a hex string like "90909090" or "90 90 90 90" into bytes.
 * Returns the number of bytes parsed, or 0 on error.
 */
static ULONG ParseHexBytes(const char *hexStr, UCHAR *buf, ULONG maxLen)
{
    ULONG count = 0;
    const char *p = hexStr;

    while (*p && count < maxLen) {
        /* skip whitespace */
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0') break;

        /* need at least two hex digits */
        char hi = *p++;
        if (*p == '\0') return 0;  /* odd number of nibbles */
        char lo = *p++;

        unsigned val;
        if (sscanf((char[]){hi, lo, '\0'}, "%02x", &val) != 1)
            return 0;

        buf[count++] = (UCHAR)val;
    }

    return count;
}

static int CmdWriteMemory(HANDLE hDev, ULONG pid, ULONG64 addr,
                           const char *hexBytes)
{
    /* Parse hex input */
    UCHAR dataBuf[MEMMON_MAX_WRITE_SIZE];
    ULONG dataLen = ParseHexBytes(hexBytes, dataBuf, sizeof(dataBuf));
    if (dataLen == 0) {
        fprintf(stderr, "[!] Invalid hex bytes.\n"
                "    Example: \"48656C6C6F\" or \"48 65 6C 6C 6F\"\n");
        return 1;
    }

    /* Build request */
    ULONG reqSize = FIELD_OFFSET(MEMMON_WRITE_REQUEST, Data) + dataLen;
    PMEMMON_WRITE_REQUEST req = (PMEMMON_WRITE_REQUEST)malloc(reqSize);
    if (!req) {
        fprintf(stderr, "[!] Out of memory\n");
        return 1;
    }

    req->ProcessId = pid;
    req->Address   = addr;
    req->Size      = dataLen;
    memcpy(req->Data, dataBuf, dataLen);

    MEMMON_WRITE_RESPONSE resp = {0};
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(hDev,
                              IOCTL_MEMMON_WRITE_MEMORY,
                              req, reqSize,
                              &resp, sizeof(resp),
                              &returned, NULL);
    free(req);

    if (!ok) {
        fprintf(stderr, "[!] DeviceIoControl failed, error %lu\n",
                GetLastError());
        return 1;
    }

    if (resp.Status != 0) {
        fprintf(stderr,
                "[!] Kernel write returned NTSTATUS 0x%08X "
                "(wrote %lu of %lu bytes)\n",
                (unsigned)resp.Status, resp.BytesWritten, dataLen);
        return 1;
    }

    printf("[+] Wrote %lu bytes to PID %lu @ 0x%llX\n",
           resp.BytesWritten, pid, (unsigned long long)addr);
    return 0;
}

/* ────────────────────────────────────────────────────────────────── */
/*  Interactive mode                                                */
/* ────────────────────────────────────────────────────────────────── */

static void PrintInteractiveHelp(void)
{
    printf(
        "\n"
        "  Commands:\n"
        "    list                              List running processes\n"
        "    read  <pid> <hex-addr> [size]     Read process memory (default 256 bytes)\n"
        "    write <pid> <hex-addr> <hex>      Write hex bytes to process memory\n"
        "    help                              Show this help\n"
        "    quit / exit                       Exit\n\n"
    );
}

static int RunInteractive(HANDLE hDev)
{
    char line[4096];

    printf("\n=== MemMon Interactive Console ===\n");
    PrintInteractiveHelp();

    for (;;) {
        printf("memmon> ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin))
            break;

        /* trim newline */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';

        if (len == 0) continue;

        /* ── Parse command ─────────────────────────────────────── */
        char cmd[32] = {0};
        sscanf(line, "%31s", cmd);

        if (_stricmp(cmd, "quit") == 0 || _stricmp(cmd, "exit") == 0)
            break;

        if (_stricmp(cmd, "help") == 0 || cmd[0] == '?') {
            PrintInteractiveHelp();
            continue;
        }

        if (_stricmp(cmd, "list") == 0) {
            CmdListProcesses(hDev);
            continue;
        }

        if (_stricmp(cmd, "read") == 0) {
            ULONG   pid  = 0;
            char    addrStr[32] = {0};
            ULONG   size = 256;

            int n = sscanf(line, "%*s %lu %31s %lu", &pid, addrStr, &size);
            if (n < 2) {
                fprintf(stderr, "Usage: read <pid> <hex-address> [size]\n");
                continue;
            }

            ULONG64 addr = _strtoui64(addrStr, NULL, 16);
            CmdReadMemory(hDev, pid, addr, size);
            continue;
        }

        if (_stricmp(cmd, "write") == 0) {
            ULONG pid = 0;
            char  addrStr[32] = {0};
            char  hexData[8192] = {0};

            /* Grab pid and address, rest is hex data */
            const char *rest = line;
            /* skip "write" */
            while (*rest && *rest != ' ') rest++;
            while (*rest == ' ') rest++;

            int n = sscanf(rest, "%lu %31s", &pid, addrStr);
            if (n < 2) {
                fprintf(stderr,
                    "Usage: write <pid> <hex-address> <hex-bytes>\n");
                continue;
            }

            /* skip past pid and address to get hex data */
            while (*rest && *rest != ' ') rest++;  /* skip pid   */
            while (*rest == ' ') rest++;
            while (*rest && *rest != ' ') rest++;  /* skip addr  */
            while (*rest == ' ') rest++;

            if (*rest == '\0') {
                fprintf(stderr,
                    "Usage: write <pid> <hex-address> <hex-bytes>\n");
                continue;
            }

            ULONG64 addr = _strtoui64(addrStr, NULL, 16);
            CmdWriteMemory(hDev, pid, addr, rest);
            continue;
        }

        fprintf(stderr, "Unknown command: %s (type 'help')\n", cmd);
    }

    return 0;
}

/* ────────────────────────────────────────────────────────────────── */
/*  Usage & main                                                    */
/* ────────────────────────────────────────────────────────────────── */

static void PrintUsage(const char *exe)
{
    printf(
        "\n"
        "MemMon — process memory monitor (kernel driver client)\n\n"
        "Usage:\n"
        "  %s                                 Interactive mode\n"
        "  %s list                            List running processes\n"
        "  %s read  <pid> <hex-addr> [size]   Read memory (default 256 bytes)\n"
        "  %s write <pid> <hex-addr> <hex>    Write hex bytes\n"
        "\n"
        "Examples:\n"
        "  %s list\n"
        "  %s read  1234 7FF600010000\n"
        "  %s read  1234 7FF600010000 512\n"
        "  %s write 1234 7FF600010000 90909090\n"
        "\n"
        "NOTE: Must be run as Administrator with the MemMon driver loaded.\n\n",
        exe, exe, exe, exe, exe, exe, exe, exe);
}

int main(int argc, char *argv[])
{
    /* ── Open the driver ──────────────────────────────────────── */
    HANDLE hDev = OpenDriver();
    if (hDev == INVALID_HANDLE_VALUE)
        return 1;

    int ret = 0;

    if (argc < 2) {
        /* No arguments → interactive mode */
        ret = RunInteractive(hDev);
    }
    else if (_stricmp(argv[1], "list") == 0) {
        ret = CmdListProcesses(hDev);
    }
    else if (_stricmp(argv[1], "read") == 0) {
        if (argc < 4) {
            PrintUsage(argv[0]);
            ret = 1;
        } else {
            ULONG   pid  = strtoul(argv[2], NULL, 10);
            ULONG64 addr = _strtoui64(argv[3], NULL, 16);
            ULONG   size = (argc >= 5) ? strtoul(argv[4], NULL, 10) : 256;
            ret = CmdReadMemory(hDev, pid, addr, size);
        }
    }
    else if (_stricmp(argv[1], "write") == 0) {
        if (argc < 5) {
            PrintUsage(argv[0]);
            ret = 1;
        } else {
            ULONG   pid  = strtoul(argv[2], NULL, 10);
            ULONG64 addr = _strtoui64(argv[3], NULL, 16);
            ret = CmdWriteMemory(hDev, pid, addr, argv[4]);
        }
    }
    else {
        PrintUsage(argv[0]);
        ret = 1;
    }

    CloseHandle(hDev);
    return ret;
}
