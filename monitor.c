/*
 * monitor.c — user-mode consumer for the MemMon shared memory channel.
 *
 * Build (Developer Command Prompt / x64 Native Tools):
 *   cl /W4 /O2 monitor.c /link /subsystem:console
 *
 * Run AFTER the driver is loaded:
 *   sc create MemMon type= kernel binPath= C:\path\to\MemMon.sys
 *   sc start  MemMon
 *   monitor.exe
 *
 * Stop with Ctrl+C.  To unload: sc stop MemMon && sc delete MemMon
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

/* ── Shared layout — must match SHARED_PACKET in driver.c exactly ── */
#define SHMEM_VIEW_BYTES 4096

typedef struct {
    volatile LONG Sequence;   /* incremented by driver; we detect new data   */
    ULONG         DataSize;   /* valid bytes in Message[]                    */
    char          Message[SHMEM_VIEW_BYTES - sizeof(LONG) - sizeof(ULONG)];
} SHARED_PACKET;

/* ── Entry point ─────────────────────────────────────────────────── */

int main(void)
{
    /*
     * "Global\" routes to \BaseNamedObjects in the kernel object namespace,
     * which is where the driver creates both objects.  Without the prefix
     * we would land in the session-local namespace and find nothing.
     */
    HANDLE hMap = OpenFileMappingW(FILE_MAP_READ, FALSE,
                                   L"Global\\MemMonShared");
    if (!hMap) {
        fprintf(stderr,
                "OpenFileMapping failed (error %lu).\n"
                "Is the driver loaded?  Run as Administrator.\n",
                GetLastError());
        return 1;
    }

    SHARED_PACKET *pkt = (SHARED_PACKET *)MapViewOfFile(hMap, FILE_MAP_READ,
                                                        0, 0, 0);
    if (!pkt) {
        fprintf(stderr, "MapViewOfFile failed (error %lu)\n", GetLastError());
        CloseHandle(hMap);
        return 1;
    }

    /*
     * The driver creates a SynchronizationEvent (auto-reset).
     * Each KeSetEvent call wakes exactly one waiting thread, then the
     * event resets automatically — no manual ResetEvent needed.
     */
    HANDLE hEvt = OpenEventW(SYNCHRONIZE, FALSE, L"Global\\MemMonDataReady");
    if (!hEvt) {
        fprintf(stderr,
                "OpenEvent failed (error %lu).\n"
                "Is the driver loaded?  Run as Administrator.\n",
                GetLastError());
        UnmapViewOfFile(pkt);
        CloseHandle(hMap);
        return 1;
    }

    printf("Connected to MemMon driver.  Waiting for data (Ctrl+C to stop)...\n\n");

    LONG lastSeq = 0;

    for (;;) {
        /*
         * Block until the driver signals new data.
         * 5-second timeout as a safety net: if we somehow miss an event
         * pulse we still wake up and re-check the sequence number.
         */
        DWORD wait = WaitForSingleObject(hEvt, 5000);
        if (wait == WAIT_FAILED) {
            fprintf(stderr, "WaitForSingleObject failed (error %lu)\n",
                    GetLastError());
            break;
        }

        /*
         * Read the sequence counter with a load-acquire barrier.
         * InterlockedCompareExchange(p, 0, 0) does an interlocked load —
         * it pairs with the InterlockedIncrement (store-release) in the
         * kernel, ensuring we see all Message/DataSize writes that happened
         * before the counter was bumped.
         */
        LONG seq = InterlockedCompareExchange((LONG *)&pkt->Sequence, 0, 0);

        if (seq == lastSeq)
            continue;   /* spurious wake or 5-s timeout with no new data */

        /*
         * Detect missed ticks: the driver wrote N times but the auto-reset
         * event only fired once, so we woke up once for N packets.
         * We can't recover the lost messages (no ring buffer here), but we
         * at least report how many were dropped.
         */
        LONG delta = seq - lastSeq;
        if (delta > 1)
            printf("  [%ld packet(s) missed between seq %d and %d]\n",
                   delta - 1, lastSeq, seq);

        lastSeq = seq;

        /* Local timestamp (wall clock) so we can see the receive latency. */
        SYSTEMTIME st;
        GetLocalTime(&st);

        printf("[recv %02d:%02d:%02d.%03d] seq=%-5d | %.*s\n",
               st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
               seq,
               (int)pkt->DataSize, pkt->Message);
    }

    CloseHandle(hEvt);
    UnmapViewOfFile(pkt);
    CloseHandle(hMap);
    return 0;
}
