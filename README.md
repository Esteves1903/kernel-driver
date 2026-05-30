# MemMon — Process Memory Monitor

A Windows kernel driver + user-mode client for reading/writing process memory,
similar in concept to open-source tools like
[System Informer](https://github.com/winsiderss/systeminformer).

---

## Project Structure

```
memmon/
├── common.h      Shared IOCTL codes and data structures
├── driver.c      Kernel driver (MemMon.sys)
├── client.c      Console client (memmon.exe)
└── README.md     This file
```

---

## Prerequisites

| Tool                   | Version          |
|------------------------|------------------|
| Visual Studio          | 2022 (v17.x)    |
| Windows Driver Kit     | WDK for VS 2022  |
| Windows SDK            | 10.0.22621+      |
| Target OS              | Windows 10/11 x64|

Install the WDK from:
https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

---

## Building

### 1. Kernel Driver (driver.sys)

1. Open Visual Studio 2022.
2. **File → New → Project → Kernel Mode Driver, Empty (KMDF)**
   (or use the "Empty WDM Driver" template).
3. Remove any auto-generated files.
4. Add `driver.c` to Source Files.
5. Project Properties:
   - **Configuration**: Release
   - **Platform**: x64
   - **C/C++ → General → Warning Level**: /W4
   - **C/C++ → Preprocessor**: add `_AMD64_`
   - **Linker → Input → Additional Dependencies**: `ntoskrnl.lib;ntstrsafe.lib`
   - **Driver Settings → Target OS Version**: Windows 10
   - **Inf2Cat → Run Inf2Cat**: No  (unless you have an INF)
6. Build → Build Solution.
7. Output: `x64/Release/MemMon.sys`

### 2. User-Mode Client (memmon.exe)

**Option A — Developer Command Prompt:**
```cmd
cl /W4 /O2 client.c /Fe:memmon.exe
```

**Option B — Visual Studio:**
1. Create a new Console Application project.
2. Add `client.c` and `common.h`.
3. Build as x64 Release.

---

## Loading the Driver

> **Always test in a Virtual Machine first!**
> A bug in kernel code causes a bluescreen (BSOD).

### Enable Test Signing (one-time, reboot required)

```cmd
bcdedit /set testsigning on
```

### Self-Sign the Driver (test only)

```cmd
makecert -r -pe -ss PrivateCertStore -n "CN=MemMonTest" MemMon.cer
signtool sign /s PrivateCertStore /n "MemMonTest" /t http://timestamp.digicert.com /fd sha256 MemMon.sys
```

### Load / Unload

```cmd
:: Load
sc create MemMon type= kernel binPath= C:\path\to\MemMon.sys
sc start MemMon

:: Verify
sc query MemMon

:: Unload
sc stop MemMon
sc delete MemMon
```

---

## Usage

Run **as Administrator**:

```
memmon.exe                              Interactive mode
memmon.exe list                         List running processes
memmon.exe read  <pid> <hex-addr> [sz]  Read memory (default 256 bytes)
memmon.exe write <pid> <hex-addr> <hex> Write hex bytes
```

### Examples

```cmd
> memmon.exe list

  PID       Process Name
  --------  --------------------
  0         [System Idle]
  4         System
  1234      notepad.exe
  ...

> memmon.exe read 1234 7FF600010000 128

  PID 1234 | 0x7FF600010000 | 128 bytes

  00007FF600010000  4D 5A 90 00 03 00 00 00  04 00 00 00 FF FF 00 00  |MZ..............|
  00007FF600010010  B8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
  ...

> memmon.exe write 1234 7FF600020000 90909090
[+] Wrote 4 bytes to PID 1234 @ 0x7FF600020000
```

### Interactive Mode

```
> memmon.exe

=== MemMon Interactive Console ===

  Commands:
    list                              List running processes
    read  <pid> <hex-addr> [size]     Read process memory
    write <pid> <hex-addr> <hex>      Write hex bytes to process memory
    help                              Show this help
    quit / exit                       Exit

memmon> list
memmon> read 1234 7FF600010000
memmon> quit
```

---

## Safety Design

| Layer                | Protection                                                      |
|----------------------|-----------------------------------------------------------------|
| Kernel address block | Rejects addresses ≥ 0xFFFF800000000000 (user-space only)        |
| SEH wrapping         | `__try/__except` around every `MmCopyVirtualMemory` call        |
| Input validation     | Checks buffer sizes, zero-length, max sizes before any copy     |
| Partial reads        | Returns bytes actually copied; client handles partial results   |
| Process ref-count    | `ObDereferenceObject` called on every code path (including err) |
| Clean unload         | Deletes symbolic link + device object in `DriverUnload`         |
| Buffered I/O         | Uses METHOD_BUFFERED — kernel copies user buffers safely        |

---

## Avoiding BSODs

The most common BSOD causes in drivers like this, and how this code avoids them:

1. **Accessing invalid memory** → `MmCopyVirtualMemory` handles page faults
   internally; SEH catches anything else.
2. **Forgetting `ObDereferenceObject`** → every `PsLookupProcessByProcessId`
   has a matching deref on all paths.
3. **Buffer overflows** → all buffer sizes validated before use;
   `METHOD_BUFFERED` means the I/O manager handles user↔kernel copies.
4. **Unload race conditions** → no background threads, no timers, no DPCs;
   unload is synchronous and safe.
5. **NULL dereference** → SystemBuffer checked implicitly through
   `InputBufferLength` / `OutputBufferLength` validation.

---

## License

This is sample/educational code. Use at your own risk.
For production use, implement proper code-signing with an EV certificate
and consider using a WDF (KMDF) framework instead of raw WDM.
