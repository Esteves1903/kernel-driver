/*
 * mapper.cpp — Manual mapper para driver kernel
 * Compilar: cl /EHsc /O2 mapper.cpp /Fe:mapper.exe /link user32.lib ntdll.lib
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <ntstatus.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ntdll.lib")

// Protótipo explícito
EXTERN_C NTSTATUS NTAPI NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// Estrutura compatível com SystemModuleInformation (classe 11)
typedef struct _SYSTEM_MODULE_ENTRY {
    HANDLE    Section;
    PVOID     MappedBase;
    PVOID     ImageBase;
    ULONG     ImageSize;
    ULONG     Flags;
    USHORT    LoadOrderIndex;
    USHORT    InitOrderIndex;
    USHORT    LoadCount;
    USHORT    OffsetToFileName;
    UCHAR     FullPathName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG               ModulesCount;
    SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

// Estruturas PE
typedef struct _PE_HEADERS {
    PIMAGE_DOS_HEADER        dos;
    PIMAGE_NT_HEADERS64      nt;
    PIMAGE_FILE_HEADER       file;
    PIMAGE_OPTIONAL_HEADER64 opt;
    PIMAGE_SECTION_HEADER    sections;
} PE_HEADERS;

bool ParsePE(PVOID image, PE_HEADERS& pe) {
    pe.dos = (PIMAGE_DOS_HEADER)image;
    if (pe.dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    
    pe.nt = (PIMAGE_NT_HEADERS64)((ULONG_PTR)image + pe.dos->e_lfanew);
    if (pe.nt->Signature != IMAGE_NT_SIGNATURE) return false;
    
    pe.file = &pe.nt->FileHeader;
    pe.opt  = &pe.nt->OptionalHeader;
    pe.sections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&pe.nt->OptionalHeader + pe.file->SizeOfOptionalHeader);
    
    return (pe.file->Machine == IMAGE_FILE_MACHINE_AMD64);
}

// Obter base do NTOSKRNL
ULONG64 GetKernelBase(const char* name = "ntoskrnl.exe") {
    ULONG size = 0;
    NTSTATUS st = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, NULL, 0, &size);
    if (st != STATUS_INFO_LENGTH_MISMATCH) return 0;

    PSYSTEM_MODULE_INFORMATION mods = (PSYSTEM_MODULE_INFORMATION)malloc(size);
    if (!mods) return 0;

    st = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, mods, size, &size);
    if (st != 0) {
        free(mods);
        return 0;
    }

    ULONG64 base = 0;
    for (ULONG i = 0; i < mods->ModulesCount; i++) {
        // Extrair só o nome do ficheiro do path completo
        const char* full = (const char*)mods->Modules[i].FullPathName;
        const char* fname = full;
        for (const char* p = full; *p; p++) {
            if (*p == '\\') fname = p + 1;
        }
        if (_stricmp(fname, name) == 0) {
            base = (ULONG64)mods->Modules[i].ImageBase;
            break;
        }
    }

    free(mods);
    return base;
}

// Resolver export
ULONG64 GetExport(ULONG64 moduleBase, const char* funcName) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(moduleBase + dos->e_lfanew);
    
    ULONG rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!rva) return 0;

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(moduleBase + rva);
    
    DWORD* names = (DWORD*)(moduleBase + exp->AddressOfNames);
    DWORD* funcs = (DWORD*)(moduleBase + exp->AddressOfFunctions);
    WORD*  ords  = (WORD*)(moduleBase + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* name = (const char*)(moduleBase + names[i]);
        if (strcmp(name, funcName) == 0) {
            return moduleBase + funcs[ords[i]];
        }
    }
    return 0;
}

// Ligação ao MemMon
HANDLE OpenMemMon() {
    return CreateFileA("\\\\.\\MemMon", GENERIC_READ | GENERIC_WRITE,
                       0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

int main(int argc, char* argv[]) {
    printf("=== Kernel Driver Mapper ===\n\n");

    ULONG64 ntBase = GetKernelBase("ntoskrnl.exe");
    if (!ntBase) {
        printf("[!] Cannot find ntoskrnl.exe. Run as Administrator.\n");
        return 1;
    }
    printf("[+] NTOSKRNL base: 0x%llX\n", ntBase);

    ULONG64 ExAlloc = GetExport(ntBase, "ExAllocatePool");
    ULONG64 RtlZero = GetExport(ntBase, "RtlZeroMemory");
    ULONG64 memcpy_ = GetExport(ntBase, "memcpy");

    if (!ExAlloc || !RtlZero || !memcpy_) {
        printf("[!] Cannot resolve essential exports.\n");
        return 1;
    }
    printf("[+] ExAllocatePool:    0x%llX\n", ExAlloc);
    printf("[+] RtlZeroMemory:     0x%llX\n", RtlZero);
    printf("[+] memcpy:            0x%llX\n", memcpy_);

    if (argc < 2) {
        printf("\n[*] Usage: mapper.exe <driver.sys>\n");
        printf("[*] Exports resolvidos. Pronto para mapear drivers.\n");
        return 0;
    }

    HANDLE hDev = OpenMemMon();
    if (hDev == INVALID_HANDLE_VALUE) {
        printf("[!] MemMon driver not loaded.\n");
        printf("    Load with: sc start MemMon\n");
        printf("    Or: kdmapper.exe MemMon.sys\n");
        return 1;
    }
    printf("[+] MemMon driver connected\n");
    printf("[*] Ready to map: %s\n", argv[1]);
    printf("[!] IOCTL_MAPPER_LOAD_DRIVER handler needed in driver.c\n");

    CloseHandle(hDev);
    return 0;
}