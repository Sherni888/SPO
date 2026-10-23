// language: C++20, file: main.cpp, target: Windows 11 x64, MSVC
// SPO — HWID spoofer for Rust / EAC 2026
// Usage:
//   spo.exe              — spoof all identifiers (auto-backup)
//   spo.exe --restore    — restore from backup
//   spo.exe --status     — show current identifiers without changing them
//   spo.exe --driver     — load/check kernel driver status
//   spo.exe --backup <f> — specify backup file path

#include <windows.h>
#include <cstdio>
#include <string>
#include <algorithm>

#include "utils.hpp"
#include "backup.hpp"
#include "spoof_registry.hpp"
#include "spoof_nic.hpp"
#include "spoof_edid.hpp"
#include "spoof_gpu.hpp"

// ── driver status check ───────────────────────────────────────────────────────

static bool IsDriverLoaded() {
    // query SCM for our driver service
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceW(scm, L"spo_drv", SERVICE_QUERY_STATUS);
    bool loaded = (svc != nullptr);
    if (svc) CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return loaded;
}

// ── status display ────────────────────────────────────────────────────────────

static void ShowStatus() {
    wprintf(L"\n=== Current Identifiers ===\n\n");

    std::wstring val;
    if (RegReadString(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid", val))
        wprintf(L"  MachineGuid    : %s\n", val.c_str());

    if (RegReadString(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001",
            L"HwProfileGuid", val))
        wprintf(L"  HwProfileGuid  : %s\n", val.c_str());

    if (RegReadString(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName",
            L"ComputerName", val))
        wprintf(L"  ComputerName   : %s\n", val.c_str());

    DWORD installDate = 0;
    if (RegReadDword(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            L"InstallDate", installDate))
        wprintf(L"  InstallDate    : 0x%08X\n", installDate);

    static constexpr wchar_t k_NicClass[] =
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\"
        L"{4D36E972-E325-11CE-BFC1-08002BE10318}";
    auto nics = RegEnumSubkeys(HKEY_LOCAL_MACHINE, k_NicClass);
    for (const auto& sub : nics) {
        if (!iswdigit(sub[0])) continue;
        std::wstring path = std::wstring(k_NicClass) + L"\\" + sub;
        std::wstring mac;
        if (RegReadString(HKEY_LOCAL_MACHINE, path.c_str(), L"NetworkAddress", mac))
            wprintf(L"  NIC %-4s MAC    : %s\n", sub.c_str(), mac.c_str());
    }

    wprintf(L"\n  Kernel driver  : %s\n", IsDriverLoaded() ? L"LOADED" : L"not loaded");
    wprintf(L"\n");
}

// ── banner ────────────────────────────────────────────────────────────────────

static void PrintBanner() {
    wprintf(
        L"\n"
        L"  ╔═══════════════════════════════════════╗\n"
        L"  ║   SPO - HWID Spoofer  [Rust/EAC 2026] ║\n"
        L"  ╚═══════════════════════════════════════╝\n"
        L"\n"
    );
}

// ── entry ─────────────────────────────────────────────────────────────────────

int wmain(int argc, wchar_t* argv[]) {
    PrintBanner();

    if (!IsElevated()) {
        wprintf(L"[!] Run as Administrator\n");
        return 1;
    }

    // parse args
    bool doRestore  = false;
    bool doStatus   = false;
    bool doDriver   = false;
    std::wstring backupPath = L"spo_backup.dat";

    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];
        if (arg == L"--restore") doRestore = true;
        else if (arg == L"--status") doStatus = true;
        else if (arg == L"--driver") doDriver = true;
        else if (arg == L"--backup" && i + 1 < argc) backupPath = argv[++i];
    }

    if (doStatus) { ShowStatus(); return 0; }

    if (doDriver) {
        wprintf(L"[*] Driver status: %s\n",
            IsDriverLoaded() ? L"LOADED" : L"NOT LOADED");
        if (!IsDriverLoaded())
            wprintf(L"[i] Load via: loader.exe --load driver\\spo_drv.sys\n");
        return 0;
    }

    if (doRestore) {
        wprintf(L"[*] Restoring from backup: %s\n\n", backupPath.c_str());
        bool ok = RestoreFromBackup(backupPath);
        wprintf(L"\n%s Restore %s\n",
            ok ? L"[+]" : L"[-]", ok ? L"complete" : L"had errors");
        return ok ? 0 : 1;
    }

    // ── spoof mode ────────────────────────────────────────────────────────────
    Backup bk(backupPath);

    wprintf(L"[*] Backup target : %s\n", backupPath.c_str());
    wprintf(L"[*] Spoofing identifiers...\n\n");

    // Registry identifiers
    wprintf(L"--- Registry ---\n");
    auto regRes = SpoofRegistryIdentifiers(bk);

    // NIC MACs
    wprintf(L"\n--- Network Adapters ---\n");
    auto nicRes = SpoofNetworkAdapters(bk);

    // EDID
    wprintf(L"\n--- Monitor EDID ---\n");
    auto edidRes = SpoofMonitorEdid(bk);

    // GPU
    wprintf(L"\n--- GPU ---\n");
    auto gpuRes = SpoofGpuIdentifiers(bk);

    // save backup
    wprintf(L"\n--- Backup ---\n");
    if (bk.Save())
        LOGOK(L"Backup saved    -> %s", backupPath.c_str());
    else
        LOGF(L"Backup save failed — restore will not be possible");

    // ── summary ───────────────────────────────────────────────────────────────
    wprintf(L"\n=== Summary ===\n");
    wprintf(L"  Registry spoof : %s\n",
        (regRes.machineGuid && regRes.hwProfileGuid) ? L"OK" : L"partial");
    wprintf(L"  NICs patched   : %d\n", nicRes.devicesPatched);
    wprintf(L"  Monitors EDID  : %d\n", edidRes.monitorsPatched);
    wprintf(L"  GPU adapters   : %d\n", gpuRes.adaptersPatched);
    wprintf(L"  Kernel driver  : %s\n",
        IsDriverLoaded() ? L"LOADED" : L"not loaded — disk serial unpatched");

    wprintf(L"\n[i] Reboot before launching Rust.\n");
    wprintf(L"[i] Disk serial + SMBIOS: loader.exe --load driver\\spo_drv.sys\n");

    if (!IsDriverLoaded()) {
        wprintf(L"\n[!] EAC 2026 fingerprint coverage without kernel driver:\n");
        wprintf(L"    covered  : MachineGuid, HwProfileGuid, ComputerName, InstallDate\n");
        wprintf(L"             : NIC MACs, EDID serials, GPU IDs\n");
        wprintf(L"    MISSING  : disk serial (IOCTL_STORAGE_QUERY_PROPERTY)\n");
        wprintf(L"             : disk ATA serial (IOCTL_ATA_PASS_THROUGH)\n");
        wprintf(L"             : SMBIOS UUID + baseboard serial\n");
        wprintf(L"    out-of-scope: TPM EK (requires hypervisor vTPM intercept)\n");
        wprintf(L"\n[!] loader.exe --load spo_drv.sys --vuln iqvw64e.sys\n");
    }

    return 0;
}
