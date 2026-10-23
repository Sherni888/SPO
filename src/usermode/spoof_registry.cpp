// language: C++20, file: spoof_registry.cpp, target: Windows 11 x64, MSVC

#include "spoof_registry.hpp"
#include "utils.hpp"

RegistrySpoofResult SpoofRegistryIdentifiers(Backup& bk) {
    RegistrySpoofResult res{};

    // ── MachineGuid ───────────────────────────────────────────────────────────
    {
        const wchar_t* path  = L"SOFTWARE\\Microsoft\\Cryptography";
        const wchar_t* vname = L"MachineGuid";
        std::wstring orig;
        if (RegReadString(HKEY_LOCAL_MACHINE, path, vname, orig))
            bk.Add(L"MachineGuid", orig);

        // stored WITHOUT braces
        std::wstring guid = RandomGuid();
        std::wstring plain = guid.substr(1, guid.size() - 2);
        if (RegWriteString(HKEY_LOCAL_MACHINE, path, vname, plain)) {
            LOGOK(L"MachineGuid     -> %s", plain.c_str());
            res.machineGuid = true;
        } else {
            LOGF(L"MachineGuid write failed (error %u)", GetLastError());
        }
    }

    // ── HwProfileGuid ─────────────────────────────────────────────────────────
    {
        const wchar_t* path =
            L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001";
        std::wstring orig;
        if (RegReadString(HKEY_LOCAL_MACHINE, path, L"HwProfileGuid", orig))
            bk.Add(L"HwProfileGuid", orig);

        auto guid = RandomGuid();
        if (RegWriteString(HKEY_LOCAL_MACHINE, path, L"HwProfileGuid", guid)) {
            LOGOK(L"HwProfileGuid   -> %s", guid.c_str());
            res.hwProfileGuid = true;
        } else {
            LOGF(L"HwProfileGuid write failed (error %u)", GetLastError());
        }
    }

    // ── ComputerName ──────────────────────────────────────────────────────────
    {
        const wchar_t* activePath =
            L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName";
        const wchar_t* pendPath =
            L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName";
        std::wstring orig;
        if (RegReadString(HKEY_LOCAL_MACHINE, activePath, L"ComputerName", orig))
            bk.Add(L"ComputerName", orig);

        auto name = RandomAlpha(8);
        RegWriteString(HKEY_LOCAL_MACHINE, activePath, L"ComputerName", name);
        if (RegWriteString(HKEY_LOCAL_MACHINE, pendPath, L"ComputerName", name)) {
            LOGOK(L"ComputerName    -> %s", name.c_str());
            res.computerName = true;
        }

        RegWriteString(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
            L"Hostname", name);
        RegWriteString(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
            L"NV Hostname", name);
    }

    // ── InstallDate / InstallTime ─────────────────────────────────────────────
    {
        const wchar_t* path =
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
        DWORD orig = 0;
        if (RegReadDword(HKEY_LOCAL_MACHINE, path, L"InstallDate", orig))
            bk.Add(L"InstallDate", std::to_wstring(orig));

        std::uniform_int_distribution<DWORD> distDate(1640995200u, 1748736000u);
        DWORD newDate = distDate(Rng());
        if (RegWriteDword(HKEY_LOCAL_MACHINE, path, L"InstallDate", newDate)) {
            LOGOK(L"InstallDate     -> 0x%08X", newDate);
            res.installDate = true;
        }

        ULONGLONG ft = (static_cast<ULONGLONG>(newDate) + 11644473600ULL) * 10000000ULL;
        RegWriteBinary(HKEY_LOCAL_MACHINE, path, L"InstallTime",
            reinterpret_cast<const uint8_t*>(&ft), sizeof(ft));
    }

    // ── ProductId ─────────────────────────────────────────────────────────────
    {
        const wchar_t* path =
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
        std::wstring orig;
        if (RegReadString(HKEY_LOCAL_MACHINE, path, L"ProductId", orig))
            bk.Add(L"ProductId", orig);

        auto part = [&]() { return RandomAlpha(5); };
        auto pid = part() + L"-" + part() + L"-" + part() + L"-" + part();
        if (RegWriteString(HKEY_LOCAL_MACHINE, path, L"ProductId", pid)) {
            LOGOK(L"ProductId       -> %s", pid.c_str());
            res.productId = true;
        }
    }

    // ── SQMClient telemetry MachineId ─────────────────────────────────────────
    {
        RegWriteString(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\SQMClient",
            L"MachineId", RandomGuid());
    }

    return res;
}
