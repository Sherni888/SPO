// language: C++20, file: spoof_nic.cpp, target: Windows 11 x64, MSVC
// NIC MAC spoofing via registry (Class key NetworkAddress)

#include "spoof_nic.hpp"
#include "utils.hpp"
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

static constexpr wchar_t k_NicClassKey[] =
    L"SYSTEM\\CurrentControlSet\\Control\\Class\\"
    L"{4D36E972-E325-11CE-BFC1-08002BE10318}";

static constexpr wchar_t k_NdisConn[] =
    L"SYSTEM\\CurrentControlSet\\Control\\Network\\"
    L"{4D36E972-E325-11CE-BFC1-08002BE10318}";

NicSpoofResult SpoofNetworkAdapters(Backup& bk) {
    NicSpoofResult res{};

    auto subs = RegEnumSubkeys(HKEY_LOCAL_MACHINE, k_NicClassKey);
    for (const auto& sub : subs) {
        if (!iswdigit(sub[0])) continue;

        std::wstring regPath = std::wstring(k_NicClassKey) + L"\\" + sub;

        std::wstring driverDesc;
        RegReadString(HKEY_LOCAL_MACHINE, regPath.c_str(), L"DriverDesc", driverDesc);
        if (driverDesc.find(L"Loopback") != std::wstring::npos) continue;
        if (driverDesc.find(L"WAN Miniport") != std::wstring::npos) continue;
        if (driverDesc.find(L"Virtual") != std::wstring::npos) continue;

        std::wstring existingMac;
        RegReadString(HKEY_LOCAL_MACHINE, regPath.c_str(), L"NetworkAddress", existingMac);
        bk.Add(L"NIC_" + sub, existingMac.empty() ? L"<unset>" : existingMac);

        auto newMac = RandomMac();
        if (RegWriteString(HKEY_LOCAL_MACHINE, regPath.c_str(),
                L"NetworkAddress", newMac)) {
            LOGOK(L"NIC %-4s MAC     -> %s  (%s)",
                sub.c_str(), newMac.c_str(),
                driverDesc.empty() ? L"?" : driverDesc.c_str());
            ++res.devicesPatched;
        } else {
            LOGF(L"NIC %s MAC write failed", sub.c_str());
        }

        RegWriteString(HKEY_LOCAL_MACHINE, regPath.c_str(),
            L"PermanentAddress", newMac);
    }

    auto nicGuids = RegEnumSubkeys(HKEY_LOCAL_MACHINE, k_NdisConn);
    int ndisPatched = 0;
    for (const auto& guidStr : nicGuids) {
        if (guidStr[0] != L'{') continue;
        std::wstring connPath = std::wstring(k_NdisConn) + L"\\" + guidStr
                                + L"\\Connection";
        std::wstring name;
        if (RegReadString(HKEY_LOCAL_MACHINE, connPath.c_str(), L"Name", name))
            ++ndisPatched;
    }
    if (ndisPatched > 0)
        LOGI(L"NDIS connections found: %d (GUID rotation needs kernel layer)", ndisPatched);

    res.ndisRegistryOk = (res.devicesPatched > 0);

    if (res.devicesPatched == 0)
        LOGW(L"No NIC devices patched — check elevation and NIC presence");

    return res;
}
